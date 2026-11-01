/**
 * k8s/node-red/settings.js — Node-RED's settings file (IAM 3.3).
 *
 * A plain file, not a template: deploy-infra.sh puts it in ConfigMap node-red-settings as
 * it is (the chart mounts it at /data/settings.js) and stamps its sha256 on the pod
 * (medcea/settings-checksum), so a change here restarts Node-RED. Everything that differs
 * per install comes from the environment, set by k8s/node-red/values.yaml.
 *
 * adminAuth: the editor and its admin API sign people in a second time, through Keycloak
 * (strategy openidconnect, client node-red; autoLogin, so it is silent behind the proxy's
 * session). The rights come from /auth-policy/permissions.json (ConfigMap node-red-auth,
 * `cli.py compile node-red` from group flows), read again at every login and every API
 * call, so a policy change needs no restart: losing every right ends the editor session at
 * the next call; a narrower set applies at the next login. There is no default user: a role
 * the policy does not list gets nothing. apps/node-red/deploy.sh and uninstall.sh call the
 * admin API with the token in Secret node-red-admin-tokens (user system:deploy).
 *
 * Fail closed: when the OIDC module (installed by the init container) or the permissions
 * file cannot be loaded, the editor refuses everyone and only the deploy token works; the
 * ingest flow keeps running and health-check.sh noderedauth FAILs. NR_ADMIN_AUTH=off
 * (kubectl set env, the break-glass) turns adminAuth off; ./deploy-infra.sh turns it on.
 *
 * No httpNodeAuth (basic auth would be one shared password): the flows' http-in endpoints
 * are reachable only through the proxy, which admits the same roles, and NetworkPolicy
 * iam-node-red. Never log a token or a profile here.
 */
const crypto = require('crypto');
const fs = require('fs');

const env = process.env;
// Fixed in the pod (k8s/node-red/values.yaml); the overrides are for tests/test_node_red_flows.py.
const POLICY = env.NR_AUTH_POLICY_FILE || '/auth-policy/permissions.json';
const OIDC_MODULE = env.NR_AUTH_OIDC_MODULE || '/opt/nr-auth/node_modules/passport-openidconnect';
const roles = new Map();   // username -> realm roles (the groups claim) at the last login

function deployToken(token) {
    const want = Buffer.from(env.NR_DEPLOY_TOKEN || '');
    const got = Buffer.from(String(token || ''));
    if (want.length >= 32 && got.length === want.length && crypto.timingSafeEqual(got, want)) {
        return Promise.resolve({ username: 'system:deploy', permissions: '*' });
    }
    return Promise.resolve(null);
}

// The union of the permissions the policy gives a person's roles, or null for none.
function permissionsFor(held) {
    const given = JSON.parse(fs.readFileSync(POLICY, 'utf8')).permissions || {};
    const out = new Set();
    for (const r of held || []) {
        [].concat(given[r] || []).forEach(s => out.add(s));
    }
    return out.size ? Array.from(out).sort() : null;
}

function user(username) {
    if (!roles.has(username)) {
        return Promise.resolve(null);
    }
    try {
        const permissions = permissionsFor(roles.get(username));
        return Promise.resolve(permissions ? { username: username, permissions: permissions } : null);
    } catch (e) {
        console.error('[medcea] adminAuth: cannot read ' + POLICY + ': ' + e.message.split('\n')[0]);
        return Promise.resolve(null);
    }
}

// The editor's own session, in seconds (adminAuth.sessionExpiryTime: Node-RED 3.1 reads it
// only inside adminAuth; the top-level `sessionExpiryTime: 28800` this file had until
// 1 Nov 2026 was ignored, so editor sessions lasted Node-RED's default of a week).
// Decision of 1 Nov 2026 ("short sessions"): about 5 minutes for every tool, unless that
// drops work. For the editor it would: the session counts from sign-in and nothing extends
// it; at its end Node-RED tells the open editor "auth fail" on its websocket and the editor
// goes to its sign-in (silent through Keycloak while the SSO session lives, as whoever is
// signed in to Keycloak now). With undeployed changes the browser first asks to leave the
// page: leaving drops them; staying keeps an editor that can no longer deploy (401) until
// the flows are exported and the page reloaded. So one hour, not five minutes: an editing
// stretch without that interruption, and the same bound the platform already accepted
// for the other tools' sessions. Within it the editor keeps the identity of whoever signed
// in to it (its token is in the browser's storage): the next person in the same browser
// gets the earlier one's editor for at most this long (manual: known gaps).
const SESSION_EXPIRY_SECONDS = 3600;

// Sessions already stored keep the expiry they were issued with: Node-RED 3.1 writes each
// as {<token>: {user, client, scope, accessToken, expires}} (expires = issue time +
// sessionExpiryTime, in ms) to <userDir>/.sessions.json on the /data volume, and checks
// only that stored value. So when this bound is lowered (the week-long sessions before
// 1 Nov 2026), the ones issued under the longer value would outlive the deploy by days.
// This file runs at every start, before the runtime loads that file: drop each stored
// session whose expiry lies beyond now + this bound (one issued under it never does; a
// minute's slack for clock steps). Its holder's editor signs in again (silent through
// Keycloak, as whoever is signed in there now). Best effort: an unreadable or malformed
// file is left to Node-RED. Logs counts only, never a token or a username.
const SESSIONS_FILE = env.NR_SESSIONS_FILE || '/data/.sessions.json';

function capStoredSessions(file, boundSeconds, now) {
    let sessions;
    try {
        sessions = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (e) {
        return 0;                                   // none yet, or Node-RED's to handle
    }
    if (!sessions || typeof sessions !== 'object' || Array.isArray(sessions)) {
        return 0;
    }
    const limit = now + (boundSeconds + 60) * 1000;
    let dropped = 0;
    for (const t of Object.keys(sessions)) {
        const exp = sessions[t] && sessions[t].expires;
        if (typeof exp !== 'number' || exp > limit) {
            delete sessions[t];
            dropped++;
        }
    }
    if (dropped) {
        try {
            const tmp = file + '.medcea-tmp';
            fs.writeFileSync(tmp, JSON.stringify(sessions), { mode: 0o600 });
            fs.renameSync(tmp, file);
            console.warn('[medcea] ended ' + dropped + ' stored editor session(s) longer than ' + boundSeconds + ' s');
        } catch (e) {
            console.error('[medcea] cannot shorten the stored editor sessions: ' + e.message.split('\n')[0]);
            return 0;
        }
    }
    return dropped;
}
capStoredSessions(SESSIONS_FILE, SESSION_EXPIRY_SECONDS, Date.now());

function adminAuth() {
    if (env.NR_ADMIN_AUTH === 'off') {
        console.warn('[medcea] NR_ADMIN_AUTH=off: the editor and its admin API have no authentication (break-glass)');
        return undefined;
    }
    let Strategy;
    try {
        Strategy = require(OIDC_MODULE).Strategy;
        JSON.parse(fs.readFileSync(POLICY, 'utf8'));
    } catch (e) {
        console.error('[medcea] adminAuth: ' + e.message.split('\n')[0] + ' — the editor refuses everyone; only the deploy token works');
        return { type: 'credentials', users: [], tokens: deployToken, sessionExpiryTime: SESSION_EXPIRY_SECONDS };
    }
    return {
        type: 'strategy',
        strategy: {
            name: 'openidconnect',
            label: 'Sign in',
            icon: 'fa-sign-in',
            autoLogin: true,
            strategy: Strategy,
            options: {
                issuer: env.NR_OIDC_ISSUER,
                authorizationURL: env.NR_OIDC_AUTH_URL,      // public: the browser goes there
                tokenURL: env.NR_OIDC_TOKEN_URL,             // in-cluster: pods do not resolve the platform's names
                userInfoURL: env.NR_OIDC_USERINFO_URL,
                clientID: 'node-red',
                clientSecret: env.NR_OIDC_CLIENT_SECRET,
                callbackURL: env.NR_OIDC_CALLBACK,
                scope: ['profile', 'groups'],      // the library adds openid
                skipUserProfile: false,
                // Nine parameters on purpose: Node-RED 3.1 gives its wrapper this function's
                // arity, and only at nine does passport-openidconnect pass the userinfo
                // profile with its claims (_json, where the groups mapper puts the roles).
                // Node-RED replaces `done`; it then asks users() for the rights.
                verify: function (issuer, uiProfile, idProfile, context, idToken, accessToken, refreshToken, params, done) {
                    const claims = (uiProfile && uiProfile._json) || {};
                    const username = claims.preferred_username || (idProfile && idProfile.username);
                    if (!username) {
                        return done(null, false);
                    }
                    roles.set(username, Array.isArray(claims.groups) ? claims.groups : []);
                    done(null, { username: username });
                }
            }
        },
        users: user,
        tokens: deployToken,
        sessionExpiryTime: SESSION_EXPIRY_SECONDS
    };
}

module.exports = {
    flowFile: 'flows.json',
    flowFilePretty: true,
    uiPort: env.PORT || 1880,

    adminAuth: adminAuth(),   // its sessionExpiryTime: SESSION_EXPIRY_SECONDS above

    diagnostics: { enabled: true, ui: true },
    runtimeState: { enabled: false, ui: false },
    // audit: every deploy, palette and login event is logged with the username
    logging: { console: { level: 'info', metrics: false, audit: true } },

    exportGlobalContextKeys: false,
    externalModules: {},
    // Palette modules come only from apps/node-red/packages.txt in git (IAM 3.3), so a
    // function node cannot install npm modules of its own either.
    functionExternalModules: false,
    functionTimeout: 0,
    functionGlobalContext: {},
    debugMaxLength: 1000,
    mqttReconnectTime: 15000,
    serialReconnectTime: 15000,

    editorTheme: {
        palette: {},
        projects: { enabled: false, workflow: { mode: 'manual' } },
        codeEditor: { lib: 'monaco', options: {} }
    }
};
