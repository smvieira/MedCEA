<#-- The platform's single entry page: Sign in (Keycloak's own form, posted to
     url.loginAction) and Request access (posted with fetch to the access
     service, apps/access, which creates the account disabled until an admin
     approves it). /#register opens the second tab; access.<domain>/register
     redirects here. No JS template literals below: ${...} is FreeMarker. -->
<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('username','password') displayInfo=false; section>
    <#if section = "header">
        <div class="tabs" role="tablist">
            <button type="button" class="tab on" id="tab-signin" role="tab" aria-selected="true" aria-controls="pane-signin">Sign in</button>
            <button type="button" class="tab" id="tab-register" role="tab" aria-selected="false" aria-controls="pane-register">Request access</button>
        </div>
    <#elseif section = "form">
        <div id="pane-signin" role="tabpanel" aria-labelledby="tab-signin">
        <#if realm.password>
            <form id="kc-form-login" class="form" onsubmit="login.disabled = true; return true;" action="${url.loginAction}" method="post">
                <#if !usernameHidden??>
                    <div class="field">
                        <label for="username" class="label"><#if !realm.loginWithEmailAllowed>${msg("username")}<#elseif !realm.registrationEmailAsUsername>${msg("usernameOrEmail")}<#else>${msg("email")}</#if></label>
                        <input tabindex="1" id="username" class="input" name="username" value="${(login.username!'')}" type="text" autofocus autocomplete="username"
                               aria-invalid="<#if messagesPerField.existsError('username','password')>true</#if>" dir="ltr"/>
                    </div>
                </#if>
                <div class="field">
                    <label for="password" class="label">${msg("password")}</label>
                    <div class="input-group">
                        <input tabindex="2" id="password" class="input" name="password" type="password" autocomplete="current-password"
                               aria-invalid="<#if messagesPerField.existsError('username','password')>true</#if>"/>
                        <button type="button" class="pw-toggle" data-for="password" aria-label="${msg("showPassword")}">Show</button>
                    </div>
                    <#if messagesPerField.existsError('username','password')>
                        <span class="field-error" aria-live="polite">${kcSanitize(messagesPerField.getFirstError('username','password'))?no_esc}</span>
                    </#if>
                </div>
                <div class="options">
                    <#if realm.rememberMe && !usernameHidden??>
                        <label class="check"><input tabindex="3" id="rememberMe" name="rememberMe" type="checkbox" <#if login.rememberMe??>checked</#if>> ${msg("rememberMe")}</label>
                    <#else><span></span></#if>
                    <#if realm.resetPasswordAllowed>
                        <a tabindex="5" class="link" href="${url.loginResetCredentialsUrl}">${msg("doForgotPassword")}</a>
                    </#if>
                </div>
                <input type="hidden" id="id-hidden-input" name="credentialId" <#if auth.selectedCredential?has_content>value="${auth.selectedCredential}"</#if>/>
                <button tabindex="4" class="btn btn-primary btn-block" name="login" id="kc-login" type="submit">${msg("doLogIn")}</button>
            </form>
        </#if>
            <p class="hint">No account yet? <a href="#register" class="link" data-tab="register">Request access</a> &mdash; an administrator reviews each request.</p>
        </div>

        <div id="pane-register" role="tabpanel" aria-labelledby="tab-register" hidden>
            <form id="reg" class="form" novalidate>
                <div class="row">
                    <div class="field"><label class="label" for="r_first">First name</label><input class="input" id="r_first" name="first_name" autocomplete="given-name" required maxlength="100"></div>
                    <div class="field"><label class="label" for="r_last">Last name</label><input class="input" id="r_last" name="last_name" autocomplete="family-name" required maxlength="100"></div>
                </div>
                <div class="field"><label class="label" for="r_email">E-mail</label><input class="input" id="r_email" name="email" type="email" autocomplete="email" required maxlength="254"></div>
                <div class="field"><label class="label" for="r_org">Organisation <span class="opt">optional</span></label><input class="input" id="r_org" name="organisation" autocomplete="organization" maxlength="200"></div>
                <div class="field"><label class="label" for="r_user">Username <span class="opt">lowercase, digits, . _ -</span></label>
                    <input class="input" id="r_user" name="username" autocomplete="username" required minlength="3" maxlength="32" pattern="[a-z0-9][a-z0-9._-]{2,31}"></div>
                <div class="row">
                    <div class="field"><label class="label" for="r_pw">Password <span class="opt">10+ characters</span></label>
                        <div class="input-group"><input class="input" id="r_pw" name="password" type="password" autocomplete="new-password" required minlength="10" maxlength="128">
                        <button type="button" class="pw-toggle" data-for="r_pw" aria-label="${msg("showPassword")}">Show</button></div></div>
                    <div class="field"><label class="label" for="r_pw2">Repeat password</label><input class="input" id="r_pw2" type="password" autocomplete="new-password" required></div>
                </div>
                <div class="field"><span class="label">Role you need</span><div class="roles" id="r_roles"><div class="muted">Loading roles…</div></div></div>
                <div class="field"><label class="label" for="r_just">Business justification <span class="opt">what you will use the platform for, 20+ characters</span></label>
                    <textarea class="input" id="r_just" name="justification" required minlength="20" maxlength="2000" rows="4"></textarea>
                    <div class="count"><span id="r_jc">0</span> / 2000</div></div>
                <input class="hp" name="website" tabindex="-1" autocomplete="off" aria-hidden="true">
                <div id="r_msg" class="alert" role="status" hidden><span class="alert-text"></span></div>
                <button id="r_go" class="btn btn-primary btn-block" type="submit">Submit request</button>
            </form>
            <p class="hint">Already approved? <a href="#signin" class="link" data-tab="signin">Sign in</a></p>
        </div>

        <script>
        (function () {
            var ACCESS = "${properties.accessUrl!''}";
            function $(id) { return document.getElementById(id); }

            // Tabs ------------------------------------------------------------
            function show(which) {
                var reg = which === 'register';
                $('pane-signin').hidden = reg; $('pane-register').hidden = !reg;
                $('tab-signin').classList.toggle('on', !reg); $('tab-register').classList.toggle('on', reg);
                $('tab-signin').setAttribute('aria-selected', String(!reg)); $('tab-register').setAttribute('aria-selected', String(reg));
                if (reg) loadRoles();
                var first = reg ? $('r_first') : $('username');
                if (first) first.focus();
            }
            $('tab-signin').onclick = function () { history.replaceState(null, '', '#signin'); show('signin'); };
            $('tab-register').onclick = function () { history.replaceState(null, '', '#register'); show('register'); };
            document.querySelectorAll('[data-tab]').forEach(function (a) {
                a.addEventListener('click', function (e) { e.preventDefault(); history.replaceState(null, '', '#' + a.dataset.tab); show(a.dataset.tab); });
            });
            if (location.hash === '#register') show('register');

            // Show / hide password ------------------------------------------
            document.querySelectorAll('.pw-toggle').forEach(function (b) {
                b.addEventListener('click', function () {
                    var i = $(b.dataset.for), vis = i.type === 'password';
                    i.type = vis ? 'text' : 'password'; b.textContent = vis ? 'Hide' : 'Show';
                });
            });

            // Request access --------------------------------------------------
            var rolesLoaded = false;
            function loadRoles() {
                if (rolesLoaded) return;
                fetch(ACCESS + '/api/register/roles').then(function (r) {
                    if (!r.ok) throw new Error();
                    return r.json();
                }).then(function (roles) {
                    rolesLoaded = true;
                    var box = $('r_roles'); box.textContent = '';
                    roles.forEach(function (role, n) {
                        var l = document.createElement('label'); l.className = 'role';
                        var i = document.createElement('input'); i.type = 'radio'; i.name = 'requested_role'; i.value = role.id; if (n === 0) i.checked = true;
                        var parts = role.label.split(' — ');
                        var t = document.createElement('span'); t.className = 'role-t'; t.textContent = parts[0];
                        var d = document.createElement('span'); d.className = 'role-d'; d.textContent = parts[1] || '';
                        var s = document.createElement('span'); s.append(t, d);
                        l.append(i, s); box.append(l);
                    });
                }).catch(function () {
                    var box = $('r_roles'); box.textContent = '';
                    var m = document.createElement('div'); m.className = 'alert alert-warning';
                    m.textContent = 'Registration is not available right now. Please try again later.';
                    box.append(m); $('r_go').disabled = true;
                });
            }
            var j = $('r_just');
            j.addEventListener('input', function () { $('r_jc').textContent = j.value.length; });
            function note(kind, text) {
                var m = $('r_msg'); m.hidden = false; m.className = 'alert alert-' + kind;
                m.querySelector('.alert-text').textContent = text;
            }
            // What is wrong with a field, from the browser's own verdict, so the
            // message never disagrees with the minlength/pattern in the markup.
            function why(el) {
                var v = el.validity, n = el.value.length;
                if (v.valueMissing) return 'required';
                if (v.tooShort) return 'at least ' + el.minLength + ' characters (you have ' + n + ')';
                if (v.tooLong) return 'at most ' + el.maxLength + ' characters (you have ' + n + ')';
                if (v.typeMismatch) return 'not a valid e-mail address';
                var hint = el.labels && el.labels[0] && el.labels[0].querySelector('.opt');
                if (v.patternMismatch && hint) return 'use ' + hint.textContent;
                return 'not valid';
            }
            $('reg').addEventListener('submit', function (e) {
                e.preventDefault();
                var f = e.target, go = $('r_go');
                var d = {}; new FormData(f).forEach(function (v, k) { d[k] = v; });
                if (!d.requested_role) return note('error', 'Choose the role you need.');
                if (d.password !== $('r_pw2').value) return note('error', 'The two passwords do not match.');
                if (!f.checkValidity()) {
                    var bad = f.querySelector(':invalid'); bad.focus();
                    var lab = bad.labels && bad.labels[0] ? bad.labels[0].firstChild.textContent.trim() : bad.name;
                    return note('error', lab + ': ' + why(bad) + '.');
                }
                go.disabled = true; go.textContent = 'Submitting…';
                fetch(ACCESS + '/api/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(d) })
                    .then(function (r) { return r.json().catch(function () { return {}; }).then(function (b) { return [r, b]; }); })
                    .then(function (rb) {
                        var r = rb[0], b = rb[1];
                        if (r.ok && b.ok) {
                            f.querySelectorAll('input,textarea,button').forEach(function (x) { x.disabled = true; });
                            go.textContent = 'Request sent';
                            return note('success', b.message);
                        }
                        go.disabled = false; go.textContent = 'Submit request';
                        note('error', b.error || ('Request failed (HTTP ' + r.status + ').'));
                    })
                    .catch(function () {
                        go.disabled = false; go.textContent = 'Submit request';
                        note('error', 'Could not reach the server. Check your connection and try again.');
                    });
            });
        })();
        </script>
    <#elseif section = "socialProviders">
        <#if realm.password && social?? && social.providers?has_content>
            <div class="social">
                <#list social.providers as p>
                    <a id="social-${p.alias}" class="btn btn-secondary btn-block" href="${p.loginUrl}">${p.displayName!}</a>
                </#list>
            </div>
        </#if>
    </#if>
</@layout.registrationLayout>
