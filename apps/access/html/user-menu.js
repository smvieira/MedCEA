/* MedCEA user menu — the signed-in person's name, opening Profile and Sign out.
 * One script for every signed-in page (portal, config UI, User Manager). Each
 * host serves it at /_account/user-menu.js through its own oauth2-proxy, and
 * /_account/api/me answers for whoever that proxy signed in.
 *
 * Usage: <div id="user-menu"></div> where it should sit (optional — without
 * it the menu pins itself top-right) and
 *        <script src="/_account/user-menu.js" defer></script>
 */
(function () {
  var css = '' +
    '.um{position:relative;font-family:"Segoe UI",system-ui,sans-serif;z-index:1000}' +
    '.um-fixed{position:fixed;top:16px;right:20px}' +
    '.um-btn{display:inline-flex;align-items:center;gap:9px;background:#1e293b;border:1px solid #2a364e;color:#e2e8f0;' +
      'padding:6px 12px 6px 6px;border-radius:999px;cursor:pointer;font:500 .875rem "Segoe UI",system-ui,sans-serif;max-width:260px}' +
    '.um-btn:hover,.um.open .um-btn{background:#2a364e;border-color:#3b82f6}' +
    '.um-av{width:28px;height:28px;border-radius:50%;background:linear-gradient(135deg,#2563eb,#16a34a);color:#fff;' +
      'display:inline-flex;align-items:center;justify-content:center;font:700 .72rem "Segoe UI",system-ui,sans-serif;flex:none;letter-spacing:.02em}' +
    '.um-nm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}' +
    '.um-car{width:10px;height:10px;flex:none;opacity:.7;transition:transform .15s}' +
    '.um.open .um-car{transform:rotate(180deg)}' +
    '.um-dd{position:absolute;right:0;top:calc(100% + 8px);min-width:200px;background:#1e2532;border:1px solid #2a364e;' +
      'border-radius:12px;box-shadow:0 12px 32px rgba(0,0,0,.5);padding:6px;display:none}' +
    '.um.open .um-dd{display:block}' +
    '.um-dd a{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:8px;color:#cbd5e1;text-decoration:none;font-size:.875rem}' +
    '.um-dd a:hover,.um-dd a:focus{background:#2a364e;color:#fff;outline:none}' +
    '.um-dd svg{width:16px;height:16px;flex:none}' +
    '.um-sep{height:1px;background:#2a364e;margin:6px 4px}';

  function icon(d) {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' + d + '</svg>';
  }
  var ICON_USER = icon('<path d="M19 21v-2a4 4 0 0 0-4-4H9a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>');
  var ICON_OUT = icon('<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" x2="9" y1="12" y2="12"/>');

  function initials(name) {
    var p = name.trim().split(/\s+/);
    return ((p[0] || '?')[0] + (p.length > 1 ? p[p.length - 1][0] : '')).toUpperCase();
  }

  function mount(host, me) {
    var root = document.createElement('div');
    root.className = 'um' + (host ? '' : ' um-fixed');
    var btn = document.createElement('button');
    btn.type = 'button'; btn.className = 'um-btn';
    btn.setAttribute('aria-haspopup', 'menu'); btn.setAttribute('aria-expanded', 'false');
    var av = document.createElement('span'); av.className = 'um-av'; av.textContent = initials(me.display_name);
    var nm = document.createElement('span'); nm.className = 'um-nm'; nm.textContent = me.display_name;
    btn.append(av, nm);
    btn.insertAdjacentHTML('beforeend', '<svg class="um-car" viewBox="0 0 10 10"><path d="M1 3l4 4 4-4" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>');

    var dd = document.createElement('div'); dd.className = 'um-dd'; dd.setAttribute('role', 'menu');
    var prof = document.createElement('a'); prof.href = '/_account/'; prof.setAttribute('role', 'menuitem');
    prof.innerHTML = ICON_USER; prof.append(document.createTextNode('Profile'));
    var sep = document.createElement('div'); sep.className = 'um-sep';
    var out = document.createElement('a'); out.href = me.sign_out || '/oauth2/sign_out'; out.setAttribute('role', 'menuitem');
    out.innerHTML = ICON_OUT; out.append(document.createTextNode('Sign out'));
    dd.append(prof, sep, out);
    root.append(btn, dd);

    function set(open) { root.classList.toggle('open', open); btn.setAttribute('aria-expanded', String(open)); }
    btn.addEventListener('click', function (e) { e.stopPropagation(); set(!root.classList.contains('open')); });
    document.addEventListener('click', function (e) { if (!root.contains(e.target)) set(false); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') set(false); });

    (host || document.body).appendChild(root);
  }

  function start() {
    var style = document.createElement('style'); style.textContent = css; document.head.appendChild(style);
    var host = document.getElementById('user-menu');
    fetch('/_account/api/me', { credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error(r.status); return r.json(); })
      .then(function (me) { mount(host, me); })
      .catch(function () {
        // Profile service unavailable: never leave someone without a way out.
        mount(host, { display_name: 'Account', sign_out: '/oauth2/sign_out' });
      });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();
