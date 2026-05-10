// CSM Layout - sidebar active state and theme toggle.
// Active link is driven by body[data-csm-page]; each nav <li> carries
// data-csm-route, which matches the page name set by the template's
// {{define "page"}} block. Falling back to URL prefix matching keeps
// deep-links and history redirects highlighted correctly.
(function() {
    var page = document.body.getAttribute('data-csm-page') || '';
    var pathname = window.location.pathname;
    var items = document.querySelectorAll('#csm-nav [data-csm-route]');
    var matched = false;
    for (var i = 0; i < items.length; i++) {
        var route = items[i].getAttribute('data-csm-route');
        var link = items[i].querySelector('a.nav-link');
        if (!link) continue;
        if (route && route === page) {
            link.classList.add('active');
            link.setAttribute('aria-current', 'page');
            matched = true;
        }
    }
    if (matched) return;
    // Fallback: match by URL prefix for routes without an explicit page name.
    for (var j = 0; j < items.length; j++) {
        var link2 = items[j].querySelector('a.nav-link');
        if (!link2) continue;
        var href = link2.getAttribute('href');
        if (href && href !== '/' && pathname.indexOf(href) === 0) {
            link2.classList.add('active');
            link2.setAttribute('aria-current', 'page');
            return;
        }
    }
})();

function applyTheme(t) {
    document.documentElement.setAttribute('data-bs-theme', t);
    document.documentElement.classList.remove('theme-dark', 'theme-light');
    document.documentElement.classList.add(t === 'light' ? 'theme-light' : 'theme-dark');
    var icon = document.querySelector('#theme-toggle i');
    if (icon) icon.className = t === 'light' ? 'ti ti-moon' : 'ti ti-sun';
}
function toggleTheme() {
    var current = document.documentElement.getAttribute('data-bs-theme') || 'dark';
    var next = current === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    localStorage.setItem('csm-theme', next);
}
applyTheme(__theme);
var _themeBtn = document.getElementById('theme-toggle');
if (_themeBtn) _themeBtn.addEventListener('click', toggleTheme);
// Display version in footer
(function() {
    var v = (typeof CSM_CONFIG !== 'undefined' && CSM_CONFIG.version) ? CSM_CONFIG.version : '';
    var el = document.getElementById('csm-version');
    if (el && v) el.textContent = 'v' + v;
})();

// Update-available banner. Reads /api/v1/status; renders nothing
// when the daemon hasn't completed a poll yet, when no newer
// release exists, or when updates.check_enabled is false (the
// snapshot omits the update block entirely in that case).
(function() {
    var banner = document.getElementById('csm-update-banner');
    if (!banner) return;

    fetch('/api/v1/status', { credentials: 'same-origin' })
        .then(function(r) { return r.ok ? r.json() : null; })
        .then(function(snap) {
            if (!snap || !snap.update || !snap.update.available || !snap.update.latest_version) return;
            var verEl = document.getElementById('csm-update-version');
            var curEl = document.getElementById('csm-update-current');
            var cmdEl = document.getElementById('csm-update-cmd');
            if (verEl) verEl.textContent = 'v' + snap.update.latest_version;
            if (curEl) curEl.textContent = 'v' + (snap.version || '');
            if (cmdEl) {
                var src = snap.update.source || 'apt';
                if (src === 'dnf') {
                    cmdEl.textContent = 'dnf upgrade csm';
                } else if (src === 'github') {
                    cmdEl.textContent = 'apt upgrade csm  # or dnf upgrade csm';
                } else {
                    cmdEl.textContent = src + ' upgrade csm';
                }
            }
            banner.classList.remove('d-none');
        })
        .catch(function() { /* network errors are handled by csm-connection-lost */ });
})();
