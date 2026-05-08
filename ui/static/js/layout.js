// CSM Layout - nav active state and theme toggle
document.querySelectorAll('#csm-nav a[href]').forEach(function(a){
    var href = a.getAttribute('href');
    if (href && href !== '#' && href !== '/' && window.location.pathname.indexOf(href) === 0) {
        a.classList.add('active');
        var dropdown = a.closest('.dropdown');
        if (dropdown) {
            var toggle = dropdown.querySelector('.nav-link.dropdown-toggle');
            if (toggle) toggle.classList.add('active');
        }
    }
});
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
