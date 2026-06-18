// CSM Login page - apply saved theme
var saved = localStorage.getItem('csm-theme');
var theme = saved || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
document.documentElement.setAttribute('data-bs-theme', theme);
document.documentElement.className = theme === 'light' ? 'theme-light' : 'theme-dark';
document.body.className = (theme === 'light' ? 'theme-light' : 'theme-dark') + ' d-flex flex-column';

// Lock the submit button on the first submit so a slow login round-trip
// cannot be double-submitted. The native POST still proceeds; the token
// input carries the credential, so disabling the button is safe.
(function() {
    var form = document.getElementById('login-form');
    var btn = document.getElementById('login-submit');
    if (!form || !btn) return;
    form.addEventListener('submit', function() {
        if (btn.disabled) return;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>Signing in...';
    });
})();
