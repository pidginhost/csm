// CSM Theme init - runs in <head> to prevent flash of wrong theme
// Blocked storage (private windows, strict settings) throws; fall back to
// the system preference instead of leaving the page unthemed.
(function() {
    var theme = null;
    try { theme = localStorage.getItem('csm-theme'); } catch (e) { /* storage unavailable */ }
    if (theme !== 'light' && theme !== 'dark') {
        theme = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    }
    document.documentElement.setAttribute('data-bs-theme', theme);
    document.documentElement.className = theme === 'light' ? 'theme-light' : 'theme-dark';
})();
