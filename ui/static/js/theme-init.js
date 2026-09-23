// CSM Theme init - runs in <head> to prevent flash of wrong theme
// Blocked storage (private windows, strict settings) throws; fall back to
// the system preference instead of leaving the page unthemed.
var __theme = null;
try { __theme = localStorage.getItem('csm-theme'); } catch (e) { /* storage unavailable */ }
if (__theme !== 'light' && __theme !== 'dark') {
    __theme = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}
document.documentElement.setAttribute('data-bs-theme', __theme);
document.documentElement.className = __theme === 'light' ? 'theme-light' : 'theme-dark';
