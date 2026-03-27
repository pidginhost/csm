// CSM Theme init — runs in <head> to prevent flash of wrong theme
var __theme = localStorage.getItem('csm-theme') || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
document.documentElement.setAttribute('data-bs-theme', __theme);
document.documentElement.className = __theme === 'light' ? 'theme-light' : 'theme-dark';
