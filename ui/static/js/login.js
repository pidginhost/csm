// CSM Login page - apply saved theme
var saved = localStorage.getItem('csm-theme');
var theme = saved || (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
document.documentElement.setAttribute('data-bs-theme', theme);
document.documentElement.className = theme === 'light' ? 'theme-light' : 'theme-dark';
document.body.className = (theme === 'light' ? 'theme-light' : 'theme-dark') + ' d-flex flex-column';
