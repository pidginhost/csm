// CSM Layout — nav active state and theme toggle
document.querySelectorAll('#csm-nav a.nav-link').forEach(function(a){
    var href = a.getAttribute('href');
    if (href && href !== '/' && window.location.pathname.indexOf(href) === 0) a.classList.add('active');
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
