// CSM Layout - sidebar state and theme toggle.
// Active link is driven by body[data-csm-page]; each nav <li> carries
// data-csm-route, which matches the page name set by the template's
// {{define "page"}} block. Falling back to URL prefix matching keeps
// deep-links and history redirects highlighted correctly.
(function() {
    var NAV_GROUP_STATE_KEY = 'csm-nav-groups';
    var page = document.body.getAttribute('data-csm-page') || '';
    var pathname = window.location.pathname;
    var items = document.querySelectorAll('#csm-nav [data-csm-route]');

    function navScope() {
        if (typeof CSM_CONFIG !== 'undefined' && CSM_CONFIG.authScope) {
            return CSM_CONFIG.authScope;
        }
        return 'admin';
    }

    function hideReadScopeAdminItems() {
        if (navScope() !== 'read') return;
        var adminOnly = document.querySelectorAll('#csm-nav [data-csm-admin-only]');
        for (var i = 0; i < adminOnly.length; i++) {
            adminOnly[i].hidden = true;
        }
    }

    function activateCurrentItem() {
        var activeGroup = null;
        var matched = false;
        var i;

        for (i = 0; i < items.length; i++) {
            if (items[i].hidden) continue;
            var route = items[i].getAttribute('data-csm-route');
            var link = items[i].querySelector('a.nav-link');
            if (!link) continue;
            if (route && route === page) {
                link.classList.add('active');
                link.setAttribute('aria-current', 'page');
                activeGroup = items[i].closest('[data-csm-nav-group]');
                matched = true;
            }
        }
        if (matched) return activeGroup;

        // Fallback: prefer the longest matching URL so /modsec/rules does
        // not get swallowed by the shorter /modsec entry.
        var best = null;
        var bestLen = -1;
        for (i = 0; i < items.length; i++) {
            if (items[i].hidden) continue;
            var link2 = items[i].querySelector('a.nav-link');
            if (!link2) continue;
            var href = link2.getAttribute('href');
            if (!href || href === '/') continue;
            if ((pathname === href || pathname.indexOf(href + '/') === 0) && href.length > bestLen) {
                best = { item: items[i], link: link2 };
                bestLen = href.length;
            }
        }
        if (!best) return null;
        best.link.classList.add('active');
        best.link.setAttribute('aria-current', 'page');
        return best.item.closest('[data-csm-nav-group]');
    }

    function readGroupState() {
        try {
            return JSON.parse(localStorage.getItem(NAV_GROUP_STATE_KEY) || '{}') || {};
        } catch (e) {
            return {};
        }
    }

    function writeGroupState(state) {
        try {
            localStorage.setItem(NAV_GROUP_STATE_KEY, JSON.stringify(state));
        } catch (e) { /* localStorage may be unavailable */ }
    }

    function setGroupExpanded(group, expanded) {
        var button = group.querySelector('[data-csm-nav-toggle]');
        var list = group.querySelector('.navbar-nav');
        group.classList.toggle('is-collapsed', !expanded);
        if (button) button.setAttribute('aria-expanded', expanded ? 'true' : 'false');
        if (list) list.hidden = !expanded;
    }

    function initNavGroups(activeGroup) {
        var state = readGroupState();
        var groups = document.querySelectorAll('#csm-nav [data-csm-nav-group]');
        for (var i = 0; i < groups.length; i++) {
            if (groups[i].hidden) continue;
            var name = groups[i].getAttribute('data-csm-nav-group');
            var expanded = state[name] !== false;
            if (groups[i] === activeGroup) {
                expanded = true;
                state[name] = true;
            }
            setGroupExpanded(groups[i], expanded);
            var toggle = groups[i].querySelector('[data-csm-nav-toggle]');
            if (toggle) {
                toggle.addEventListener('click', function() {
                    var group = this.closest('[data-csm-nav-group]');
                    if (!group) return;
                    var groupName = group.getAttribute('data-csm-nav-group');
                    var nextExpanded = group.classList.contains('is-collapsed');
                    setGroupExpanded(group, nextExpanded);
                    state[groupName] = nextExpanded;
                    writeGroupState(state);
                });
            }
        }
        writeGroupState(state);
    }

    hideReadScopeAdminItems();
    var activeGroup = activateCurrentItem();
    initNavGroups(activeGroup);
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

    CSM.request('/api/v1/status', { headers: { Accept: 'application/json' }, allowNonOK: true, silent: true })
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
        .catch(function() { /* optional update banner */ });
})();

// Auto-refresh pill: shows "Updated Ns ago" and lets the user pause or
// trigger a manual refresh. Wired against CSM.refresh which receives
// bump() calls from CSM.request on every successful response, so the
// pill stays accurate without per-page wiring.
(function() {
    var pill = document.getElementById('csm-refresh-pill');
    var ageEl = document.getElementById('csm-refresh-age');
    var nowBtn = document.getElementById('csm-refresh-now');
    var toggleBtn = document.getElementById('csm-refresh-toggle');
    if (!pill || !ageEl || !nowBtn || !toggleBtn || typeof CSM === 'undefined' || !CSM.refresh) return;

    pill.classList.remove('d-none');
    nowBtn.classList.remove('d-none');
    toggleBtn.classList.remove('d-none');

    function ageLabel(ms) {
        if (!ms) return 'Never updated';
        var diff = Math.max(0, Math.floor((Date.now() - ms) / 1000));
        if (diff < 5) return 'Updated just now';
        if (diff < 60) return 'Updated ' + diff + 's ago';
        if (diff < 3600) return 'Updated ' + Math.floor(diff / 60) + 'm ago';
        if (diff < 86400) return 'Updated ' + Math.floor(diff / 3600) + 'h ago';
        return 'Updated ' + Math.floor(diff / 86400) + 'd ago';
    }

    function paintAge() {
        ageEl.textContent = ageLabel(CSM.refresh.lastFetchAt);
    }

    function paintToggle() {
        var enabled = CSM.refresh.enabled;
        toggleBtn.setAttribute('aria-pressed', enabled ? 'true' : 'false');
        var icon = toggleBtn.querySelector('i');
        if (icon) icon.className = enabled ? 'ti ti-player-pause' : 'ti ti-player-play';
        toggleBtn.title = enabled ? 'Auto-refresh: on (click to pause)' : 'Auto-refresh: paused (click to resume)';
        toggleBtn.setAttribute('aria-label', enabled ? 'Pause auto-refresh' : 'Resume auto-refresh');
        pill.classList.toggle('text-muted', enabled);
        pill.classList.toggle('text-warning', !enabled);
    }

    paintAge();
    paintToggle();

    // Tick once a second so "Ns ago" stays current without waiting for
    // the next fetch.
    var tickId = setInterval(paintAge, 1000);
    window.addEventListener('beforeunload', function() { clearInterval(tickId); });
    window.addEventListener('csm:refresh-bump', paintAge);
    window.addEventListener('csm:refresh-toggle', paintToggle);

    nowBtn.addEventListener('click', function() { CSM.refresh.manual(); });
    toggleBtn.addEventListener('click', function() { CSM.refresh.setEnabled(!CSM.refresh.enabled); });
})();

// What's new badge (WEB_ROADMAP P5.7). Shows a notification dot on a
// header button whenever the running daemon version differs from the
// version the operator has acknowledged in localStorage. Clicking the
// button opens the GitHub releases page in a new tab and records the
// current version as acknowledged so the dot clears.
(function() {
    var btn = document.getElementById('csm-whats-new');
    if (!btn) return;
    var current = (typeof CSM_CONFIG !== 'undefined' && CSM_CONFIG.version) ? String(CSM_CONFIG.version) : '';
    if (!current) return;
    var STORAGE_KEY = 'csm-whatsnew-ack';
    var acknowledged = '';
    try { acknowledged = localStorage.getItem(STORAGE_KEY) || ''; } catch (e) { /* localStorage unavailable */ }
    var dot = btn.querySelector('.csm-whats-new-dot');
    btn.classList.remove('d-none');
    if (acknowledged !== current) {
        if (dot) dot.style.display = '';
        btn.setAttribute('title', "What's new in v" + current);
        btn.setAttribute('aria-label', "What's new in v" + current);
    } else if (dot) {
        dot.style.display = 'none';
    }
    btn.addEventListener('click', function() {
        try { localStorage.setItem(STORAGE_KEY, current); } catch (e) { /* ignore */ }
        if (dot) dot.style.display = 'none';
    });
})();
