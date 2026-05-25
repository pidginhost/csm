// CSM.prefs - operator preferences applied at layout boot (WEB_ROADMAP P5.4).
//
// Loads the current operator's saved user prefs from /api/v1/prefs/user once
// per page load, applies them to the document chrome (density / timezone /
// default auto-refresh / per-table column visibility) and exposes a small
// imperative API for the preferences modal and other features that need to
// read or write the operator's prefs.
//
// All UI consumers should access state through CSM.prefs.user, never via
// localStorage directly, so that one operator's preferences travel with their
// token across browsers and devices.
var CSM = CSM || {};

CSM.prefs = (function() {
    var DEFAULTS = {
        density: 'comfortable',
        timezone: 'local',
        auto_refresh: 'on',
        table_columns: {}
    };

    var state = cloneDefaults();
    var loadPromise = null;
    var listeners = [];

    function cloneDefaults() {
        return {
            density: DEFAULTS.density,
            timezone: DEFAULTS.timezone,
            auto_refresh: DEFAULTS.auto_refresh,
            table_columns: {}
        };
    }

    function merge(target, src) {
        if (!src || typeof src !== 'object') return target;
        if (typeof src.density === 'string' && src.density) target.density = src.density;
        if (typeof src.timezone === 'string' && src.timezone) target.timezone = src.timezone;
        if (typeof src.auto_refresh === 'string' && src.auto_refresh) target.auto_refresh = src.auto_refresh;
        if (src.table_columns && typeof src.table_columns === 'object') {
            target.table_columns = {};
            Object.keys(src.table_columns).forEach(function(k) {
                var v = src.table_columns[k];
                if (Array.isArray(v)) {
                    target.table_columns[k] = v.slice();
                }
            });
        }
        return target;
    }

    function applyDensity() {
        var density = state.density === 'compact' ? 'compact' : 'comfortable';
        document.documentElement.setAttribute('data-csm-density', density);
    }

    function applyAutoRefresh() {
        // Server prefs only seed a fresh device. Once the operator has clicked
        // the topbar toggle in this browser the localStorage choice wins, so a
        // saved "off" preference does not override an explicit per-device "on".
        if (!CSM || !CSM.refresh || typeof CSM.refresh.setEnabled !== 'function') return;
        if (CSM.refresh.hasPersistedChoice) return;
        if (state.auto_refresh === 'off') {
            CSM.refresh.setEnabled(false, { transient: true });
        }
    }

    function applyAll() {
        applyDensity();
        applyAutoRefresh();
        document.documentElement.setAttribute('data-csm-tz', state.timezone || 'local');
        listeners.slice().forEach(function(fn) {
            try { fn(state); } catch (e) { /* listeners must not throw */ }
        });
    }

    function load() {
        if (loadPromise) return loadPromise;
        if (typeof CSM === 'undefined' || !CSM.request) {
            loadPromise = Promise.resolve(state);
            applyAll();
            return loadPromise;
        }
        loadPromise = CSM.request('/api/v1/prefs/user', {
            headers: { Accept: 'application/json' },
            allowNonOK: true,
            silent: true
        }).then(function(r) {
            return r && r.ok ? r.json() : null;
        }).then(function(blob) {
            merge(state, blob);
            applyAll();
            return state;
        }).catch(function() {
            applyAll();
            return state;
        });
        return loadPromise;
    }

    function save(patch) {
        var next = cloneDefaults();
        merge(next, state);
        merge(next, patch);
        if (typeof CSM === 'undefined' || !CSM.request) {
            state = next;
            applyAll();
            return Promise.resolve(state);
        }
        return CSM.request('/api/v1/prefs/user', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                Accept: 'application/json',
                'X-CSRF-Token': CSM.csrfToken
            },
            body: JSON.stringify(next),
            allowNonOK: false
        }).then(function(r) { return r.json(); }).then(function(blob) {
            state = cloneDefaults();
            merge(state, blob);
            applyAll();
            return state;
        });
    }

    function get() { return state; }

    function onChange(fn) {
        if (typeof fn !== 'function') return function() {};
        listeners.push(fn);
        try { fn(state); } catch (e) { /* swallow */ }
        return function() {
            listeners = listeners.filter(function(other) { return other !== fn; });
        };
    }

    // Format a Date according to the operator's timezone preference. Returns
    // a YYYY-MM-DD HH:MM:SS string in the chosen zone. "server" defers to
    // the layout's data-csm-server-tz hint; "local" uses the browser tz.
    function formatDateTime(d) {
        if (!(d instanceof Date)) return '';
        var tz = state.timezone || 'local';
        var opts = { year: 'numeric', month: '2-digit', day: '2-digit',
                     hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false };
        if (tz === 'server') {
            var server = document.documentElement.getAttribute('data-csm-server-tz') || 'UTC';
            opts.timeZone = server;
        } else if (tz !== 'local') {
            opts.timeZone = tz;
        }
        try {
            return new Intl.DateTimeFormat('en-GB', opts).format(d).replace(',', '');
        } catch (e) {
            return d.toString();
        }
    }

    return {
        user: state,
        load: load,
        save: save,
        get: get,
        onChange: onChange,
        formatDateTime: formatDateTime,
        defaults: function() { return cloneDefaults(); }
    };
})();

// Kick off loading immediately. Pages that need to wait can chain on
// CSM.prefs.load(); pages that don't simply benefit from the eventual apply.
if (typeof CSM !== 'undefined' && CSM.prefs) {
    CSM.prefs.load();
}
