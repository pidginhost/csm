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
// token across browsers and devices. The server copy is the source of truth;
// this browser keeps the last one it saw so the first render already uses it.
var CSM = CSM || {};

CSM.prefs = (function() {
    var DEFAULTS = {
        density: 'comfortable',
        timezone: 'local',
        auto_refresh: 'on',
        table_columns: {}
    };

    var CACHE_KEY = 'csm-prefs';

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

    // replaceState swaps in src while keeping the one object CSM.prefs.user
    // exposes.
    function replaceState(src) {
        var next = merge(cloneDefaults(), src);
        Object.keys(state).forEach(function(k) { delete state[k]; });
        Object.assign(state, next);
    }

    function readCache() {
        try {
            var raw = window.localStorage.getItem(CACHE_KEY);
            return raw ? JSON.parse(raw) : null;
        } catch (e) {
            return null;
        }
    }

    // writeCache reports whether the next page load will see state.
    function writeCache() {
        try {
            var raw = JSON.stringify(state);
            window.localStorage.setItem(CACHE_KEY, raw);
            return window.localStorage.getItem(CACHE_KEY) === raw;
        } catch (e) {
            return false;
        }
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
        var want = state.auto_refresh !== 'off';
        if (CSM.refresh.enabled !== want) CSM.refresh.setEnabled(want, { transient: true });
    }

    function applyAll() {
        applyDensity();
        applyAutoRefresh();
        document.documentElement.setAttribute('data-csm-tz', state.timezone || 'local');
        listeners.slice().forEach(function(fn) {
            try { fn(state); } catch (e) { /* listeners must not throw */ }
        });
    }

    // Dates already on screen were formatted in this zone. A different zone
    // needs a reload, because pages do not re-render their dates.
    merge(state, readCache());
    var renderedZone = state.timezone;
    applyAll();

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
            if (!blob) {
                applyAll();
                return state;
            }
            replaceState(blob);
            var cached = writeCache();
            applyAll();
            // Only reload when the next load will start from this copy, so a
            // browser that cannot store it never reloads in a loop.
            if (cached && state.timezone !== renderedZone) window.location.reload();
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
            replaceState(blob);
            writeCache();
            applyAll();
            if (state.timezone !== renderedZone) window.location.reload();
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

    // serverZone describes the server's zone from the layout: its IANA name
    // when the daemon knows it, else its current UTC offset in minutes.
    function serverZone() {
        var html = document.documentElement;
        var name = html.getAttribute('data-csm-server-tz') || '';
        var offset = parseInt(html.getAttribute('data-csm-server-offset') || '0', 10);
        return { name: name, offsetMinutes: isFinite(offset) ? offset : 0 };
    }

    function offsetLabel(minutes) {
        var sign = minutes < 0 ? '-' : '+';
        var abs = Math.abs(minutes);
        return 'UTC' + sign + String(Math.floor(abs / 60)).padStart(2, '0') + ':' + String(abs % 60).padStart(2, '0');
    }

    // Format a Date according to the operator's timezone preference. Returns
    // a YYYY-MM-DD HH:MM:SS string in the chosen zone. "server" uses the
    // server's zone, "local" the browser's.
    function formatDateTime(d) {
        if (!(d instanceof Date)) return '';
        var tz = state.timezone || 'local';
        var opts = { year: 'numeric', month: '2-digit', day: '2-digit',
                     hour: '2-digit', minute: '2-digit', second: '2-digit',
                     hour12: false, hourCycle: 'h23' };
        if (tz === 'server') {
            var zone = serverZone();
            if (zone.name) {
                opts.timeZone = zone.name;
            } else {
                // No zone name: shift by the offset and format as UTC.
                d = new Date(d.getTime() + zone.offsetMinutes * 60000);
                opts.timeZone = 'UTC';
            }
        } else if (tz !== 'local') {
            opts.timeZone = tz;
        }
        try {
            var parts = {};
            new Intl.DateTimeFormat('en-GB', opts).formatToParts(d).forEach(function(part) {
                parts[part.type] = part.value;
            });
            return parts.year + '-' + parts.month + '-' + parts.day + ' ' +
                   parts.hour + ':' + parts.minute + ':' + parts.second;
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
        serverZone: serverZone,
        offsetLabel: offsetLabel,
        defaults: function() { return cloneDefaults(); }
    };
})();

// Kick off loading immediately. The last known copy is already applied, so
// pages rendering before the server answers use it.
if (typeof CSM !== 'undefined' && CSM.prefs) {
    CSM.prefs.load();
}
