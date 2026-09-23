// CSM.prefs - operator preferences applied at layout boot (WEB_ROADMAP P5.4).
//
// Loads the current operator's saved user prefs from /api/v1/prefs/user once
// per page load, applies them to the document chrome (density / timezone /
// default auto-refresh / per-table column visibility) and exposes a small
// imperative API for the preferences modal and other features that need to
// read or write the operator's prefs.
//
// All UI consumers should access state through CSM.prefs.get(), never via
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

    // replaceState swaps in src while keeping the one object CSM.prefs.get()
    // returns.
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
        if (CSM.initDates) CSM.initDates();
        listeners.slice().forEach(function(fn) {
            try { fn(state); } catch (e) { /* listeners must not throw */ }
        });
    }

    // Dates already on screen were formatted in this zone. A different zone
    // needs a reload, because pages do not re-render their dates.
    merge(state, readCache());
    var renderedZone = state.timezone;

    function load() {
        if (loadPromise) return loadPromise;
        // Apply the last known copy while the server copy loads.
        applyAll();
        if (typeof CSM === 'undefined' || !CSM.request) {
            loadPromise = Promise.resolve(state);
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
            replaceState(next);
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
            var cached = writeCache();
            applyAll();
            if (cached && state.timezone !== renderedZone) window.location.reload();
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

    // zoneKey names the zone dates are shown in: an IANA name, 'local', or
    // the server's fixed offset when its zone has no name.
    function zoneKey() {
        var tz = state.timezone || 'local';
        if (tz !== 'server') return tz;
        var zone = serverZone();
        return zone.name || ('offset:' + zone.offsetMinutes);
    }

    // Building an Intl formatter costs far more than using one, and table
    // date filters ask for boundaries once per row, so keep one per zone.
    var zoneFormatters = {};
    function zoneFormatter(tz) {
        if (!zoneFormatters[tz]) {
            zoneFormatters[tz] = new Intl.DateTimeFormat('en-US', {
                timeZone: tz, hourCycle: 'h23',
                year: 'numeric', month: '2-digit', day: '2-digit',
                hour: '2-digit', minute: '2-digit', second: '2-digit'
            });
        }
        return zoneFormatters[tz];
    }

    // zoneOffsetMinutes is how far the operator's zone is ahead of UTC at the
    // instant ms.
    function zoneOffsetMinutes(ms) {
        var key = zoneKey();
        if (key === 'local') return -new Date(ms).getTimezoneOffset();
        if (key.indexOf('offset:') === 0) return +key.slice(7);
        try {
            var parts = {};
            zoneFormatter(key).formatToParts(new Date(ms)).forEach(function(part) {
                parts[part.type] = part.value;
            });
            var wall = Date.UTC(+parts.year, +parts.month - 1, +parts.day, +parts.hour, +parts.minute, +parts.second);
            return Math.round((wall - Math.floor(ms / 1000) * 1000) / 60000);
        } catch (e) {
            return -new Date(ms).getTimezoneOffset();
        }
    }

    // Boundaries are remembered per zone and day: a table filter asks for the
    // same two once per row.
    var boundaries = {};
    var boundaryCount = 0;

    // dayBoundary returns the instant (ms) a calendar day YYYY-MM-DD starts in
    // the operator's zone or, with endExclusive, the instant the next day
    // starts. A malformed or impossible day returns null.
    function dayBoundary(value, endExclusive) {
        var memoKey = zoneKey() + '|' + value + '|' + (endExclusive ? 1 : 0);
        if (Object.prototype.hasOwnProperty.call(boundaries, memoKey)) return boundaries[memoKey];
        if (boundaryCount >= 256) {
            boundaries = {};
            boundaryCount = 0;
        }
        boundaryCount++;
        return (boundaries[memoKey] = computeDayBoundary(value, endExclusive));
    }

    function computeDayBoundary(value, endExclusive) {
        var m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value || '');
        if (!m) return null;
        var y = +m[1], mo = +m[2] - 1, d = +m[3];
        var check = new Date(Date.UTC(y, mo, d));
        if (check.getUTCFullYear() !== y || check.getUTCMonth() !== mo || check.getUTCDate() !== d) return null;
        var wall = Date.UTC(y, mo, d + (endExclusive ? 1 : 0));
        // Look on both sides of midnight: it can occur twice, or be skipped
        // entirely. Pick the first occurrence; in a gap find the clock jump
        // itself so no part of the preceding day enters the range.
        var before = wall - zoneOffsetMinutes(wall - 36 * 3600000) * 60000;
        var after = wall - zoneOffsetMinutes(wall + 36 * 3600000) * 60000;
        var lo = Math.min(before, after), hi = Math.max(before, after);
        if (lo + zoneOffsetMinutes(lo) * 60000 >= wall) return lo;
        while (hi - lo > 1) {
            var mid = lo + Math.floor((hi - lo) / 2);
            if (mid + zoneOffsetMinutes(mid) * 60000 >= wall) hi = mid;
            else lo = mid;
        }
        return hi;
    }

    // dayRange turns an inclusive pair of days into the instants the API
    // filters on: the first day's start and the start of the day after the
    // last. A missing or malformed day is left out.
    function dayRange(fromDay, toDay) {
        var from = dayBoundary(fromDay, false);
        var to = dayBoundary(toDay, true);
        return {
            from: from === null ? '' : new Date(from).toISOString(),
            to: to === null ? '' : new Date(to).toISOString()
        };
    }

    // today returns the current day in the operator's zone as YYYY-MM-DD.
    function today() {
        return formatDateTime(new Date()).slice(0, 10);
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
        load: load,
        save: save,
        get: get,
        onChange: onChange,
        formatDateTime: formatDateTime,
        serverZone: serverZone,
        offsetLabel: offsetLabel,
        dayBoundary: dayBoundary,
        dayRange: dayRange,
        today: today,
        defaults: function() { return cloneDefaults(); }
    };
})();

// Kick off loading immediately. The last known copy is already applied, so
// pages rendering before the server answers use it.
if (typeof CSM !== 'undefined' && CSM.prefs) {
    CSM.prefs.load();
}
