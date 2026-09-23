// CSM runtime: text, number and time formatting, and address validation.
// Pages put the output of these helpers into markup, so each returns
// escaped or empty text.
var CSM = CSM || {};

(function() {

// Shared HTML-escape helper used across all pages. Safe for both text nodes
// inserted through innerHTML and quoted HTML attribute values.
CSM.esc = function(s) {
    return (s === null || s === undefined ? '' : String(s))
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
};

CSM.attr = CSM.esc;

// Parse an ISO 8601 or SQL-style "YYYY-MM-DD HH:MM:SS" timestamp to epoch
// millis. Space-separated stamps are normalised to ISO first so parsing does
// not depend on engine-specific Date leniency. Returns NaN when unparseable.
// This is the single home for the normalisation regex that pages used to
// copy inline before their own new Date() calls.
CSM.parseTimestamp = function(raw) {
    if (raw === null || raw === undefined || raw === '') return NaN;
    var iso = String(raw).replace(/^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})/, '$1T$2');
    return new Date(iso).getTime();
};

// Relative timestamps: converts ISO or "YYYY-MM-DD HH:MM:SS" to "2m ago",
// "1h ago", or "in 3h" for a time still ahead (an expiry). A value that is
// not a time gives '', never the raw value: pages put the result in markup.
function csmRelativeSpan(sec) {
    if (sec < 3600) return Math.floor(sec / 60) + 'm';
    if (sec < 86400) return Math.floor(sec / 3600) + 'h';
    if (sec < 604800) return Math.floor(sec / 86400) + 'd';
    return Math.floor(sec / 604800) + 'w';
}

CSM.timeAgo = function(dateStr) {
    if (!dateStr) return '';
    var ts = CSM.parseTimestamp(dateStr);
    if (isNaN(ts)) return '';
    var diff = Math.floor((Date.now() - ts) / 1000);
    if (diff < 0) return -diff < 60 ? 'in under 1m' : 'in ' + csmRelativeSpan(-diff);
    if (diff < 60) return 'just now';
    return csmRelativeSpan(diff) + ' ago';
};

// Refresh relative times. Only elements that opt in with data-time-ago are
// rewritten; data-timestamp alone is a sort and filter key, and rewriting
// every element carrying it destroyed absolute dates and whole table rows.
CSM.initTimeAgo = function() {
    var els = document.querySelectorAll('[data-time-ago]');
    for (var i = 0; i < els.length; i++) {
        var raw = els[i].getAttribute('data-time-ago');
        if (!raw) continue;
        els[i].textContent = CSM.timeAgo(raw);
        els[i].title = (typeof CSM.fmtDate === 'function') ? CSM.fmtDate(raw) : raw;
    }
};

// Auto-refresh relative timestamps every 60 seconds
(function() {
    var _timeAgoInterval = null;
    function _startTimeAgo() {
        // Run once immediately when DOM is ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', function() {
                CSM.initTimeAgo();
            });
        } else {
            CSM.initTimeAgo();
        }
        // Refresh every 60s
        if (!_timeAgoInterval) {
            _timeAgoInterval = setInterval(CSM.initTimeAgo, 60000);
        }
    }
    _startTimeAgo();
})();

// Format file sizes: bytes -> "1.2 KB", "3.4 MB"
CSM.formatSize = function(bytes) {
    if (bytes == null || (typeof bytes === 'string' && bytes.trim() === '')) return '';
    bytes = Number(bytes);
    if (!isFinite(bytes)) return '';
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
};

// Format number with locale thousands separator. Missing values and values
// that are not numbers stay blank.
CSM.formatNumber = function(n) {
    if (n == null || (typeof n === 'string' && n.trim() === '')) return '';
    var v = Number(n);
    if (!isFinite(v)) return '';
    try {
        return v.toLocaleString();
    } catch (e) {
        var parts = String(v).split('.');
        parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ',');
        return parts.join('.');
    }
};

// Format a duration in seconds as its two largest units: "45s", "2m 5s",
// "1h 30m", "1d 1h". The API sends every duration in seconds. Anything that
// is not a duration gives ''.
CSM.formatDuration = function(seconds) {
    if (seconds === null || seconds === undefined || seconds === '') return '';
    var total = Math.floor(Number(seconds));
    if (!isFinite(total) || total < 0) return '';
    if (total === 0) return '0s';
    var units = [['d', 86400], ['h', 3600], ['m', 60], ['s', 1]];
    for (var i = 0; i < units.length; i++) {
        var n = Math.floor(total / units[i][1]);
        if (n === 0) continue;
        var out = n + units[i][0];
        if (i + 1 < units.length) {
            var rest = Math.floor((total % units[i][1]) / units[i + 1][1]);
            if (rest > 0) out += ' ' + rest + units[i + 1][0];
        }
        return out;
    }
    return '';
};

// Format ISO timestamp to "YYYY-MM-DD HH:MM" using the operator timezone.
// Pass { tz: true } as opts to append timezone abbreviation.
CSM.fmtDate = function(ts, opts) {
    if (!ts) return '\u2014';
    var d = new Date(ts);
    if (isNaN(d.getTime())) return '\u2014';
    var result = '';
    if (CSM.prefs && typeof CSM.prefs.formatDateTime === 'function') {
        result = CSM.prefs.formatDateTime(d).replace(/:\d{2}$/, '');
    }
    if (!result) {
        var y = d.getFullYear();
        var m = String(d.getMonth() + 1).padStart(2, '0');
        var day = String(d.getDate()).padStart(2, '0');
        var h = String(d.getHours()).padStart(2, '0');
        var min = String(d.getMinutes()).padStart(2, '0');
        result = y + '-' + m + '-' + day + ' ' + h + ':' + min;
    }
    if (opts && opts.tz) {
        try {
            var pref = CSM.prefs && CSM.prefs.get ? CSM.prefs.get().timezone : 'local';
            var fmtOpts = { timeZoneName: 'short' };
            if (pref === 'server') {
                var zone = CSM.prefs.serverZone();
                if (!zone.name) return result + ' ' + CSM.prefs.offsetLabel(zone.offsetMinutes);
                fmtOpts.timeZone = zone.name;
            } else if (pref && pref !== 'local') {
                fmtOpts.timeZone = pref;
            }
            var tz = d.toLocaleTimeString('en-us', fmtOpts).split(' ').pop();
            result += ' ' + tz;
        } catch (e) {
            result += ' ' + d.toLocaleTimeString('en-us', { timeZoneName: 'short' }).split(' ').pop();
        }
    }
    return result;
};

// Server-rendered dates (<time data-csm-date datetime="...">) carry the
// instant; rewrite their text in the operator's time zone.
CSM.initDates = function(root) {
    var els = (root || document).querySelectorAll('[data-csm-date]');
    for (var i = 0; i < els.length; i++) {
        var raw = els[i].getAttribute('datetime');
        if (!raw) continue;
        var text = CSM.fmtDate(raw, { tz: true });
        if (text !== '\u2014') els[i].textContent = text;
    }
};

// Dotted-quad IPv4: four octets 0-255, no leading zeros ("01.0.0.1" is invalid).
function isValidIPv4(s) {
    var parts = s.split('.');
    if (parts.length !== 4) return false;
    for (var i = 0; i < 4; i++) {
        var n = parseInt(parts[i], 10);
        if (isNaN(n) || n < 0 || n > 255 || parts[i] !== String(n)) return false;
    }
    return true;
}

// IPv6 grammar: at most one "::" compression, 1-4 hex digits per group, an
// optional embedded IPv4 allowed only as the final group (e.g. "::ffff:1.2.3.4").
// Without "::" there must be exactly 8 groups; with "::" fewer than 8, since the
// compression stands for one or more zero groups. The old check accepted any
// string of hex and colons, so ":::::" and over-length addresses passed.
function isValidIPv6(s) {
    if (s.length > 45) return false;
    var halves = s.split('::');
    if (halves.length > 2) return false;
    var compressed = halves.length === 2;
    var groups = compressed
        ? (halves[0] ? halves[0].split(':') : []).concat(halves[1] ? halves[1].split(':') : [])
        : s.split(':');
    var count = 0;
    for (var i = 0; i < groups.length; i++) {
        var g = groups[i];
        if (g.indexOf('.') >= 0) {
            if (i !== groups.length - 1 || !isValidIPv4(g)) return false;
            count += 2; // an embedded IPv4 occupies two 16-bit groups
            continue;
        }
        if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return false;
        count += 1;
    }
    return compressed ? count <= 7 : count === 8;
}

// Client-side IP format validator (IPv4 and IPv6). A UX pre-check; the daemon
// remains the authority via netip.
CSM.validateIP = function(s) {
    if (!s) return false;
    return s.indexOf(':') >= 0 ? isValidIPv6(s) : isValidIPv4(s);
};

// Client-side CIDR validator: address part must be a valid IP and the prefix a
// decimal length within range (0-32 for IPv4, 0-128 for IPv6). Rejects "/99",
// "1.2.3.4/abc", and a missing prefix.
CSM.validateCIDR = function(s) {
    if (!s) return false;
    var slash = s.indexOf('/');
    if (slash < 0) return false;
    var addr = s.slice(0, slash);
    var prefix = s.slice(slash + 1);
    if (!/^\d{1,3}$/.test(prefix) || !CSM.validateIP(addr)) return false;
    var max = addr.indexOf(':') >= 0 ? 128 : 32;
    var n = parseInt(prefix, 10);
    return n >= 0 && n <= max;
};

})();
