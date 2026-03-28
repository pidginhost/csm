// CSRF helper — reads token from <meta name="csrf-token"> and provides fetch wrapper
var CSM = CSM || {};
CSM.csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';

// Wrapper for POST requests with CSRF token
CSM.post = function(url, body) {
    return fetch(url, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': CSM.csrfToken
        },
        body: JSON.stringify(body)
    }).then(function(r) { return r.json(); });
};

// Shared HTML-escape helper used across all pages
CSM.esc = function(s) {
    var d = document.createElement('div');
    d.appendChild(document.createTextNode(s || ''));
    return d.innerHTML;
};

// Relative timestamps: converts ISO or "YYYY-MM-DD HH:MM:SS" to "2m ago", "1h ago", etc.
CSM.timeAgo = function(dateStr) {
    if (!dateStr) return '';
    // Normalise "YYYY-MM-DD HH:MM:SS" to ISO by inserting a T
    var iso = String(dateStr).replace(/^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})/, '$1T$2');
    var ts = new Date(iso).getTime();
    if (isNaN(ts)) return dateStr;
    var diff = Math.floor((Date.now() - ts) / 1000);
    if (diff < 60) return 'just now';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    if (diff < 604800) return Math.floor(diff / 86400) + 'd ago';
    return Math.floor(diff / 604800) + 'w ago';
};

// Find all elements with data-timestamp and set relative time, full timestamp as title
CSM.initTimeAgo = function() {
    var els = document.querySelectorAll('[data-timestamp]');
    for (var i = 0; i < els.length; i++) {
        var raw = els[i].getAttribute('data-timestamp');
        els[i].textContent = CSM.timeAgo(raw);
        els[i].title = raw;
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
