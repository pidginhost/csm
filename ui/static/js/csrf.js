// Parse CSM_CONFIG from JSON data block (avoids inline script for CSP compliance)
var CSM_CONFIG = JSON.parse(document.getElementById('csm-config').textContent);

// CSRF helper - reads token from <meta name="csrf-token"> and provides fetch wrapper
var CSM = CSM || {};
CSM.csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';

// Wrapper for POST requests with CSRF token
CSM.post = function(url, body) {
    var resolvedUrl = (typeof CSM.apiUrl === 'function') ? CSM.apiUrl(url) : url;
    return fetch(resolvedUrl, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': CSM.csrfToken
        },
        body: JSON.stringify(body)
    }).then(function(r) {
        if (!r.ok) {
            return r.json().catch(function() { throw new Error('HTTP ' + r.status); })
                .then(function(body) { throw new Error(body.error || 'HTTP ' + r.status); });
        }
        return r.json();
    });
};

// Wrapper for DELETE requests with CSRF token
CSM.delete = function(url, body) {
    var resolvedUrl = (typeof CSM.apiUrl === 'function') ? CSM.apiUrl(url) : url;
    var opts = {
        method: 'DELETE',
        credentials: 'same-origin',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': CSM.csrfToken
        }
    };
    if (body !== undefined) { opts.body = JSON.stringify(body); }
    return fetch(resolvedUrl, opts).then(function(r) {
        if (!r.ok) {
            return r.json().catch(function() { throw new Error('HTTP ' + r.status); })
                .then(function(body) { throw new Error(body.error || 'HTTP ' + r.status); });
        }
        return r.json();
    });
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

// Format file sizes: bytes -> "1.2 KB", "3.4 MB"
CSM.formatSize = function(bytes) {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1048576) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / 1048576).toFixed(1) + ' MB';
};

// Format ISO timestamp to "YYYY-MM-DD HH:MM TZ" in browser-local timezone
CSM.fmtDate = function(s) {
    if (!s) return '\u2014';
    var d = new Date(s);
    if (isNaN(d.getTime())) return s;
    var pad = function(n) { return n < 10 ? '0' + n : n; };
    var tz = '';
    try {
        tz = ' ' + d.toLocaleTimeString('en-US', { timeZoneName: 'short' }).split(' ').pop();
    } catch(e) {}
    return d.getFullYear() + '-' + pad(d.getMonth()+1) + '-' + pad(d.getDate()) +
           ' ' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + tz;
};

// Render a loading skeleton placeholder
CSM.loading = function(el) {
    if (el) el.innerHTML = '<div class="card-body text-center text-muted py-4"><span class="spinner-border spinner-border-sm me-2"></span>Loading...</div>';
};

// Render an error state with retry button
CSM.loadError = function(el, retryFn) {
    if (!el) return;
    el.innerHTML = '<div class="card-body text-center py-4"><div class="text-danger mb-2">Failed to load data</div>' +
        (retryFn ? '<button class="btn btn-sm btn-outline-secondary csm-retry-btn">Retry</button>' : '') + '</div>';
    if (retryFn) {
        var btn = el.querySelector('.csm-retry-btn');
        if (btn) btn.addEventListener('click', retryFn);
    }
};

// Click-to-copy: delegated handler for .csm-copy elements
document.addEventListener('click', function(e) {
    var el = e.target.closest('.csm-copy');
    if (el) {
        e.stopPropagation();
        CSM.copyText(el.textContent.trim(), el);
    }
});

// Copy text to clipboard with visual feedback
CSM.copyText = function(text, el) {
    navigator.clipboard.writeText(text).then(function() {
        if (el) {
            var orig = el.textContent;
            el.textContent = 'Copied!';
            setTimeout(function() { el.textContent = orig; }, 1000);
        } else {
            CSM.toast('Copied to clipboard', 'success');
        }
    }).catch(function() {});
};

// Resolve API URLs - use CGI proxy path if in WHM context
CSM.apiUrl = function(path) {
    if (window.location.pathname.indexOf('addon_csm.cgi') >= 0) {
        return 'addon_csm.cgi?path=' + path;
    }
    return path;
};

// Fetch wrapper with 30s timeout and error toast
CSM.fetch = function(url, options) {
    var resolvedUrl = (typeof CSM.apiUrl === 'function') ? CSM.apiUrl(url) : url;
    var controller = new AbortController();
    var timeoutId = setTimeout(function() { controller.abort(); }, 30000);
    var opts = Object.assign({}, options || {}, { signal: controller.signal, credentials: 'same-origin' });
    return fetch(resolvedUrl, opts).then(function(r) {
        clearTimeout(timeoutId);
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
    }).catch(function(err) {
        clearTimeout(timeoutId);
        if (err.name === 'AbortError') {
            CSM.toast('Request timed out', 'danger');
        } else {
            CSM.toast('Request failed: ' + err.message, 'danger');
        }
        throw err;
    });
};

// Polling utility with visibility-pause and exponential backoff
CSM.poll = function(url, interval, callback) {
    var baseInterval = interval;
    var currentInterval = interval;
    var maxInterval = 300000; // 5 minutes
    var timerId = null;
    var stopped = false;

    function run() {
        if (stopped) return;
        fetch((typeof CSM.apiUrl === 'function') ? CSM.apiUrl(url) : url, { credentials: 'same-origin' })
            .then(function(r) {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.json();
            })
            .then(function(data) {
                currentInterval = baseInterval; // reset on success
                callback(null, data);
            })
            .catch(function(err) {
                currentInterval = Math.min(currentInterval * 2, maxInterval);
                callback(err, null);
            })
            .finally(function() {
                if (!stopped && !document.hidden) {
                    timerId = setTimeout(run, currentInterval);
                }
            });
    }

    function onVisibility() {
        if (document.hidden) {
            if (timerId) { clearTimeout(timerId); timerId = null; }
        } else if (!stopped) {
            currentInterval = baseInterval;
            if (!timerId) { timerId = setTimeout(run, 100); }
        }
    }

    document.addEventListener('visibilitychange', onVisibility);
    timerId = setTimeout(run, currentInterval);

    return {
        stop: function() {
            stopped = true;
            if (timerId) { clearTimeout(timerId); timerId = null; }
            document.removeEventListener('visibilitychange', onVisibility);
        }
    };
};

// Debounce utility
CSM.debounce = function(fn, delay) {
    var timer = null;
    return function() {
        var ctx = this, args = arguments;
        if (timer) clearTimeout(timer);
        timer = setTimeout(function() { fn.apply(ctx, args); }, delay);
    };
};
