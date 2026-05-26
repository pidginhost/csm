// Tabler v1.4+ exposes its bundled Bootstrap component classes on
// `window.tabler` (e.g. tabler.Modal, tabler.Tab, tabler.Offcanvas) and
// no longer populates the legacy `window.bootstrap` global. Every page
// script and shared helper in this UI still calls window.bootstrap.X,
// so alias the namespace once at load time instead of touching every
// call site. Safe to run when bootstrap is already defined (preserves
// any standalone bootstrap.bundle.min.js operators already loaded).
if (typeof window !== 'undefined' && !window.bootstrap && window.tabler) {
    window.bootstrap = window.tabler;
}

// Parse CSM_CONFIG from JSON data block (avoids inline script for CSP compliance)
var CSM_CONFIG = JSON.parse(document.getElementById('csm-config').textContent);

// CSRF helper - reads token from <meta name="csrf-token"> and provides fetch wrapper
var CSM = CSM || {};
CSM.csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';

// Wrapper for POST requests with CSRF token
CSM.post = function(url, body) {
    return CSM.request(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': CSM.csrfToken
        },
        body: JSON.stringify(body),
        silent: true
    }).then(function(r) { return r.json(); });
};

// Wrapper for DELETE requests with CSRF token
CSM.delete = function(url, body) {
    var opts = {
        method: 'DELETE',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': CSM.csrfToken
        },
        silent: true
    };
    if (body !== undefined) { opts.body = JSON.stringify(body); }
    return CSM.request(url, opts).then(function(r) { return r.json(); });
};

// Shared HTML-escape helper used across all pages. Safe for both text nodes
// inserted through innerHTML and quoted HTML attribute values.
CSM.esc = function(s) {
    return String(s || '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
};

CSM.attr = CSM.esc;

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

// Format number with locale thousands separator. Missing values stay blank.
CSM.formatNumber = function(n) {
    if (n == null || (typeof n === 'string' && n.trim() === '')) return '';
    var v = Number(n);
    if (!isFinite(v)) return String(n);
    try {
        return v.toLocaleString();
    } catch (e) {
        var parts = String(v).split('.');
        parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ',');
        return parts.join('.');
    }
};

// Format ratio (0..1 or 0..100) as a percentage. round = decimals to keep.
CSM.formatPercent = function(v, round) {
    if (v == null || (typeof v === 'string' && v.trim() === '')) return '';
    var n = Number(v);
    if (!isFinite(n)) return '';
    if (n <= 1 && n >= -1) n = n * 100;
    var d = (round == null) ? 0 : Number(round);
    if (!isFinite(d) || d < 0) d = 0;
    d = Math.min(20, Math.floor(d));
    return n.toFixed(d) + '%';
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
                var server = document.documentElement.getAttribute('data-csm-server-tz') || 'UTC';
                fmtOpts.timeZone = server;
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
    }).catch(function() { /* clipboard API unavailable — intentionally silent */ });
};

// Resolve API URLs. The WHM addon redirects operators to the daemon UI, so
// browser requests stay same-origin with the daemon after login.
CSM.apiUrl = function(path) {
    return path;
};

// Single fetch primitive. All other helpers (CSM.get, CSM.fetch, CSM.poll,
// CSM.post, CSM.delete) call this and inherit its 30s timeout + abort
// signal. Direct `fetch()` calls from page scripts are forbidden and
// enforced by a static_ui_test.go regression.
//
// Options:
//   timeoutMs   number   default 30000; pass 0 to disable.
//   allowNonOK  bool     default false. When true the resolved promise
//                        carries the raw Response even for !r.ok status
//                        codes; the caller is responsible for inspecting
//                        r.status (used by settings.js for 412/422 paths).
//   silent      bool     default false. Suppresses the auto-toast on
//                        failure (used by background pollers that have
//                        their own error UI).
// All other keys are forwarded to fetch() unchanged.
CSM.request = function(url, options) {
    var resolvedUrl = (typeof CSM.apiUrl === 'function') ? CSM.apiUrl(url) : url;
    options = options || {};
    var timeoutMs = (options.timeoutMs == null) ? 30000 : options.timeoutMs;
    var allowNonOK = !!options.allowNonOK;
    var silent = !!options.silent;
    var controller = new AbortController();
    var timeoutId = (timeoutMs > 0) ? setTimeout(function() { controller.abort(); }, timeoutMs) : null;
    var opts = Object.assign({}, options, { signal: controller.signal, credentials: 'same-origin' });
    delete opts.timeoutMs;
    delete opts.allowNonOK;
    delete opts.silent;
    return fetch(resolvedUrl, opts).then(function(r) {
        if (timeoutId) clearTimeout(timeoutId);
        if (allowNonOK) {
            if (r.ok && CSM.refresh) CSM.refresh.bump();
            return r;
        }
        if (!r.ok) {
            return r.json().catch(function() { throw new Error('HTTP ' + r.status); })
                .then(function(body) { throw new Error(body.error || 'HTTP ' + r.status); });
        }
        if (CSM.refresh) CSM.refresh.bump();
        return r;
    }).catch(function(err) {
        if (timeoutId) clearTimeout(timeoutId);
        if (!silent) {
            if (err.name === 'AbortError') {
                CSM.toast('Request timed out', 'error');
            } else {
                CSM.toast('Request failed: ' + err.message, 'error');
            }
        }
        throw err;
    });
};

// Fetch wrapper with 30s timeout and error toast
CSM.fetch = function(url, options) {
    return CSM.request(url, options).then(function(r) { return r.json(); });
};

CSM.get = function(url, options) {
    var opts = Object.assign({}, options || {});
    opts.headers = Object.assign({ Accept: 'application/json' }, opts.headers || {});
    return CSM.fetch(url, opts);
};

// Shared refresh tracker. Successful CSM.request calls bump() to keep
// lastFetchAt current, while background refresh loops observe enabled
// so the layout pause control can stop scheduled fetches.
CSM.refresh = (function() {
    var STORAGE_KEY = 'csm-autorefresh';
    var timers = [];
    // subscribers counts every poller / interval / explicit listener so
    // manual() can fall back to window.location.reload() on pages that
    // never registered a refreshable callback - otherwise the topbar
    // Refresh button is a no-op there.
    var subscribers = 0;
    var raw = null;
    try { raw = localStorage.getItem(STORAGE_KEY); } catch (e) { /* localStorage may be unavailable */ }
    // Default ON unless user explicitly turned it off.
    var enabled = raw !== 'off';
    var hasPersistedChoice = (raw === 'on' || raw === 'off');
    var lastFetchAt = 0;

    function addTimer(timer) {
        timers.push(timer);
    }

    function removeTimer(timer) {
        for (var i = timers.length - 1; i >= 0; i--) {
            if (timers[i] === timer) {
                timers.splice(i, 1);
                return;
            }
        }
    }

    function eachTimer(fn) {
        var snapshot = timers.slice();
        for (var i = 0; i < snapshot.length; i++) {
            fn(snapshot[i]);
        }
    }

    function invokeTimer(fn) {
        try {
            fn();
        } catch (e) {
            setTimeout(function() { throw e; }, 0);
        }
    }

    function createInterval(fn, interval) {
        var timerId = null;
        var stopped = false;
        var delay = Math.max(0, Number(interval) || 0);
        subscribers++;

        function clearTimer() {
            if (timerId) {
                clearTimeout(timerId);
                timerId = null;
            }
        }

        function schedule() {
            clearTimer();
            if (stopped || document.hidden || !enabled) return;
            timerId = setTimeout(function() {
                timerId = null;
                if (stopped || document.hidden || !enabled) return;
                invokeTimer(fn);
                schedule();
            }, delay);
        }

        function runNow() {
            if (stopped || document.hidden) return;
            clearTimer();
            invokeTimer(fn);
            schedule();
        }

        var timer = {
            pause: clearTimer,
            schedule: schedule,
            runNow: runNow,
            stop: function() {
                if (stopped) return;
                stopped = true;
                subscribers = Math.max(0, subscribers - 1);
                clearTimer();
                removeTimer(timer);
            }
        };
        addTimer(timer);
        schedule();
        return { stop: timer.stop };
    }

    var api = {
        get enabled() { return enabled; },
        get lastFetchAt() { return lastFetchAt; },
        get hasPersistedChoice() { return hasPersistedChoice; },
        setEnabled: function(next, opts) {
            enabled = !!next;
            opts = opts || {};
            if (!opts.transient) {
                hasPersistedChoice = true;
                try { localStorage.setItem(STORAGE_KEY, enabled ? 'on' : 'off'); } catch (e) { /* ignore */ }
            }
            window.dispatchEvent(new CustomEvent('csm:refresh-toggle', { detail: { enabled: enabled } }));
        },
        bump: function() {
            lastFetchAt = Date.now();
            window.dispatchEvent(new CustomEvent('csm:refresh-bump', { detail: { at: lastFetchAt } }));
        },
        manual: function() {
            window.dispatchEvent(new CustomEvent('csm:refresh-now'));
            // No interval / poller / explicit subscriber means the page
            // fetched its data once at load and ignores the event, so the
            // operator would see the refresh icon "spin" with no effect.
            // Fall back to a full reload so the click is never a no-op.
            if (subscribers === 0) {
                window.location.reload();
            }
        },
        onRefresh: function(fn) {
            if (typeof fn !== 'function') return function() {};
            subscribers++;
            var wrapped = function() { try { fn(); } catch (e) { /* swallow */ } };
            window.addEventListener('csm:refresh-now', wrapped);
            var unsubscribed = false;
            return function() {
                if (unsubscribed) return;
                unsubscribed = true;
                subscribers = Math.max(0, subscribers - 1);
                window.removeEventListener('csm:refresh-now', wrapped);
            };
        },
        _bumpSubscriber: function() { subscribers++; },
        _dropSubscriber: function() { subscribers = Math.max(0, subscribers - 1); },
        interval: function(fn, interval) {
            return createInterval(fn, interval);
        }
    };

    window.addEventListener('csm:refresh-toggle', function(ev) {
        if (ev.detail && ev.detail.enabled) {
            eachTimer(function(timer) { timer.schedule(); });
            return;
        }
        eachTimer(function(timer) { timer.pause(); });
    });

    window.addEventListener('csm:refresh-now', function() {
        eachTimer(function(timer) { timer.runNow(); });
    });

    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            eachTimer(function(timer) { timer.pause(); });
            return;
        }
        eachTimer(function(timer) { timer.schedule(); });
    });

    return api;
})();

// Tracks the EventSource connection used by the header pill. Handlers guard
// against stale sources because browser callbacks can arrive after close()
// while a replacement stream is already active.
CSM.sse = (function() {
    var STATES = { connecting: 'connecting', connected: 'connected', reconnecting: 'reconnecting', disconnected: 'disconnected' };
    var state = STATES.disconnected;
    var es = null;
    var retryDelay = 0;
    var retryTimer = null;
    var baseDelay = 1000;
    var maxDelay = 30000;
    var url = '/api/v1/events';
    var started = false;

    function setState(next) {
        if (state === next) return;
        state = next;
        window.dispatchEvent(new CustomEvent('csm:sse-state', { detail: { state: next } }));
    }

    function clearRetry() {
        if (retryTimer) {
            clearTimeout(retryTimer);
            retryTimer = null;
        }
    }

    function closeStream() {
        if (es) {
            try { es.close(); } catch (e) { /* ignore */ }
            es = null;
        }
        clearRetry();
    }

    function scheduleReconnect() {
        clearRetry();
        if (!started || document.hidden) return;
        retryDelay = retryDelay ? Math.min(retryDelay * 2, maxDelay) : baseDelay;
        var jitter = retryDelay * (0.5 + Math.random() * 0.5);
        retryTimer = setTimeout(function() { retryTimer = null; connect(); }, jitter);
    }

    function connect() {
        if (!started || document.hidden) return;
        if (typeof EventSource === 'undefined') {
            setState(STATES.disconnected);
            return;
        }
        closeStream();
        setState(state === STATES.connected ? STATES.reconnecting : STATES.connecting);
        var resolvedUrl = (typeof CSM.apiUrl === 'function') ? CSM.apiUrl(url) : url;
        var source = null;
        try {
            source = new EventSource(resolvedUrl);
        } catch (e) {
            setState(STATES.reconnecting);
            scheduleReconnect();
            return;
        }
        es = source;
        source.onopen = function() {
            if (source !== es) return;
            retryDelay = 0;
            setState(STATES.connected);
        };
        source.onerror = function() {
            if (source !== es) return;
            if (source.readyState === EventSource.CLOSED) {
                closeStream();
                setState(STATES.reconnecting);
                scheduleReconnect();
            } else {
                setState(STATES.reconnecting);
            }
        };
        source.onmessage = function(ev) {
            if (source !== es) return;
            window.dispatchEvent(new CustomEvent('csm:sse-message', { detail: { raw: ev.data } }));
        };
    }

    document.addEventListener('visibilitychange', function() {
        if (!started) return;
        if (document.hidden) {
            closeStream();
            setState(STATES.disconnected);
        } else {
            retryDelay = 0;
            connect();
        }
    });

    return {
        get state() { return state; },
        start: function(u) {
            if (u) url = u;
            started = true;
            if (!document.hidden) connect();
        },
        stop: function() {
            started = false;
            closeStream();
            setState(STATES.disconnected);
        }
    };
})();

// Connection-lost banner: tracks consecutive fetch failures
(function() {
    var failCount = 0;
    var origFetch = CSM.fetch;
    CSM.fetch = function(url, opts) {
        return origFetch(url, opts).then(function(resp) {
            if (failCount > 0) {
                failCount = 0;
                var banner = document.getElementById('csm-connection-lost');
                if (banner) banner.classList.add('d-none');
            }
            return resp;
        }).catch(function(err) {
            failCount++;
            if (failCount >= 3) {
                var banner = document.getElementById('csm-connection-lost');
                if (banner) banner.classList.remove('d-none');
            }
            throw err;
        });
    };
})();

// Polling utility with visibility-pause and exponential backoff. Routes
// the fetch through CSM.request so the 30s timeout and AbortController
// apply uniformly; silent:true keeps the auto-toast off so the callback
// can decide how to surface errors.
//
// Lifecycle is an explicit state machine: idle -> scheduled -> running ->
// (scheduled | stopped). Synchronous throws (in the helper, in the
// callback, anywhere along the chain) cannot wedge the poller because
// scheduleNext() runs from a finally-equivalent that wraps the entire
// dispatch in try/catch as a last resort. While document.hidden the
// scheduled timer is cleared; when visibility returns and the poller
// is idle, the next run fires immediately without resetting an existing
// error backoff. One document-level visibility listener dispatches to
// active pollers, so creating and stopping pollers cannot leak per-poller
// listeners.
(function() {
    var pollers = [];

    function addPoller(poller) {
        pollers.push(poller);
        // CSM.poll counts toward the manual-refresh subscriber tally so
        // the Refresh button does not fall back to a full page reload
        // when a poller is the one keeping the page fresh.
        if (CSM.refresh && typeof CSM.refresh._bumpSubscriber === 'function') {
            CSM.refresh._bumpSubscriber();
        }
    }

    function removePoller(poller) {
        for (var i = pollers.length - 1; i >= 0; i--) {
            if (pollers[i] === poller) {
                pollers.splice(i, 1);
                if (CSM.refresh && typeof CSM.refresh._dropSubscriber === 'function') {
                    CSM.refresh._dropSubscriber();
                }
                return;
            }
        }
    }

    document.addEventListener('visibilitychange', function() {
        var snapshot = pollers.slice();
        for (var i = 0; i < snapshot.length; i++) {
            snapshot[i].onVisibility();
        }
    });

    // Pause/resume pollers when the user flips the layout auto-refresh
    // toggle. Scheduled timers are cleared while paused; in-flight
    // requests finish and park before scheduling the next cycle.
    window.addEventListener('csm:refresh-toggle', function(ev) {
        var enabled = ev.detail && ev.detail.enabled;
        var snapshot = pollers.slice();
        for (var i = 0; i < snapshot.length; i++) {
            if (enabled) {
                snapshot[i].onResume();
            } else {
                snapshot[i].onPause();
            }
        }
    });

    // Manual refresh forces a one-shot fetch even while auto-refresh is
    // paused, then returns the poller to the normal enabled/paused state.
    window.addEventListener('csm:refresh-now', function() {
        var snapshot = pollers.slice();
        for (var i = 0; i < snapshot.length; i++) {
            snapshot[i].onRefreshNow();
        }
    });

    CSM.poll = function(url, interval, callback) {
        var baseInterval = interval;
        var currentInterval = interval;
        var maxInterval = 300000; // 5 minutes
        var timerId = null;
        var timerSeq = 0;
        var state = 'scheduled';
        var poller = { onVisibility: onVisibility, onPause: onPause, onResume: onResume, onRefreshNow: onRefreshNow };

        function clearTimer() {
            if (timerId) {
                clearTimeout(timerId);
                timerId = null;
                timerSeq++;
            }
        }

        function scheduleNext(delayMs, force) {
            if (state === 'stopped' || document.hidden) {
                if (state !== 'stopped') state = 'idle';
                return;
            }
            if (!force && CSM.refresh && !CSM.refresh.enabled) {
                clearTimer();
                state = 'idle';
                return;
            }
            clearTimer();
            state = 'scheduled';
            var seq = ++timerSeq;
            timerId = setTimeout(function() { run(seq, !!force); }, delayMs);
        }

        function emit(err, data) {
            if (state === 'stopped') return;
            try { callback(err, data); } catch (_cbErr) { /* swallow callback throw */ }
        }

        function fail(err) {
            if (state === 'stopped') return;
            currentInterval = Math.min(currentInterval * 2, maxInterval);
            emit(err, null);
        }

        function run(seq, force) {
            if (seq !== timerSeq) return;
            timerId = null;
            if (state === 'stopped') return;
            if (document.hidden) { state = 'idle'; return; }
            if (state !== 'scheduled') return;
            if (!force && CSM.refresh && !CSM.refresh.enabled) { state = 'idle'; return; }
            state = 'running';
            var promise;
            try {
                promise = CSM.request(url, { silent: true })
                    .then(function(r) { return r.json(); });
            } catch (e) {
                fail(e);
                scheduleNext(currentInterval + Math.random() * currentInterval * 0.3);
                return;
            }
            promise.then(function(data) {
                if (state === 'stopped') return;
                currentInterval = baseInterval;
                emit(null, data);
            }).catch(function(err) {
                fail(err);
            }).finally(function() {
                scheduleNext(currentInterval + Math.random() * currentInterval * 0.3);
            });
        }

        function onVisibility() {
            if (state === 'stopped') return;
            if (document.hidden) {
                clearTimer();
                if (state === 'scheduled') state = 'idle';
            } else if (state === 'idle') {
                scheduleNext(100);
            }
        }

        function onPause() {
            if (state === 'stopped') return;
            if (state === 'scheduled') {
                clearTimer();
                state = 'idle';
            }
        }

        // Re-enter from idle or an existing timer so resuming does not
        // wait for a stale scheduled delay.
        function onResume() {
            if (state === 'stopped' || document.hidden) return;
            if (state !== 'idle' && state !== 'scheduled') return;
            currentInterval = baseInterval;
            scheduleNext(100);
        }

        function onRefreshNow() {
            if (state === 'stopped' || document.hidden) return;
            if (state === 'running') return;
            currentInterval = baseInterval;
            scheduleNext(0, true);
        }

        addPoller(poller);
        scheduleNext(currentInterval);

        return {
            stop: function() {
                if (state === 'stopped') return;
                state = 'stopped';
                clearTimer();
                removePoller(poller);
            }
        };
    };
})();

// Client-side IP format validator (IPv4 and IPv6)
CSM.validateIP = function(s) {
    if (!s) return false;
    // IPv6: contains colons
    if (s.indexOf(':') >= 0) return /^[0-9a-fA-F:]+$/.test(s) && s.length <= 45;
    // IPv4: reject leading zeros like "01.02.03.04"
    var parts = s.split('.');
    if (parts.length !== 4) return false;
    for (var i = 0; i < 4; i++) {
        var n = parseInt(parts[i], 10);
        if (isNaN(n) || n < 0 || n > 255 || parts[i] !== String(n)) return false;
    }
    return true;
};

// Debounce utility
CSM.debounce = function(fn, delay) {
    var timer = null;
    var debounced = function() {
        var ctx = this, args = arguments;
        if (timer) clearTimeout(timer);
        timer = setTimeout(function() {
            timer = null;
            fn.apply(ctx, args);
        }, delay);
    };
    debounced.cancel = function() {
        if (timer) {
            clearTimeout(timer);
            timer = null;
        }
    };
    return debounced;
};

function csmCSVCell(value) {
    var val = value != null ? String(value) : '';
    if (/^[\t\r\n=+\-@]/.test(val) || /^\s+[=+\-@]/.test(val)) {
        val = "'" + val;
    }
    return '"' + val.replace(/"/g, '""') + '"';
}

// Client-side table export (CSV / JSON)
CSM.exportTable = function(data, columns, format, filename) {
    var content, mime;
    if (format === 'json') {
        var filtered = data.map(function(row) {
            var obj = {};
            columns.forEach(function(col) { obj[col.key] = row[col.key] != null ? row[col.key] : ''; });
            return obj;
        });
        content = JSON.stringify(filtered, null, 2);
        mime = 'application/json';
    } else {
        var lines = [columns.map(function(c) { return csmCSVCell(c.label || c.key); }).join(',')];
        data.forEach(function(row) {
            lines.push(columns.map(function(c) {
                return csmCSVCell(row[c.key]);
            }).join(','));
        });
        content = lines.join('\n');
        mime = 'text/csv';
    }
    if (!data.length) { CSM.toast('No data to export.', 'warning'); return; }
    var blob = new Blob([content], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename + '.' + format;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
};

// URL state helpers. Convention:
//   - Query string carries filter / search / paging state so the
//     browser back/forward stack and bookmarks survive reloads.
//   - Hash fragment carries legacy in-page anchors only (incident id,
//     expanded row id).
//
// Pages that need to persist filter state call CSM.urlState.bind to
// wire one or more inputs declaratively; ad-hoc callers use get / set
// / push / replace / clear / subscribe.
CSM.urlState = (function() {
    function hasURLValue(value) {
        return value !== undefined && value !== null && String(value) !== '';
    }
    function setParam(url, key, value) {
        if (hasURLValue(value)) url.searchParams.set(key, String(value));
        else url.searchParams.delete(key);
    }
    function own(obj, key) {
        return Object.prototype.hasOwnProperty.call(obj, key);
    }
    function eventName(el) {
        if (String(el.tagName || '').toUpperCase() === 'SELECT') return 'change';
        var type = String(el.type || '').toLowerCase();
        if (type === 'date' || type === 'time' || type === 'datetime-local' || type === 'month' || type === 'week') return 'change';
        return 'input';
    }
    function stateValue(state, defaults, name) {
        if (own(state, name)) return state[name] == null ? '' : String(state[name]);
        if (own(defaults, name)) return defaults[name] == null ? '' : String(defaults[name]);
        return '';
    }
    function clearHashIfRequested(url, opts) {
        if (opts && opts.clearHash) url.hash = '';
    }
    function writeParams(params, push, opts) {
        var url = new URL(window.location);
        Object.keys(params || {}).forEach(function(k) {
            setParam(url, k, params[k]);
        });
        clearHashIfRequested(url, opts);
        if (push) history.pushState(null, '', url);
        else history.replaceState(null, '', url);
    }

    return {
        get: function(key) {
            return new URLSearchParams(window.location.search).get(key) || '';
        },
        getAll: function() {
            var out = {};
            new URLSearchParams(window.location.search).forEach(function(value, key) {
                out[key] = value;
            });
            return out;
        },
        set: function(params, opts) {
            writeParams(params, false, opts);
        },
        push: function(params, opts) {
            writeParams(params, true, opts);
        },
        clear: function(keys, opts) {
            var url = new URL(window.location);
            (keys || []).forEach(function(k) { url.searchParams.delete(k); });
            clearHashIfRequested(url, opts);
            history.replaceState(null, '', url);
        },
        replace: function(params, opts) {
            var url = new URL(window.location);
            Array.from(url.searchParams.keys()).forEach(function(k) {
                url.searchParams.delete(k);
            });
            Object.keys(params || {}).forEach(function(k) {
                setParam(url, k, params[k]);
            });
            clearHashIfRequested(url, opts);
            history.replaceState(null, '', url);
        },
        // subscribe(fn) calls fn(getAll()) on popstate (back/forward) so the
        // page can re-apply state after the browser walks history. Returns an
        // unsubscribe function.
        subscribe: function(fn) {
            function handler() { fn(CSM.urlState.getAll()); }
            window.addEventListener('popstate', handler);
            return function() { window.removeEventListener('popstate', handler); };
        },
        // bind({ inputs: { paramName: el, ... }, defaults: { paramName: 'x' } })
        // wires each input two-way to URL state:
        //   - on load, sets input.value from the URL (or defaults if absent);
        //   - on input/change, writes the input value back to the URL,
        //     omitting the param when the value matches its default.
        // Returns an unsubscribe function that removes the listeners.
        bind: function(opts) {
            opts = opts || {};
            var inputs = opts.inputs || {};
            var defaults = opts.defaults || {};
            var debounceMs = (opts.debounceMs == null) ? 200 : opts.debounceMs;
            var listeners = [];
            var applying = false;

            function applyState(state) {
                applying = true;
                try {
                    Object.keys(inputs).forEach(function(name) {
                        var el = inputs[name];
                        if (!el) return;
                        var desired = stateValue(state || {}, defaults, name);
                        if (el.value !== desired) {
                            el.value = desired;
                            // Dispatch so dependent table / chart listeners pick up
                            // restored values during page-load and history navigation.
                            el.dispatchEvent(new Event(eventName(el), { bubbles: true }));
                        }
                    });
                } finally {
                    applying = false;
                }
            }

            applyState(CSM.urlState.getAll());

            Object.keys(inputs).forEach(function(name) {
                var el = inputs[name];
                if (!el) return;
                var sync = CSM.debounce(function() {
                    var v = el.value || '';
                    var patch = {};
                    patch[name] = (v && v !== stateValue({}, defaults, name)) ? v : '';
                    CSM.urlState.set(patch);
                }, debounceMs);
                var inputHandler = function() {
                    if (applying) return;
                    sync();
                };
                var evt = eventName(el);
                el.addEventListener(evt, inputHandler);
                listeners.push({ el: el, evt: evt, fn: inputHandler, cancel: sync.cancel });
            });

            var unsubscribePopstate = CSM.urlState.subscribe(function(state) { applyState(state); });

            return function() {
                unsubscribePopstate();
                listeners.forEach(function(l) {
                    l.el.removeEventListener(l.evt, l.fn);
                    if (l.cancel) l.cancel();
                });
            };
        }
    };
})();
