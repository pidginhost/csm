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

// Format ISO timestamp to "YYYY-MM-DD HH:MM" in browser-local timezone.
// Pass { tz: true } as opts to append timezone abbreviation.
CSM.fmtDate = function(ts, opts) {
    if (!ts) return '\u2014';
    var d = new Date(ts);
    if (isNaN(d.getTime())) return '\u2014';
    var y = d.getFullYear();
    var m = String(d.getMonth() + 1).padStart(2, '0');
    var day = String(d.getDate()).padStart(2, '0');
    var h = String(d.getHours()).padStart(2, '0');
    var min = String(d.getMinutes()).padStart(2, '0');
    var result = y + '-' + m + '-' + day + ' ' + h + ':' + min;
    if (opts && opts.tz) {
        var tz = d.toLocaleTimeString('en-us', { timeZoneName: 'short' }).split(' ').pop();
        result += ' ' + tz;
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
        if (allowNonOK) return r;
        if (!r.ok) {
            return r.json().catch(function() { throw new Error('HTTP ' + r.status); })
                .then(function(body) { throw new Error(body.error || 'HTTP ' + r.status); });
        }
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
    }

    function removePoller(poller) {
        for (var i = pollers.length - 1; i >= 0; i--) {
            if (pollers[i] === poller) {
                pollers.splice(i, 1);
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

    CSM.poll = function(url, interval, callback) {
        var baseInterval = interval;
        var currentInterval = interval;
        var maxInterval = 300000; // 5 minutes
        var timerId = null;
        var timerSeq = 0;
        var state = 'scheduled';
        var poller = { onVisibility: onVisibility };

        function clearTimer() {
            if (timerId) {
                clearTimeout(timerId);
                timerId = null;
                timerSeq++;
            }
        }

        function scheduleNext(delayMs) {
            if (state === 'stopped' || document.hidden) {
                if (state !== 'stopped') state = 'idle';
                return;
            }
            clearTimer();
            state = 'scheduled';
            var seq = ++timerSeq;
            timerId = setTimeout(function() { run(seq); }, delayMs);
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

        function run(seq) {
            if (seq !== timerSeq) return;
            timerId = null;
            if (state === 'stopped') return;
            if (document.hidden) { state = 'idle'; return; }
            if (state !== 'scheduled') return;
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

// Client-side table export (CSV / JSON)
CSM.exportTable = function(data, columns, format, filename) {
    var content, mime;
    if (format === 'json') {
        var filtered = data.map(function(row) {
            var obj = {};
            columns.forEach(function(col) { obj[col.key] = row[col.key]; });
            return obj;
        });
        content = JSON.stringify(filtered, null, 2);
        mime = 'application/json';
    } else {
        var lines = [columns.map(function(c) {
            return '"' + (c.label || c.key).replace(/"/g, '""') + '"';
        }).join(',')];
        data.forEach(function(row) {
            lines.push(columns.map(function(c) {
                var val = row[c.key] != null ? String(row[c.key]) : '';
                return '"' + val.replace(/"/g, '""') + '"';
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

// URL state helpers (WEB_ROADMAP P2.1). Convention:
//   - Query string carries filter / search / paging state so the
//     browser back/forward stack and bookmarks survive reloads.
//   - Hash fragment carries in-page anchors only (settings section,
//     incident id, expanded row id).
//
// Pages that need to persist filter state call CSM.urlState.bind to
// wire one or more inputs declaratively; ad-hoc callers use get / set
// / replace / clear / subscribe.
CSM.urlState = {
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
    set: function(params) {
        var url = new URL(window.location);
        Object.keys(params).forEach(function(k) {
            if (params[k]) url.searchParams.set(k, params[k]);
            else url.searchParams.delete(k);
        });
        history.replaceState(null, '', url);
    },
    clear: function(keys) {
        var url = new URL(window.location);
        (keys || []).forEach(function(k) { url.searchParams.delete(k); });
        history.replaceState(null, '', url);
    },
    replace: function(params) {
        var url = new URL(window.location);
        Array.from(url.searchParams.keys()).forEach(function(k) {
            url.searchParams.delete(k);
        });
        Object.keys(params || {}).forEach(function(k) {
            if (params[k]) url.searchParams.set(k, params[k]);
        });
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
        var current = CSM.urlState.getAll();
        var listeners = [];
        Object.keys(inputs).forEach(function(name) {
            var el = inputs[name];
            if (!el) return;
            var initial = (current[name] != null && current[name] !== '')
                ? current[name]
                : (defaults[name] != null ? defaults[name] : '');
            if (initial !== '' && el.value !== initial) {
                el.value = initial;
                // Dispatch so dependent table / chart listeners pick up
                // the restored value during their own page-load wiring.
                var initEvt = (el.tagName === 'SELECT') ? 'change' : 'input';
                el.dispatchEvent(new Event(initEvt, { bubbles: true }));
            }
            var sync = CSM.debounce(function() {
                var v = el.value || '';
                var patch = {};
                patch[name] = (v && v !== (defaults[name] || '')) ? v : '';
                CSM.urlState.set(patch);
            }, debounceMs);
            var evt = (el.tagName === 'SELECT') ? 'change' : 'input';
            el.addEventListener(evt, sync);
            listeners.push({ el: el, evt: evt, fn: sync });
        });
        return function() {
            listeners.forEach(function(l) { l.el.removeEventListener(l.evt, l.fn); });
        };
    }
};
