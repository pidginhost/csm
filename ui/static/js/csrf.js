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

// Per-request limits the bulk endpoints enforce. Keep them equal to the
// server constants; the Web UI tests compare the two.
CSM.QUARANTINE_BULK_MAX = 100;
CSM.THREAT_BULK_MAX = 100;
CSM.SUPPRESS_BULK_MAX = 100;
CSM.DISMISS_BULK_MAX = 500;
CSM.FIX_BULK_BODY_MAX = 65536;

// Send items to an endpoint that accepts at most `size` per request, one batch
// after another, so a large selection is not refused as a whole. body(batch)
// builds each request body and onBatch(response) sees each reply as it lands,
// which lets a caller report what already happened if a later batch fails.
CSM.postBatches = function(url, items, size, body, onBatch) {
    var chain = Promise.resolve();
    for (var i = 0; i < items.length; i += size) {
        (function(batch) {
            chain = chain.then(function() {
                return CSM.post(url, body(batch)).then(onBatch);
            });
        })(items.slice(i, i + size));
    }
    return chain;
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

// Render a loading skeleton placeholder
CSM.loading = function(el) {
    if (el) el.innerHTML = '<div class="card-body text-center text-muted py-4"><span class="spinner-border spinner-border-sm me-2"></span>Loading...</div>';
};

// errorText is the text of a caught failure. String(err) starts with
// "Error: ", which reads as "Error: Error: ..." after a page's own prefix.
CSM.errorText = function(err) {
    if (err && typeof err.message === 'string' && err.message) return err.message;
    if (typeof err === 'string' && err) return err;
    return 'request failed';
};

// loadError shows that a load failed inside el: what failed, why, and a
// Retry button. It hides el's content instead of replacing it, so a loader
// that fills elements inside el still finds them. A loader that rebuilds el
// wipes the error with it; one that only fills elements inside el calls
// CSM.clearLoadError(el) when it succeeds. Inside a table body the error is
// one row across the table.
//   opts.title  what failed (default "Failed to load data")
//   opts.error  the caught failure, shown as the reason
CSM.loadError = function(el, retryFn, opts) {
    if (!el) return;
    opts = opts || {};
    CSM.clearLoadError(el);
    var inTable = el.tagName === 'TBODY';
    var body = document.createElement(inTable ? 'td' : 'div');
    // Card padding, unless el already is a padded card body.
    var padded = !inTable && !el.classList.contains('card-body');
    body.className = (padded ? 'card-body ' : '') + 'text-center py-4';
    var title = document.createElement('div');
    title.className = 'text-danger mb-2';
    title.textContent = opts.title || 'Failed to load data';
    body.appendChild(title);
    if (opts.error) {
        var reason = document.createElement('div');
        reason.className = 'text-muted small mb-2';
        reason.textContent = CSM.errorText(opts.error);
        body.appendChild(reason);
    }
    if (retryFn) {
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-sm btn-outline-secondary csm-retry-btn';
        btn.textContent = 'Retry';
        btn.addEventListener('click', function() {
            CSM.clearLoadError(el);
            retryFn();
        });
        body.appendChild(btn);
    }
    Array.prototype.slice.call(el.childNodes).forEach(function(node) {
        if (node.nodeType === 3) {
            if (!/\S/.test(node.nodeValue)) return;
            var span = document.createElement('span');
            el.replaceChild(span, node);
            span.appendChild(node);
            node = span;
        }
        if (node.nodeType !== 1 || node.hidden) return;
        node.hidden = true;
        node.setAttribute('data-csm-load-error-hidden', '');
    });
    var block = body;
    if (inTable) {
        block = document.createElement('tr');
        body.setAttribute('colspan', String(tableColumns(el)));
        block.appendChild(body);
    }
    block.classList.add('csm-load-error');
    el.appendChild(block);

    function tableColumns(tbody) {
        var table = tbody.parentNode;
        var head = table && table.querySelector('thead tr');
        var row = head || tbody.querySelector('tr');
        return row && row.children.length ? row.children.length : 1;
    }
};

// clearLoadError removes the error CSM.loadError put in el and shows the
// content it hid.
CSM.clearLoadError = function(el) {
    if (!el) return;
    Array.prototype.slice.call(el.children).forEach(function(child) {
        if (child.classList.contains('csm-load-error')) {
            el.removeChild(child);
        } else if (child.hasAttribute('data-csm-load-error-hidden')) {
            child.removeAttribute('data-csm-load-error-hidden');
            child.hidden = false;
        }
    });
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
//   refresh     bool     true marks a GET as a data load; false excludes
//                        detail lookups even during page load. Otherwise
//                        the page-load or refresh-handler context decides.
// All other keys are forwarded to fetch() unchanged.
// Every page request goes through CSM.request, so connection health and
// session expiry are tracked here. The banner is the single signal for an
// unreachable daemon: network failures, timeouts and 5xx answers count toward
// it, and any other answer proves the daemon is up and clears it.
CSM.connection = (function() {
    var failures = 0;
    // dismissed hides the banner for the rest of this outage; the next
    // outage, after the server answered again, shows it again.
    var dismissed = false;
    function banner() { return document.getElementById('csm-connection-lost'); }
    document.addEventListener('click', function(e) {
        if (!e.target.closest || !e.target.closest('[data-csm-dismiss-connection]')) return;
        dismissed = true;
        var b = banner();
        if (b) b.classList.add('d-none');
    });
    return {
        up: function() {
            failures = 0;
            dismissed = false;
            var b = banner();
            if (b) b.classList.add('d-none');
        },
        down: function() {
            failures++;
            if (failures < 3 || dismissed) return;
            var b = banner();
            if (b) b.classList.remove('d-none');
        },
        isLost: function() { return failures >= 3; }
    };
})();

var csmSessionRedirected = false;
var csmRecentErrorToasts = {};

// The same error from a poller that keeps failing is shown once per window,
// and not at all while the banner already says the daemon is unreachable.
function csmRequestErrorToast(err) {
    var unreachable = err.name === 'AbortError' || err.csmNetwork || (err.status >= 500);
    if (unreachable && CSM.connection.isLost()) return;
    var message = err.name === 'AbortError' ? 'Request timed out' : 'Request failed: ' + err.message;
    var now = Date.now();
    if (csmRecentErrorToasts[message] && now - csmRecentErrorToasts[message] < 30000) return;
    csmRecentErrorToasts[message] = now;
    CSM.toast(message, 'error');
}

// Operator activity. A browser session ends after an idle period, so timer
// polls must not keep it alive: only requests made within a minute of the
// operator's own input carry X-CSM-Active, which the server counts.
var csmLastInput = 0;
CSM.ACTIVE_WINDOW_MS = 60000;
['pointerdown', 'keydown', 'wheel', 'touchstart'].forEach(function(type) {
    document.addEventListener(type, function() { csmLastInput = Date.now(); }, { capture: true, passive: true });
});

function csmCopyHeaders(headers) {
    var copy = {};
    if (Array.isArray(headers)) {
        var values = new Map();
        headers.forEach(function(pair) {
            var name = String(pair[0]).toLowerCase();
            var value = String(pair[1]);
            values.set(name, values.has(name) ? values.get(name) + ', ' + value : value);
        });
        copy = Object.fromEntries(values);
    } else if (headers && typeof headers.forEach === 'function') {
        headers.forEach(function(value, name) { copy[name] = value; });
    } else {
        copy = Object.assign({}, headers);
    }
    return copy;
}

CSM.request = function(url, options) {
    var resolvedUrl = (typeof CSM.apiUrl === 'function') ? CSM.apiUrl(url) : url;
    options = options || {};
    var headers = csmCopyHeaders(options.headers);
    // Options may be reused after the input window closes. Never retain
    // an activity marker from a previous dispatch or mutate the caller.
    Object.keys(headers).forEach(function(name) {
        if (name.toLowerCase() === 'x-csm-active') delete headers[name];
    });
    if (csmLastInput && Date.now() - csmLastInput < CSM.ACTIVE_WINDOW_MS) {
        headers['X-CSM-Active'] = '1';
    }
    var timeoutMs = (options.timeoutMs == null) ? 30000 : options.timeoutMs;
    // Only a data load moves "Updated N ago": a GET sent while the page
    // loads, by a refresh tick or handler, or marked refresh (pollers). An
    // action or a detail lookup does not make the page fresher.
    var dataLoad = String(options.method || 'GET').toUpperCase() === 'GET' &&
        options.refresh !== false && (options.refresh === true || !CSM.refresh || CSM.refresh.inDataLoad);
    var allowNonOK = !!options.allowNonOK;
    var silent = !!options.silent;
    var controller = new AbortController();
    var timeoutId = (timeoutMs > 0) ? setTimeout(function() { controller.abort(); }, timeoutMs) : null;
    var opts = Object.assign({}, options, { headers: headers, signal: controller.signal, credentials: 'same-origin' });
    delete opts.timeoutMs;
    delete opts.refresh;
    delete opts.allowNonOK;
    delete opts.silent;
    return fetch(resolvedUrl, opts).then(function(r) {
        if (timeoutId) clearTimeout(timeoutId);
        if (r.status >= 500) CSM.connection.down(); else CSM.connection.up();
        if (r.status === 401) {
            // The browser session ended (expiry, revocation or restart).
            // Every open request sees it; the page leaves once.
            if (!csmSessionRedirected) {
                csmSessionRedirected = true;
                window.location.assign('/login');
            }
            var expired = new Error('Session expired');
            expired.csmSessionExpired = true;
            throw expired;
        }
        if (allowNonOK) {
            if (r.ok && dataLoad && CSM.refresh) CSM.refresh.bump();
            return r;
        }
        if (!r.ok) {
            return r.json().catch(function() { return {}; }).then(function(body) {
                var httpErr = new Error((body && body.error) || 'HTTP ' + r.status);
                httpErr.status = r.status;
                throw httpErr;
            });
        }
        if (dataLoad && CSM.refresh) CSM.refresh.bump();
        return r;
    }, function(err) {
        // fetch itself rejected: the request never got an answer.
        if (timeoutId) clearTimeout(timeoutId);
        if (err.name !== 'AbortError') err.csmNetwork = true;
        CSM.connection.down();
        throw err;
    }).catch(function(err) {
        if (!silent && !err.csmSessionExpired) csmRequestErrorToast(err);
        throw err;
    });
};

// Fetch wrapper with 30s timeout and error toast
CSM.fetch = function(url, options) {
    return CSM.request(url, options).then(function(r) { return r.json(); });
};

CSM.get = function(url, options) {
    var opts = Object.assign({}, options || {});
    opts.headers = csmCopyHeaders(opts.headers);
    if (!Object.keys(opts.headers).some(function(name) { return name.toLowerCase() === 'accept'; })) {
        opts.headers.Accept = 'application/json';
    }
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
    // depth > 0 while a refresh tick or handler runs; requests it sends
    // are data loads. So is everything sent before the page finished loading.
    var depth = 0;
    var pageLoaded = false;
    window.addEventListener('load', function() { pageLoaded = true; });
    // autoCount is the timers and pollers that refresh on their own; the
    // pause control is shown only while there is one.
    var autoCount = 0;

    function track(fn) {
        depth++;
        try { return fn(); } finally { depth--; }
    }

    function changeAuto(delta) {
        autoCount = Math.max(0, autoCount + delta);
        window.dispatchEvent(new CustomEvent('csm:refresh-auto', { detail: { active: autoCount > 0 } }));
    }

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
            track(fn);
        } catch (e) {
            setTimeout(function() { throw e; }, 0);
        }
    }

    // opts.whileLive is a slower interval used while the event stream is
    // connected: live updates then keep the page current, and the timer is
    // only a safety net.
    function createInterval(fn, interval, opts) {
        var timerId = null;
        var stopped = false;
        var delay = Math.max(0, Number(interval) || 0);
        var liveDelay = opts && Number(opts.whileLive) > 0 ? Number(opts.whileLive) : 0;
        function currentDelay() {
            return (liveDelay && CSM.sse && CSM.sse.state === 'connected') ? liveDelay : delay;
        }
        // Creation counts as a run: the page loads its data when it starts.
        var lastRun = Date.now();
        subscribers++;
        changeAuto(1);

        function clearTimer() {
            if (timerId) {
                clearTimeout(timerId);
                timerId = null;
            }
        }

        function schedule(wait) {
            clearTimer();
            if (stopped || document.hidden || !enabled) return;
            timerId = setTimeout(function() {
                timerId = null;
                if (stopped || document.hidden || !enabled) return;
                lastRun = Date.now();
                invokeTimer(fn);
                schedule();
            }, wait == null ? currentDelay() : wait);
        }

        function runNow() {
            if (stopped || document.hidden) return;
            clearTimer();
            lastRun = Date.now();
            invokeTimer(fn);
            schedule();
        }

        // resume runs when the tab becomes visible: at once if a run is
        // overdue, otherwise on the normal schedule. Pages rely on this and
        // keep no visibility handlers of their own, which used to start a
        // second set of timers and reload while auto-refresh was paused.
        function resume() {
            if (stopped || document.hidden || !enabled) return;
            var due = currentDelay();
            if (Date.now() - lastRun >= due) runNow();
            else schedule(due - (Date.now() - lastRun));
        }

        var timer = {
            pause: clearTimer,
            schedule: schedule,
            resume: resume,
            runNow: runNow,
            stop: function() {
                if (stopped) return;
                stopped = true;
                subscribers = Math.max(0, subscribers - 1);
                changeAuto(-1);
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
        get inDataLoad() { return depth > 0 || !pageLoaded; },
        get hasAuto() { return autoCount > 0; },
        // track runs fn as a data load, for work started outside a refresh
        // tick, such as a live update.
        track: track,
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
            var wrapped = function() { try { track(fn); } catch (e) { /* swallow */ } };
            window.addEventListener('csm:refresh-now', wrapped);
            var unsubscribed = false;
            return function() {
                if (unsubscribed) return;
                unsubscribed = true;
                subscribers = Math.max(0, subscribers - 1);
                window.removeEventListener('csm:refresh-now', wrapped);
            };
        },
        _bumpSubscriber: function() { subscribers++; changeAuto(1); },
        _dropSubscriber: function() { subscribers = Math.max(0, subscribers - 1); changeAuto(-1); },
        interval: function(fn, interval, opts) {
            return createInterval(fn, interval, opts);
        }
    };

    // The event stream connecting or dropping changes which interval a
    // timer uses; reschedule from its last run.
    window.addEventListener('csm:sse-state', function() {
        eachTimer(function(timer) { timer.resume(); });
    });

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
        eachTimer(function(timer) { timer.resume(); });
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
        // A retry after a drop stays "reconnecting"; only a first connection
        // or one after the tab was hidden reads "connecting".
        setState(state === STATES.connected || state === STATES.reconnecting ? STATES.reconnecting : STATES.connecting);
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

// Live updates. The event stream carries each finding as it is dispatched;
// onFinding hands a page the findings of a burst in one batch, a moment after
// the burst ends, so a flood of findings reloads a page once. While
// auto-refresh is paused the page is left alone, as its timers are. The
// page's reload counts as a data load for "Updated N ago".
CSM.live = {
    get connected() { return !!(CSM.sse && CSM.sse.state === 'connected'); },
    onFinding: function(fn, opts) {
        var wait = opts && opts.wait != null ? opts.wait : 1500;
        var batch = [];
        var timer = null;
        function flush() {
            timer = null;
            var items = batch;
            batch = [];
            if (CSM.refresh && !CSM.refresh.enabled) return;
            if (CSM.refresh && CSM.refresh.track) CSM.refresh.track(function() { fn(items); });
            else fn(items);
        }
        function onMessage(ev) {
            var f;
            try { f = JSON.parse(ev.detail && ev.detail.raw); } catch (e) { return; }
            if (!f || typeof f !== 'object') return;
            batch.push(f);
            if (!timer) timer = setTimeout(flush, wait);
        }
        window.addEventListener('csm:sse-message', onMessage);
        return function() {
            window.removeEventListener('csm:sse-message', onMessage);
            if (timer) { clearTimeout(timer); timer = null; }
            batch = [];
        };
    }
};

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

    window.addEventListener('csm:sse-state', function() {
        var snapshot = pollers.slice();
        for (var i = 0; i < snapshot.length; i++) snapshot[i].onLiveChange();
    });

    // Manual refresh forces a one-shot fetch even while auto-refresh is
    // paused, then returns the poller to the normal enabled/paused state.
    window.addEventListener('csm:refresh-now', function() {
        var snapshot = pollers.slice();
        for (var i = 0; i < snapshot.length; i++) {
            snapshot[i].onRefreshNow();
        }
    });

    // opts.whileLive, as for CSM.refresh.interval, is the slower interval
    // used while the event stream is connected.
    CSM.poll = function(url, interval, callback, opts) {
        function baseInterval() {
            return (opts && Number(opts.whileLive) > 0 && CSM.sse && CSM.sse.state === 'connected') ? Number(opts.whileLive) : interval;
        }
        var currentInterval = baseInterval();
        var maxInterval = 300000; // 5 minutes
        var timerId = null;
        var timerSeq = 0;
        var state = 'scheduled';
        var poller = { onVisibility: onVisibility, onPause: onPause, onResume: onResume, onRefreshNow: onRefreshNow, onLiveChange: onLiveChange };

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
                promise = CSM.request(url, { silent: true, refresh: true })
                    .then(function(r) { return r.json(); });
            } catch (e) {
                fail(e);
                scheduleNext(currentInterval + Math.random() * currentInterval * 0.3);
                return;
            }
            promise.then(function(data) {
                if (state === 'stopped') return;
                currentInterval = baseInterval();
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
            currentInterval = baseInterval();
            scheduleNext(100);
        }

        function onLiveChange() {
            if (state !== 'scheduled') return;
            currentInterval = baseInterval();
            scheduleNext(currentInterval);
        }

        function onRefreshNow() {
            if (state === 'stopped' || document.hidden) return;
            if (state === 'running') return;
            currentInterval = baseInterval();
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
