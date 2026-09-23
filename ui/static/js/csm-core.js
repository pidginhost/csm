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

// Every other script adds to this namespace.
var CSM = CSM || {};

(function() {

// The CSRF token for state-changing requests, from <meta name="csrf-token">.
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

// errorText is the text of a caught failure. String(err) starts with
// "Error: ", which reads as "Error: Error: ..." after a page's own prefix.
CSM.errorText = function(err) {
    if (err && typeof err.message === 'string' && err.message) return err.message;
    if (typeof err === 'string' && err) return err;
    return 'request failed';
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

})();
