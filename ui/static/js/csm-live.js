// CSM runtime: keeping pages current. The refresh tracker and its timers,
// the live event stream, and polling.
var CSM = CSM || {};

(function() {

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

})();
