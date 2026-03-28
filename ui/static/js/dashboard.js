// CSM Dashboard — WebSocket live feed + auto-refresh
// Detects WHM proxy mode and falls back to polling when WebSocket isn't available
(function() {
    'use strict';

    var feed = document.getElementById('live-feed-entries');
    var wsStatus = document.getElementById('ws-status');
    var reconnectDelay = 1000;
    var ws;
    var wsDisabled = false;

    // Detect if running through WHM CGI proxy (WebSocket won't work through CGI)
    var isProxy = window.location.pathname.indexOf('addon_csm.cgi') >= 0 ||
                  window.location.search.indexOf('path=') >= 0;

    var _pollingStarted = false;
    function startPolling() {
        if (_pollingStarted) return;
        _pollingStarted = true;
        setInterval(pollFindings, 10000);
    }

    function connect() {
        if (isProxy || wsDisabled) {
            // WHM proxy can't handle WebSocket — use polling instead
            if (wsStatus) wsStatus.className = 'status-dot bg-yellow';
            startPolling();
            return;
        }

        var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        ws = new WebSocket(proto + '//' + location.host + '/ws/findings');

        ws.onopen = function() {
            reconnectDelay = 1000;
            if (wsStatus) wsStatus.className = 'status-dot status-dot-animated bg-green';
        };

        ws.onmessage = function(e) {
            try {
                var findings = JSON.parse(e.data);
                for (var i = 0; i < findings.length; i++) {
                    addEntry(findings[i]);
                }
            } catch(err) { /* malformed JSON */ }
        };

        ws.onclose = function() {
            if (wsStatus) wsStatus.className = 'status-dot bg-red';
            // After 5 failed reconnects, switch to polling
            if (reconnectDelay > 16000) {
                wsDisabled = true;
                if (wsStatus) wsStatus.className = 'status-dot bg-yellow';
                startPolling();
                return;
            }
            setTimeout(function() {
                reconnectDelay = Math.min(reconnectDelay * 2, 30000);
                connect();
            }, reconnectDelay);
        };

        ws.onerror = function() { ws.close(); };
    }

    // Polling fallback — fetch recent history
    var lastPollTimestamp = '';
    function pollFindings() {
        fetch(CSM.apiUrl('/api/v1/history?limit=10&offset=0'), { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var findings = data.findings || [];
                for (var i = findings.length - 1; i >= 0; i--) {
                    var f = findings[i];
                    var ts = f.timestamp || '';
                    if (ts > lastPollTimestamp) {
                        addEntry(f);
                        lastPollTimestamp = ts;
                    }
                }
            })
            .catch(function() {});
    }

    function addEntry(f) {
        if (!feed) return;
        var div = document.createElement('div');
        div.className = 'list-group-item';

        var sevClass = 'warning';
        var sevLabel = 'WARNING';
        if (f.severity === 2) { sevClass = 'critical'; sevLabel = 'CRITICAL'; }
        else if (f.severity === 1) { sevClass = 'high'; sevLabel = 'HIGH'; }

        var now = new Date();
        var time = now.getHours().toString().padStart(2,'0') + ':' +
                   now.getMinutes().toString().padStart(2,'0') + ':' +
                   now.getSeconds().toString().padStart(2,'0');

        div.innerHTML = '<div class="row align-items-center">' +
            '<div class="col-auto"><span class="text-muted font-monospace small">' + time + '</span></div>' +
            '<div class="col-auto"><span class="badge badge-' + sevClass + '">' + sevLabel + '</span></div>' +
            '<div class="col"><span class="font-monospace small">' + CSM.esc(f.check) + '</span> — ' + CSM.esc(f.message) + '</div>' +
            '</div>';

        feed.insertBefore(div, feed.firstChild);

        while (feed.children.length > 15) {
            feed.removeChild(feed.lastChild);
        }

        var empty = feed.querySelector('.text-center');
        if (empty) empty.remove();
    }


    // Auto-refresh stats every 30 seconds
    function refreshStats() {
        fetch(CSM.apiUrl('/api/v1/stats'), { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (!data.last_24h) return;
                var s = data.last_24h;
                setText('stat-critical', s.critical);
                setText('stat-high', s.high);
                setText('stat-warning', s.warning);
                setText('stat-total', s.total);
            })
            .catch(function() {});
    }

    function setText(id, val) {
        var el = document.getElementById(id);
        if (el) el.textContent = val;
    }

    // Initialize
    if (feed) {
        connect();
        setInterval(refreshStats, 30000);
    }
})();
