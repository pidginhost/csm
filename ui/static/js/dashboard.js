// CSM Dashboard — WebSocket live feed + auto-refresh
(function() {
    'use strict';

    var feed = document.getElementById('live-feed-entries');
    var wsStatus = document.getElementById('ws-status');
    var reconnectDelay = 1000;
    var ws;

    function connect() {
        var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        // Cookie auth is sent automatically by the browser on same-origin WebSocket
        ws = new WebSocket(proto + '//' + location.host + '/ws/findings');

        ws.onopen = function() {
            reconnectDelay = 1000;
            if (wsStatus) wsStatus.className = 'dot';
        };

        ws.onmessage = function(e) {
            try {
                var findings = JSON.parse(e.data);
                for (var i = 0; i < findings.length; i++) {
                    addEntry(findings[i]);
                }
            } catch(err) {}
        };

        ws.onclose = function() {
            if (wsStatus) wsStatus.className = 'dot disconnected';
            setTimeout(function() {
                reconnectDelay = Math.min(reconnectDelay * 2, 30000);
                connect();
            }, reconnectDelay);
        };

        ws.onerror = function() { ws.close(); };
    }

    function addEntry(f) {
        if (!feed) return;
        var div = document.createElement('div');
        div.className = 'entry';

        var sevClass = 'warning';
        var sevLabel = 'WARNING';
        if (f.severity === 2) { sevClass = 'critical'; sevLabel = 'CRITICAL'; }
        else if (f.severity === 1) { sevClass = 'high'; sevLabel = 'HIGH'; }

        var now = new Date();
        var time = now.getHours().toString().padStart(2,'0') + ':' +
                   now.getMinutes().toString().padStart(2,'0') + ':' +
                   now.getSeconds().toString().padStart(2,'0');

        div.innerHTML = '<span class="time">' + time + '</span>' +
            '<span class="badge ' + sevClass + '">' + sevLabel + '</span>' +
            '<span class="msg">' + escapeHtml(f.check) + ' — ' + escapeHtml(f.message) + '</span>';

        feed.insertBefore(div, feed.firstChild);

        // Keep max 50 entries
        while (feed.children.length > 50) {
            feed.removeChild(feed.lastChild);
        }

        // Remove empty state
        var empty = feed.querySelector('.empty-state');
        if (empty) empty.remove();
    }

    function escapeHtml(s) {
        var div = document.createElement('div');
        div.appendChild(document.createTextNode(s || ''));
        return div.innerHTML;
    }

    // Auto-refresh stats every 30 seconds
    function refreshStats() {
        fetch('/api/v1/stats', { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
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
