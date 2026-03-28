// CSM Dashboard — polling-based live feed + auto-refresh
(function() {
    'use strict';

    var feed = document.getElementById('live-feed-entries');

    // Polling — fetch recent history every 10 seconds
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
                if (data.last_critical_ago) {
                    setText('stat-last-critical', data.last_critical_ago);
                }
            })
            .catch(function() {});
    }

    function setText(id, val) {
        var el = document.getElementById(id);
        if (el) el.textContent = val;
    }

    // Initialize
    if (feed) {
        pollFindings();
        setInterval(pollFindings, 10000);
        refreshStats();
        setInterval(refreshStats, 30000);
        // Reload page every 5 minutes for timeline chart freshness
        setTimeout(function() { location.reload(); }, 300000);
    }
})();
