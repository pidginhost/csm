// CSM Dashboard — polling-based live feed + auto-refresh
(function() {
    'use strict';

    var feed = document.getElementById('live-feed-entries');

    // Notification toggle — gated on BOTH browser permission AND user preference
    // localStorage 'csm-notif' stores the user's opt-in choice ('on' or 'off')
    var notifBtn = document.getElementById('notif-toggle');
    if (notifBtn && 'Notification' in window) {
        notifBtn.classList.remove('d-none');
        var notifPref = localStorage.getItem('csm-notif'); // 'on', 'off', or null
        function updateNotifIcon() {
            var icon = notifBtn.querySelector('i');
            var isActive = Notification.permission === 'granted' && notifPref === 'on';
            if (Notification.permission === 'denied') {
                notifBtn.classList.add('d-none');
            } else if (isActive) {
                icon.className = 'ti ti-bell-ringing';
                notifBtn.title = 'Desktop alerts ON (click to disable)';
            } else {
                icon.className = 'ti ti-bell';
                notifBtn.title = 'Enable desktop alerts';
            }
        }
        updateNotifIcon();
        notifBtn.addEventListener('click', function() {
            if (Notification.permission === 'granted') {
                // Toggle preference
                notifPref = (notifPref === 'on') ? 'off' : 'on';
                localStorage.setItem('csm-notif', notifPref);
                updateNotifIcon();
            } else if (Notification.permission === 'default') {
                Notification.requestPermission().then(function(result) {
                    if (result === 'granted') {
                        notifPref = 'on';
                        localStorage.setItem('csm-notif', 'on');
                    }
                    updateNotifIcon();
                });
            }
        });
    }

    // Polling — fetch recent history every 10 seconds
    // Initialize lastPollTimestamp from server-rendered feed items to avoid
    // duplicating them on first poll (and after page auto-reload)
    var lastPollTimestamp = '';
    var serverItems = feed ? feed.querySelectorAll('.feed-item[data-ts]') : [];
    if (serverItems.length > 0) {
        lastPollTimestamp = serverItems[0].getAttribute('data-ts') || '';
    }
    function pollFindings() {
        fetch(CSM.apiUrl('/api/v1/history?limit=10&offset=0'), { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var findings = data.findings || [];
                var internalChecks = { auto_response: 1, auto_block: 1, check_timeout: 1, health: 1 };
                var maxTs = lastPollTimestamp;
                for (var i = findings.length - 1; i >= 0; i--) {
                    var f = findings[i];
                    var ts = f.timestamp || '';
                    if (ts > maxTs) maxTs = ts;
                    if (ts > lastPollTimestamp && !internalChecks[f.check]) {
                        addEntry(f);
                    }
                }
                lastPollTimestamp = maxTs;
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

        // Use finding's actual timestamp, fall back to current time
        var ts = f.timestamp || new Date().toISOString();
        var time = CSM.fmtDate(ts).substring(11); // "HH:MM TZ"
        if (!time || time === '\u2014') {
            var now = new Date();
            time = now.getHours().toString().padStart(2,'0') + ':' +
                   now.getMinutes().toString().padStart(2,'0');
        }

        div.setAttribute('data-ts', ts);
        div.innerHTML = '<div class="row align-items-center">' +
            '<div class="col-auto"><span class="text-muted font-monospace small">' + time + '</span></div>' +
            '<div class="col-auto"><span class="badge badge-' + sevClass + '">' + sevLabel + '</span></div>' +
            '<div class="col"><span class="font-monospace small">' + CSM.esc(f.check) + '</span> — ' + CSM.esc(f.message) + '</div>' +
            '</div>';

        feed.insertBefore(div, feed.firstChild);

        // Browser notification for critical findings
        if (f.severity === 2 && 'Notification' in window && Notification.permission === 'granted' && localStorage.getItem('csm-notif') === 'on') {
            new Notification('CSM Critical Alert', {
                body: f.check + ': ' + f.message,
                tag: f.check + ':' + f.message
            });
        }

        while (feed.children.length > 10) {
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
                // Update accounts at risk widget
                renderAccountsAtRisk(data.accounts_at_risk || []);
                // Update auto-response summary
                renderAutoResponse(data.auto_response || {});
                // Update top targeted accounts
                renderTopTargeted(data.top_accounts || []);
            })
            .catch(function() {});
    }

    function refreshScanStatus() {
        fetch(CSM.apiUrl('/api/v1/status'), { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                setText('scan-status', data.scan_running ? 'Scanning...' : 'Idle');
                if (data.last_scan_time) {
                    setText('scan-detail', 'Last scan: ' + CSM.timeAgo(data.last_scan_time));
                }
            })
            .catch(function() {});
    }

    var sevClasses = { 2: 'critical', 1: 'high', 0: 'warning' };
    var sevLabelsMap = { 2: 'CRITICAL', 1: 'HIGH', 0: 'WARNING' };

    function renderAccountsAtRisk(accounts) {
        var el = document.getElementById('accounts-at-risk');
        if (!el) return;
        if (!accounts || accounts.length === 0) {
            el.innerHTML = '<div class="text-muted text-center py-3">No accounts at risk</div>';
            return;
        }
        var html = '<div class="list-group list-group-flush">';
        for (var i = 0; i < accounts.length; i++) {
            var a = accounts[i];
            var cls = sevClasses[a.severity] || 'warning';
            html += '<div class="list-group-item">';
            html += '<div class="d-flex align-items-center">';
            html += '<span class="badge badge-' + cls + ' me-2">' + (sevLabelsMap[a.severity] || '?') + '</span>';
            html += '<a href="/account?name=' + CSM.esc(a.account) + '" class="font-monospace">' + CSM.esc(a.account) + '</a>';
            html += '<span class="ms-auto text-muted small">' + a.findings + ' findings</span>';
            html += '</div></div>';
        }
        html += '</div>';
        el.innerHTML = html;
    }

    function renderAutoResponse(ar) {
        var el = document.getElementById('auto-response-summary');
        if (!el) return;
        var total = (ar.blocked || 0) + (ar.quarantined || 0) + (ar.killed || 0);
        if (total === 0) {
            el.innerHTML = '<div class="text-muted text-center py-3">No auto-response actions today</div>';
            return;
        }
        var html = '<div class="d-flex flex-column gap-3">';
        html += '<div class="d-flex align-items-center justify-content-between">';
        html += '<span><i class="ti ti-shield-off text-danger"></i>&nbsp;IPs Blocked</span>';
        html += '<span class="h3 mb-0">' + (ar.blocked || 0) + '</span></div>';
        html += '<div class="d-flex align-items-center justify-content-between">';
        html += '<span><i class="ti ti-lock text-warning"></i>&nbsp;Files Quarantined</span>';
        html += '<span class="h3 mb-0">' + (ar.quarantined || 0) + '</span></div>';
        html += '<div class="d-flex align-items-center justify-content-between">';
        html += '<span><i class="ti ti-skull text-critical"></i>&nbsp;Processes Killed</span>';
        html += '<span class="h3 mb-0">' + (ar.killed || 0) + '</span></div>';
        html += '</div>';
        el.innerHTML = html;
    }

    function renderTopTargeted(accounts) {
        var el = document.getElementById('top-targeted-accounts');
        if (!el) return;
        if (!accounts || accounts.length === 0) {
            el.innerHTML = '<div class="text-muted text-center py-3">No targeted accounts</div>';
            return;
        }
        var maxCount = accounts[0].count || 1;
        var html = '<div class="list-group list-group-flush">';
        for (var i = 0; i < accounts.length; i++) {
            var a = accounts[i];
            var pct = Math.round(a.count / maxCount * 100);
            html += '<div class="list-group-item">';
            html += '<div class="d-flex align-items-center mb-1">';
            html += '<a href="/account?name=' + CSM.esc(a.account) + '" class="font-monospace">' + CSM.esc(a.account) + '</a>';
            html += '<span class="ms-auto text-muted small">' + a.count + '</span></div>';
            html += '<div class="progress progress-sm"><div class="progress-bar bg-primary" style="width:' + pct + '%"></div></div>';
            html += '</div>';
        }
        html += '</div>';
        el.innerHTML = html;
    }

    function setText(id, val) {
        var el = document.getElementById(id);
        if (el) el.textContent = val;
    }

    // Initialize — two cadences with failure isolation
    if (feed) {
        // Fast cadence (10s): findings + scan status, independent of each other
        function fastPoll() {
            try { pollFindings(); } catch(e) {}
            try { refreshScanStatus(); } catch(e) {}
        }
        fastPoll();
        setInterval(fastPoll, 10000);

        // Slow cadence (60s): stats (24h aggregates don't need 30s refresh)
        refreshStats();
        setInterval(function() {
            try { refreshStats(); } catch(e) {}
        }, 60000);
    }
})();
