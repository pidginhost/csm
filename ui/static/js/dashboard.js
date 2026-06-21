// CSM Dashboard - polling-based live feed + auto-refresh + Chart.js charts
(function() {
    'use strict';

    var _intervals = [];
    var _pollers = [];

    function _trackInterval(handle) { _intervals.push(handle); return handle; }
    function _stopIntervals() {
        for (var i = 0; i < _intervals.length; i++) _intervals[i].stop();
        _intervals = [];
    }

    function _cleanup() {
        _stopIntervals();
        for (var j = 0; j < _pollers.length; j++) _pollers[j].stop();
        _pollers = [];
    }

    window.addEventListener('beforeunload', _cleanup);
    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            _stopIntervals();
        } else {
            // Restart intervals on visibility restore
            _startPolling();
        }
    });

    // --- Chart.js global defaults for dark/light theme ---
    var isDark = document.documentElement.classList.contains('theme-dark');
    var gridColor = isDark ? 'rgba(45,58,78,0.6)' : 'rgba(230,232,235,0.8)';
    var textColor = isDark ? '#6b7a8d' : '#9da9b5';

    Chart.defaults.color = textColor;
    Chart.defaults.font.family = '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
    Chart.defaults.font.size = 11;
    Chart.defaults.plugins.legend.display = false;
    Chart.defaults.animation.duration = 600;

    // Notification toggle - gated on BOTH browser permission AND user preference
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

    // Desktop critical-finding notifications. Polls /api/v1/history and
    // fires browser Notifications for new severity=2 entries; the dashboard
    // no longer renders a live feed but the alert path stays useful.
    var lastNotifTimestamp = '';
    var notifInternalChecks = { auto_response: 1, auto_block: 1, check_timeout: 1, health: 1 };

    function _maybeNotify(f) {
        if (f.severity !== 2) return;
        if (!('Notification' in window)) return;
        if (Notification.permission !== 'granted') return;
        if (localStorage.getItem('csm-notif') !== 'on') return;
        new Notification('CSM Critical Alert', {
            body: (f.check || 'finding') + ': ' + (f.message || ''),
            tag: (f.check || '') + ':' + (f.message || '')
        });
    }

    function pollFindings() {
        CSM.get('/api/v1/history?limit=10&offset=0')
            .then(function(data) {
                var findings = data.findings || [];
                var maxTs = lastNotifTimestamp;
                for (var i = findings.length - 1; i >= 0; i--) {
                    var f = findings[i];
                    var ts = f.timestamp || '';
                    if (ts > maxTs) maxTs = ts;
                    if (lastNotifTimestamp !== '' && ts > lastNotifTimestamp && !notifInternalChecks[f.check]) {
                        _maybeNotify(f);
                    }
                }
                lastNotifTimestamp = maxTs;
            })
            .catch(function(err) { console.error('pollFindings:', err); });
    }

        // Centralised empty/error-state renderer for the three summary cards.
    // Cards that fail to load get a visible error instead of a permanent
    // "Loading..." spinner.
    function renderCardError(id, msg) {
        var el = document.getElementById(id);
        if (!el) return;
        el.textContent = '';
        var box = document.createElement('div');
        box.className = 'text-center text-muted py-3';
        var ic = document.createElement('i');
        ic.className = 'ti ti-alert-circle me-1 text-warning';
        box.appendChild(ic);
        box.appendChild(document.createTextNode(msg));
        el.appendChild(box);
    }

    // --- System health pill (top of page) ---
    function renderHealthPill(cls, dotCls, label, title) {
        var pill = document.getElementById('system-health-pill');
        if (!pill) return;
        pill.className = 'badge ' + cls;
        var dot = pill.querySelector('.status-dot');
        if (dot) dot.className = 'status-dot me-1 ' + dotCls;
        var lbl = pill.querySelector('.health-label');
        if (lbl) lbl.textContent = label;
        if (title) pill.title = title;
    }
    function loadHealthPill() {
        Promise.all([
            CSM.get('/api/v1/health'),
            CSM.get('/api/v1/status')
        ]).then(function(res) {
            var health = res[0] || {};
            var status = res[1] || {};
            // Fanotify fallback is normal on platforms where fanotify isn't
            // available (e.g. some Ubuntu/Nginx setups), so it is not a
            // problem -- the uptime card already surfaces the fallback badge.
            var problems = [];
            if (!health.daemon_mode) problems.push('daemon not in service mode');
            if (!health.log_watchers) problems.push('no log watchers active');
            if (!health.rules_loaded) problems.push('no YARA rules loaded');

            // The pill tier comes from the server so active incident severity
            // and daemon liveness stay in one posture decision.
            var label = 'Healthy';
            var cls = 'health-ok';
            var dotCls = 'bg-green';
            var posture = String(status.security_posture || '');
            if (posture === 'critical') {
                label = 'Critical';
                cls = 'health-crit';
                dotCls = 'bg-red';
            } else if (posture === 'warning') {
                label = 'Warning';
                cls = 'health-warn';
                dotCls = 'bg-yellow';
            } else if (!posture) {
                if (problems.length >= 2) {
                    label = 'Degraded';
                    cls = 'health-crit';
                    dotCls = 'bg-red';
                } else if (problems.length === 1) {
                    label = 'Warning';
                    cls = 'health-warn';
                    dotCls = 'bg-yellow';
                }
            }
            var bySev = status.incidents_open_by_severity || {};
            var openParts = [];
            if (bySev.critical) openParts.push(bySev.critical + ' critical');
            if (bySev.high) openParts.push(bySev.high + ' high');
            var title = 'Uptime: ' + (status.uptime || health.uptime || '?') +
                '\nRules: ' + (health.rules_loaded || 0) +
                '\nWatchers: ' + (health.log_watchers || 0) +
                (status.scan_running ? '\nScan: in progress' : '') +
                (openParts.length ? '\nActive incidents: ' + openParts.join(', ') : '') +
                (problems.length ? '\nIssues: ' + problems.join(', ') : '');
            renderHealthPill(cls, dotCls, label, title);
        }).catch(function(err) {
            console.error('loadHealthPill:', err);
            renderHealthPill('health-crit', 'bg-red', 'Unreachable', 'Dashboard cannot reach the daemon API');
        });
    }

    // Auto-refresh stats every 60 seconds
    function refreshStats() {
        CSM.get('/api/v1/stats')
            .then(function(data) {
                if (!data.last_24h) return;
                var s = data.last_24h;
                setText('stat-critical', s.critical);
                setText('stat-high', s.high);
                setText('stat-warning', s.warning);
                // Keep text and data-timestamp aligned so CSM.initTimeAgo ticks
                // against the correct baseline when a fresh critical arrives.
                var lastCritEl = document.getElementById('stat-last-critical');
                if (lastCritEl) {
                    if (data.last_critical_iso) {
                        lastCritEl.setAttribute('data-timestamp', data.last_critical_iso);
                    } else {
                        lastCritEl.removeAttribute('data-timestamp');
                    }
                    if (data.last_critical_ago) {
                        lastCritEl.textContent = data.last_critical_ago;
                    }
                }
                renderAccountsAtRisk(data.accounts_at_risk || []);
                renderAutoResponse(data.auto_response || {}, data.by_check || {});
                renderBruteForce(data.brute_force || {});
            })
            .catch(function(err) {
                console.error('refreshStats:', err);
                renderCardError('accounts-at-risk', 'Failed to load');
                renderCardError('auto-response-summary', 'Failed to load');
                renderCardError('brute-force-summary', 'Failed to load');
            });
    }

    var sevClasses = {}; for (var sk in CSM.sevMap) sevClasses[sk] = CSM.sevMap[sk].cls;
    var sevLabelsMap = {}; for (var sl in CSM.sevMap) sevLabelsMap[sl] = CSM.sevMap[sl].label;

    function renderAccountsAtRisk(accounts) {
        var el = document.getElementById('accounts-at-risk');
        if (!el) return;
        el.textContent = '';
        if (!accounts || accounts.length === 0) {
            var empty = document.createElement('div');
            empty.className = 'text-muted text-center py-3';
            empty.textContent = 'No accounts at risk';
            el.appendChild(empty);
            return;
        }
        var list = document.createElement('div');
        list.className = 'list-group list-group-flush';
        for (var i = 0; i < accounts.length; i++) {
            var a = accounts[i];
            var cls = sevClasses[a.severity] || 'warning';
            var item = document.createElement('div');
            item.className = 'list-group-item';
            var flex = document.createElement('div');
            flex.className = 'd-flex align-items-center';
            var badge = document.createElement('span');
            badge.className = 'badge badge-' + cls + ' me-2';
            badge.textContent = sevLabelsMap[a.severity] || '?';
            var link = document.createElement('a');
            link.href = '/account?name=' + encodeURIComponent(a.account);
            link.className = 'font-monospace';
            link.textContent = a.account;
            var count = document.createElement('span');
            count.className = 'ms-auto text-muted small';
            count.textContent = a.findings + ' findings';
            flex.appendChild(badge);
            flex.appendChild(link);
            flex.appendChild(count);
            item.appendChild(flex);
            list.appendChild(item);
        }
        el.appendChild(list);
    }

    function renderAutoResponse(ar, byCheck) {
        var el = document.getElementById('auto-response-summary');
        if (!el) return;
        el.textContent = '';

        var container = document.createElement('div');

        // Auto-response counters (compact row)
        var arItems = [
            { icon: 'ti-shield-off', color: 'text-danger', label: 'Blocked', val: ar.blocked || 0 },
            { icon: 'ti-lock', color: 'text-warning', label: 'Quarantined', val: ar.quarantined || 0 },
            { icon: 'ti-skull', color: 'text-critical', label: 'Killed', val: ar.killed || 0 }
        ];
        var arRow = document.createElement('div');
        arRow.className = 'd-flex gap-3 mb-3';
        for (var i = 0; i < arItems.length; i++) {
            var pill = document.createElement('div');
            pill.className = 'text-center flex-fill';
            var valEl = document.createElement('div');
            valEl.className = 'h2 mb-0 ' + arItems[i].color;
            valEl.textContent = arItems[i].val;
            var labelEl = document.createElement('div');
            labelEl.className = 'text-muted small';
            var ic = document.createElement('i');
            ic.className = 'ti ' + arItems[i].icon + ' me-1';
            labelEl.appendChild(ic);
            labelEl.appendChild(document.createTextNode(arItems[i].label));
            pill.appendChild(valEl);
            pill.appendChild(labelEl);
            arRow.appendChild(pill);
        }
        container.appendChild(arRow);

        // Top check types from by_check (fills remaining space)
        if (byCheck) {
            var checks = [];
            for (var ck in byCheck) {
                if (byCheck.hasOwnProperty(ck) && ck !== 'auto_response' && ck !== 'auto_block' && ck !== 'health' && ck !== 'check_timeout') {
                    checks.push({ name: ck, count: byCheck[ck] });
                }
            }
            checks.sort(function(a, b) { return b.count - a.count; });
            if (checks.length > 5) checks = checks.slice(0, 5);
            if (checks.length > 0) {
                var divider = document.createElement('div');
                divider.className = 'text-muted small mb-2';
                divider.textContent = 'Top Check Types (24h)';
                container.appendChild(divider);
                for (var j = 0; j < checks.length; j++) {
                    var row = document.createElement('div');
                    row.className = 'd-flex align-items-center justify-content-between mb-1';
                    var nameSpan = document.createElement('span');
                    nameSpan.className = 'font-monospace small';
                    nameSpan.textContent = checks[j].name;
                    var countSpan = document.createElement('span');
                    countSpan.className = 'text-muted small';
                    countSpan.textContent = checks[j].count;
                    row.appendChild(nameSpan);
                    row.appendChild(countSpan);
                    container.appendChild(row);
                }
            }
        }

        el.appendChild(container);
    }

    function renderBruteForce(bf) {
        var el = document.getElementById('brute-force-summary');
        if (!el) return;
        el.textContent = '';

        if (!bf || bf.total_attacks === 0) {
            var empty = document.createElement('div');
            empty.className = 'text-muted text-center py-3';
            empty.textContent = 'No brute force attacks detected';
            el.appendChild(empty);
            return;
        }

        // Stats row — built with DOM methods (no innerHTML)
        var stats = document.createElement('div');
        stats.className = 'px-3 pt-3 pb-2';
        var row = document.createElement('div');
        row.className = 'row text-center';
        function addStat(value, label, cls) {
            var col = document.createElement('div');
            col.className = 'col-4';
            var h = document.createElement('div');
            h.className = 'h3 mb-0' + (cls ? ' ' + cls : '');
            h.textContent = String(value || 0);
            var sub = document.createElement('div');
            sub.className = 'text-muted small';
            sub.textContent = label;
            col.appendChild(h);
            col.appendChild(sub);
            row.appendChild(col);
        }
        addStat(bf.total_attacks, 'Attacks');
        addStat(bf.unique_ips, 'Unique IPs');
        addStat(bf.wp_login_count, 'wp-login', 'text-danger');
        stats.appendChild(row);
        el.appendChild(stats);

        // Top attacker IPs
        var ips = bf.top_ips || [];
        if (ips.length > 0) {
            var maxCount = ips[0].count || 1;
            var list = document.createElement('div');
            list.className = 'list-group list-group-flush border-top';
            for (var i = 0; i < ips.length && i < 5; i++) {
                var ip = ips[i];
                var pct = Math.round(ip.count / maxCount * 100);
                var item = document.createElement('div');
                item.className = 'list-group-item py-2';
                var header = document.createElement('div');
                header.className = 'd-flex align-items-center mb-1';
                var ipSpan = document.createElement('span');
                ipSpan.className = 'font-monospace small';
                ipSpan.textContent = ip.ip;
                var countSpan = document.createElement('span');
                countSpan.className = 'ms-auto badge bg-red-lt';
                countSpan.textContent = ip.count;
                header.appendChild(ipSpan);
                header.appendChild(countSpan);
                var progress = document.createElement('div');
                progress.className = 'progress progress-sm';
                var bar = document.createElement('div');
                bar.className = 'progress-bar bg-danger';
                bar.style.width = pct + '%';
                progress.appendChild(bar);
                item.appendChild(header);
                item.appendChild(progress);
                list.appendChild(item);
            }
            el.appendChild(list);
        }
    }

    function setText(id, val) {
        var el = document.getElementById(id);
        if (el) el.textContent = val;
    }

    // Initialize - two cadences with failure isolation
    function _startPolling() {
        // Stop any live pollers first so a repeated visibilitychange (or
        // init followed by the first visible event) cannot stack loops.
        _stopIntervals();
        // Fast cadence (10s): notification poll
        function fastPoll() {
            try { pollFindings(); } catch(e) { console.error('fastPoll:', e); }
        }
        fastPoll();
        _trackInterval(CSM.refresh.interval(fastPoll, 10000));

        // Slow cadence (60s): stats + health pill + challenge summary
        function loadChallengeSummary() {
            var el = document.getElementById('dash-challenge-summary');
            if (!el) return;
            CSM.get('/api/v1/challenge/stats').then(function(d) {
                var byCheck = d.routed_by_check || {};
                var scanner = byCheck['http_scanner_profile'] || 0;
                var total = Object.keys(byCheck).reduce(function(s, k) { return s + (byCheck[k] || 0); }, 0);
                function stat(label, val, cls) {
                    return '<div class="col-6 col-md-3">' +
                        '<div class="h1 m-0 ' + cls + '">' + (val || 0) + '</div>' +
                        '<div class="subheader">' + label + '</div></div>';
                }
                el.innerHTML = '<div class="row g-3 text-center">' +
                    stat('Pending now', d.pending, '') +
                    stat('Escalated to block', d.escalated, (d.escalated ? 'text-danger' : '')) +
                    stat('Scanner routed', scanner, '') +
                    stat('Total routed', total, 'text-secondary') +
                    '</div>';
            }).catch(function() { el.innerHTML = '<div class="text-muted small">Unavailable.</div>'; });
        }

        refreshStats();
        loadHealthPill();
        loadChallengeSummary();
        _trackInterval(CSM.refresh.interval(function() {
            try { refreshStats(); } catch(e) { console.error('refreshStats:', e); }
            try { loadHealthPill(); } catch(e) { console.error('loadHealthPill:', e); }
            try { loadChallengeSummary(); } catch(e) { console.error('loadChallengeSummary:', e); }
        }, 60000));
    }
    _startPolling();
})();

// ============================================================================
// Chart.js charts - 24h Timeline, Attack Types, 30-Day Trend
// ============================================================================
(function() {
    'use strict';

    function getThemeColor(varName, fallback) {
        var val = getComputedStyle(document.documentElement).getPropertyValue(varName).trim();
        return val || fallback;
    }

    function buildColors() {
        var isDark = document.documentElement.classList.contains('theme-dark');
        var critical = getThemeColor('--csm-critical', '#d63939');
        var high     = getThemeColor('--csm-high',     '#f76707');
        var warning  = getThemeColor('--csm-warning',  '#f59f00');
        return {
            critical:   critical,
            criticalBg: isDark ? critical + 'd9' : critical + 'cc',
            high:       high,
            highBg:     isDark ? high + 'd9' : high + 'cc',
            warning:    warning,
            warningBg:  isDark ? warning + 'd9' : warning + 'cc'
        };
    }

    function buildTooltipStyle() {
        var isDark = document.documentElement.classList.contains('theme-dark');
        return {
            backgroundColor: isDark ? '#1e293b' : '#fff',
            titleColor: isDark ? '#c8d3e0' : '#1a2234',
            bodyColor: isDark ? '#c8d3e0' : '#1a2234',
            borderColor: isDark ? '#2d3a4e' : '#e6e8eb',
            borderWidth: 1,
            cornerRadius: 6,
            padding: 10,
            displayColors: true,
            boxPadding: 4
        };
    }

    function buildGridColor() {
        var isDark = document.documentElement.classList.contains('theme-dark');
        return isDark ? 'rgba(45,58,78,0.6)' : 'rgba(230,232,235,0.8)';
    }

    var isDark = document.documentElement.classList.contains('theme-dark');
    var gridColor = buildGridColor();
    var COLORS = buildColors();
    var tooltipStyle = buildTooltipStyle();

    // --- 24-Hour Timeline ---
    var timelineChart = null;
    function loadTimeline() {
        var canvas = document.getElementById('timeline-chart');
        if (!canvas) return;

        CSM.get('/api/v1/stats/timeline')
            .then(function(hours) {
                if (!hours || !hours.length) return;
                var prevErr = canvas.parentElement && canvas.parentElement.querySelector('.chart-error');
                if (prevErr) { prevErr.remove(); canvas.style.display = ''; }

                var labels = [];
                var critData = [], highData = [], warnData = [];

                for (var i = 0; i < hours.length; i++) {
                    labels.push(hours[i].hour);
                    critData.push(hours[i].critical);
                    highData.push(hours[i].high);
                    warnData.push(hours[i].warning);
                }

                var config = {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [
                            {
                                label: 'Critical',
                                data: critData,
                                borderColor: COLORS.critical,
                                backgroundColor: 'rgba(214,57,57,0.18)',
                                fill: 'origin',
                                tension: 0.3,
                                pointRadius: 2,
                                pointHoverRadius: 5,
                                borderWidth: 2
                            },
                            {
                                label: 'High',
                                data: highData,
                                borderColor: COLORS.high,
                                backgroundColor: COLORS.high,
                                fill: false,
                                tension: 0.3,
                                pointRadius: 2,
                                pointHoverRadius: 5,
                                borderWidth: 2
                            },
                            {
                                label: 'Warning',
                                data: warnData,
                                borderColor: COLORS.warning,
                                backgroundColor: COLORS.warning,
                                fill: false,
                                tension: 0.3,
                                pointRadius: 2,
                                pointHoverRadius: 5,
                                borderWidth: 2
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        interaction: {
                            mode: 'index',
                            intersect: false
                        },
                        plugins: {
                            legend: {
                                display: true,
                                position: 'top',
                                labels: {
                                    boxWidth: 10,
                                    boxHeight: 10,
                                    usePointStyle: true,
                                    pointStyle: 'circle',
                                    padding: 16
                                }
                            },
                            tooltip: Object.assign({}, tooltipStyle, {
                                callbacks: {
                                    title: function(items) {
                                        return items[0].label;
                                    },
                                    footer: function(items) {
                                        var total = 0;
                                        items.forEach(function(item) { total += item.parsed.y; });
                                        return 'Total: ' + total;
                                    }
                                }
                            })
                        },
                        scales: {
                            x: {
                                grid: { display: false },
                                ticks: {
                                    maxRotation: 0,
                                    callback: function(val, idx) {
                                        return idx % 3 === 0 ? this.getLabelForValue(val) : '';
                                    }
                                }
                            },
                            y: {
                                beginAtZero: true,
                                grid: { color: gridColor },
                                ticks: {
                                    precision: 0
                                }
                            }
                        }
                    }
                };

                if (timelineChart) {
                    timelineChart.data = config.data;
                    timelineChart.update();
                } else {
                    timelineChart = new Chart(canvas, config);
                }
            })
            .catch(function(err) {
                console.error('loadTimeline:', err);
                var parent = canvas.parentElement;
                if (parent && !parent.querySelector('.chart-error')) {
                    var msg = document.createElement('div');
                    msg.className = 'text-muted text-center py-3 chart-error';
                    msg.textContent = 'Failed to load timeline data';
                    parent.appendChild(msg);
                    canvas.style.display = 'none';
                }
            });
    }

    // --- Top Attack Types (horizontal bar) ---
    var attackColors = {
        brute_force:  '#d63939',
        waf_block:    '#f76707',
        webshell:     '#a855f7',
        phishing:     '#e64980',
        c2:           '#ae3ec9',
        recon:        '#4299e1',
        spam:         '#f59f00',
        cpanel_login: '#f76707',
        file_upload:  '#0ca678',
        reputation:   '#e8590c',
        other:        '#6b7a8d'
    };

    var attackLabelsMap = {
        brute_force:  'Brute Force',
        waf_block:    'WAF Block',
        webshell:     'Webshell',
        phishing:     'Phishing',
        c2:           'C2 / Callback',
        recon:        'Recon / Scan',
        spam:         'Spam',
        cpanel_login: 'cPanel Login',
        file_upload:  'File Upload',
        reputation:   'Known Malicious IP',
        other:        'Other'
    };

    var attackChart = null;
    function loadAttackTypes() {
        var canvas = document.getElementById('attack-types-chart');
        if (!canvas) return;

        CSM.get('/api/v1/threat/stats')
            .then(function(data) {
                var prevErr = canvas.parentElement && canvas.parentElement.querySelector('.chart-error');
                if (prevErr) { prevErr.remove(); canvas.style.display = ''; }
                // Prefer the 24h-scoped map so this card matches the adjacent
                // "Findings Timeline (24h)". Fall back to lifetime `by_type`
                // to stay compatible with older daemons during rollout.
                var byType = data.by_type_24h || data.by_type || {};
                var entries = [];
                for (var key in byType) {
                    if (byType.hasOwnProperty(key)) {
                        entries.push({ type: key, count: byType[key] });
                    }
                }
                entries.sort(function(a, b) { return b.count - a.count; });
                entries = entries.slice(0, 8);

                if (entries.length === 0) {
                    if (attackChart) { attackChart.destroy(); attackChart = null; }
                    canvas.style.display = 'none';
                    var parent = canvas.parentElement;
                    var msg = parent.querySelector('.chart-empty');
                    if (!msg) {
                        msg = document.createElement('div');
                        msg.className = 'text-muted text-center py-3 chart-empty';
                        msg.textContent = 'No attack data in the last 24h';
                        parent.appendChild(msg);
                    }
                    return;
                }
                // Remove empty message if present
                canvas.style.display = '';
                var emptyMsg = canvas.parentElement.querySelector('.chart-empty');
                if (emptyMsg) emptyMsg.remove();

                var labels = [], counts = [], colors = [], borderClrs = [];
                for (var i = 0; i < entries.length; i++) {
                    var e = entries[i];
                    labels.push(attackLabelsMap[e.type] || e.type);
                    counts.push(e.count);
                    var c = attackColors[e.type] || '#6b7a8d';
                    colors.push(c + (isDark ? 'dd' : 'cc'));
                    borderClrs.push(c);
                }

                var config = {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: [{
                            data: counts,
                            backgroundColor: colors,
                            borderColor: borderClrs,
                            borderWidth: 1,
                            borderRadius: 3
                        }]
                    },
                    options: {
                        indexAxis: 'y',
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false },
                            tooltip: Object.assign({}, tooltipStyle, {
                                callbacks: {
                                    label: function(ctx) {
                                        return ctx.parsed.x + ' events';
                                    }
                                }
                            })
                        },
                        scales: {
                            x: {
                                beginAtZero: true,
                                grid: { color: gridColor },
                                ticks: { precision: 0 }
                            },
                            y: {
                                grid: { display: false },
                                ticks: {
                                    font: { size: 11 }
                                }
                            }
                        }
                    }
                };

                if (attackChart) {
                    attackChart.data = config.data;
                    attackChart.update();
                } else {
                    attackChart = new Chart(canvas, config);
                }
            })
            .catch(function(err) {
                console.error('loadAttackTypes:', err);
                var parent = canvas.parentElement;
                if (parent && !parent.querySelector('.chart-error')) {
                    var msg = document.createElement('div');
                    msg.className = 'text-muted text-center py-3 chart-error';
                    msg.textContent = 'Failed to load attack-type data';
                    parent.appendChild(msg);
                    canvas.style.display = 'none';
                }
            });
    }

    // --- Trend (period-selectable line chart with filled area) ---
    var trendChart = null;
    var VALID_TREND_DAYS = { 7: 1, 30: 1, 90: 1 };
    function currentTrendDays() {
        var stored = parseInt(localStorage.getItem('csm-trend-days') || '30', 10);
        return VALID_TREND_DAYS[stored] ? stored : 30;
    }

    // Compute yesterday-vs-today delta from the last two daily buckets and
    // render it alongside the 24h stat cards.
    function renderStatDeltas(days) {
        if (!days || days.length < 2) return;
        var today = days[days.length - 1];
        var yesterday = days[days.length - 2];
        var pairs = [
            ['stat-critical-delta', today.critical - yesterday.critical],
            ['stat-high-delta',     today.high     - yesterday.high],
            ['stat-warning-delta',  today.warning  - yesterday.warning]
        ];
        for (var i = 0; i < pairs.length; i++) {
            var el = document.getElementById(pairs[i][0]);
            if (!el) continue;
            var d = pairs[i][1];
            el.classList.remove('up', 'down', 'flat');
            if (d > 0) {
                el.classList.add('up');
                el.textContent = '+' + d + ' vs yesterday';
            } else if (d < 0) {
                el.classList.add('down');
                el.textContent = d + ' vs yesterday';
            } else {
                el.classList.add('flat');
                el.textContent = 'flat vs yesterday';
            }
        }
    }

    function loadTrend() {
        var canvas = document.getElementById('trend-chart');
        if (!canvas) return;

        var days = currentTrendDays();
        var title = document.getElementById('trend-title');
        if (title) title.textContent = days + '-Day Trend';

        CSM.get('/api/v1/stats/trend?days=' + days)
            .then(function(rows) {
                if (!rows || !rows.length) return;
                var prevErr = canvas.parentElement && canvas.parentElement.querySelector('.chart-error');
                if (prevErr) { prevErr.remove(); canvas.style.display = ''; }
                renderStatDeltas(rows);

                var labels = [], critData = [], highData = [], warnData = [];
                for (var i = 0; i < rows.length; i++) {
                    // Show short date labels: "03/15"
                    labels.push(rows[i].date.slice(5));
                    critData.push(rows[i].critical);
                    highData.push(rows[i].high);
                    warnData.push(rows[i].warning);
                }
                // Pick a tick-skip that keeps at most ~8 labels on screen.
                var tickSkip = Math.max(1, Math.ceil(rows.length / 8));

                var config = {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [
                            {
                                label: 'Critical',
                                data: critData,
                                borderColor: COLORS.critical,
                                backgroundColor: 'rgba(214,57,57,0.15)',
                                fill: 'origin',
                                tension: 0.3,
                                pointRadius: 2,
                                pointHoverRadius: 5,
                                borderWidth: 2
                            },
                            {
                                label: 'High',
                                data: highData,
                                borderColor: COLORS.high,
                                backgroundColor: COLORS.high,
                                fill: false,
                                tension: 0.3,
                                pointRadius: 2,
                                pointHoverRadius: 5,
                                borderWidth: 2
                            },
                            {
                                label: 'Warning',
                                data: warnData,
                                borderColor: COLORS.warning,
                                backgroundColor: COLORS.warning,
                                fill: false,
                                tension: 0.3,
                                pointRadius: 2,
                                pointHoverRadius: 5,
                                borderWidth: 2
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        interaction: {
                            mode: 'index',
                            intersect: false
                        },
                        plugins: {
                            legend: {
                                display: true,
                                position: 'top',
                                labels: {
                                    boxWidth: 10,
                                    boxHeight: 10,
                                    usePointStyle: true,
                                    pointStyle: 'circle',
                                    padding: 16
                                }
                            },
                            tooltip: Object.assign({}, tooltipStyle, {
                                callbacks: {
                                    title: function(items) {
                                        return items[0].label;
                                    },
                                    footer: function(items) {
                                        var total = 0;
                                        items.forEach(function(item) { total += item.parsed.y; });
                                        return 'Total: ' + total;
                                    }
                                }
                            })
                        },
                        scales: {
                            x: {
                                grid: { display: false },
                                ticks: {
                                    maxRotation: 0,
                                    callback: function(val, idx) {
                                        return idx % tickSkip === 0 ? this.getLabelForValue(val) : '';
                                    }
                                }
                            },
                            y: {
                                beginAtZero: true,
                                grid: { color: gridColor },
                                ticks: { precision: 0 }
                            }
                        }
                    }
                };

                if (trendChart) {
                    trendChart.data = config.data;
                    trendChart.update();
                } else {
                    trendChart = new Chart(canvas, config);
                }
            })
            .catch(function(err) {
                console.error('loadTrend:', err);
                var parent = canvas.parentElement;
                if (parent && !parent.querySelector('.chart-error')) {
                    var msg = document.createElement('div');
                    msg.className = 'text-muted text-center py-3 chart-error';
                    msg.textContent = 'Failed to load trend data';
                    parent.appendChild(msg);
                    canvas.style.display = 'none';
                }
            });
    }

    // --- Load all charts and set up auto-refresh ---
    var _chartIntervals = [];

    function _stopChartIntervals() {
        for (var i = 0; i < _chartIntervals.length; i++) _chartIntervals[i].stop();
        _chartIntervals = [];
    }

    // Restore saved trend period and wire the 7/30/90 selector.
    (function wireTrendPeriod() {
        var current = currentTrendDays();
        var btns = document.querySelectorAll('.trend-period-btn');
        btns.forEach(function(b) {
            var d = parseInt(b.getAttribute('data-days'), 10);
            b.classList.toggle('active', d === current);
            b.addEventListener('click', function() {
                var picked = parseInt(this.getAttribute('data-days'), 10);
                if (!VALID_TREND_DAYS[picked]) return;
                localStorage.setItem('csm-trend-days', String(picked));
                btns.forEach(function(x) {
                    x.classList.toggle('active', parseInt(x.getAttribute('data-days'), 10) === picked);
                });
                // Tick-skip is baked into the chart's x-axis callback closure,
                // so recreate the chart to pick up the new density.
                if (trendChart) { trendChart.destroy(); trendChart = null; }
                loadTrend();
            });
        });
    })();

    function _startChartPolling() {
        // Refresh theme-derived values in case theme changed since page load
        gridColor    = buildGridColor();
        COLORS       = buildColors();
        tooltipStyle = buildTooltipStyle();

        loadTimeline();
        loadAttackTypes();
        loadTrend();
        loadPriorityQueue();

        _startChartIntervals();
    }

    function _startChartIntervals() {
        // Stop existing chart intervals first so a repeated
        // visibilitychange (or init then first visible) cannot stack pollers.
        _stopChartIntervals();
        // Refresh charts every 60 seconds
        _chartIntervals.push(CSM.refresh.interval(function() {
            try { loadTimeline(); } catch(e) { console.error('loadTimeline:', e); }
            try { loadAttackTypes(); } catch(e) { console.error('loadAttackTypes:', e); }
        }, 60000));

        // Refresh trend every 5 minutes (daily data doesn't change fast)
        _chartIntervals.push(CSM.refresh.interval(function() {
            try { loadTrend(); } catch(e) { console.error('loadTrend:', e); }
        }, 300000));

        _chartIntervals.push(CSM.refresh.interval(function() {
            try { loadComponents(); } catch(e) { console.error('loadComponents:', e); }
        }, 30000));

        _startPriorityQueueInterval();
    }

    function _startPriorityQueueInterval() {
        _chartIntervals.push(CSM.refresh.interval(function() {
            try { loadPriorityQueue(); } catch(e) { console.error('loadPriorityQueue:', e); }
        }, 60000));
    }

    function _cleanupCharts() {
        _stopChartIntervals();
        if (timelineChart) { timelineChart.destroy(); timelineChart = null; }
        if (attackChart) { attackChart.destroy(); attackChart = null; }
        if (trendChart) { trendChart.destroy(); trendChart = null; }
    }

    window.addEventListener('beforeunload', _cleanupCharts);
    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            _stopChartIntervals();
        } else {
            // Restart refresh intervals (charts survive tab switches);
            // _startChartIntervals stops the prior set before re-adding.
            _startChartIntervals();
            // Immediate refresh on return
            try { loadTimeline(); } catch(e) {}
            try { loadAttackTypes(); } catch(e) {}
            try { loadTrend(); } catch(e) {}
            try { loadPriorityQueue(); } catch(e) {}
            try { loadComponents(); } catch(e) {}
        }
    });

    // --- Theme reactivity: update chart colors when dark/light mode toggles ---
    function updateChartTheme() {
        var dark = document.documentElement.classList.contains('theme-dark');
        var newGridColor = dark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)';
        var newTextColor = dark ? '#94a3b8' : '#64748b';
        Chart.defaults.color = newTextColor;
        Chart.defaults.borderColor = newGridColor;
        Object.values(Chart.instances).forEach(function(chart) {
            if (chart.options.scales) {
                Object.keys(chart.options.scales).forEach(function(axis) {
                    if (chart.options.scales[axis].grid) chart.options.scales[axis].grid.color = newGridColor;
                    if (chart.options.scales[axis].ticks) chart.options.scales[axis].ticks.color = newTextColor;
                });
            }
            chart.update('none');
        });
    }

    new MutationObserver(function(mutations) {
        mutations.forEach(function(m) { if (m.attributeName === 'class') updateChartTheme(); });
    }).observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });


    // --- Priority queue: active incidents + top critical/high findings --------
    var _statusClasses = { open: 'danger', contained: 'warning', resolved: 'success', dismissed: 'secondary' };

    function _queueItemHTML(item) {
        // item: { sevClass, sevLabel, title, summary, ageISO, action, href, kind }
        var sev = item.sevClass || 'warning';
        var sevLabel = item.sevLabel || 'WARN';
        var ageISO = item.ageISO || '';
        var ageText = ageISO ? CSM.timeAgo(ageISO) : '';
        var actionHTML = '';
        if (item.action && item.href) {
            actionHTML = '<span class="btn btn-sm btn-ghost-secondary csm-queue-item__action">' + CSM.esc(item.action) + '</span>';
        }
        var kindBadge = item.kind ? '<span class="badge bg-secondary-lt me-1">' + CSM.esc(item.kind) + '</span>' : '';
        var html = '<a class="csm-queue-item" href="' + CSM.attr(item.href || '#') + '">';
        html += '<span class="csm-queue-item__sev"><span class="badge badge-' + CSM.attr(sev) + '">' + CSM.esc(sevLabel) + '</span></span>';
        html += '<span class="csm-queue-item__main">';
        html += '<div class="csm-queue-item__title">' + kindBadge + CSM.esc(item.title || '') + '</div>';
        if (item.summary) html += '<div class="csm-queue-item__summary">' + CSM.esc(item.summary) + '</div>';
        html += '</span>';
        if (ageText) html += '<span class="csm-queue-item__age" data-timestamp="' + CSM.attr(ageISO) + '">' + CSM.esc(ageText) + '</span>';
        html += actionHTML;
        html += '</a>';
        return html;
    }

    function _renderPriorityQueue(items) {
        var el = document.getElementById('priority-queue');
        if (!el) return;
        if (!items || items.length === 0) {
            el.innerHTML = CSM.emptyStateBlock({
                icon: 'circle-check',
                title: 'No urgent items',
                reason: 'No active incidents and no recent critical or high findings need action.'
            });
            return;
        }
        var html = '';
        for (var i = 0; i < items.length; i++) html += _queueItemHTML(items[i]);
        el.innerHTML = html;
        CSM.initTimeAgo();
    }

    function _kindLabel(kind) {
        if (!kind) return 'incident';
        return String(kind).replace(/_/g, ' ');
    }

    function _incidentOwner(inc) {
        var key = inc.correlation_key || {};
        if (inc.mailbox || inc.domain || inc.account) return inc.mailbox || inc.domain || inc.account;
        if (key.mailbox || key.domain || key.account) return key.mailbox || key.domain || key.account;
        if (key.remote_ip) return key.remote_ip;
        if (key.pid) return 'pid=' + key.pid;
        if (key.uid) return 'uid=' + key.uid;
        return 'unknown';
    }

    function _sevForIncident(s) {
        if (s === 'CRITICAL') return { sevClass: 'critical', sevLabel: 'CRITICAL' };
        if (s === 'HIGH')     return { sevClass: 'high',     sevLabel: 'HIGH' };
        return { sevClass: 'warning', sevLabel: 'WARNING' };
    }

    function _sevForFinding(severity) {
        var s = String(severity || '').toUpperCase();
        if (s === 'CRITICAL') return { sevClass: 'critical', sevLabel: 'CRITICAL' };
        if (s === 'HIGH')     return { sevClass: 'high',     sevLabel: 'HIGH' };
        return { sevClass: 'warning', sevLabel: 'WARNING' };
    }

    function _updateSubtitle(activeIncidents, critFindings, highFindings) {
        var sub = document.getElementById('dashboard-summary');
        if (!sub) return;
        var parts = [];
        parts.push(activeIncidents + ' active incident' + (activeIncidents === 1 ? '' : 's'));
        parts.push(critFindings + ' critical');
        parts.push(highFindings + ' high');
        sub.textContent = parts.join(' · ') + ' (24h)';
    }

    function loadPriorityQueue() {
        var incidentReq = CSM.get('/api/v1/incidents?status=active&limit=5').catch(function() { return null; });
        var findingsReq = CSM.get('/api/v1/findings/enriched?limit=20').catch(function() { return null; });
        var statsReq = CSM.get('/api/v1/stats').catch(function() { return null; });
        Promise.all([incidentReq, findingsReq, statsReq]).then(function(results) {
            var incData = results[0];
            var findData = results[1];
            var statsData = results[2];
            var incidents = [];
            if (incData && Array.isArray(incData.items)) incidents = incData.items;
            else if (Array.isArray(incData)) incidents = incData;

            // incidents is only the first page (limit=5) used to render the
            // queue. The subtitle count must be the true active-incident total
            // from the envelope, not the capped slice length, or the header
            // reads "5 active incidents" while hundreds are open or contained.
            var activeTotal = (incData && typeof incData.total === 'number') ? incData.total : incidents.length;

            var findings = [];
            if (findData && Array.isArray(findData.findings)) {
                findings = findData.findings;
            } else if (Array.isArray(findData)) {
                findings = findData;
            }

            // The subtitle is labelled "(24h)", so its critical/high counts must
            // come from /stats (genuinely 24h-windowed). The findings/enriched
            // counts are all-active and would mislabel the window.
            var crit24h = 0, high24h = 0;
            if (statsData && statsData.last_24h) {
                if (typeof statsData.last_24h.critical === 'number') crit24h = statsData.last_24h.critical;
                if (typeof statsData.last_24h.high === 'number')     high24h = statsData.last_24h.high;
            }

            // Take top 5 incidents + up to 5 critical/high findings (newest first)
            var items = [];
            for (var i = 0; i < Math.min(incidents.length, 5); i++) {
                var inc = incidents[i];
                var sevInfo = _sevForIncident(inc.severity);
                var owner = _incidentOwner(inc);
                items.push({
                    sevClass: sevInfo.sevClass,
                    sevLabel: sevInfo.sevLabel,
                    kind: _kindLabel(inc.kind),
                    title: owner,
                    summary: (inc.findings || []).length + ' correlated finding' + (((inc.findings || []).length === 1) ? '' : 's'),
                    ageISO: inc.updated_at || inc.created_at || '',
                    action: 'Open incident',
                    href: '/incident#' + encodeURIComponent(inc.id || '')
                });
            }

            var critHighFindings = [];
            for (var j = 0; j < findings.length; j++) {
                var f = findings[j];
                var sev = String(f.severity || '').toUpperCase();
                if ((sev === 'CRITICAL' || sev === 'HIGH') && critHighFindings.length < 5) {
                    critHighFindings.push(f);
                }
            }
            for (var k = 0; k < critHighFindings.length; k++) {
                var fi = critHighFindings[k];
                var fSev = _sevForFinding(fi.severity);
                items.push({
                    sevClass: fSev.sevClass,
                    sevLabel: fSev.sevLabel,
                    kind: fi.check || 'finding',
                    title: fi.account || fi.check || 'finding',
                    summary: fi.message || '',
                    ageISO: fi.last_seen || fi.first_seen || '',
                    action: 'Review',
                    href: '/findings'
                });
            }

            _renderPriorityQueue(items);
            _updateSubtitle(activeTotal, crit24h, high24h);
        });
    }

    // --- System posture chips ------------------------------------------------
    function _postureChip(label, state, ok, tooltip) {
        var cls = ok ? 'csm-status-strip__chip--ok' : 'csm-status-strip__chip--warn';
        var icon = ok ? 'ti-check' : 'ti-circle-off';
        return '<span class="csm-status-strip__chip ' + cls + '" title="' + CSM.attr(tooltip || '') + '">' +
            '<i class="ti ' + icon + '"></i>' +
            '<span class="csm-status-strip__chip-value">' + CSM.esc(label) + '</span>' +
            '<span class="csm-status-strip__chip-label">' + CSM.esc(state) + '</span>' +
        '</span>';
    }

    function renderFeatureFlags() {
        var el = document.getElementById('components-feature-flags');
        if (!el) return;
        var cfg = (typeof CSM_CONFIG !== 'undefined') ? CSM_CONFIG : {};
        // Five operator-config flags. Runtime watcher state (fanotify,
        // signature loader, log watchers) lives in the Components matrix
        // below to avoid duplication.
        var html = '<div class="d-flex flex-wrap gap-2 mb-3">';
        html += _postureChip('Firewall',     cfg.firewall      ? 'enabled' : 'off', !!cfg.firewall,     'Outbound block engine state');
        html += _postureChip('Auto-response', cfg.autoResponse ? 'enabled' : 'off', !!cfg.autoResponse, 'Automatic block / quarantine response');
        html += _postureChip('Email AV',     cfg.emailAV       ? 'enabled' : 'off', !!cfg.emailAV,      'ClamAV / yara scanning of outgoing mail');
        html += _postureChip('Threat Intel', cfg.threatIntel   ? 'enabled' : 'off', !!cfg.threatIntel,  'AbuseIPDB / upstream IP reputation');
        html += _postureChip('Challenge',    cfg.challenge     ? 'on'      : 'off', !!cfg.challenge,    'Browser CAPTCHA challenge for suspicious IPs');
        html += '</div>';
        el.innerHTML = html;
    }

    // --- Components matrix ---------------------------------------------------
    function _componentBadge(status, reason) {
        var map = {
            ok:       { cls: 'bg-success-lt', label: 'ok' },
            idle:     { cls: 'bg-secondary-lt', label: 'idle' },
            deaf:     { cls: 'bg-warning-lt', label: 'deaf' },
            degraded: { cls: 'bg-danger-lt', label: 'degraded' },
            unknown:  { cls: 'bg-secondary-lt', label: 'unknown' }
        };
        var entry = map[status] || map.unknown;
        var titleAttr = '';
        if (reason) {
            titleAttr = ' title="' + CSM.attr(reason) + '"';
        }
        return '<span class="badge ' + entry.cls + '"' + titleAttr + '>' + entry.label + '</span>';
    }

    function _componentRow(row) {
        var since = row.changed_ago ? row.changed_ago : '-';
        var sinceISO = row.changed_at_iso ? ' title="' + CSM.attr(row.changed_at_iso) + '"' : '';
        var lastEvent = row.last_event_ago ? row.last_event_ago : '-';
        var lastEventTitle = row.last_event_iso ? row.last_event_iso : '';
        if (lastEventTitle && row.last_event_check) {
            lastEventTitle += ' (' + row.last_event_check + ')';
        }
        var lastEventISO = lastEventTitle ? ' title="' + CSM.attr(lastEventTitle) + '"' : '';
        return '<tr>' +
            '<td class="csm-component-name text-truncate" title="' + CSM.attr(row.name) + '">' + CSM.esc(row.label || row.name) + '</td>' +
            '<td>' + _componentBadge(row.status, row.upstream_reason) + '</td>' +
            '<td class="text-muted small"' + sinceISO + '>' + CSM.esc(since) + '</td>' +
            '<td class="text-muted small"' + lastEventISO + '>' + CSM.esc(lastEvent) + '</td>' +
            '</tr>';
    }

    function loadComponents() {
        var el = document.getElementById('components-matrix');
        if (!el) return;
        CSM.get('/api/v1/components', { silent: true })
            .then(function(rows) {
                if (!rows || rows.length === 0) {
                    el.innerHTML = '<div class="csm-empty py-3"><div class="csm-empty__reason text-muted text-center">No watchers registered</div></div>';
                    return;
                }
                // Split rows by status so degraded / ok watchers stay
                // prominent and "idle" (attached, no events in 7d) collapse
                // behind a single summary. Idle is the normal state for
                // platform-specific watchers on hosts that simply have not
                // generated those events yet, so listing every one of them
                // at full weight made the card look noisier than it is.
                // "deaf" rows stay in the prominent table alongside ok /
                // degraded; only true "idle" (attached, no events, upstream
                // either alive or unprobed) collapses behind the disclosure.
                var nonIdle = [];
                var idle = [];
                rows.forEach(function(row) {
                    if (row.status === 'idle') {
                        idle.push(row);
                    } else {
                        nonIdle.push(row);
                    }
                });

                var html = '';
                if (nonIdle.length > 0) {
                    html += '<div class="table-responsive"><table class="table table-sm card-table mb-0">' +
                        '<thead><tr>' +
                            '<th>Component</th>' +
                            '<th>Status</th>' +
                            '<th>Since</th>' +
                            '<th>Last event</th>' +
                        '</tr></thead><tbody>';
                    nonIdle.forEach(function(row) { html += _componentRow(row); });
                    html += '</tbody></table></div>';
                }
                if (idle.length > 0) {
                    var label = CSM.esc(String(idle.length)) + ' watcher' + (idle.length === 1 ? '' : 's') +
                        ' idle <span class="text-muted small">&middot; no events in 7 days</span>';
                    var idleHTML = '<details class="csm-idle-watchers small mt-2">' +
                        '<summary class="text-muted py-2">' + label + '</summary>' +
                        '<div class="table-responsive"><table class="table table-sm card-table mb-0">' +
                            '<thead><tr>' +
                                '<th>Component</th>' +
                                '<th>Status</th>' +
                                '<th>Since</th>' +
                                '<th>Last event</th>' +
                            '</tr></thead><tbody>';
                    idle.forEach(function(row) { idleHTML += _componentRow(row); });
                    idleHTML += '</tbody></table></div></details>';
                    html += idleHTML;
                }
                if (!html) {
                    html = '<div class="csm-empty py-3"><div class="csm-empty__reason text-muted text-center">No watchers registered</div></div>';
                }
                el.innerHTML = html;
            })
            .catch(function(err) {
                console.error('loadComponents:', err);
                el.innerHTML = '<div class="text-muted text-center py-3 small">Components unavailable: ' + CSM.esc(err.message || 'error') + '</div>';
            });
    }

    // Wire refresh + initial load
    var _pqBtn = document.getElementById('priority-queue-refresh');
    if (_pqBtn) _pqBtn.addEventListener('click', loadPriorityQueue);
    var _compBtn = document.getElementById('components-refresh');
    if (_compBtn) _compBtn.addEventListener('click', loadComponents);
    try { renderFeatureFlags(); } catch (e) {}
    try { loadComponents(); } catch (e) {}

    _startChartPolling();
})();
