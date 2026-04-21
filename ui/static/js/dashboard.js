// CSM Dashboard - polling-based live feed + auto-refresh + Chart.js charts
(function() {
    'use strict';

    var _intervals = [];
    var _pollers = [];

    function _trackInterval(id) { _intervals.push(id); return id; }

    function _cleanup() {
        for (var i = 0; i < _intervals.length; i++) clearInterval(_intervals[i]);
        _intervals = [];
        for (var j = 0; j < _pollers.length; j++) _pollers[j].stop();
        _pollers = [];
    }

    window.addEventListener('beforeunload', _cleanup);
    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            for (var i = 0; i < _intervals.length; i++) clearInterval(_intervals[i]);
            _intervals = [];
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

    var feed = document.getElementById('live-feed-entries');

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

    // --- Feed enhancement helpers ---
    // Note: innerHTML usage below only renders CSM.esc()-escaped server data and
    // static markup - no raw user input is injected without escaping.

    function addRelativeTime(item) {
        var row = item.querySelector('.row');
        if (!row) return;
        if (item.querySelector('.feed-relative-time')) return;
        var span = document.createElement('div');
        span.className = 'col-auto feed-relative-time';
        var ts = item.getAttribute('data-ts') || new Date().toISOString();
        var inner = document.createElement('span');
        inner.className = 'text-muted small';
        inner.setAttribute('data-timestamp', ts);
        inner.textContent = CSM.timeAgo(ts);
        span.appendChild(inner);
        row.appendChild(span);
    }

    function attachFeedItemListeners(item) {
        CSM.makeClickable(item);
        item.addEventListener('click', function(e) {
            if (e.target.closest('button')) return;
            var d = this.querySelector('.detail');
            if (d) d.classList.toggle('d-none');
        });
        var fixBtn = item.querySelector('.feed-fix-btn');
        if (fixBtn) {
            fixBtn.addEventListener('click', function(e) {
                e.stopPropagation();
                fixFromFeed(this);
            });
        }
    }

    function fixFromFeed(btn) {
        var key = btn.getAttribute('data-key') || '';
        var check = btn.getAttribute('data-check');
        var message = btn.getAttribute('data-message');
        var desc = btn.getAttribute('data-fixdesc');
        CSM.confirm('Apply fix?\n\n' + desc).then(function() {
            btn.disabled = true;
            btn.textContent = '';
            var spinner = document.createElement('span');
            spinner.className = 'spinner-border spinner-border-sm';
            btn.appendChild(spinner);
            CSM.post('/api/v1/fix', {key: key, check: check, message: message}).then(function(data) {
                if (data.success) {
                    btn.textContent = '';
                    var icon = document.createElement('i');
                    icon.className = 'ti ti-check';
                    btn.appendChild(icon);
                    btn.className = 'btn btn-success btn-sm';
                    btn.closest('.list-group-item').style.opacity = '0.3';
                    CSM.toast('Fix applied successfully', 'success');
                } else {
                    CSM.toast('Fix failed: ' + (data.error || 'unknown'), 'error');
                    btn.disabled = false;
                    btn.textContent = '';
                    var ic = document.createElement('i');
                    ic.className = 'ti ti-tool';
                    btn.appendChild(ic);
                }
            }).catch(function(e) {
                CSM.toast('Error: ' + e, 'error');
                btn.disabled = false;
                btn.textContent = '';
                var ic = document.createElement('i');
                ic.className = 'ti ti-tool';
                btn.appendChild(ic);
            });
        }).catch(function() { /* cancelled */ });
    }

    // Clean up the old overview-collapsed flag; the toggle was removed.
    try { localStorage.removeItem('csm-overview-collapsed'); } catch (_) {}

    // --- Live Feed: severity chip + search filter ---
    var feedFilterSeverities = { critical: true, high: true, warning: true };
    var feedFilterSearch = '';

    function applyFeedFilters() {
        if (!feed) return;
        var needle = feedFilterSearch.toLowerCase();
        var items = feed.querySelectorAll('.feed-item');
        for (var i = 0; i < items.length; i++) {
            var item = items[i];
            var sev = item.getAttribute('data-sev') || 'warning';
            var passSev = !!feedFilterSeverities[sev];
            var text = item.textContent.toLowerCase();
            var passSearch = needle === '' || text.indexOf(needle) !== -1;
            item.classList.toggle('feed-hidden', !(passSev && passSearch));
        }
    }

    document.querySelectorAll('.feed-sev-chip').forEach(function(chip) {
        chip.addEventListener('click', function() {
            var sevNum = this.getAttribute('data-sev');
            var key = sevNum === '2' ? 'critical' : sevNum === '1' ? 'high' : 'warning';
            feedFilterSeverities[key] = !feedFilterSeverities[key];
            this.classList.toggle('active', feedFilterSeverities[key]);
            applyFeedFilters();
        });
    });
    var feedSearchEl = document.getElementById('feed-search');
    if (feedSearchEl) {
        var feedSearchTimer;
        feedSearchEl.addEventListener('input', function() {
            clearTimeout(feedSearchTimer);
            var val = this.value;
            feedSearchTimer = setTimeout(function() {
                feedFilterSearch = val;
                applyFeedFilters();
            }, 150);
        });
    }

    // Initial pass: enhance server-rendered feed items
    document.querySelectorAll('.feed-item').forEach(function(item) {
        addRelativeTime(item);
        attachFeedItemListeners(item);
    });

    // Periodically update relative times
    _trackInterval(setInterval(CSM.initTimeAgo, 5000));

    // Polling - fetch recent history every 10 seconds
    var lastPollTimestamp = '';
    var serverItems = feed ? feed.querySelectorAll('.feed-item[data-ts]') : [];
    if (serverItems.length > 0) {
        lastPollTimestamp = serverItems[0].getAttribute('data-ts') || '';
    }
    function _setPollStatus(ok, err) {
        var dot = document.getElementById('poll-status-dot');
        if (!dot) return;
        if (ok) {
            dot.className = 'status-dot bg-yellow';
            dot.title = 'Polling active';
        } else {
            dot.className = 'status-dot bg-red';
            dot.title = 'Polling failed' + (err ? ': ' + err : '');
        }
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
                _setPollStatus(true);
            })
            .catch(function(err) {
                console.error('pollFindings:', err);
                _setPollStatus(false, err);
            });
    }

    function addEntry(f) {
        if (!feed) return;
        var div = document.createElement('div');
        div.className = 'list-group-item';

        var sevClass = 'warning';
        var sevLabel = 'WARNING';
        if (f.severity === 2) { sevClass = 'critical'; sevLabel = 'CRITICAL'; }
        else if (f.severity === 1) { sevClass = 'high'; sevLabel = 'HIGH'; }

        var ts = f.timestamp || new Date().toISOString();
        var timeStr = CSM.fmtDate(ts).substring(11);
        if (!timeStr || timeStr === '\u2014') {
            var now = new Date();
            timeStr = now.getHours().toString().padStart(2,'0') + ':' +
                   now.getMinutes().toString().padStart(2,'0');
        }

        div.setAttribute('data-ts', ts);
        div.setAttribute('data-sev', sevClass);
        div.setAttribute('data-check', f.check || '');
        div.classList.add('feed-item');

        // Build entry DOM safely
        var row = document.createElement('div');
        row.className = 'row align-items-center';

        var colTime = document.createElement('div');
        colTime.className = 'col-auto';
        var spanTime = document.createElement('span');
        spanTime.className = 'text-muted font-monospace small';
        spanTime.textContent = timeStr;
        colTime.appendChild(spanTime);

        var colBadge = document.createElement('div');
        colBadge.className = 'col-auto';
        var badge = document.createElement('span');
        badge.className = 'badge badge-' + sevClass;
        badge.textContent = sevLabel;
        colBadge.appendChild(badge);

        var colMsg = document.createElement('div');
        colMsg.className = 'col';
        var checkSpan = document.createElement('span');
        checkSpan.className = 'font-monospace small';
        checkSpan.textContent = f.check;
        colMsg.appendChild(checkSpan);
        colMsg.appendChild(document.createTextNode(' \u2014 ' + f.message));

        row.appendChild(colTime);
        row.appendChild(colBadge);
        row.appendChild(colMsg);
        div.appendChild(row);

        feed.insertBefore(div, feed.firstChild);

        div.classList.add('feed-highlight');
        addRelativeTime(div);
        attachFeedItemListeners(div);
        applyFeedFilters();

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
            fetch(CSM.apiUrl('/api/v1/health'), { credentials: 'same-origin' }).then(function(r) { return r.json(); }),
            fetch(CSM.apiUrl('/api/v1/status'), { credentials: 'same-origin' }).then(function(r) { return r.json(); })
        ]).then(function(res) {
            var health = res[0] || {};
            var status = res[1] || {};
            var problems = [];
            if (!health.daemon_mode) problems.push('daemon not in service mode');
            if (!health.fanotify) problems.push('fanotify unavailable (fallback)');
            if (!health.log_watchers) problems.push('no log watchers active');
            if (!health.rules_loaded) problems.push('no YARA rules loaded');

            var label = 'Healthy';
            var cls = 'health-ok';
            var dotCls = 'bg-green';
            if (problems.length >= 2) {
                label = 'Degraded';
                cls = 'health-crit';
                dotCls = 'bg-red';
            } else if (problems.length === 1) {
                label = 'Warning';
                cls = 'health-warn';
                dotCls = 'bg-yellow';
            }
            var title = 'Uptime: ' + (status.uptime || health.uptime || '?') +
                '\nRules: ' + (health.rules_loaded || 0) +
                '\nWatchers: ' + (health.log_watchers || 0) +
                (status.scan_running ? '\nScan: in progress' : '') +
                (problems.length ? '\nIssues: ' + problems.join(', ') : '');
            renderHealthPill(cls, dotCls, label, title);
        }).catch(function(err) {
            console.error('loadHealthPill:', err);
            renderHealthPill('health-crit', 'bg-red', 'Unreachable', 'Dashboard cannot reach the daemon API');
        });
    }

    // Auto-refresh stats every 60 seconds
    function refreshStats() {
        fetch(CSM.apiUrl('/api/v1/stats'), { credentials: 'same-origin' })
            .then(function(r) {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.json();
            })
            .then(function(data) {
                if (!data.last_24h) return;
                var s = data.last_24h;
                setText('stat-critical', s.critical);
                setText('stat-high', s.high);
                setText('stat-warning', s.warning);
                if (data.last_critical_ago) {
                    setText('stat-last-critical', data.last_critical_ago);
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

    function refreshScanStatus() {
        fetch(CSM.apiUrl('/api/v1/status'), { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                setText('scan-status', data.scan_running ? 'Scanning...' : 'Idle');
                if (data.last_scan_time) {
                    setText('scan-detail', 'Last scan: ' + CSM.timeAgo(data.last_scan_time));
                }
            })
            .catch(function(err) { console.error('refreshScanStatus:', err); });
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

    // Initialize - three cadences with failure isolation
    function _startPolling() {
        if (!feed) return;
        // Fast cadence (10s): findings + scan status
        function fastPoll() {
            try { pollFindings(); } catch(e) { console.error('fastPoll:', e); }
            try { refreshScanStatus(); } catch(e) { console.error('fastPoll:', e); }
        }
        fastPoll();
        _trackInterval(setInterval(fastPoll, 10000));

        // Slow cadence (60s): stats + health pill
        refreshStats();
        loadHealthPill();
        _trackInterval(setInterval(function() {
            try { refreshStats(); } catch(e) { console.error('refreshStats:', e); }
            try { loadHealthPill(); } catch(e) { console.error('loadHealthPill:', e); }
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

        fetch(CSM.apiUrl('/api/v1/stats/timeline'), { credentials: 'same-origin' })
            .then(function(r) {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.json();
            })
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

        fetch(CSM.apiUrl('/api/v1/threat/stats'), { credentials: 'same-origin' })
            .then(function(r) {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.json();
            })
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

        fetch(CSM.apiUrl('/api/v1/stats/trend?days=' + days), { credentials: 'same-origin' })
            .then(function(r) {
                if (!r.ok) throw new Error('HTTP ' + r.status);
                return r.json();
            })
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

        // Refresh charts every 60 seconds
        _chartIntervals.push(setInterval(function() {
            try { loadTimeline(); } catch(e) { console.error('loadTimeline:', e); }
            try { loadAttackTypes(); } catch(e) { console.error('loadAttackTypes:', e); }
        }, 60000));

        // Refresh trend every 5 minutes (daily data doesn't change fast)
        _chartIntervals.push(setInterval(function() {
            try { loadTrend(); } catch(e) { console.error('loadTrend:', e); }
        }, 300000));
    }

    function _cleanupCharts() {
        for (var i = 0; i < _chartIntervals.length; i++) clearInterval(_chartIntervals[i]);
        _chartIntervals = [];
        if (timelineChart) { timelineChart.destroy(); timelineChart = null; }
        if (attackChart) { attackChart.destroy(); attackChart = null; }
        if (trendChart) { trendChart.destroy(); trendChart = null; }
    }

    window.addEventListener('beforeunload', _cleanupCharts);
    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            for (var i = 0; i < _chartIntervals.length; i++) clearInterval(_chartIntervals[i]);
            _chartIntervals = [];
        } else {
            // Restart refresh intervals (charts survive tab switches)
            _chartIntervals.push(setInterval(function() {
                try { loadTimeline(); } catch(e) {}
                try { loadAttackTypes(); } catch(e) {}
            }, 60000));
            _chartIntervals.push(setInterval(function() {
                try { loadTrend(); } catch(e) {}
            }, 300000));
            // Immediate refresh on return
            try { loadTimeline(); } catch(e) {}
            try { loadAttackTypes(); } catch(e) {}
            try { loadTrend(); } catch(e) {}
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

    _startChartPolling();
})();
