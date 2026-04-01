// CSM Dashboard — polling-based live feed + auto-refresh + charts
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

    // --- Feed enhancement helpers (formerly in dashboard-page.js) ---

    function addRelativeTime(item) {
        var row = item.querySelector('.row');
        if (!row) return;
        if (item.querySelector('.feed-relative-time')) return;
        var span = document.createElement('div');
        span.className = 'col-auto feed-relative-time';
        // Use the finding's actual timestamp from data-ts, not Date.now()
        var ts = item.getAttribute('data-ts') || new Date().toISOString();
        span.innerHTML = '<span class="text-muted small" data-timestamp="' + CSM.esc(ts) + '">' + CSM.timeAgo(ts) + '</span>';
        row.appendChild(span);
    }

    function attachFeedItemListeners(item) {
        CSM.makeClickable(item);
        item.style.cursor = 'pointer';
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
        var check = btn.getAttribute('data-check');
        var message = btn.getAttribute('data-message');
        var desc = btn.getAttribute('data-fixdesc');
        CSM.confirm('Apply fix?\n\n' + desc).then(function() {
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
            CSM.post('/api/v1/fix', {check: check, message: message}).then(function(data) {
                if (data.success) {
                    btn.innerHTML = '<i class="ti ti-check"></i>';
                    btn.className = 'btn btn-success btn-sm';
                    btn.closest('.list-group-item').style.opacity = '0.3';
                    CSM.toast('Fix applied successfully', 'success');
                } else {
                    CSM.toast('Fix failed: ' + (data.error || 'unknown'), 'error');
                    btn.disabled = false;
                    btn.innerHTML = '<i class="ti ti-tool"></i>';
                }
            }).catch(function(e) {
                CSM.toast('Error: ' + e, 'error');
                btn.disabled = false;
                btn.innerHTML = '<i class="ti ti-tool"></i>';
            });
        }).catch(function() { /* cancelled */ });
    }

    // Initial pass: enhance server-rendered feed items
    document.querySelectorAll('.feed-item').forEach(function(item) {
        addRelativeTime(item);
        attachFeedItemListeners(item);
    });

    // Periodically update relative times via the shared CSM.initTimeAgo helper
    setInterval(CSM.initTimeAgo, 5000);

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

        // Directly enhance the new entry (replaces MutationObserver pattern)
        div.classList.add('feed-highlight');
        addRelativeTime(div);
        attachFeedItemListeners(div);

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

// --- Timeline chart (reads data from #timeline-chart data-bars attribute) ---
(function(){
    var container = document.getElementById('timeline-chart');
    if (!container) return;
    var raw = container.getAttribute('data-bars');
    if (!raw) return;
    var srcBars;
    try { srcBars = JSON.parse(raw); } catch(e) { return; }
    var bars = [];
    for (var i = 0; i < srcBars.length; i++) {
        var s = srcBars[i];
        bars.push({h: s.Hour, c: s.Critical, hi: s.High, w: s.Warning, t: s.Total});
    }

    var vW = 1400, vH = 160;
    var padL = 38, padR = 8, padT = 8, padB = 22;
    var chartW = vW - padL - padR;
    var chartH = vH - padT - padB;
    var barW = chartW / 24;
    var barPad = Math.max(1, barW * 0.12);

    var maxVal = 1;
    for (var i = 0; i < bars.length; i++) { if (bars[i].t > maxVal) maxVal = bars[i].t; }
    var gridLines = 4;
    var step = Math.ceil(maxVal / gridLines);
    if (step === 0) step = 1;
    maxVal = step * gridLines;

    var isDark = document.documentElement.classList.contains('theme-dark');
    var gridColor = isDark ? '#2d3a4e' : '#e6e8eb';
    var textColor = isDark ? '#6b7a8d' : '#9da9b5';

    var svg = '<svg viewBox="0 0 '+vW+' '+vH+'" preserveAspectRatio="xMidYMid meet" style="display:block;width:100%;height:auto">';

    for (var g = 0; g <= gridLines; g++) {
        var val = step * g;
        var y = padT + chartH - (val / maxVal * chartH);
        svg += '<line x1="'+padL+'" y1="'+y+'" x2="'+(vW-padR)+'" y2="'+y+'" stroke="'+gridColor+'" stroke-width="0.5"/>';
        svg += '<text x="'+(padL-6)+'" y="'+(y+3.5)+'" text-anchor="end" fill="'+textColor+'" font-size="9">'+val+'</text>';
    }

    // Invisible hover zones for each bar column, plus visible stacked bars
    for (var i = 0; i < bars.length; i++) {
        var b = bars[i];
        var x = padL + i * barW + barPad;
        var bw = barW - barPad * 2;
        if (bw < 3) bw = 3;
        var baseY = padT + chartH;

        if (b.w > 0) {
            var wH = b.w / maxVal * chartH;
            svg += '<rect x="'+x+'" y="'+(baseY-wH)+'" width="'+bw+'" height="'+wH+'" fill="#f59f00" rx="1.5" class="timeline-bar"/>';
            baseY -= wH;
        }
        if (b.hi > 0) {
            var hH = b.hi / maxVal * chartH;
            svg += '<rect x="'+x+'" y="'+(baseY-hH)+'" width="'+bw+'" height="'+hH+'" fill="#f76707" rx="1.5" class="timeline-bar"/>';
            baseY -= hH;
        }
        if (b.c > 0) {
            var cH = b.c / maxVal * chartH;
            svg += '<rect x="'+x+'" y="'+(baseY-cH)+'" width="'+bw+'" height="'+cH+'" fill="#d63939" rx="1.5" class="timeline-bar"/>';
        }

        // Invisible hit area for tooltip
        svg += '<rect x="'+(padL + i * barW)+'" y="'+padT+'" width="'+barW+'" height="'+chartH+'" fill="transparent" class="timeline-hover" data-idx="'+i+'"/>';

        if (i % 3 === 0) {
            svg += '<text x="'+(padL+i*barW+barW/2)+'" y="'+(vH-4)+'" text-anchor="middle" fill="'+textColor+'" font-size="9">'+b.h+'</text>';
        }
    }

    svg += '<line x1="'+padL+'" y1="'+(padT+chartH)+'" x2="'+(vW-padR)+'" y2="'+(padT+chartH)+'" stroke="'+gridColor+'" stroke-width="0.5"/>';
    svg += '</svg>';
    container.innerHTML = svg;

    // Tooltip behavior
    var tooltip = document.getElementById('timeline-tooltip');
    if (tooltip) {
        container.parentElement.addEventListener('mousemove', function(e) {
            var hoverEl = document.elementFromPoint(e.clientX, e.clientY);
            if (!hoverEl || !hoverEl.classList.contains('timeline-hover')) {
                tooltip.classList.remove('visible');
                return;
            }
            var idx = parseInt(hoverEl.getAttribute('data-idx'), 10);
            if (isNaN(idx) || idx < 0 || idx >= bars.length) {
                tooltip.classList.remove('visible');
                return;
            }
            var b = bars[idx];
            tooltip.textContent = b.h + ' \u2014 ' + b.t + ' total (' + b.c + ' crit, ' + b.hi + ' high, ' + b.w + ' warn)';

            // Position the tooltip above the hovered bar
            var parentRect = container.parentElement.getBoundingClientRect();
            tooltip.style.left = (e.clientX - parentRect.left) + 'px';
            tooltip.style.top = (e.clientY - parentRect.top - 10) + 'px';
            tooltip.classList.add('visible');
        });

        container.parentElement.addEventListener('mouseleave', function() {
            tooltip.classList.remove('visible');
        });
    }

    // Store bars globally so other code can reference them
    window._csmTimelineBars = bars;
})();

// --- Top Attack Types bar chart ---
(function(){
    var colors = {
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

    var labels = {
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

    function renderAttackTypesChart() {
        var container = document.getElementById('attack-types-chart');
        if (!container) return;

        fetch(CSM.apiUrl('/api/v1/threat/stats'), { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var byType = data.by_type || {};
                // Sort by count descending, take top 8
                var entries = [];
                for (var key in byType) {
                    if (byType.hasOwnProperty(key)) {
                        entries.push({ type: key, count: byType[key] });
                    }
                }
                entries.sort(function(a, b) { return b.count - a.count; });
                entries = entries.slice(0, 8);

                if (entries.length === 0) {
                    container.innerHTML = '<div class="text-muted text-center py-3">No attack data yet</div>';
                    return;
                }

                var maxCount = entries[0].count || 1;
                var html = '';
                for (var i = 0; i < entries.length; i++) {
                    var e = entries[i];
                    var label = labels[e.type] || e.type;
                    var color = colors[e.type] || '#6b7a8d';
                    var pct = Math.round((e.count / maxCount) * 100);
                    html += '<div class="bar-chart-row">' +
                        '<div class="bar-chart-label" title="' + CSM.esc(label) + '">' + CSM.esc(label) + '</div>' +
                        '<div class="bar-chart-track"><div class="bar-chart-fill" style="width:' + pct + '%;background:' + color + '"></div></div>' +
                        '<div class="bar-chart-value">' + e.count + '</div>' +
                        '</div>';
                }
                container.innerHTML = html;
            })
            .catch(function() {
                container.innerHTML = '<div class="text-muted text-center py-3">Could not load attack data</div>';
            });
    }

    renderAttackTypesChart();
    setInterval(renderAttackTypesChart, 60000);
})();

// --- 30-Day Trend Chart ---
(function(){
    function loadTrend() {
        fetch(CSM.apiUrl('/api/v1/stats/trend'), { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(days) {
                var container = document.getElementById('trend-chart');
                if (!container || !days || !days.length) return;
                var maxVal = 1;
                days.forEach(function(d) { if (d.total > maxVal) maxVal = d.total; });
                var w = container.clientWidth || 800;
                var barW = Math.floor((w - 60) / days.length) - 2;
                if (barW < 4) barW = 4;
                var h = 120;
                var padL = 30, padB = 18;
                var chartH = h - padB;

                var isDark = document.documentElement.classList.contains('theme-dark');
                var textColor = isDark ? '#6b7a8d' : '#9da9b5';

                var svg = '<svg width="' + w + '" height="' + h + '">';
                days.forEach(function(d, i) {
                    var x = padL + i * (barW + 2);
                    var barH = Math.max(1, Math.round(d.total / maxVal * (chartH - 4)));
                    var color = d.critical > 0 ? '#d63939' : d.high > 0 ? '#f76707' : d.total > 0 ? '#f59f00' : '#2d3a4e';
                    svg += '<rect x="' + x + '" y="' + (chartH - barH) + '" width="' + barW + '" height="' + barH + '" fill="' + color + '" rx="1.5">';
                    svg += '<title>' + d.date + ': ' + d.total + ' (' + d.critical + ' crit, ' + d.high + ' high, ' + d.warning + ' warn)</title></rect>';
                    if (i % 7 === 0) {
                        svg += '<text x="' + (x + barW/2) + '" y="' + (h - 2) + '" text-anchor="middle" fill="' + textColor + '" style="font-size:9px">' + d.date.slice(5) + '</text>';
                    }
                });
                svg += '</svg>';
                container.innerHTML = svg;
            })
            .catch(function() {
                var c = document.getElementById('trend-chart');
                if (c) c.innerHTML = '<div class="text-muted text-center py-3">Could not load trend data</div>';
            });
    }
    loadTrend();
})();
