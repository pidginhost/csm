// CSM Email Dashboard
(function() {
    'use strict';

    var EMAIL_CHECKS = 'mail_queue,mail_per_account,email_phishing_content,email_malware,email_av_degraded,email_av_timeout,email_av_parse_error';
    var EMAIL_BLOCKED_KEYWORDS = ['mail', 'smtp', 'spam', 'phish', 'mailer'];

    // Set default date filter to today
    var today = new Date().toISOString().substring(0, 10);
    var fromEl = document.getElementById('filter-from');
    var toEl = document.getElementById('filter-to');
    if (fromEl) fromEl.value = today;
    if (toEl) toEl.value = today;

    // --- Right column: email stats ---

    function loadEmailStats() {
        fetch(CSM.apiUrl('/api/v1/email/stats'), { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                renderQueueHealth(data);
                renderTopSenders(data.top_senders || []);
                renderSMTPFirewall(data);
                // Update queue stat card with color
                var qEl = document.getElementById('stat-queue');
                if (qEl) {
                    qEl.textContent = data.queue_size;
                    qEl.className = 'h1 mb-0';
                    if (data.queue_size >= data.queue_crit) qEl.classList.add('text-critical');
                    else if (data.queue_size >= data.queue_warn) qEl.classList.add('text-warning');
                    else qEl.classList.add('text-green');
                }
            })
            .catch(function() {
                CSM.loadError(document.getElementById('queue-health'));
                CSM.loadError(document.getElementById('top-senders'));
                CSM.loadError(document.getElementById('smtp-firewall'));
            });
    }

    function renderQueueHealth(data) {
        var el = document.getElementById('queue-health');
        if (!el) return;
        var pct = Math.min(100, Math.round(data.queue_size / data.queue_crit * 100));
        var color = 'bg-green';
        if (data.queue_size >= data.queue_crit) color = 'bg-danger';
        else if (data.queue_size >= data.queue_warn) color = 'bg-warning';

        el.innerHTML =
            '<div class="d-flex justify-content-between mb-1">' +
            '<span class="text-muted small">Queue Size</span>' +
            '<span class="fw-bold">' + data.queue_size + ' / ' + data.queue_crit + '</span></div>' +
            '<div class="progress progress-sm mb-2"><div class="progress-bar ' + color + '" style="width:' + pct + '%"></div></div>' +
            '<div class="d-flex justify-content-between text-muted small">' +
            '<span>0</span><span>' + data.queue_warn + ' warn</span><span>' + data.queue_crit + ' crit</span></div>';
    }

    function renderTopSenders(senders) {
        var el = document.getElementById('top-senders');
        if (!el) return;
        if (!senders || senders.length === 0) {
            el.innerHTML = '<div class="text-muted text-center py-3">No outbound email activity</div>';
            return;
        }
        var maxCount = senders[0].count || 1;
        var html = '<div class="list-group list-group-flush">';
        for (var i = 0; i < senders.length; i++) {
            var s = senders[i];
            var pct = Math.round(s.count / maxCount * 100);
            var countClass = s.count >= 100 ? 'text-danger fw-bold' : 'text-muted';
            html += '<div class="list-group-item" style="cursor:pointer" data-sender-domain="' + CSM.esc(s.domain) + '">';
            html += '<div class="d-flex align-items-center mb-1">';
            html += '<span class="font-monospace small">' + CSM.esc(s.domain) + '</span>';
            html += '<span class="ms-auto small ' + countClass + '">' + s.count + '</span></div>';
            html += '<div class="progress progress-sm"><div class="progress-bar bg-primary" style="width:' + pct + '%"></div></div>';
            html += '</div>';
        }
        html += '</div>';
        el.innerHTML = html;

        // Click sender domain to filter findings table
        var items = el.querySelectorAll('[data-sender-domain]');
        for (var j = 0; j < items.length; j++) {
            CSM.makeClickable(items[j]);
            items[j].addEventListener('click', function() {
                var domain = this.getAttribute('data-sender-domain');
                var searchEl = document.getElementById('email-search');
                if (searchEl) {
                    searchEl.value = domain;
                    searchEl.dispatchEvent(new Event('input'));
                }
            });
        }
    }

    function renderSMTPFirewall(data) {
        var el = document.getElementById('smtp-firewall');
        if (!el) return;
        var stateClass = data.smtp_block ? 'text-danger' : 'text-green';
        var stateLabel = data.smtp_block ? 'Restricted' : 'Open';
        var stateIcon = data.smtp_block ? 'ti-lock' : 'ti-lock-open';

        var html = '<div class="mb-3">';
        html += '<div class="d-flex align-items-center mb-1">';
        html += '<span class="text-muted small">Outbound SMTP</span>';
        html += '<span class="ms-auto fw-bold ' + stateClass + '"><i class="ti ' + stateIcon + '"></i> ' + stateLabel + '</span></div>';

        if (data.smtp_block && data.smtp_allow_users && data.smtp_allow_users.length > 0) {
            html += '<div class="text-muted small mb-2">Allowed: ' + data.smtp_allow_users.map(CSM.esc).join(', ') + '</div>';
        }
        html += '</div>';

        // Port flood rules
        if (data.port_flood && data.port_flood.length > 0) {
            html += '<div class="mb-3"><div class="text-muted small mb-1">Rate Limits</div>';
            for (var i = 0; i < data.port_flood.length; i++) {
                var pf = data.port_flood[i];
                html += '<div class="small">Port ' + pf.port + ': ' + pf.hits + ' conn / ' + pf.seconds + 's</div>';
            }
            html += '</div>';
        }

        // Blocked IPs count — loaded separately
        html += '<div class="d-flex align-items-center">';
        html += '<span class="text-muted small">Email-related Blocked IPs</span>';
        html += '<span class="ms-auto fw-bold" id="smtp-blocked-count">—</span></div>';

        el.innerHTML = html;

        // Load blocked IPs and count email-related ones
        loadBlockedIPCount();
    }

    function loadBlockedIPCount() {
        fetch(CSM.apiUrl('/api/v1/blocked-ips'), { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var ips = data.ips || data || [];
                var count = 0;
                for (var i = 0; i < ips.length; i++) {
                    var reason = (ips[i].reason || '').toLowerCase();
                    for (var k = 0; k < EMAIL_BLOCKED_KEYWORDS.length; k++) {
                        if (reason.indexOf(EMAIL_BLOCKED_KEYWORDS[k]) >= 0) {
                            count++;
                            break;
                        }
                    }
                }
                var el = document.getElementById('smtp-blocked-count');
                if (el) el.textContent = count;
            })
            .catch(function(err) { console.error('loadBlockedIPCount:', err); });
    }

    // --- Left column: findings table + timeline ---

    var emailTable = null;

    function loadFindings() {
        // Always fetch all email checks for the date range — stat cards need the full set
        var from = (document.getElementById('filter-from') || {}).value || '';
        var to = (document.getElementById('filter-to') || {}).value || '';
        var params = 'checks=' + EMAIL_CHECKS + '&limit=5000';
        if (from) params += '&from=' + from;
        if (to) params += '&to=' + to;
        fetch(CSM.apiUrl('/api/v1/history?' + params), { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var allFindings = data.findings || [];
                // Stat cards always reflect full date range, no check/severity filter
                updateStatCards(allFindings);
                // Apply check type and severity filters client-side for table + timeline
                var sev = (document.getElementById('filter-severity') || {}).value || '';
                var check = (document.getElementById('filter-check') || {}).value || '';
                var filtered = allFindings;
                if (sev || check) {
                    filtered = allFindings.filter(function(f) {
                        if (sev && String(f.severity) !== sev) return false;
                        if (check && f.check !== check) return false;
                        return true;
                    });
                }
                renderFindingsTable(filtered);
                renderTimeline(filtered);
            })
            .catch(function() {
                var tbody = document.getElementById('email-tbody');
                if (tbody) tbody.innerHTML = '<tr><td colspan="5" class="text-center text-danger py-4">Failed to load data</td></tr>';
            });
    }

    function renderFindingsTable(findings) {
        var tbody = document.getElementById('email-tbody');
        if (!tbody) return;

        if (findings.length === 0) {
            tbody.innerHTML = CSM.emptyState('No email findings in this period', 5);
            emailTable = null;
            return;
        }

        var html = '';

        for (var i = 0; i < findings.length; i++) {
            var f = findings[i];
            var cls = CSM.severityClass(f.severity);
            var action = '';

            if (f.check === 'email_phishing_content') {
                action = '<button class="btn btn-warning btn-sm email-quarantine-btn" ' +
                    'data-check="' + CSM.esc(f.check) + '" ' +
                    'data-message="' + CSM.esc(f.message) + '" ' +
                    'data-details="' + CSM.esc(f.details || '') + '" ' +
                    'title="Quarantine spool message"><i class="ti ti-lock"></i></button>';
            } else if (f.check === 'mail_per_account') {
                var domain = extractDomain(f.message);
                if (domain) {
                    action = '<a href="/incident?account=' + encodeURIComponent(domain) + '" class="btn btn-outline-primary btn-sm" title="Investigate"><i class="ti ti-search"></i></a>';
                }
            }

            html += '<tr data-sev="' + cls + '">';
            html += '<td>' + CSM.severityBadge(f.severity) + '</td>';
            html += '<td><span class="font-monospace small">' + CSM.esc(f.check) + '</span></td>';
            html += '<td>' + CSM.esc(f.message) + '</td>';
            html += '<td data-timestamp="' + CSM.esc(f.timestamp || '') + '">' + CSM.fmtDate(f.timestamp) + '</td>';
            var expandBtn = f.details ? ' <button class="btn btn-ghost-secondary btn-sm expand-btn" title="Show details"><i class="ti ti-chevron-down"></i></button>' : '';
            html += '<td>' + action + expandBtn + '</td>';
            html += '</tr>';

            // Detail row (hidden, toggled on click)
            if (f.details) {
                html += '<tr class="details-row" style="display:none"><td colspan="5"><div class="small text-muted" style="white-space:pre-wrap">' + CSM.esc(f.details) + '</div></td></tr>';
            }
        }

        tbody.innerHTML = html;

        // Initialize CSM.Table for sort/pagination
        emailTable = new CSM.Table({
            tableId: 'email-table',
            perPage: 25,
            searchId: 'email-search',
            sortable: true,
            detailRows: true,
            stateKey: 'csm-email-table'
        });

        // Update relative timestamps
        CSM.initTimeAgo();
    }

    function confirmQuarantine(check, message, details, btn) {
        var body = document.getElementById('csm-confirm-body');
        var okBtn = document.getElementById('csm-confirm-ok');
        var cancelBtn = document.getElementById('csm-confirm-cancel');
        if (!body || !okBtn) return;

        body.textContent = 'Quarantine this email spool message?\n\n' + message;
        var modal = new bootstrap.Modal(document.getElementById('csm-confirm-modal'));
        modal.show();

        var handler = function() {
            okBtn.removeEventListener('click', handler);
            modal.hide();
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
            CSM.post(CSM.apiUrl('/api/v1/fix'), { check: check, message: message, details: details })
                .then(function(r) {
                    CSM.toast(r.action || 'Message quarantined', 'success');
                    loadFindings();
                    loadEmailStats();
                })
                .catch(function(err) {
                    CSM.toast(err.message || 'Quarantine failed', 'danger');
                    btn.disabled = false;
                    btn.innerHTML = '<i class="ti ti-lock"></i>';
                });
        };
        okBtn.addEventListener('click', handler);
        cancelBtn.addEventListener('click', function once() {
            cancelBtn.removeEventListener('click', once);
            okBtn.removeEventListener('click', handler);
        });
    }

    function extractDomain(message) {
        // "High email volume from example.com: 150 messages" -> "example.com"
        var match = message.match(/from\s+(\S+?):/);
        return match ? match[1] : '';
    }

    function updateStatCards(findings) {
        var phishing = 0, accounts = {}, queueAlerts = 0;
        for (var i = 0; i < findings.length; i++) {
            var f = findings[i];
            if (f.check === 'email_phishing_content') phishing++;
            else if (f.check === 'mail_per_account') {
                var d = extractDomain(f.message);
                if (d) accounts[d] = true;
            }
            else if (f.check === 'mail_queue') queueAlerts++;
        }
        setText('stat-phishing', phishing);
        setText('stat-accounts', Object.keys(accounts).length);
        setText('stat-queue-alerts', queueAlerts);
    }

    // --- Timeline ---

    function renderTimeline(findings) {
        var el = document.getElementById('email-timeline');
        if (!el) return;

        if (findings.length === 0) {
            el.innerHTML = '<div class="text-muted text-center small">No events in this period</div>';
            return;
        }

        // Group by hour
        var buckets = {};
        for (var i = 0; i < findings.length; i++) {
            var f = findings[i];
            var ts = new Date(f.timestamp);
            if (isNaN(ts.getTime())) continue;
            var key = ts.toISOString().substring(0, 13); // "2026-03-29T14"
            if (!buckets[key]) buckets[key] = { critical: 0, high: 0, warning: 0 };
            if (f.severity === 2) buckets[key].critical++;
            else if (f.severity === 1) buckets[key].high++;
            else buckets[key].warning++;
        }

        var keys = Object.keys(buckets).sort();
        var maxTotal = 1;
        for (var k = 0; k < keys.length; k++) {
            var b = buckets[keys[k]];
            var total = b.critical + b.high + b.warning;
            if (total > maxTotal) maxTotal = total;
        }

        var barWidth = Math.max(8, Math.floor((el.clientWidth - 20) / Math.max(keys.length, 1)) - 2);
        var html = '<div style="display:flex;align-items:flex-end;gap:2px;height:80px">';
        for (var m = 0; m < keys.length; m++) {
            var bk = buckets[keys[m]];
            var t = bk.critical + bk.high + bk.warning;
            var h = Math.max(4, Math.round(t / maxTotal * 80));
            var cH = Math.round(bk.critical / t * h);
            var hH = Math.round(bk.high / t * h);
            var wH = Math.max(0, h - cH - hH);
            var hour = keys[m].substring(11, 13) + ':00';
            html += '<div title="' + hour + ': ' + t + ' events" style="width:' + barWidth + 'px;display:flex;flex-direction:column;justify-content:flex-end">';
            if (cH > 0) html += '<div style="height:' + cH + 'px;background:#d63939;border-radius:2px 2px 0 0"></div>';
            if (hH > 0) html += '<div style="height:' + hH + 'px;background:#f76707"></div>';
            if (wH > 0) html += '<div style="height:' + wH + 'px;background:#f59f00;border-radius:0 0 2px 2px"></div>';
            html += '</div>';
        }
        html += '</div>';

        // Hour labels
        html += '<div style="display:flex;gap:2px">';
        for (var n = 0; n < keys.length; n++) {
            var lbl = keys[n].substring(11, 13);
            // Show every 3rd label to avoid crowding
            var show = (n % 3 === 0 || n === keys.length - 1);
            html += '<div style="width:' + barWidth + 'px;text-align:center;font-size:9px;color:var(--tblr-muted)">' + (show ? lbl : '') + '</div>';
        }
        html += '</div>';

        el.innerHTML = html;
    }

    // --- Email AV Status & Quarantine ---

    function loadAVStatus() {
        fetch(CSM.apiUrl('/api/v1/email/av/status'), { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                // AV engines badge
                var badge = document.getElementById('av-status-badge');
                if (badge) {
                    if (data.clamd_available && data.yarax_available) {
                        badge.className = 'badge bg-green'; badge.textContent = 'Both Up';
                    } else if (data.clamd_available || data.yarax_available) {
                        badge.className = 'badge bg-yellow'; badge.textContent = 'Degraded';
                    } else if (data.enabled) {
                        badge.className = 'badge bg-red'; badge.textContent = 'Down';
                    } else {
                        badge.className = 'badge bg-secondary'; badge.textContent = 'Disabled';
                    }
                }

                // Sidebar status dots
                var clamdDot = document.getElementById('clamd-dot');
                var clamdStatusEl = document.getElementById('clamd-status');
                if (clamdDot && clamdStatusEl) {
                    clamdDot.className = 'status-dot ' + (data.clamd_available ? 'status-dot-green' : 'status-dot-red');
                    clamdStatusEl.textContent = data.clamd_available ? 'Connected' : 'Unavailable';
                }

                var yaraxDot = document.getElementById('yarax-dot');
                var yaraxStatusEl = document.getElementById('yarax-status');
                if (yaraxDot && yaraxStatusEl) {
                    yaraxDot.className = 'status-dot ' + (data.yarax_available ? 'status-dot-green' : 'status-dot-red');
                    yaraxStatusEl.textContent = data.yarax_available ? 'Active' : 'Unavailable';
                }

                var yaraxRulesEl = document.getElementById('yarax-rules');
                if (yaraxRulesEl) yaraxRulesEl.textContent = data.yarax_rule_count || 0;

                var watcherModeEl = document.getElementById('watcher-mode');
                if (watcherModeEl) watcherModeEl.textContent = data.watcher_mode || '--';

                // Malware blocked stat card
                var malwareBlocked = document.getElementById('stat-malware-blocked');
                if (malwareBlocked) malwareBlocked.textContent = data.quarantined || 0;
            })
            .catch(function(err) { console.error('loadAVStatus:', err); });
    }

    function loadQuarantine() {
        fetch(CSM.apiUrl('/api/v1/email/quarantine'), { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var container = document.getElementById('quarantine-table');
                if (!container) return;

                if (!data || data.length === 0) {
                    container.innerHTML = '<p class="text-muted">No quarantined messages.</p>';
                    return;
                }

                var html = '<div class="table-responsive"><table class="table table-vcenter card-table">';
                html += '<thead><tr><th>Time</th><th>Dir</th><th>From</th><th>To</th><th>Subject</th><th>Threat</th><th>Actions</th></tr></thead><tbody>';
                for (var i = 0; i < data.length; i++) {
                    var msg = data[i];
                    var time = CSM.timeAgo ? CSM.timeAgo(msg.quarantined_at) : CSM.esc(msg.quarantined_at);
                    var dir = msg.direction === 'inbound'
                        ? '<span class="badge bg-blue">IN</span>'
                        : '<span class="badge bg-orange">OUT</span>';
                    var findings = msg.findings || [];
                    var threats = [];
                    for (var j = 0; j < findings.length; j++) {
                        threats.push(findings[j].signature + ' (' + findings[j].engine + ')');
                    }
                    var to = (msg.to || []).join(', ');
                    var msgID = CSM.esc(msg.message_id);
                    html += '<tr>';
                    html += '<td>' + time + '</td>';
                    html += '<td>' + dir + '</td>';
                    html += '<td>' + CSM.esc(msg.from) + '</td>';
                    html += '<td>' + CSM.esc(to) + '</td>';
                    html += '<td>' + CSM.esc(msg.subject) + '</td>';
                    html += '<td><code>' + CSM.esc(threats.join(', ')) + '</code></td>';
                    html += '<td>';
                    html += '<button class="btn btn-sm btn-warning" data-email-release="' + msgID + '">Release</button> ';
                    html += '<button class="btn btn-sm btn-danger" data-email-delete="' + msgID + '">Delete</button>';
                    html += '</td>';
                    html += '</tr>';
                }
                html += '</tbody></table></div>';
                container.innerHTML = html;
            })
            .catch(function(err) { console.error('loadQuarantine:', err); });
    }

    function releaseMessage(msgID) {
        if (!confirm('Release this message back to the mail queue? Only do this for confirmed false positives.')) return;
        CSM.post(CSM.apiUrl('/api/v1/email/quarantine/' + encodeURIComponent(msgID) + '/release'), {})
            .then(function() { loadQuarantine(); loadAVStatus(); })
            .catch(function(err) { CSM.toast('Release failed: ' + err.message, 'danger'); });
    }

    function deleteMessage(msgID) {
        if (!confirm('Permanently delete this quarantined message?')) return;
        fetch(CSM.apiUrl('/api/v1/email/quarantine/' + encodeURIComponent(msgID)), {
            method: 'DELETE',
            credentials: 'same-origin',
            headers: { 'X-CSRF-Token': CSM.csrfToken }
        }).then(function() { loadQuarantine(); loadAVStatus(); })
          .catch(function(err) { CSM.toast('Delete failed: ' + err.message, 'danger'); });
    }

    // --- Utilities ---

    function setText(id, val) {
        var el = document.getElementById(id);
        if (el) el.textContent = val;
    }

    // --- Filter form ---

    var filterForm = document.getElementById('email-filters');
    if (filterForm) {
        filterForm.addEventListener('submit', function(e) {
            e.preventDefault();
            loadFindings();
        });
    }

    // --- Initialize ---

    // Event delegation for email findings table
    var emailTbody = document.getElementById('email-tbody');
    if (emailTbody) {
        emailTbody.addEventListener('click', function(e) {
            // Expand button
            var expandBtn = e.target.closest('.expand-btn');
            if (expandBtn) {
                var row = expandBtn.closest('tr');
                if (row && emailTable) {
                    emailTable.toggleDetail(row);
                    var next = row.nextElementSibling;
                    expandBtn.classList.toggle('expanded', next && next.style.display !== 'none');
                }
                return;
            }
            // Quarantine button
            var qBtn = e.target.closest('.email-quarantine-btn');
            if (qBtn) {
                e.stopPropagation();
                confirmQuarantine(
                    qBtn.getAttribute('data-check'),
                    qBtn.getAttribute('data-message'),
                    qBtn.getAttribute('data-details'),
                    qBtn
                );
                return;
            }
        });
    }

    var quarantineTable = document.getElementById('quarantine-table');
    if (quarantineTable) {
        quarantineTable.addEventListener('click', function(e) {
            var releaseBtn = e.target.closest('[data-email-release]');
            if (releaseBtn) {
                releaseMessage(releaseBtn.getAttribute('data-email-release'));
                return;
            }

            var deleteBtn = e.target.closest('[data-email-delete]');
            if (deleteBtn) {
                deleteMessage(deleteBtn.getAttribute('data-email-delete'));
            }
        });
    }

    loadEmailStats();
    loadFindings();
    loadAVStatus();
    loadQuarantine();

    var _emailIntervals = [];
    function _startEmailPolling() {
        _emailIntervals.push(setInterval(function() {
            try { loadEmailStats(); } catch(e) { console.error('email stats:', e); }
        }, 30000));
        _emailIntervals.push(setInterval(function() {
            try { loadFindings(); } catch(e) { console.error('email findings:', e); }
        }, 30000));
        _emailIntervals.push(setInterval(function() {
            try { loadAVStatus(); } catch(e) { console.error('email AV:', e); }
        }, 30000));
        _emailIntervals.push(setInterval(function() {
            try { loadQuarantine(); } catch(e) { console.error('email quarantine:', e); }
        }, 30000));
    }
    _startEmailPolling();

    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            for (var i = 0; i < _emailIntervals.length; i++) clearInterval(_emailIntervals[i]);
            _emailIntervals = [];
        } else {
            _startEmailPolling();
        }
    });
    window.addEventListener('beforeunload', function() {
        for (var i = 0; i < _emailIntervals.length; i++) clearInterval(_emailIntervals[i]);
        _emailIntervals = [];
    });
})();
