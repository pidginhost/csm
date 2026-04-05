// CSM Email Dashboard
(function() {
    'use strict';

    var EMAIL_CHECKS = 'mail_queue,mail_per_account,email_phishing_content,email_malware,email_av_degraded,email_av_timeout,email_av_parse_error,email_compromised_account,email_spam_outbreak,email_credential_leak,email_auth_failure_realtime,exim_frozen_realtime';
    var EMAIL_BLOCKED_KEYWORDS = ['mail', 'smtp', 'spam', 'phish', 'mailer'];

    // Restore filter state from URL, falling back to today's date
    var today = new Date().toISOString().substring(0, 10);
    var fromEl = document.getElementById('filter-from');
    var toEl = document.getElementById('filter-to');
    var sevEl = document.getElementById('filter-severity');
    var checkEl = document.getElementById('filter-check');
    var searchEl = document.getElementById('email-search');
    if (fromEl) fromEl.value = CSM.urlState.get('from') || today;
    if (toEl) toEl.value = CSM.urlState.get('to') || today;
    if (sevEl && CSM.urlState.get('severity')) sevEl.value = CSM.urlState.get('severity');
    if (checkEl && CSM.urlState.get('check')) checkEl.value = CSM.urlState.get('check');
    if (searchEl && CSM.urlState.get('search')) searchEl.value = CSM.urlState.get('search');

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

        var frozen = data.frozen_count || 0;
        var oldest = data.oldest_age || '';

        el.textContent = '';

        // Queue size bar
        var row1 = document.createElement('div');
        row1.className = 'd-flex justify-content-between mb-1';
        var label1 = document.createElement('span');
        label1.className = 'text-muted small';
        label1.textContent = 'Queue Size';
        var val1 = document.createElement('span');
        val1.className = 'fw-bold';
        val1.textContent = data.queue_size + ' / ' + data.queue_crit;
        row1.appendChild(label1);
        row1.appendChild(val1);
        el.appendChild(row1);

        var progWrap = document.createElement('div');
        progWrap.className = 'progress progress-sm mb-3';
        var progBar = document.createElement('div');
        progBar.className = 'progress-bar ' + color;
        progBar.style.width = pct + '%';
        progWrap.appendChild(progBar);
        el.appendChild(progWrap);

        // Additional stats
        var stats = [
            ['Frozen Messages', frozen, frozen > 0 ? 'text-warning fw-bold' : ''],
            ['Oldest Message', oldest || 'none', oldest && oldest.indexOf('d') >= 0 ? 'text-danger fw-bold' : ''],
            ['Warn Threshold', data.queue_warn, ''],
            ['Crit Threshold', data.queue_crit, '']
        ];
        for (var s = 0; s < stats.length; s++) {
            var row = document.createElement('div');
            row.className = 'd-flex justify-content-between mb-1';
            var lbl = document.createElement('span');
            lbl.className = 'text-muted small';
            lbl.textContent = stats[s][0];
            var v = document.createElement('span');
            v.className = 'small ' + stats[s][2];
            v.textContent = stats[s][1];
            row.appendChild(lbl);
            row.appendChild(v);
            el.appendChild(row);
        }

        // Protection features status (merged into same card)
        var hr = document.createElement('hr');
        hr.className = 'my-2';
        el.appendChild(hr);

        var protTitle = document.createElement('div');
        protTitle.className = 'subheader mb-2';
        protTitle.textContent = 'Protection Features';
        el.appendChild(protTitle);

        var features = [
            ['Password Audit', '24h cycle'],
            ['Geo Login', 'Realtime'],
            ['Rate Limiting', 'Realtime'],
            ['Forwarder Audit', 'Realtime + 24h'],
            ['DKIM/SPF', 'Realtime']
        ];
        for (var p = 0; p < features.length; p++) {
            var frow = document.createElement('div');
            frow.className = 'd-flex justify-content-between mb-1';
            var fl = document.createElement('span');
            fl.className = 'text-muted small';
            fl.textContent = features[p][0];
            var fv = document.createElement('span');
            fv.className = 'small text-green';
            fv.textContent = features[p][1];
            frow.appendChild(fl);
            frow.appendChild(fv);
            el.appendChild(frow);
        }
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
            html += '<div class="list-group-item feed-item" data-sender-domain="' + CSM.esc(s.domain) + '">';
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

        // Blocked IPs count - loaded separately
        html += '<div class="d-flex align-items-center">';
        html += '<span class="text-muted small">Email-related Blocked IPs</span>';
        html += '<span class="ms-auto fw-bold" id="smtp-blocked-count">-</span></div>';

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
        // Always fetch all email checks for the date range - stat cards need the full set
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
                renderRecentThreats(filtered);
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

            // Extract useful fields from message and details
            var account = extractAccountFromMessage(f.message, f.details);
            var ip = extractIPFromMessage(f.message, f.details);
            var shortMsg = f.message;
            // Make check name human-readable
            var checkLabel = f.check.replace(/_/g, ' ').replace(/realtime$/, '').replace(/^email /, '');

            html += '<tr data-sev="' + cls + '">';
            html += '<td>' + CSM.severityBadge(f.severity) + '</td>';
            html += '<td><span class="small">' + CSM.esc(checkLabel) + '</span></td>';
            html += '<td>' + CSM.esc(account || '') + '</td>';
            html += '<td><code>' + CSM.esc(ip || '') + '</code></td>';
            html += '<td class="text-wrap" style="max-width:400px">' + CSM.esc(shortMsg) + '</td>';
            html += '<td data-timestamp="' + CSM.esc(f.timestamp || '') + '">' + CSM.fmtDate(f.timestamp) + '</td>';
            html += '</tr>';

            // Detail row (hidden, toggled by clicking the row)
            if (f.details) {
                html += '<tr class="details-row"><td colspan="6"><div class="small text-muted csm-detail">' + CSM.esc(f.details) + '</div></td></tr>';
            }
        }

        function extractAccountFromMessage(msg, details) {
            // "Email authentication failure for admin@arvamet.ro from 73.85.44.247"
            var m = msg.match(/for (\S+@\S+)/);
            if (m) return m[1];
            // "Account office@nordkey.ro has outgoing mail hold"
            m = msg.match(/Account (\S+@\S+)/);
            if (m) return m[1];
            // "Compromised email account user@domain"
            m = msg.match(/account (\S+@\S+)/);
            if (m) return m[1];
            // "High email volume from example.com"
            m = msg.match(/volume from (\S+)/);
            if (m) return m[1];
            // Fallback: extract set_id from details
            if (details) {
                m = details.match(/set_id=(\S+)/);
                if (m) return m[1].replace(/[)]/g, '');
            }
            // Fallback: extract Sender from details
            if (details) {
                m = details.match(/Sender (\S+@\S+)/);
                if (m) return m[1];
            }
            // "Domain example.com has exceeded"
            m = msg.match(/Domain (\S+)/);
            if (m) return m[1];
            return '';
        }

        function extractIPFromMessage(msg, details) {
            // "... from 1.2.3.4"
            var m = msg.match(/from (\d+\.\d+\.\d+\.\d+)/);
            if (m) return m[1];
            // Fallback: [IP] in details
            if (details) {
                m = details.match(/\[(\d+\.\d+\.\d+\.\d+)\]/);
                if (m) return m[1];
            }
            return '';
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
        var compromisedAccounts = 0, spamOutbreaks = 0, credLeaks = 0;
        for (var i = 0; i < findings.length; i++) {
            var f = findings[i];
            if (f.check === 'email_phishing_content') phishing++;
            else if (f.check === 'mail_per_account') {
                var d = extractDomain(f.message);
                if (d) accounts[d] = true;
            }
            else if (f.check === 'mail_queue') queueAlerts++;
            else if (f.check === 'email_compromised_account') compromisedAccounts++;
            else if (f.check === 'email_spam_outbreak') spamOutbreaks++;
            else if (f.check === 'email_credential_leak') credLeaks++;
        }
        setText('stat-phishing', phishing);
        setText('stat-accounts', Object.keys(accounts).length);
        var totalCompromised = compromisedAccounts + spamOutbreaks + credLeaks;
        setText('stat-compromised', totalCompromised);

        // Breakdown detail under the number
        var detail = [];
        if (compromisedAccounts > 0) detail.push(compromisedAccounts + ' compromised');
        if (spamOutbreaks > 0) detail.push(spamOutbreaks + ' spam outbreaks');
        if (credLeaks > 0) detail.push(credLeaks + ' credential leaks');
        var detailEl = document.getElementById('stat-compromised-detail');
        if (detailEl) detailEl.textContent = detail.join(', ') || 'No incidents';

        setText('stat-queue-alerts', queueAlerts);
    }

    // --- Recent Threats (replaces timeline chart) ---
    // All user-supplied values escaped via CSM.esc() before insertion

    function renderRecentThreats(findings) {
        var el = document.getElementById('recent-threats');
        if (!el) return;

        var threats = [];
        for (var i = 0; i < findings.length; i++) {
            var f = findings[i];
            if (f.severity < 1) continue;
            if (f.check === 'exim_frozen_realtime' || f.check === 'email_auth_failure_realtime') continue;
            threats.push(f);
        }

        if (threats.length === 0) {
            el.textContent = '';
            var empty = document.createElement('div');
            empty.className = 'text-muted text-center py-3';
            empty.textContent = 'No actionable threats today';
            el.appendChild(empty);
            return;
        }

        var limit = Math.min(threats.length, 10);
        var container = document.createElement('div');
        container.className = 'list-group list-group-flush';

        for (var j = 0; j < limit; j++) {
            var t = threats[j];
            var sevClass = t.severity === 2 ? 'bg-red' : 'bg-orange';
            var account = extractAccountFromMsg(t.message);
            var checkLabel = t.check.replace(/_/g, ' ').replace(/realtime$/, '').replace(/^email /, '');

            var item = document.createElement('div');
            item.className = 'list-group-item py-2';

            var row = document.createElement('div');
            row.className = 'd-flex align-items-center';

            var account = extractAccountFromMsg(t.message, t.details);

            var sevDot = document.createElement('span');
            sevDot.className = 'status-dot ' + (t.severity === 2 ? 'status-dot-red' : 'status-dot-orange') + ' me-2';
            row.appendChild(sevDot);

            var acctSpan = document.createElement('strong');
            acctSpan.className = 'font-monospace';
            acctSpan.textContent = account || 'unknown';
            row.appendChild(acctSpan);

            var sep = document.createElement('span');
            sep.className = 'text-muted mx-1';
            sep.textContent = '-';
            row.appendChild(sep);

            var typeSpan = document.createElement('span');
            typeSpan.className = 'small';
            typeSpan.textContent = checkLabel;
            row.appendChild(typeSpan);

            var timeSpan = document.createElement('span');
            timeSpan.className = 'ms-auto text-muted small';
            timeSpan.textContent = CSM.fmtDate(t.timestamp);
            row.appendChild(timeSpan);

            item.appendChild(row);

            // Show a useful description, not the generic message
            var description = t.message;
            if (!account && description.indexOf('Account has') === 0) {
                // Old finding without account in message - try to show something useful from details
                description = 'Spam detected by cPanel';
            }

            var msgDiv = document.createElement('div');
            msgDiv.className = 'small text-muted text-truncate mt-1';
            msgDiv.textContent = description;
            item.appendChild(msgDiv);

            container.appendChild(item);
        }

        el.textContent = '';
        el.appendChild(container);

        if (threats.length > 10) {
            var more = document.createElement('div');
            more.className = 'text-center text-muted small py-1';
            more.textContent = '+' + (threats.length - 10) + ' more';
            el.appendChild(more);
        }
    }

    function extractAccountFromMsg(msg, details) {
        var m = msg.match(/for (\S+@\S+)/);
        if (m) return m[1];
        m = msg.match(/Account (\S+@\S+)/);
        if (m) return m[1];
        m = msg.match(/account (\S+@\S+)/);
        if (m) return m[1];
        if (details) {
            m = details.match(/Sender (\S+@\S+)/);
            if (m) return m[1];
            m = details.match(/set_id=(\S+)/);
            if (m) return m[1].replace(/[)]/g, '');
        }
        m = msg.match(/Domain (\S+)/);
        if (m) return m[1];
        return '';
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
        CSM.confirm('Release this message back to the mail queue? Only do this for confirmed false positives.').then(function() {
            CSM.post(CSM.apiUrl('/api/v1/email/quarantine/' + encodeURIComponent(msgID) + '/release'), {})
                .then(function() { loadQuarantine(); loadAVStatus(); })
                .catch(function(err) { CSM.toast('Release failed: ' + err.message, 'danger'); });
        }).catch(function() { /* cancelled */ });
    }

    function deleteMessage(msgID) {
        CSM.confirm('Permanently delete this quarantined message?').then(function() {
            fetch(CSM.apiUrl('/api/v1/email/quarantine/' + encodeURIComponent(msgID)), {
                method: 'DELETE',
                credentials: 'same-origin',
                headers: { 'X-CSRF-Token': CSM.csrfToken }
            }).then(function() { loadQuarantine(); loadAVStatus(); })
              .catch(function(err) { CSM.toast('Delete failed: ' + err.message, 'danger'); });
        }).catch(function() { /* cancelled */ });
    }

    // --- Utilities ---

    function setText(id, val) {
        var el = document.getElementById(id);
        if (el) el.textContent = val;
    }

    // --- Filter form ---

    function syncEmailURL() {
        var fromVal = (document.getElementById('filter-from') || {}).value || '';
        var toVal = (document.getElementById('filter-to') || {}).value || '';
        var sevVal = (document.getElementById('filter-severity') || {}).value || '';
        var checkVal = (document.getElementById('filter-check') || {}).value || '';
        var searchVal = (document.getElementById('email-search') || {}).value || '';
        // Don't sync dates that match today (default)
        var todayStr = new Date().toISOString().substring(0, 10);
        CSM.urlState.set({
            from: fromVal !== todayStr ? fromVal : '',
            to: toVal !== todayStr ? toVal : '',
            severity: sevVal,
            check: checkVal,
            search: searchVal
        });
    }

    var filterForm = document.getElementById('email-filters');
    if (filterForm) {
        filterForm.addEventListener('submit', function(e) {
            e.preventDefault();
            syncEmailURL();
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
