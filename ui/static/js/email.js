// CSM Email Workbench (phase 8.3)
// Layout: status strip + action groups + protection state + tabs
(function() {
    'use strict';

    var EMAIL_BLOCKED_KEYWORDS = ['mail', 'smtp', 'spam', 'phish', 'mailer'];
    var EMAIL_FINDINGS_LIMIT = 250; // first viewport row cap from the plan
    var EMAIL_CHECKS = [
        'mail_queue',
        'mail_per_account',
        'exim_frozen_realtime',
        'email_phishing_content',
        'email_malware',
        'email_av_degraded',
        'email_av_timeout',
        'email_av_parse_error',
        'email_av_quarantine_error',
        'email_compromised_account',
        'email_credential_leak',
        'email_weak_password',
        'email_spam_outbreak',
        'email_rate_critical',
        'email_rate_warning',
        'email_cloud_relay_abuse',
        'email_php_relay_abuse',
        'email_php_relay_action_failed',
        'email_php_relay_rate_limit_hit',
        'email_auth_failure_realtime',
        'email_suspicious_geo',
        'mail_bruteforce',
        'mail_subnet_spray',
        'mail_account_spray',
        'mail_account_compromised',
        'smtp_bruteforce',
        'smtp_subnet_spray',
        'smtp_account_spray',
        'smtp_probe_abuse',
        'email_dkim_failure',
        'email_spf_rejection',
        'email_pipe_forwarder',
        'email_suspicious_forwarder'
    ].join(',');
    var _emailExportData = [];
    var emailTable = null;
    var quarantineLoaded = false;
    var authGroupsLoaded = false;

    function localDateInputValue(date) {
        var d = date || new Date();
        var m = String(d.getMonth() + 1).padStart(2, '0');
        var day = String(d.getDate()).padStart(2, '0');
        return d.getFullYear() + '-' + m + '-' + day;
    }

    // ---------- Filter state from URL ----------
    var today = localDateInputValue();
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
    var initialTab = CSM.urlState.get('tab');

    // ---------- Status strip (replaces 6-card stat row) ----------

    function chip(opts) {
        var span = document.createElement('span');
        span.className = 'csm-status-strip__chip' + (opts.cls ? ' ' + opts.cls : '');
        if (opts.title) span.title = opts.title;
        var icon = document.createElement('i');
        icon.className = 'ti ' + (opts.icon || 'ti-circle');
        span.appendChild(icon);
        var val = document.createElement('span');
        val.className = 'csm-status-strip__chip-value';
        val.textContent = opts.value;
        span.appendChild(val);
        var lbl = document.createElement('span');
        lbl.className = 'csm-status-strip__chip-label';
        lbl.textContent = opts.label;
        span.appendChild(lbl);
        return span;
    }

    var _strip = { stats: null, av: null, groups: null };

    function refreshStatusStrip() {
        var el = document.getElementById('email-status-strip');
        if (!el) return;
        el.replaceChildren();
        if (_strip.stats) {
            var s = _strip.stats;
            var qcls = '';
            if (s.queue_size >= s.queue_crit) qcls = 'csm-status-strip__chip--crit';
            else if (s.queue_size >= s.queue_warn) qcls = 'csm-status-strip__chip--warn';
            else qcls = 'csm-status-strip__chip--ok';
            el.appendChild(chip({ icon: 'ti-mailbox', value: String(s.queue_size), label: 'queue', cls: qcls,
                title: 'Mail queue size (warn ' + s.queue_warn + ', crit ' + s.queue_crit + ')' }));
            if ((s.frozen_count || 0) > 0) {
                el.appendChild(chip({ icon: 'ti-snowflake', value: String(s.frozen_count), label: 'frozen',
                    cls: 'csm-status-strip__chip--warn', title: 'Frozen messages in the queue' }));
            }
            if (s.oldest_age) {
                el.appendChild(chip({ icon: 'ti-clock', value: s.oldest_age, label: 'oldest',
                    title: 'Age of the oldest queued message' }));
            }
        }
        if (_strip.av) {
            var av = _strip.av;
            var avcls = 'csm-status-strip__chip--ok', avval = 'AV up';
            if (!av.enabled) { avcls = ''; avval = 'AV off'; }
            else if (!av.clamd_available && !av.yarax_available) { avcls = 'csm-status-strip__chip--crit'; avval = 'AV down'; }
            else if (!av.clamd_available || !av.yarax_available) { avcls = 'csm-status-strip__chip--warn'; avval = 'AV degraded'; }
            el.appendChild(chip({ icon: 'ti-virus-search', value: avval, label: '', cls: avcls,
                title: 'ClamAV: ' + (av.clamd_available ? 'up' : 'down') + ' / YARA-X: ' + (av.yarax_available ? 'up' : 'down') }));
            if ((av.quarantined || 0) > 0) {
                el.appendChild(chip({ icon: 'ti-lock', value: String(av.quarantined), label: 'quarantined',
                    title: 'Currently quarantined messages' }));
            }
        }
        if (_strip.groups) {
            var counts = _strip.groups;
            if (counts.compromised > 0) {
                el.appendChild(chip({ icon: 'ti-user-x', value: String(counts.compromised), label: 'compromised',
                    cls: 'csm-status-strip__chip--crit', title: 'Compromised account groups' }));
            }
            if (counts.spam > 0) {
                el.appendChild(chip({ icon: 'ti-mail-exclamation', value: String(counts.spam), label: 'spam outbreaks',
                    cls: 'csm-status-strip__chip--crit', title: 'Spam outbreak groups' }));
            }
            if (counts.auth > 0) {
                el.appendChild(chip({ icon: 'ti-lock-access', value: String(counts.auth), label: 'auth-failure clusters',
                    cls: 'csm-status-strip__chip--warn', title: 'Auth-failure clusters' }));
            }
        }
    }

    // ---------- Mail protection state column ----------

    function loadEmailStats() {
        CSM.get('/api/v1/email/stats')
            .then(function(data) {
                _strip.stats = data;
                refreshStatusStrip();
                renderProtectionQueue(data);
                renderProtectionQueue(data, 'queue-health');
                renderSMTPFirewall(data);
                var sendersPane = document.getElementById('email-pane-senders');
                if (sendersPane && sendersPane.classList.contains('active')) {
                    renderTopSenders(data.top_senders || []);
                } else {
                    // Hold the data for first activation
                    _pendingSenders = data.top_senders || [];
                }
            })
            .catch(function() {
                CSM.loadError(document.getElementById('protection-queue'));
                CSM.loadError(document.getElementById('queue-health'));
                CSM.loadError(document.getElementById('smtp-firewall'));
            });
    }

    var _pendingSenders = null;

    function emailDateQuery(base) {
        var qs = base || '';
        var from = (document.getElementById('filter-from') || {}).value || '';
        var to = (document.getElementById('filter-to') || {}).value || '';
        if (from) qs += (qs ? '&' : '') + 'from=' + encodeURIComponent(from);
        if (to) qs += (qs ? '&' : '') + 'to=' + encodeURIComponent(to);
        return qs;
    }

    function renderProtectionQueue(data, targetId) {
        var el = document.getElementById(targetId || 'protection-queue');
        if (!el) return;
        var pct = Math.min(100, Math.round(data.queue_size / Math.max(1, data.queue_crit) * 100));
        var color = 'bg-green';
        if (data.queue_size >= data.queue_crit) color = 'bg-danger';
        else if (data.queue_size >= data.queue_warn) color = 'bg-warning';
        el.replaceChildren();

        function row(label, value, cls) {
            var r = document.createElement('div');
            r.className = 'd-flex justify-content-between mb-1';
            var l = document.createElement('span');
            l.className = 'text-muted small';
            l.textContent = label;
            var v = document.createElement('span');
            v.className = 'small ' + (cls || '');
            v.textContent = value;
            r.appendChild(l);
            r.appendChild(v);
            return r;
        }

        var head = document.createElement('div');
        head.className = 'd-flex justify-content-between mb-1';
        var hl = document.createElement('span');
        hl.className = 'text-muted small';
        hl.textContent = 'Queue size';
        var hv = document.createElement('span');
        hv.className = 'fw-bold';
        hv.textContent = data.queue_size + ' / ' + data.queue_crit;
        head.appendChild(hl); head.appendChild(hv);
        el.appendChild(head);

        var pwrap = document.createElement('div');
        pwrap.className = 'progress progress-sm mb-2';
        var pbar = document.createElement('div');
        pbar.className = 'progress-bar ' + color;
        CSM.setProgressBar(pbar, pct);
        pwrap.appendChild(pbar);
        el.appendChild(pwrap);

        el.appendChild(row('Frozen', data.frozen_count || 0, (data.frozen_count || 0) > 0 ? 'text-warning fw-bold' : ''));
        var oldest = data.oldest_age || '';
        el.appendChild(row('Oldest', oldest || 'none', oldest && oldest.indexOf('d') >= 0 ? 'text-danger fw-bold' : ''));
        el.appendChild(row('Warn threshold', data.queue_warn, ''));
        el.appendChild(row('Crit threshold', data.queue_crit, ''));
    }

    function renderSMTPFirewall(data) {
        var el = document.getElementById('smtp-firewall');
        if (!el) return;
        el.replaceChildren();
        var head = document.createElement('div');
        head.className = 'd-flex align-items-center mb-1';
        var lbl = document.createElement('span');
        lbl.className = 'text-muted small';
        lbl.textContent = 'Outbound SMTP';
        var st = document.createElement('span');
        st.className = 'ms-auto fw-bold ' + (data.smtp_block ? 'text-danger' : 'text-green');
        st.textContent = data.smtp_block ? 'Restricted' : 'Open';
        head.appendChild(lbl); head.appendChild(st);
        el.appendChild(head);

        if (data.smtp_block && data.smtp_allow_users && data.smtp_allow_users.length > 0) {
            var allowed = document.createElement('div');
            allowed.className = 'text-muted small mb-1';
            allowed.textContent = 'Allowed: ' + data.smtp_allow_users.join(', ');
            el.appendChild(allowed);
        }
        if (data.port_flood && data.port_flood.length > 0) {
            for (var i = 0; i < data.port_flood.length; i++) {
                var pf = data.port_flood[i];
                var pfRow = document.createElement('div');
                pfRow.className = 'small text-muted';
                pfRow.textContent = 'Port ' + pf.port + ': ' + pf.hits + ' / ' + pf.seconds + 's';
                el.appendChild(pfRow);
            }
        }
        var bcRow = document.createElement('div');
        bcRow.className = 'd-flex align-items-center';
        var bl = document.createElement('span');
        bl.className = 'text-muted small';
        bl.textContent = 'Mail-related blocks';
        var bv = document.createElement('span');
        bv.className = 'ms-auto fw-bold';
        bv.id = 'smtp-blocked-count';
        bv.textContent = '-';
        bcRow.appendChild(bl); bcRow.appendChild(bv);
        el.appendChild(bcRow);
        loadBlockedIPCount();
    }

    function loadBlockedIPCount() {
        CSM.get('/api/v1/blocked-ips', { silent: true })
            .then(function(data) {
                var ips = data.ips || data || [];
                var count = 0;
                for (var i = 0; i < ips.length; i++) {
                    var reason = (ips[i].reason || '').toLowerCase();
                    for (var k = 0; k < EMAIL_BLOCKED_KEYWORDS.length; k++) {
                        if (reason.indexOf(EMAIL_BLOCKED_KEYWORDS[k]) >= 0) { count++; break; }
                    }
                }
                var el = document.getElementById('smtp-blocked-count');
                if (el) el.textContent = count;
            })
            .catch(function() { /* non-fatal */ });
    }

    // ---------- Top senders (Senders tab) ----------

    function renderTopSenders(senders) {
        var el = document.getElementById('top-senders');
        if (!el) return;
        // Suppress count=1 noise unless every sender has only 1 hit (plan rule).
        var meaningful = senders.filter(function(s) { return s.count > 1; });
        if (meaningful.length > 0) senders = meaningful;
        if (!senders || senders.length === 0) {
            el.replaceChildren();
            var empty = document.createElement('div');
            empty.className = 'text-muted text-center py-3';
            empty.textContent = 'No notable outbound activity';
            el.appendChild(empty);
            return;
        }
        var maxCount = senders[0].count || 1;
        var html = '<div class="list-group list-group-flush">';
        for (var i = 0; i < senders.length; i++) {
            var s = senders[i];
            var pct = Math.round(s.count / maxCount * 100);
            var countClass = s.count >= 100 ? 'text-danger fw-bold' : 'text-muted';
            html += '<div class="list-group-item feed-item" data-sender-domain="' + CSM.attr(s.domain) + '">';
            html += '<div class="d-flex align-items-center mb-1">';
            html += '<span class="font-monospace small">' + CSM.esc(s.domain) + '</span>';
            html += '<span class="ms-auto small ' + countClass + '">' + s.count + '</span></div>';
            html += '<div class="progress progress-sm"><div class="progress-bar bg-primary csm-progress-zero" role="progressbar" aria-valuemin="0" aria-valuemax="100" data-csm-progress="' + CSM.attr(pct) + '"></div></div>';
            html += '</div>';
        }
        html += '</div>';
        el.innerHTML = html;
        CSM.applyProgressBars(el);
        var items = el.querySelectorAll('[data-sender-domain]');
        for (var j = 0; j < items.length; j++) {
            CSM.makeClickable(items[j]);
            items[j].addEventListener('click', function() {
                var domain = this.getAttribute('data-sender-domain');
                var sb = document.getElementById('email-search');
                if (sb) {
                    sb.value = domain;
                    sb.dispatchEvent(new Event('input'));
                    activateTab('findings');
                }
            });
        }
    }

    // ---------- AV status (right column dots) ----------

    function loadAVStatus() {
        CSM.get('/api/v1/email/av/status', { silent: true })
            .then(function(data) {
                _strip.av = data;
                refreshStatusStrip();
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
            })
            .catch(function() { /* non-fatal */ });
    }

    // ---------- Action groups (first viewport, left) ----------

    function kindLabel(kind) {
        switch (kind) {
            case 'compromised_account': return 'Compromised';
            case 'spam_outbreak':       return 'Spam outbreak';
            case 'auth_failure':        return 'Auth failures';
            case 'queue_alert':         return 'Queue alert';
            case 'malware':             return 'Malware';
        }
        return kind;
    }

    function ageLabel(iso) {
        if (!iso) return '';
        if (CSM.timeAgo) return CSM.timeAgo(iso);
        return iso;
    }

    function loadActionGroups() {
        var qs = emailDateQuery('limit=50');
        CSM.get('/api/v1/email/groups?' + qs)
            .then(function(data) {
                renderActionGroups(data.groups || []);
            })
            .catch(function() {
                var el = document.getElementById('email-action-groups');
                if (el) {
                    el.replaceChildren();
                    el.appendChild(buildEmpty('alert-circle', 'Could not load action groups', 'Retry from the refresh button.'));
                }
            });
    }

    function buildEmpty(icon, title, reason) {
        var wrap = document.createElement('div');
        wrap.className = 'csm-empty';
        var i = document.createElement('div');
        i.className = 'csm-empty__icon';
        var ie = document.createElement('i');
        ie.className = 'ti ti-' + icon;
        i.appendChild(ie);
        wrap.appendChild(i);
        if (title) {
            var t = document.createElement('div');
            t.className = 'csm-empty__title';
            t.textContent = title;
            wrap.appendChild(t);
        }
        if (reason) {
            var r = document.createElement('div');
            r.className = 'csm-empty__reason';
            r.textContent = reason;
            wrap.appendChild(r);
        }
        return wrap;
    }

    function renderActionGroups(groups) {
        var el = document.getElementById('email-action-groups');
        if (!el) return;
        var counts = { compromised: 0, spam: 0, auth: 0, queue: 0, malware: 0 };
        for (var i = 0; i < groups.length; i++) {
            switch (groups[i].kind) {
                case 'compromised_account': counts.compromised++; break;
                case 'spam_outbreak':       counts.spam++; break;
                case 'auth_failure':        counts.auth++; break;
                case 'queue_alert':         counts.queue++; break;
                case 'malware':             counts.malware++; break;
            }
        }
        _strip.groups = counts;
        refreshStatusStrip();

        var countEl = document.getElementById('email-groups-count');
        if (countEl) countEl.textContent = groups.length === 0 ? '' : groups.length + ' groups';

        el.replaceChildren();
        if (groups.length === 0) {
            el.appendChild(buildEmpty('circle-check', 'Nothing to action', 'No grouped email signals in the selected window.'));
            return;
        }

        for (var k = 0; k < groups.length; k++) {
            var g = groups[k];
            var statusHTML = '<span class="badge bg-secondary-lt">' + CSM.esc(kindLabel(g.kind)) + '</span>';
            var item = CSM.summaryItem({
                severity: g.severity,
                title: g.title,
                meta: g.summary,
                count: g.count,
                age: ageLabel(g.last_seen),
                statusHTML: statusHTML,
                onClick: (function(group) {
                    return function() { openGroupDetail(group); };
                })(g),
            });
            el.appendChild(item);
        }
    }

    function openGroupDetail(g) {
        var bodyHTML = '';
        bodyHTML += '<dl class="row mb-2"><dt class="col-4 text-muted">Kind</dt><dd class="col-8">' + CSM.esc(kindLabel(g.kind)) + '</dd>';
        bodyHTML += '<dt class="col-4 text-muted">Subject</dt><dd class="col-8">' + CSM.esc(g.subject) + '</dd>';
        bodyHTML += '<dt class="col-4 text-muted">Hits</dt><dd class="col-8">' + g.count + '</dd>';
        bodyHTML += '<dt class="col-4 text-muted">First seen</dt><dd class="col-8">' + CSM.fmtDate(g.first_seen) + '</dd>';
        bodyHTML += '<dt class="col-4 text-muted">Last seen</dt><dd class="col-8">' + CSM.fmtDate(g.last_seen) + '</dd></dl>';

        if (g.top_ips && g.top_ips.length > 0) {
            bodyHTML += '<div class="mb-2"><div class="subheader">Top source IPs</div><div class="font-monospace small">';
            for (var i = 0; i < g.top_ips.length; i++) {
                bodyHTML += '<div>' + CSM.esc(g.top_ips[i]) + '</div>';
            }
            bodyHTML += '</div></div>';
        }
        if (g.domains && g.domains.length > 0) {
            bodyHTML += '<div class="mb-2"><div class="subheader">Domains</div><div class="font-monospace small">' + g.domains.map(CSM.esc).join(', ') + '</div></div>';
        }
        if (g.message_ids && g.message_ids.length > 0) {
            bodyHTML += '<div class="mb-2"><div class="subheader">Message IDs</div><div class="font-monospace small">' + g.message_ids.map(CSM.esc).join(', ') + '</div></div>';
        }
        if (g.sample_findings && g.sample_findings.length > 0) {
            bodyHTML += '<div class="mb-2"><div class="subheader">Sample findings</div>';
            for (var s = 0; s < g.sample_findings.length; s++) {
                var f = g.sample_findings[s];
                bodyHTML += '<div class="mb-2 border-start border-2 ps-2 small">';
                bodyHTML += '<div>' + CSM.severityBadge(f.severity) + ' <code>' + CSM.esc(f.check) + '</code></div>';
                bodyHTML += '<div class="text-muted">' + CSM.fmtDate(f.timestamp) + '</div>';
                bodyHTML += '<div>' + CSM.esc(f.message || '') + '</div>';
                bodyHTML += '</div>';
            }
            bodyHTML += '</div>';
        }

        CSM.detailPanel.open({
            title: 'Email group: ' + g.title,
            bodyHTML: bodyHTML,
        });
    }

    // ---------- Auth failures tab (kind=auth_failure) ----------

    function loadAuthGroups() {
        if (authGroupsLoaded) return;
        authGroupsLoaded = true;
        CSM.get('/api/v1/email/groups?' + emailDateQuery('kind=auth_failure&limit=200'))
            .then(function(data) {
                var el = document.getElementById('email-auth-groups');
                if (!el) return;
                el.replaceChildren();
                var groups = data.groups || [];
                if (groups.length === 0) {
                    el.appendChild(buildEmpty('lock-check', 'No auth-failure clusters', 'No mailbox or IP exceeded the auth-failure threshold in this window.'));
                    return;
                }
                for (var i = 0; i < groups.length; i++) {
                    var g = groups[i];
                    var item = CSM.summaryItem({
                        severity: g.severity,
                        title: g.title,
                        meta: g.summary,
                        count: g.count,
                        age: ageLabel(g.last_seen),
                        onClick: (function(group) { return function() { openGroupDetail(group); }; })(g),
                    });
                    el.appendChild(item);
                }
            })
            .catch(function() {
                var el = document.getElementById('email-auth-groups');
                if (!el) return;
                el.replaceChildren();
                el.appendChild(buildEmpty('alert-circle', 'Could not load clusters', 'Retry from the refresh button.'));
                authGroupsLoaded = false;
            });
    }

    // ---------- Findings tab (table) ----------

    function loadFindings() {
        var from = (document.getElementById('filter-from') || {}).value || '';
        var to = (document.getElementById('filter-to') || {}).value || '';
        var sev = (document.getElementById('filter-severity') || {}).value || '';
        var check = (document.getElementById('filter-check') || {}).value || '';
        var params = 'checks=' + encodeURIComponent(check || EMAIL_CHECKS) + '&limit=' + EMAIL_FINDINGS_LIMIT;
        if (from) params += '&from=' + encodeURIComponent(from);
        if (to)   params += '&to=' + encodeURIComponent(to);
        if (sev)  params += '&severity=' + encodeURIComponent(sev);
        CSM.get('/api/v1/history?' + params)
            .then(function(data) {
                var findings = data.findings || [];
                renderFindingsTable(findings);
                var label = document.getElementById('email-total-label');
                if (label) {
                    var totalAll = data.total != null ? data.total : findings.length;
                    label.textContent = findings.length + ' / ' + totalAll;
                }
            })
            .catch(function() {
                var tbody = document.getElementById('email-tbody');
                if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="text-center text-danger py-4">Failed to load findings</td></tr>';
            });
    }

    function extractAccount(msg, details) {
        var m = (msg || '').match(/for (\S+@\S+)/);
        if (m) return m[1];
        m = (msg || '').match(/Account (\S+@\S+)/);
        if (m) return m[1];
        m = (msg || '').match(/account (\S+@\S+)/);
        if (m) return m[1];
        if (details) {
            m = details.match(/Sender (\S+@\S+)/);
            if (m) return m[1];
            m = details.match(/set_id=(\S+)/);
            if (m) return m[1].replace(/[)]/g, '');
        }
        m = (msg || '').match(/Domain (\S+)/);
        if (m) return m[1];
        return '';
    }

    function extractIP(msg, details) {
        var m = (msg || '').match(/from (\d+\.\d+\.\d+\.\d+)/);
        if (m) return m[1];
        if (details) {
            m = details.match(/\[(\d+\.\d+\.\d+\.\d+)\]/);
            if (m) return m[1];
        }
        return '';
    }

    function renderFindingsTable(findings) {
        var tbody = document.getElementById('email-tbody');
        if (!tbody) return;

        _emailExportData = findings.map(function(f) {
            return {
                check: f.check,
                severity: f.severity === 2 ? 'critical' : f.severity === 1 ? 'high' : 'warning',
                message: f.message,
                account: extractAccount(f.message, f.details),
                timestamp: f.timestamp || ''
            };
        });

        if (findings.length === 0) {
            tbody.innerHTML = CSM.emptyState('No email findings in this period', 6);
            emailTable = null;
            return;
        }

        var html = '';
        for (var i = 0; i < findings.length; i++) {
            var f = findings[i];
            var cls = CSM.severityClass(f.severity);
            var account = extractAccount(f.message, f.details);
            var ip = extractIP(f.message, f.details);
            var checkLabel = f.check.replace(/_/g, ' ').replace(/realtime$/, '').replace(/^email /, '');
            html += '<tr data-sev="' + cls + '">';
            html += '<td>' + CSM.severityBadge(f.severity) + '</td>';
            html += '<td><span class="small">' + CSM.esc(checkLabel) + '</span></td>';
            html += '<td>' + CSM.esc(account || '') + '</td>';
            html += '<td><code>' + CSM.esc(ip || '') + '</code></td>';
            html += '<td class="text-wrap csm-tw-400">' + CSM.esc(f.message || '') + '</td>';
            html += '<td data-timestamp="' + CSM.attr(f.timestamp || '') + '">' + CSM.fmtDate(f.timestamp) + '</td>';
            html += '</tr>';
            if (f.details) {
                html += '<tr class="details-row"><td colspan="6"><div class="small text-muted csm-detail">' + CSM.esc(f.details) + '</div></td></tr>';
            }
        }
        tbody.innerHTML = html;

        emailTable = new CSM.Table({
            tableId: 'email-table',
            perPage: 25,
            searchId: 'email-search',
            sortable: true,
            detailRows: true,
            mobileRowCard: true,
            stateKey: 'csm-email-table',
            countTargetId: 'email-total-label',
            emptyState: {
                icon: 'mail-search',
                title: 'No findings match',
                reason: 'Try clearing the search or filter selections.'
            }
        });
        if (CSM.initTimeAgo) CSM.initTimeAgo();
    }

    // ---------- Quarantine tab ----------

    function loadQuarantine() {
        quarantineLoaded = true;
        CSM.get('/api/v1/email/quarantine')
            .then(function(data) {
                var container = document.getElementById('quarantine-table');
                if (!container) return;
                if (!data || data.length === 0) {
                    container.innerHTML = '<p class="text-muted">No quarantined messages.</p>';
                    return;
                }
                var html = '<div class="table-responsive"><table class="table table-vcenter card-table table-sm csm-table-rowcard">';
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
                    var msgID = CSM.attr(msg.message_id);
                    html += '<tr>';
                    html += '<td data-label="Time">' + time + '</td>';
                    html += '<td data-label="Dir">' + dir + '</td>';
                    html += '<td data-label="From">' + CSM.esc(msg.from) + '</td>';
                    html += '<td data-label="To">' + CSM.esc(to) + '</td>';
                    html += '<td data-label="Subject">' + CSM.esc(msg.subject) + '</td>';
                    html += '<td data-label="Threat"><code>' + CSM.esc(threats.join(', ')) + '</code></td>';
                    html += '<td data-label="Actions">';
                    html += '<button class="btn btn-sm btn-warning" data-email-release="' + msgID + '">Release</button> ';
                    html += '<button class="btn btn-sm btn-danger" data-email-delete="' + msgID + '">Delete</button>';
                    html += '</td>';
                    html += '</tr>';
                }
                html += '</tbody></table></div>';
                container.innerHTML = html;
            })
            .catch(function() {
                quarantineLoaded = false;
                var container = document.getElementById('quarantine-table');
                if (container) container.innerHTML = '<p class="text-danger">Failed to load quarantine.</p>';
            });
    }

    function releaseMessage(msgID) {
        CSM.confirm('Release this message back to the mail queue? Only do this for confirmed false positives.').then(function() {
            CSM.post('/api/v1/email/quarantine/' + encodeURIComponent(msgID) + '/release', {})
                .then(function() { loadQuarantine(); loadAVStatus(); })
                .catch(function(err) { CSM.toast('Release failed: ' + (err.message || ''), 'error'); });
        }).catch(function() { /* cancelled */ });
    }

    function deleteMessage(msgID) {
        CSM.confirm('Permanently delete this quarantined message?').then(function() {
            CSM.delete('/api/v1/email/quarantine/' + encodeURIComponent(msgID))
                .then(function() { loadQuarantine(); loadAVStatus(); })
                .catch(function(err) { CSM.toast('Delete failed: ' + (err.message || ''), 'error'); });
        }).catch(function() { /* cancelled */ });
    }

    // ---------- Tab activation ----------

    function activateTab(name) {
        var btn = document.getElementById('email-tab-' + name);
        if (btn && window.bootstrap && window.bootstrap.Tab) {
            window.bootstrap.Tab.getOrCreateInstance(btn).show();
        }
    }

    function activeEmailTab() {
        var btn = document.querySelector('[id^="email-tab-"].active');
        if (!btn || !btn.id) return 'findings';
        return btn.id.replace('email-tab-', '');
    }

    function loadActiveEmailTab(force) {
        var id = activeEmailTab();
        if (id === 'auth') {
            if (force) authGroupsLoaded = false;
            loadAuthGroups();
        } else if (id === 'queue') {
            if (_strip.stats) renderProtectionQueue(_strip.stats, 'queue-health');
        } else if (id === 'quarantine') {
            if (force) quarantineLoaded = false;
            if (!quarantineLoaded) loadQuarantine();
        } else if (id === 'senders') {
            if (_pendingSenders) {
                renderTopSenders(_pendingSenders);
                _pendingSenders = null;
            } else if (force) {
                loadEmailStats();
            }
        }
    }

    var tabButtons = document.querySelectorAll('[data-bs-toggle="tab"]');
    for (var t = 0; t < tabButtons.length; t++) {
        tabButtons[t].addEventListener('shown.bs.tab', function(ev) {
            var id = ev.target.id.replace('email-tab-', '');
            CSM.urlState.set({ tab: id === 'findings' ? '' : id });
            if (id === 'auth')        loadAuthGroups();
            else if (id === 'queue')  { if (_strip.stats) renderProtectionQueue(_strip.stats, 'queue-health'); }
            else if (id === 'quarantine' && !quarantineLoaded) loadQuarantine();
            else if (id === 'senders') {
                if (_pendingSenders) {
                    renderTopSenders(_pendingSenders);
                    _pendingSenders = null;
                } else {
                    loadEmailStats();
                }
            }
        });
    }

    // ---------- Filter handlers (auto-apply on change) ----------

    function syncEmailURL() {
        var fromVal = (document.getElementById('filter-from') || {}).value || '';
        var toVal = (document.getElementById('filter-to') || {}).value || '';
        var sevVal = (document.getElementById('filter-severity') || {}).value || '';
        var checkVal = (document.getElementById('filter-check') || {}).value || '';
        var searchVal = (document.getElementById('email-search') || {}).value || '';
        var todayStr = localDateInputValue();
        CSM.urlState.set({
            from: fromVal !== todayStr ? fromVal : '',
            to: toVal !== todayStr ? toVal : '',
            severity: sevVal,
            check: checkVal,
            search: searchVal
        });
    }

    ['filter-from', 'filter-to', 'filter-severity', 'filter-check'].forEach(function(id) {
        var el = document.getElementById(id);
        if (!el) return;
        el.addEventListener('change', function() {
            syncEmailURL();
            loadFindings();
            loadActionGroups();
            authGroupsLoaded = false; // re-fetch on next tab activation
            if (activeEmailTab() === 'auth') loadAuthGroups();
        });
    });

    // ---------- Quarantine action delegation ----------

    var quarantineTable = document.getElementById('quarantine-table');
    if (quarantineTable) {
        quarantineTable.addEventListener('click', function(e) {
            var releaseBtn = e.target.closest('[data-email-release]');
            if (releaseBtn) { releaseMessage(releaseBtn.getAttribute('data-email-release')); return; }
            var deleteBtn = e.target.closest('[data-email-delete]');
            if (deleteBtn) { deleteMessage(deleteBtn.getAttribute('data-email-delete')); }
        });
    }

    // ---------- Refresh button ----------

    var refreshBtn = document.getElementById('email-refresh');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            loadEmailStats();
            loadAVStatus();
            loadActionGroups();
            loadFindings();
            authGroupsLoaded = false;
            loadActiveEmailTab(true);
        });
    }

    // ---------- Export ----------

    var _emailExportCols = [
        {key:'check', label:'Check'},
        {key:'severity', label:'Severity'},
        {key:'message', label:'Message'},
        {key:'account', label:'Account'},
        {key:'timestamp', label:'Time'}
    ];
    document.querySelectorAll('[data-export]').forEach(function(el) {
        el.addEventListener('click', function(e) {
            e.preventDefault();
            CSM.exportTable(_emailExportData, _emailExportCols, this.getAttribute('data-export'), 'csm-email-findings');
        });
    });

    // ---------- Initialize ----------

    if (initialTab) activateTab(initialTab);
    loadEmailStats();
    loadAVStatus();
    loadActionGroups();
    loadFindings();
    loadActiveEmailTab(false);

    // Polling: refresh stats / groups / findings every 30s when tab is visible.
    var _emailIntervals = [];
    function _startEmailPolling() {
        _emailIntervals.push(setInterval(function() {
            try { loadEmailStats(); } catch(e) {}
        }, 30000));
        _emailIntervals.push(setInterval(function() {
            try { loadAVStatus(); } catch(e) {}
        }, 30000));
        _emailIntervals.push(setInterval(function() {
            try { loadActionGroups(); } catch(e) {}
        }, 60000));
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

    var subtitle = document.getElementById('email-subtitle');
    if (subtitle) subtitle.textContent = 'Grouped action queue, mail protection state, and per-tab raw findings.';
})();
