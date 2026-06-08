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
    var forwardersLoaded = false;
    var _forwarders = [];
    var deliverabilityLoaded = false;
    var outboundAbuseLoaded = false;
    var queueCompositionLoaded = false;

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

    var _emailQuarBulk = null;
    var _emailQuarTable = null;
    var _emailQuarURLUnbind = null;
    var _emailQuarDateListenersBound = false;

    function _emailQuarLocalDateMillis(value, endExclusive) {
        if (!value) return null;
        var parts = String(value).match(/^(\d{4})-(\d{2})-(\d{2})$/);
        if (!parts) return null;
        var year = Number(parts[1]);
        var month = Number(parts[2]) - 1;
        var day = Number(parts[3]);
        var d = new Date(year, month, day);
        if (isNaN(d.getTime())) return null;
        if (d.getFullYear() !== year || d.getMonth() !== month || d.getDate() !== day) return null;
        if (endExclusive) d.setDate(d.getDate() + 1);
        return d.getTime();
    }

    function _emailQuarURLInputs(fromEl, toEl) {
        return {
            email_quar_q: document.getElementById('email-quar-search'),
            email_quar_dir: document.getElementById('email-quar-dir'),
            email_quar_from: fromEl,
            email_quar_to: toEl
        };
    }

    function _bindEmailQuarURLState(fromEl, toEl) {
        if (_emailQuarURLUnbind) _emailQuarURLUnbind();
        _emailQuarURLUnbind = CSM.urlState.bind({ inputs: _emailQuarURLInputs(fromEl, toEl) });
    }

    function _resetEmailQuarTable() {
        if (_emailQuarTable) {
            if (_emailQuarTable._searchDebounce && _emailQuarTable._searchDebounce.cancel) _emailQuarTable._searchDebounce.cancel();
            _emailQuarTable.controlsEl = null;
            _emailQuarTable.countTargetEl = null;
            _emailQuarTable.allRows = [];
            _emailQuarTable.filteredRows = [];
            _emailQuarTable.tbody = null;
            _emailQuarTable.table = null;
            _emailQuarTable.rowFilter = null;
            _emailQuarTable = null;
        }
        var controls = document.getElementById('email-quar-table-controls');
        if (controls) controls.remove();
    }

    function _emailQuarUpdateBulk() {
        var releaseBtn = document.getElementById('email-quar-bulk-release');
        var deleteBtn = document.getElementById('email-quar-bulk-delete');
        var selectAll = document.getElementById('email-quar-select-all');
        if (!_emailQuarBulk && !selectAll && !document.querySelector('.email-quar-cb')) {
            [releaseBtn, deleteBtn].forEach(function(btn) {
                if (!btn) return;
                btn.disabled = true;
                btn.classList.add('d-none');
            });
            return;
        }
        if (_emailQuarBulk) { _emailQuarBulk.refresh(); return; }
        if (!releaseBtn && !deleteBtn) return;
        _emailQuarBulk = CSM.bulk({
            rowCheckboxSelector: '.email-quar-cb',
            selectAllEl: selectAll,
            selectAllSelector: '#email-quar-select-all',
            valueAttr: 'data-id',
            buttons: [
                { el: releaseBtn, labelTemplate: 'Release {n} message(s)' },
                { el: deleteBtn,  labelTemplate: 'Delete {n} message(s)' }
            ]
        });
    }

    function _bindEmailQuarDateFilters(fromEl, toEl) {
        if (_emailQuarDateListenersBound) return;
        function onDate() {
            if (_emailQuarTable) {
                _emailQuarTable.currentPage = 1;
                _emailQuarTable.applyFilters();
            }
        }
        if (fromEl) fromEl.addEventListener('change', onDate);
        if (toEl) toEl.addEventListener('change', onDate);
        _emailQuarDateListenersBound = true;
    }

    function loadQuarantine() {
        quarantineLoaded = true;
        CSM.get('/api/v1/email/quarantine')
            .then(function(data) {
                var container = document.getElementById('quarantine-table');
                if (!container) return;
                var fromEl = document.getElementById('email-quar-from');
                var toEl = document.getElementById('email-quar-to');
                _resetEmailQuarTable();
                if (!data || data.length === 0) {
                    _bindEmailQuarURLState(fromEl, toEl);
                    container.innerHTML = '<p class="text-muted">No quarantined messages.</p>';
                    _emailQuarUpdateBulk();
                    return;
                }
                var html = '<div class="table-responsive"><table class="table table-vcenter card-table table-sm csm-table-rowcard" id="email-quar-table">';
                html += '<thead><tr><th><input type="checkbox" class="form-check-input" id="email-quar-select-all"></th><th>Time</th><th>Dir</th><th>From</th><th>To</th><th>Subject</th><th>Threat</th><th>Actions</th></tr></thead><tbody>';
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
                    // Stash search-relevant fields on the row so the
                    // shared search input matches against just these
                    // (instead of the whole DOM text including badges).
                    var searchBlob = String(msg.from || '') + ' ' + String(to || '') + ' ' + String(msg.subject || '');
                    html += '<tr data-direction="' + CSM.attr(msg.direction || '') + '" data-quar-timestamp="' + CSM.attr(msg.quarantined_at || '') + '" data-search="' + CSM.attr(searchBlob.toLowerCase()) + '">';
                    html += '<td><input type="checkbox" class="form-check-input email-quar-cb" data-id="' + msgID + '"></td>';
                    html += '<td data-label="Time" data-timestamp="' + CSM.attr(msg.quarantined_at || '') + '">' + CSM.esc(time) + '</td>';
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
                function _inRange(row) {
                    var raw = row.getAttribute('data-quar-timestamp') || '';
                    if (!raw) return true;
                    var ts = new Date(raw.replace(/^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})/, '$1T$2')).getTime();
                    if (isNaN(ts)) return true;
                    var from = fromEl ? _emailQuarLocalDateMillis(fromEl.value, false) : null;
                    var to = toEl ? _emailQuarLocalDateMillis(toEl.value, true) : null;
                    if (from !== null && ts < from) return false;
                    if (to !== null && ts >= to) return false;
                    return true;
                }
                _emailQuarTable = new CSM.Table({
                    tableId: 'email-quar-table',
                    perPage: 25,
                    searchId: 'email-quar-search',
                    searchAttr: 'data-search',
                    sortable: true,
                    stateKey: 'csm-email-quarantine',
                    mobileRowCard: true,
                    filters: [{ id: 'email-quar-dir', attr: 'data-direction' }],
                    rowFilter: _inRange
                });
                _bindEmailQuarDateFilters(fromEl, toEl);
                _bindEmailQuarURLState(fromEl, toEl);
                _emailQuarUpdateBulk();
            })
            .catch(function() {
                quarantineLoaded = false;
                var container = document.getElementById('quarantine-table');
                if (container) container.innerHTML = '<p class="text-danger">Failed to load quarantine.</p>';
            });
    }

    // Bulk release / delete wired through CSM.bulk's selectedValues.
    var _bulkReleaseBtn = document.getElementById('email-quar-bulk-release');
    if (_bulkReleaseBtn) {
        _bulkReleaseBtn.addEventListener('click', function() {
            if (!_emailQuarBulk) return;
            var ids = _emailQuarBulk.selectedValues();
            if (ids.length === 0) return;
            CSM.confirm('Release ' + ids.length + ' message(s) back to the mail queue?').then(function() {
                var succeeded = 0, failed = 0;
                var chain = Promise.resolve();
                ids.forEach(function(id) {
                    chain = chain.then(function() {
                        return CSM.post('/api/v1/email/quarantine/' + encodeURIComponent(id) + '/release', {})
                            .then(function() { succeeded++; })
                            .catch(function() { failed++; });
                    });
                });
                chain.then(function() {
                    CSM.toast('Released ' + succeeded + ' of ' + (succeeded + failed), failed > 0 ? 'warning' : 'success');
                    loadQuarantine();
                    loadAVStatus();
                });
            }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
        });
    }
    var _bulkDeleteBtn = document.getElementById('email-quar-bulk-delete');
    if (_bulkDeleteBtn) {
        _bulkDeleteBtn.addEventListener('click', function() {
            if (!_emailQuarBulk) return;
            var ids = _emailQuarBulk.selectedValues();
            if (ids.length === 0) return;
            CSM.confirm('Permanently delete ' + ids.length + ' quarantined message(s)?').then(function() {
                var succeeded = 0, failed = 0;
                var chain = Promise.resolve();
                ids.forEach(function(id) {
                    chain = chain.then(function() {
                        return CSM.delete('/api/v1/email/quarantine/' + encodeURIComponent(id))
                            .then(function() { succeeded++; })
                            .catch(function() { failed++; });
                    });
                });
                chain.then(function() {
                    CSM.toast('Deleted ' + succeeded + ' of ' + (succeeded + failed), failed > 0 ? 'warning' : 'success');
                    loadQuarantine();
                    loadAVStatus();
                });
            }).catch(function() { /* cancelled */ });
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

    // ---------- Forwarders tab (inventory table) ----------

    // Provider class -> badge colour. Free providers are the reputation-risk
    // case (forwarding spam to them tanks the outbound IP), so they read red.
    var FWD_PROVIDER_BADGE = Object.create(null);
    FWD_PROVIDER_BADGE.yahoo = 'bg-red';
    FWD_PROVIDER_BADGE.gmail = 'bg-red';
    FWD_PROVIDER_BADGE.outlook = 'bg-red';
    FWD_PROVIDER_BADGE.external = 'bg-yellow';
    FWD_PROVIDER_BADGE.local = 'bg-green';

    function providerBadge(provider) {
        provider = String(provider || '');
        var cls = Object.prototype.hasOwnProperty.call(FWD_PROVIDER_BADGE, provider)
            ? FWD_PROVIDER_BADGE[provider]
            : 'bg-secondary';
        return '<span class="badge ' + CSM.attr(cls) + ' me-1">' + CSM.esc(provider) + '</span>';
    }

    function loadForwarders() {
        if (forwardersLoaded) return;
        forwardersLoaded = true;
        CSM.get('/api/v1/email/forwarders')
            .then(function(data) {
                _forwarders = (data && data.forwarders) || [];
                renderForwarders();
            })
            .catch(function() {
                forwardersLoaded = false;
                var tb = document.getElementById('email-fwd-tbody');
                if (tb) tb.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4">Could not load forwarders. Retry from the refresh button.</td></tr>';
            });
    }

    var heldLoaded = false;

    function loadHeld() {
        if (heldLoaded) return;
        heldLoaded = true;
        CSM.get('/api/v1/email/held')
            .then(renderHeld)
            .catch(function() {
                heldLoaded = false;
                var tb = document.getElementById('email-held-tbody');
                if (tb) tb.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4">Could not load held forwards.</td></tr>';
            });
    }

    function renderHeld(msgs) {
        var tb = document.getElementById('email-held-tbody');
        if (!tb) return;
        msgs = Array.isArray(msgs) ? msgs : [];
        var c = document.getElementById('email-held-count');
        if (c) c.textContent = msgs.length ? '(' + msgs.length + ')' : '';
        if (msgs.length === 0) {
            tb.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4">Nothing held.</td></tr>';
            return;
        }
        var html = '';
        for (var i = 0; i < msgs.length; i++) {
            var m = msgs[i] || {};
            var reasons = '';
            var rs = Array.isArray(m.reasons) ? m.reasons : [];
            for (var j = 0; j < rs.length; j++) {
                reasons += '<span class="badge bg-red-lt me-1">' + CSM.esc(rs[j]) + '</span>';
            }
            html += '<tr>';
            html += '<td class="small text-muted">' + CSM.esc(ageLabel(m.held_at)) + '</td>';
            html += '<td class="font-monospace small">' + CSM.esc(m.forwarder) + '</td>';
            html += '<td class="font-monospace small">' + CSM.esc(m.recipient) + '</td>';
            html += '<td>' + (reasons || '<span class="text-muted">--</span>') + '</td>';
            html += '<td class="text-end">' +
                '<button type="button" class="btn btn-sm btn-ghost-secondary" data-held-release="' + CSM.attr(m.id) + '"><i class="ti ti-mail-forward"></i>&nbsp;Release</button> ' +
                '<button type="button" class="btn btn-sm btn-ghost-danger" data-held-delete="' + CSM.attr(m.id) + '" aria-label="Delete held forward"><i class="ti ti-trash"></i></button>' +
                '</td>';
            html += '</tr>';
        }
        tb.innerHTML = html;
    }

    function releaseHeld(id) {
        CSM.confirm('Release this held forward copy to its external recipient? Only do this for confirmed false positives.').then(function() {
            CSM.post('/api/v1/email/held/' + encodeURIComponent(id) + '/release', {})
                .then(function() { CSM.toast('Released held forward', 'success'); heldLoaded = false; loadHeld(); })
                .catch(function(err) { CSM.toast('Release failed: ' + (err.message || ''), 'error'); });
        }).catch(function() { /* cancelled */ });
    }

    function deleteHeld(id) {
        CSM.confirm('Permanently delete this held forward copy?').then(function() {
            CSM.delete('/api/v1/email/held/' + encodeURIComponent(id))
                .then(function() { CSM.toast('Deleted held forward', 'success'); heldLoaded = false; loadHeld(); })
                .catch(function(err) { CSM.toast('Delete failed: ' + (err.message || ''), 'error'); });
        }).catch(function() { /* cancelled */ });
    }

    var _heldBody = document.getElementById('email-held-tbody');
    if (_heldBody) {
        _heldBody.addEventListener('click', function(e) {
            var rel = e.target.closest('[data-held-release]');
            if (rel) { releaseHeld(rel.getAttribute('data-held-release')); return; }
            var del = e.target.closest('[data-held-delete]');
            if (del) { deleteHeld(del.getAttribute('data-held-delete')); }
        });
    }

    function forwarderMatchesFilter(f, mode) {
        if (mode === 'external') return f.has_external;
        if (mode === 'free') return f.has_free_provider;
        if (mode === 'forward_only') return f.forward_only;
        return true;
    }

    function forwarderMatchesSearch(f, q) {
        if (!q) return true;
        if (f.source.toLowerCase().indexOf(q) !== -1) return true;
        if (f.owner && f.owner.toLowerCase().indexOf(q) !== -1) return true;
        for (var i = 0; i < f.destinations.length; i++) {
            if (f.destinations[i].address.toLowerCase().indexOf(q) !== -1) return true;
        }
        return false;
    }

    function renderForwarders() {
        var tb = document.getElementById('email-fwd-tbody');
        if (!tb) return;
        var mode = (document.getElementById('email-fwd-filter') || {}).value || '';
        var q = ((document.getElementById('email-fwd-search') || {}).value || '').trim().toLowerCase();

        var rows = _forwarders.filter(function(f) {
            return forwarderMatchesFilter(f, mode) && forwarderMatchesSearch(f, q);
        });

        var countEl = document.getElementById('email-fwd-count');
        if (countEl) countEl.textContent = rows.length + ' of ' + _forwarders.length;

        if (rows.length === 0) {
            var msg = _forwarders.length === 0
                ? 'No forwarders found on this host.'
                : 'No forwarders match the current filter.';
            tb.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4">' + msg + '</td></tr>';
            return;
        }

        var html = '';
        for (var i = 0; i < rows.length; i++) {
            var f = rows[i];
            var dests = '';
            for (var d = 0; d < f.destinations.length; d++) {
                dests += '<div class="font-monospace small">' + CSM.esc(f.destinations[d].address) + '</div>';
            }
            var badges = '';
            for (var p = 0; p < f.providers.length; p++) {
                badges += providerBadge(f.providers[p]);
            }
            var copy = f.forward_only
                ? '<span class="badge bg-red-lt">Forward-only</span>'
                : '<span class="badge bg-green-lt">Keep local</span>';
            html += '<tr>';
            html += '<td class="font-monospace small">' + CSM.esc(f.source) + '</td>';
            html += '<td>' + (f.owner ? CSM.esc(f.owner) : '<span class="text-muted">--</span>') + '</td>';
            html += '<td>' + dests + '</td>';
            html += '<td>' + badges + '</td>';
            html += '<td>' + copy + '</td>';
            html += '</tr>';
        }
        tb.innerHTML = html;
    }

    // ---------- Deliverability tab (outbound deferral intel) ----------

    function deliverabilityArray(value) {
        return Array.isArray(value) ? value : [];
    }

    function formatIntegerString(digits) {
        return digits.replace(/^0+(?=\d)/, '').replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    }

    function formatDeferralCount(value) {
        if (value == null || (typeof value === 'string' && value.trim() === '')) return '0';
        if (typeof value === 'string') {
            var trimmed = value.trim();
            if (/^\d+$/.test(trimmed)) return formatIntegerString(trimmed);
            value = Number(trimmed);
        }
        if (typeof value !== 'number' || !isFinite(value) || value <= 0) return '0';
        return CSM.formatNumber(Math.floor(value));
    }

    function reasonBadges(reasons) {
        reasons = deliverabilityArray(reasons);
        if (!reasons || reasons.length === 0) return '<span class="text-muted">--</span>';
        var out = '';
        for (var i = 0; i < reasons.length; i++) {
            var r = reasons[i] || {};
            out += '<span class="badge bg-secondary-lt me-1">' + CSM.esc(r.code) + ' &times;' + CSM.esc(formatDeferralCount(r.count)) + '</span>';
        }
        return out;
    }

    function loadDeliverability() {
        if (deliverabilityLoaded) return;
        deliverabilityLoaded = true;
        CSM.get('/api/v1/email/deferrals')
            .then(function(data) { renderDeliverability(data || {}); })
            .catch(function() {
                deliverabilityLoaded = false;
                var msg = 'Could not load deferral activity. Retry from the refresh button.';
                setRowMessage('email-deliv-providers-body', 3, msg);
                setRowMessage('email-deliv-ips-body', 3, msg);
            });
    }

    function setRowMessage(tbodyID, cols, msg) {
        var tb = document.getElementById(tbodyID);
        if (tb) tb.innerHTML = '<tr><td colspan="' + cols + '" class="text-center text-muted py-4">' + msg + '</td></tr>';
    }

    function renderDeliverability(data) {
        data = data || {};
        var providers = deliverabilityArray(data.providers);
        var ips = deliverabilityArray(data.outbound_ips);
        var total = formatDeferralCount(data.deferrals);

        var summary = document.getElementById('email-deliv-summary');
        if (summary) {
            summary.textContent = total === '0'
                ? 'No outbound deferrals seen in the recent log window.'
                : total + ' outbound deferral(s) across ' + providers.length + ' provider(s) and ' + ips.length + ' sending IP(s).';
        }

        if (providers.length === 0) {
            setRowMessage('email-deliv-providers-body', 3, 'No providers are deferring mail from this server.');
        } else {
            var ph = '';
            for (var i = 0; i < providers.length; i++) {
                var p = providers[i] || {};
                ph += '<tr>';
                ph += '<td>' + providerBadge(p.provider) + '</td>';
                ph += '<td class="text-end">' + CSM.esc(formatDeferralCount(p.deferrals)) + '</td>';
                ph += '<td>' + reasonBadges(p.reasons) + '</td>';
                ph += '</tr>';
            }
            var pb = document.getElementById('email-deliv-providers-body');
            if (pb) pb.innerHTML = ph;
        }

        if (ips.length === 0) {
            setRowMessage('email-deliv-ips-body', 3, 'No sending IP has been deferred.');
        } else {
            var ih = '';
            for (var j = 0; j < ips.length; j++) {
                var ip = ips[j] || {};
                var by = '';
                var byList = deliverabilityArray(ip.providers);
                for (var k = 0; k < byList.length; k++) {
                    var item = byList[k] || {};
                    by += providerBadge(item.provider) + '<span class="text-muted small me-2">&times;' + CSM.esc(formatDeferralCount(item.count)) + '</span>';
                }
                ih += '<tr>';
                ih += '<td class="font-monospace small">' + CSM.esc(ip.ip) + '</td>';
                ih += '<td class="text-end">' + CSM.esc(formatDeferralCount(ip.deferrals)) + '</td>';
                ih += '<td>' + (by || '<span class="text-muted">--</span>') + '</td>';
                ih += '</tr>';
            }
            var ib = document.getElementById('email-deliv-ips-body');
            if (ib) ib.innerHTML = ih;
        }
    }

    // ---------- Outbound mail abuse (Outbound abuse tab) ----------

    function loadOutboundAbuse() {
        var body = document.getElementById('outbound-abuse-body');
        if (!body) return;
        CSM.get('/api/v1/email/relay-abuse?' + emailDateQuery('limit=20'))
            .then(function(resp) {
                outboundAbuseLoaded = true;
                renderOutboundAbuse(resp);
            })
            .catch(function() {
                body.innerHTML = '<div class="csm-empty"><div class="csm-empty__reason">Failed to load outbound mail abuse.</div></div>';
            });
    }

    function renderOutboundAbuse(resp) {
        var body = document.getElementById('outbound-abuse-body');
        var entries = (resp && resp.entries) || [];
        if (entries.length === 0) {
            body.innerHTML = '<div class="csm-empty"><div class="csm-empty__reason">No outbound mail abuse detected.</div></div>';
            return;
        }
        var html = '<div class="table-responsive"><table class="table table-vcenter card-table table-sm">';
        html += '<thead><tr><th>Severity</th><th>Type</th><th>Source IP</th><th>Account</th><th>Mails</th><th>Detected</th><th></th></tr></thead><tbody>';
        for (var i = 0; i < entries.length; i++) {
            var e = entries[i];
            var rid = 'oab-' + i;
            html += '<tr>';
            html += '<td>' + CSM.severityBadge(e.severity) + '</td>';
            html += '<td>' + CSM.esc(e.path_label) + '</td>';
            html += '<td>' + (e.source_ip ? '<code>' + CSM.esc(e.source_ip) + '</code>' : '<span class="text-muted">-</span>') + '</td>';
            html += '<td>' + CSM.esc(e.cp_user || '') + '</td>';
            html += '<td>' + CSM.esc(String(e.trigger_count)) + '</td>';
            html += '<td>' + (CSM.timeAgo ? CSM.timeAgo(e.detected_at) : CSM.esc(e.detected_at)) + '</td>';
            html += '<td class="text-end">';
            if (e.source_ip) {
                html += '<button class="btn btn-sm btn-outline-danger oab-block" data-ip="' + CSM.esc(e.source_ip) + '" data-reason="' + CSM.esc('PHP mail relay abuse: ' + e.path_label + ' (' + e.trigger_count + ' messages)') + '">Block 24h</button>';
            }
            if (e.sites && e.sites.length > 0) {
                html += ' <button class="btn btn-sm btn-link oab-toggle" data-target="' + rid + '">Sites (' + e.sites.length + ')</button>';
            }
            html += '</td></tr>';
            if (e.sites && e.sites.length > 0) {
                html += '<tr id="' + rid + '" class="d-none"><td colspan="7"><div class="table-responsive"><table class="table table-sm mb-0"><thead><tr><th>Site</th><th>Script</th><th>Hits</th><th>Last seen</th><th>Sample subject</th></tr></thead><tbody>';
                for (var j = 0; j < e.sites.length; j++) {
                    var st = e.sites[j];
                    html += '<tr><td>' + CSM.esc(st.site) + '</td><td><code>' + CSM.esc(st.script) + '</code></td><td>' + CSM.esc(String(st.hits)) + '</td><td>' + (CSM.timeAgo ? CSM.timeAgo(st.last_seen) : CSM.esc(st.last_seen)) + '</td><td class="text-wrap csm-tw-400">' + CSM.esc(st.sample_subject || '') + '</td></tr>';
                }
                html += '</tbody></table></div></td></tr>';
            }
        }
        html += '</tbody></table></div>';
        body.innerHTML = html;

        body.querySelectorAll('.oab-toggle').forEach(function(btn) {
            btn.addEventListener('click', function() {
                var row = document.getElementById(btn.getAttribute('data-target'));
                if (row) row.classList.toggle('d-none');
            });
        });
        body.querySelectorAll('.oab-block').forEach(function(btn) {
            btn.addEventListener('click', function() {
                btn.disabled = true;
                CSM.post('/api/v1/block-ip', { ip: btn.getAttribute('data-ip'), reason: btn.getAttribute('data-reason'), duration: '24h' })
                    .then(function() { btn.textContent = 'Blocked'; })
                    .catch(function() { btn.disabled = false; btn.textContent = 'Block failed'; });
            });
        });
    }

    // ---------- Queue composition (Queue tab) ----------

    function loadQueueComposition() {
        if (queueCompositionLoaded) return;
        queueCompositionLoaded = true;
        CSM.get('/api/v1/email/queue-composition')
            .then(function(data) { renderQueueComposition(data || {}); })
            .catch(function() {
                queueCompositionLoaded = false;
                var el = document.getElementById('queue-composition');
                if (el) el.innerHTML = '<div class="text-muted small">Could not load queue composition. Retry from the refresh button.</div>';
            });
    }

    function queueCount(value) {
        var n = Number(value);
        if (!isFinite(n) || n < 0) return 0;
        return Math.floor(n);
    }

    function renderQueueComposition(data) {
        var el = document.getElementById('queue-composition');
        if (!el) return;
        var total = queueCount(data.total);
        if (total === 0) {
            el.innerHTML = '<div class="text-muted small">The mail queue is empty.</div>';
            return;
        }
        var bounce = queueCount(data.bounce);
        var real = queueCount(data.real);
        var frozen = queueCount(data.frozen);
        var flushable = queueCount(data.flushable_backscatter);
        var bouncePct = Math.round(bounce / total * 100);

        var html = '<div class="row g-2 mb-3">';
        html += metricCol('Total', CSM.formatNumber(total), '');
        html += metricCol('Real mail', CSM.formatNumber(real), 'text-success');
        html += metricCol('Backscatter', CSM.formatNumber(bounce) + ' (' + bouncePct + '%)', bounce > 0 ? 'text-danger' : 'text-muted');
        html += metricCol('Frozen', CSM.formatNumber(frozen), frozen > 0 ? 'text-warning' : 'text-muted');
        html += metricCol('Oldest', data.oldest_age || '--', '');
        html += '</div>';

        // Flush is offered only for frozen null-sender messages: undeliverable
        // backscatter that cannot belong to a real sender or a live retry.
        if (flushable > 0) {
            html += '<button type="button" class="btn btn-sm btn-outline-danger mb-3" id="flush-backscatter-btn">' +
                '<i class="ti ti-trash"></i>&nbsp;Flush ' + CSM.formatNumber(flushable) + ' frozen backscatter message(s)</button>';
        }

        var recips = deliverabilityArray(data.top_recipients);
        if (recips.length > 0) {
            html += '<div class="subheader mb-1 small">Top stuck recipients</div>';
            html += '<div class="list-group list-group-flush">';
            for (var i = 0; i < recips.length; i++) {
                var rc = recips[i] || {};
                html += '<div class="list-group-item py-1 px-0 d-flex">';
                html += '<span class="font-monospace small">' + CSM.esc(rc.address) + '</span>';
                html += '<span class="ms-auto small text-muted">' + CSM.formatNumber(queueCount(rc.count)) + '</span>';
                html += '</div>';
            }
            html += '</div>';
        }
        el.innerHTML = html;
    }

    function metricCol(label, value, cls) {
        return '<div class="col-auto"><div class="small text-muted">' + CSM.esc(label) + '</div>' +
            '<div class="h3 mb-0 ' + CSM.attr(cls || '') + '">' + CSM.esc(String(value)) + '</div></div>';
    }

    function flushBackscatter() {
        CSM.confirm('Remove all frozen null-sender bounce messages from the mail queue? This deletes undeliverable backscatter only -- real mail and live retries are not touched.').then(function() {
            CSM.post('/api/v1/email/queue/flush-backscatter', {})
                .then(function(res) {
                    CSM.toast('Removed ' + queueCount(res && res.removed) + ' backscatter message(s)', 'success');
                    queueCompositionLoaded = false;
                    loadQueueComposition();
                    loadEmailStats(); // refresh the queue-size chip in the status strip
                })
                .catch(function(err) { CSM.toast('Flush failed: ' + (err.message || ''), 'error'); });
        }).catch(function() { /* cancelled */ });
    }

    var queueCompEl = document.getElementById('queue-composition');
    if (queueCompEl) {
        queueCompEl.addEventListener('click', function(e) {
            if (e.target.closest('#flush-backscatter-btn')) flushBackscatter();
        });
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
            if (force) queueCompositionLoaded = false;
            loadQueueComposition();
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
        } else if (id === 'forwarders') {
            if (force) { forwardersLoaded = false; heldLoaded = false; }
            loadForwarders();
            loadHeld();
        } else if (id === 'deliverability') {
            if (force) deliverabilityLoaded = false;
            loadDeliverability();
        } else if (id === 'outbound-abuse') {
            if (force) outboundAbuseLoaded = false;
            loadOutboundAbuse();
        }
    }

    var tabButtons = document.querySelectorAll('[data-bs-toggle="tab"]');
    for (var t = 0; t < tabButtons.length; t++) {
        tabButtons[t].addEventListener('shown.bs.tab', function(ev) {
            var id = ev.target.id.replace('email-tab-', '');
            CSM.urlState.set({ tab: id === 'findings' ? '' : id });
            if (id === 'auth')        loadAuthGroups();
            else if (id === 'queue')  { if (_strip.stats) renderProtectionQueue(_strip.stats, 'queue-health'); loadQueueComposition(); }
            else if (id === 'quarantine' && !quarantineLoaded) loadQuarantine();
            else if (id === 'senders') {
                if (_pendingSenders) {
                    renderTopSenders(_pendingSenders);
                    _pendingSenders = null;
                } else {
                    loadEmailStats();
                }
            }
            else if (id === 'forwarders') { loadForwarders(); loadHeld(); }
            else if (id === 'deliverability') loadDeliverability();
            else if (id === 'outbound-abuse') { if (!outboundAbuseLoaded) loadOutboundAbuse(); }
        });
    }

    // ---------- Forwarders filter/search (client-side, no refetch) ----------

    ['email-fwd-filter', 'email-fwd-search'].forEach(function(id) {
        var el = document.getElementById(id);
        if (!el) return;
        var evt = id === 'email-fwd-search' ? 'input' : 'change';
        el.addEventListener(evt, renderForwarders);
    });

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
            forwardersLoaded = false;
            heldLoaded = false;
            deliverabilityLoaded = false;
            outboundAbuseLoaded = false;
            queueCompositionLoaded = false;
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
    function _stopEmailIntervals() {
        for (var i = 0; i < _emailIntervals.length; i++) _emailIntervals[i].stop();
        _emailIntervals = [];
    }

    function _startEmailPolling() {
        _emailIntervals.push(CSM.refresh.interval(function() {
            try { loadEmailStats(); } catch(e) {}
        }, 30000));
        _emailIntervals.push(CSM.refresh.interval(function() {
            try { loadAVStatus(); } catch(e) {}
        }, 30000));
        _emailIntervals.push(CSM.refresh.interval(function() {
            try { loadActionGroups(); } catch(e) {}
        }, 60000));
    }
    _startEmailPolling();

    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            _stopEmailIntervals();
        } else {
            _startEmailPolling();
        }
    });
    window.addEventListener('beforeunload', function() {
        _stopEmailIntervals();
    });

    var subtitle = document.getElementById('email-subtitle');
    if (subtitle) subtitle.textContent = 'Grouped action queue, mail protection state, and per-tab raw findings.';
})();
