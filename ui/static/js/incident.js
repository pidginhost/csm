// CSM incidents
(function() {
    'use strict';

    var statusClasses = {
        open: 'danger',
        contained: 'warning',
        resolved: 'success',
        dismissed: 'secondary'
    };
    var incidents = [];
    var selectedID = '';
    var pendingIncidentID = '';
    var pageOffset = 0;
    var pageTotal = 0;
    var groupedPageOffset = 0;
    var groupedPageTotal = 0;
    var groupedPageReturned = 0;

    function currentHours() {
        var active = document.querySelector('.incident-hours-btn.active');
        return active ? active.getAttribute('data-hours') : '72';
    }

    function switchTab(name) {
        var tabs = [
            { tab: 'incidents-tab', panel: 'incidents-panel', name: 'incidents' },
            { tab: 'grouped-tab',   panel: 'grouped-panel',   name: 'grouped' },
            { tab: 'timeline-tab',  panel: 'timeline-panel',  name: 'timeline' },
        ];
        for (var i = 0; i < tabs.length; i++) {
            var entry = tabs[i];
            var active = entry.name === name;
            var tabEl = document.getElementById(entry.tab);
            var panelEl = document.getElementById(entry.panel);
            if (tabEl) {
                tabEl.classList.toggle('active', active);
                tabEl.setAttribute('aria-selected', active ? 'true' : 'false');
            }
            if (panelEl) {
                panelEl.classList.toggle('d-none', !active);
            }
        }
        if (name === 'grouped') loadGroups();
    }

    // ---------- Grouped tab ----------

    function ageLabel(iso) {
        if (!iso) return '';
        if (CSM.timeAgo) return CSM.timeAgo(iso);
        return iso;
    }

    function kindLabel(k) {
        switch (k) {
            case 'mailbox_takeover':       return 'Mailbox takeover';
            case 'mailbox_bruteforce':     return 'Mailbox brute force';
            case 'web_account_compromise': return 'Web account compromise';
            case 'web_attack':             return 'Web attack';
            case 'credential_spray':       return 'Credential spray';
            case 'post_exploit_process':   return 'Post-exploit process';
            case 'host_integrity_risk':    return 'Host integrity';
            case 'host_takeover':          return 'Host takeover';
        }
        return k;
    }

    function severityNumber(label) {
        if (label === 'CRITICAL') return 2;
        if (label === 'HIGH') return 1;
        return 0;
    }

    function incidentSourceIP(inc) {
        if (!inc) return '';
        if (inc.correlation_key && inc.correlation_key.remote_ip) return inc.correlation_key.remote_ip;
        var counts = {};
        var best = '';
        var bestCount = 0;
        var tl = inc.timeline || [];
        for (var i = 0; i < tl.length; i++) {
            var ip = tl[i].remote_ip;
            if (!ip) continue;
            counts[ip] = (counts[ip] || 0) + 1;
            if (counts[ip] > bestCount || (counts[ip] === bestCount && (best === '' || ip < best))) {
                best = ip;
                bestCount = counts[ip];
            }
        }
        return best;
    }

    function firewallStatusClass(baseClass, tone) {
        var classes = (baseClass || '').split(/\s+/).filter(function(cls) {
            return cls && cls !== 'text-muted' && cls !== 'text-danger'
                && cls !== 'text-warning' && cls !== 'text-success';
        });
        classes.push('text-' + tone);
        return classes.join(' ');
    }

    function setFirewallStatus(target, expectedIP, text, tone) {
        if (!target || target.getAttribute('data-csm-fw-ip') !== expectedIP) return;
        target.textContent = text;
        target.className = firewallStatusClass(target.getAttribute('data-csm-fw-base-class') || '', tone);
    }

    function attachFirewallStatus(targetID, ip) {
        var el = document.getElementById(targetID);
        if (!el) return;
        var requestedIP = ip || '';
        el.setAttribute('data-csm-fw-ip', requestedIP);
        el.setAttribute('data-csm-fw-base-class', el.className || '');
        if (!requestedIP) {
            setFirewallStatus(el, requestedIP, 'no source IP', 'muted');
            return;
        }
        CSM.get('/api/v1/firewall/check?ip=' + encodeURIComponent(ip))
            .then(function(r) {
                var target = document.getElementById(targetID);
                if (!r || r.success === false) {
                    setFirewallStatus(target, requestedIP, 'lookup failed', 'muted');
                    return;
                }
                if (r.permanent) {
                    setFirewallStatus(target, requestedIP, 'Blocked (permanent) -- ' + r.permanent, 'danger');
                    return;
                }
                if (r.temporary) {
                    setFirewallStatus(target, requestedIP, 'Blocked (temporary) -- ' + r.temporary, 'danger');
                    return;
                }
                if (r.cphulk) {
                    setFirewallStatus(target, requestedIP, 'cPanel hulk blocked', 'warning');
                    return;
                }
                setFirewallStatus(target, requestedIP, 'Not blocked', 'success');
            })
            .catch(function() {
                var target = document.getElementById(targetID);
                setFirewallStatus(target, requestedIP, 'lookup failed', 'muted');
            });
    }


    function currentGroupedPageSize() {
        var sel = document.getElementById('grouped-page-size');
        var n = parseInt(sel ? sel.value : '50', 10);
        return n > 0 ? n : 50;
    }

    function loadGroups() {
        var content = document.getElementById('grouped-content');
        var footer = document.getElementById('grouped-footer');
        if (!content) return;
        var status = (document.getElementById('grouped-status-filter') || {}).value || 'active';
        var kind = (document.getElementById('grouped-kind-filter') || {}).value || '';
        var limit = currentGroupedPageSize();
        var qs = 'status=' + encodeURIComponent(status)
            + '&limit=' + encodeURIComponent(limit)
            + '&offset=' + encodeURIComponent(groupedPageOffset);
        if (kind) qs += '&kind=' + encodeURIComponent(kind);
        CSM.get('/api/v1/incidents/groups?' + qs)
            .then(function(data) {
                groupedPageTotal = (data && typeof data.total_groups === 'number') ? data.total_groups : 0;
                groupedPageReturned = (data && Array.isArray(data.groups)) ? data.groups.length : 0;
                if (groupedPageTotal > 0 && groupedPageReturned === 0 && groupedPageOffset >= groupedPageTotal) {
                    groupedPageOffset = lastGroupedPageOffset();
                    loadGroups();
                    return;
                }
                renderGroups(data, content, footer);
                renderGroupedPagination();
            })
            .catch(function() {
                groupedPageTotal = 0;
                groupedPageReturned = 0;
                content.replaceChildren();
                var empty = document.createElement('div');
                empty.className = 'csm-empty';
                empty.innerHTML = '<div class="csm-empty__icon"><i class="ti ti-alert-circle"></i></div>'
                    + '<div class="csm-empty__reason">Could not load groups.</div>';
                content.appendChild(empty);
                if (footer) footer.textContent = '';
                renderGroupedPagination();
            });
    }

    function lastGroupedPageOffset() {
        var limit = currentGroupedPageSize();
        if (groupedPageTotal <= 0) return 0;
        return Math.floor((groupedPageTotal - 1) / limit) * limit;
    }

    function setGroupedPageOffset(off) {
        groupedPageOffset = Math.max(0, off);
        loadGroups();
    }

    function renderGroupedPagination() {
        var footer = document.getElementById('grouped-pagination');
        if (!footer) return;
        var limit = currentGroupedPageSize();
        if (groupedPageTotal <= 0) {
            footer.classList.add('d-none');
            return;
        }
        footer.classList.remove('d-none');
        var pageNum = Math.floor(groupedPageOffset / limit) + 1;
        var totalPages = Math.max(1, Math.ceil(groupedPageTotal / limit));
        var first = groupedPageOffset + 1;
        var last = Math.min(groupedPageOffset + groupedPageReturned, groupedPageTotal);
        var summary = document.getElementById('grouped-page-summary');
        if (summary) summary.textContent = 'Showing ' + first + '-' + last + ' of ' + groupedPageTotal;
        var indicator = document.getElementById('grouped-page-indicator');
        if (indicator) indicator.textContent = pageNum + ' / ' + totalPages;
        var pf = document.getElementById('grouped-page-first'); if (pf) pf.disabled = groupedPageOffset === 0;
        var pp = document.getElementById('grouped-page-prev');  if (pp) pp.disabled = groupedPageOffset === 0;
        var pn = document.getElementById('grouped-page-next');  if (pn) pn.disabled = groupedPageOffset + limit >= groupedPageTotal;
        var pl = document.getElementById('grouped-page-last');  if (pl) pl.disabled = groupedPageOffset + limit >= groupedPageTotal;
    }

    function renderGroups(data, content, footer) {
        content.replaceChildren();
        var groups = (data && data.groups) || [];
        if (groups.length === 0) {
            var empty = document.createElement('div');
            empty.className = 'csm-empty';
            empty.innerHTML = '<div class="csm-empty__icon"><i class="ti ti-circle-check"></i></div>'
                + '<div class="csm-empty__title">No groups</div>'
                + '<div class="csm-empty__reason">No incidents match the selected filters.</div>';
            content.appendChild(empty);
            if (footer) footer.textContent = '';
            return;
        }
        for (var i = 0; i < groups.length; i++) {
            var g = groups[i];
            var sourceText = g.source_kind === 'ip'
                ? g.source
                : g.source_kind === 'host'
                    ? 'host'
                : g.source_kind === '_unkeyed'
                    ? 'unkeyed'
                    : g.source_kind + ': ' + g.source;
            var titleHTML = '<code>' + CSM.esc(sourceText) + '</code>'
                + ' <span class="text-muted">' + CSM.esc(kindLabel(g.kind)) + '</span>';
            var meta = g.open_count + ' open';
            if (g.contained_count) meta += ', ' + g.contained_count + ' contained';
            if (g.resolved_count) meta += ', ' + g.resolved_count + ' resolved';
            var item = CSM.summaryItem({
                severity: severityNumber(g.severity_max),
                titleHTML: titleHTML,
                meta: meta,
                count: g.incident_count,
                age: ageLabel(g.last_seen),
                onClick: (function(group) { return function() { openGroupDetail(group); }; })(g),
            });
            content.appendChild(item);
        }
        if (footer) {
            var summary = data.total_groups + ' group' + (data.total_groups === 1 ? '' : 's')
                + ' from ' + data.scanned_incidents + ' incident' + (data.scanned_incidents === 1 ? '' : 's');
            if (data.truncated) summary += ' (scan capped)';
            footer.textContent = summary;
        }
    }

    function openGroupDetail(g) {
        var bodyHTML = '<dl class="row mb-2">';
        bodyHTML += '<dt class="col-4 text-muted">Kind</dt><dd class="col-8">' + CSM.esc(kindLabel(g.kind)) + '</dd>';
        bodyHTML += '<dt class="col-4 text-muted">Source</dt><dd class="col-8 font-monospace">' + CSM.esc(g.source || '(unkeyed)') + '</dd>';
        bodyHTML += '<dt class="col-4 text-muted">Incidents</dt><dd class="col-8">' + g.incident_count + '</dd>';
        bodyHTML += '<dt class="col-4 text-muted">Open</dt><dd class="col-8">' + g.open_count + '</dd>';
        if (g.contained_count) bodyHTML += '<dt class="col-4 text-muted">Contained</dt><dd class="col-8">' + g.contained_count + '</dd>';
        if (g.resolved_count) bodyHTML += '<dt class="col-4 text-muted">Resolved</dt><dd class="col-8">' + g.resolved_count + '</dd>';
        bodyHTML += '<dt class="col-4 text-muted">Severity max</dt><dd class="col-8">' + CSM.esc(g.severity_max) + '</dd>';
        bodyHTML += '<dt class="col-4 text-muted">First seen</dt><dd class="col-8">' + CSM.fmtDate(g.first_seen) + '</dd>';
        bodyHTML += '<dt class="col-4 text-muted">Last seen</dt><dd class="col-8">' + CSM.fmtDate(g.last_seen) + '</dd>';
        if (g.source_kind === 'ip' && g.source) {
            bodyHTML += '<dt class="col-4 text-muted">Firewall</dt><dd class="col-8 text-muted" id="csm-group-fw-status">Checking...</dd>';
        }
        bodyHTML += '</dl>';
        if (g.sample_ids && g.sample_ids.length > 0) {
            bodyHTML += '<div class="mb-2"><div class="subheader">Sample incidents</div>';
            for (var i = 0; i < g.sample_ids.length; i++) {
                var sid = CSM.esc(g.sample_ids[i]);
                bodyHTML += '<div><a href="#' + sid + '" data-csm-incident-id="' + sid + '">' + sid + '</a></div>';
            }
            bodyHTML += '</div>';
        }
        CSM.detailPanel.open({
            title: 'Group: ' + (g.source || '(unkeyed)'),
            bodyHTML: bodyHTML,
        });
        if (g.source_kind === 'ip' && g.source) {
            attachFirewallStatus('csm-group-fw-status', g.source);
        }
        var panel = CSM.detailPanel.element();
        if (panel) {
            var links = panel.querySelectorAll('[data-csm-incident-id]');
            for (var l = 0; l < links.length; l++) {
                links[l].addEventListener('click', function(ev) {
                    ev.preventDefault();
                    var id = this.getAttribute('data-csm-incident-id');
                    CSM.detailPanel.close();
                    switchTab('incidents');
                    openIncident(id, true);
                });
            }
        }
    }

    function currentPageSize() {
        var sel = document.getElementById('incident-page-size');
        var n = parseInt(sel ? sel.value : '50', 10);
        return n > 0 ? n : 50;
    }

    function currentStatusParam() {
        var status = document.getElementById('incident-status-filter').value;
        return status === 'all' ? '' : status;
    }

    function incidentIDFromHash() {
        var raw = window.location.hash || '';
        if (raw.length <= 1) return '';
        try {
            return decodeURIComponent(raw.slice(1));
        } catch (e) {
            return raw.slice(1);
        }
    }

    function setIncidentHash(id) {
        if (!id || !window.history || !window.history.replaceState) return;
        window.history.replaceState(null, '', window.location.pathname + window.location.search + '#' + encodeURIComponent(id));
    }

    function openIncident(id, updateHash) {
        if (!id) return;
        selectedID = id;
        if (updateHash !== false) setIncidentHash(id);
        renderIncidentList();
        loadIncidentDetail(id);
    }

    function loadIncidents() {
        var container = document.getElementById('incidents-content');
        CSM.loading(container);
        var limit = currentPageSize();
        var statusParam = currentStatusParam();
        var params = 'limit=' + encodeURIComponent(limit) + '&offset=' + encodeURIComponent(pageOffset);
        params += '&status=' + encodeURIComponent(statusParam);
        CSM.get('/api/v1/incidents?' + params)
            .then(function(data) {
                if (data && Array.isArray(data.items)) {
                    incidents = data.items;
                    pageTotal = typeof data.total === 'number' ? data.total : data.items.length;
                    pageOffset = typeof data.offset === 'number' ? data.offset : pageOffset;
                } else if (Array.isArray(data)) {
                    incidents = data;
                    pageTotal = data.length;
                    pageOffset = 0;
                } else {
                    incidents = [];
                    pageTotal = 0;
                }
                if (pageTotal > 0 && incidents.length === 0 && pageOffset >= pageTotal) {
                    pageOffset = lastPageOffset();
                    selectedID = '';
                    loadIncidents();
                    return;
                }
                renderIncidentList();
                renderPagination();
            })
            .catch(function() { CSM.loadError(container, loadIncidents); });
    }

    function renderPagination() {
        var footer = document.getElementById('incidents-pagination');
        if (!footer) return;
        var limit = currentPageSize();
        if (pageTotal <= 0) {
            footer.classList.add('d-none');
            return;
        }
        footer.classList.remove('d-none');
        var pageNum = Math.floor(pageOffset / limit) + 1;
        var totalPages = Math.max(1, Math.ceil(pageTotal / limit));
        var first = pageOffset + 1;
        var last = Math.min(pageOffset + incidents.length, pageTotal);
        document.getElementById('incidents-page-summary').textContent =
            'Showing ' + first + '-' + last + ' of ' + pageTotal;
        document.getElementById('incidents-page-indicator').textContent =
            pageNum + ' / ' + totalPages;

        document.getElementById('incidents-page-first').disabled = pageOffset === 0;
        document.getElementById('incidents-page-prev').disabled = pageOffset === 0;
        document.getElementById('incidents-page-next').disabled = pageOffset + limit >= pageTotal;
        document.getElementById('incidents-page-last').disabled = pageOffset + limit >= pageTotal;
    }

    function setPageOffset(off) {
        pageOffset = Math.max(0, off);
        selectedID = '';
        loadIncidents();
    }

    function lastPageOffset() {
        var limit = currentPageSize();
        if (pageTotal <= 0) return 0;
        return Math.floor((pageTotal - 1) / limit) * limit;
    }

    function renderIncidentList() {
        var container = document.getElementById('incidents-content');
        var rows = incidents;
        if (rows.length === 0) {
            container.innerHTML = '<div class="card-body text-center text-muted py-4">No incidents match the current filter.</div>';
            if (pendingIncidentID) {
                var pending = pendingIncidentID;
                pendingIncidentID = '';
                loadIncidentDetail(pending);
            } else {
                CSM.detailPanel.close();
            }
            return;
        }

        var html = '<div class="table-responsive"><table class="table table-vcenter card-table" id="incidents-correlated-table">';
        html += '<thead><tr><th>Status</th><th>Severity</th><th>Kind</th><th>Owner</th><th>Findings</th><th>Updated</th></tr></thead><tbody>';
        for (var i = 0; i < rows.length; i++) {
            var inc = rows[i];
            var owner = inc.mailbox || inc.domain || inc.account || keySummary(inc.correlation_key) || 'unknown';
            var active = inc.id === selectedID ? ' class="table-active"' : '';
            html += '<tr data-incident-id="' + CSM.attr(inc.id) + '"' + active + '>';
            html += '<td><span class="badge bg-' + (statusClasses[inc.status] || 'secondary') + '-lt">' + CSM.esc(inc.status) + '</span></td>';
            html += '<td data-sort="' + severityNumber(inc.severity) + '"><span class="badge badge-' + CSM.severityClassFromLabel(inc.severity) + '">' + CSM.esc(inc.severity || 'UNKNOWN') + '</span></td>';
            html += '<td>' + CSM.esc(labelize(inc.kind)) + '</td>';
            html += '<td><span class="text-truncate d-inline-block csm-tw-260">' + CSM.esc(owner) + '</span></td>';
            html += '<td>' + ((inc.findings || []).length) + '</td>';
            html += '<td class="text-muted text-nowrap" data-timestamp="' + CSM.attr(inc.updated_at) + '">' + CSM.esc(CSM.timeAgo(inc.updated_at)) + '</td>';
            html += '</tr>';
        }
        html += '</tbody></table></div>';
        container.innerHTML = html;
        new CSM.Table({
            tableId: 'incidents-correlated-table',
            perPage: 0,
            search: false,
            sortable: true,
            stateKey: 'csm-incidents-correlated',
            controls: false,
            persistPerPage: false,
            mobileRowCard: true
        });
        CSM.initTimeAgo();

        var trs = container.querySelectorAll('tr[data-incident-id]');
        trs.forEach(function(tr) {
            tr.addEventListener('click', function() {
                openIncident(this.getAttribute('data-incident-id'), true);
            });
        });

        if (pendingIncidentID) {
            var pending = pendingIncidentID;
            pendingIncidentID = '';
            loadIncidentDetail(pending);
        }
    }

    function loadIncidentDetail(id) {
        selectedID = id;
        CSM.detailPanel.open({
            title: 'Incident',
            bodyHTML: '<div class="text-center text-muted py-4"><span class="spinner-border spinner-border-sm"></span> Loading...</div>'
        });
        CSM.get('/api/v1/incidents/' + encodeURIComponent(id))
            .then(function(inc) { renderIncidentDetail(inc); })
            .catch(function() {
                CSM.detailPanel.open({
                    title: 'Incident',
                    bodyHTML: CSM.emptyStateBlock({
                        icon: 'alert-circle',
                        title: 'Incident not found',
                        reason: 'The incident may have been compacted or the link is no longer valid.'
                    }),
                    footerHTML: '<button class="btn btn-outline-secondary btn-sm" type="button" data-incident-retry="' + CSM.attr(id) + '">Retry</button>'
                });
                var panel = CSM.detailPanel.element();
                var retry = panel && panel.querySelector('[data-incident-retry]');
                if (retry) retry.addEventListener('click', function() { loadIncidentDetail(this.getAttribute('data-incident-retry')); });
            });
    }

    function renderIncidentDetail(inc) {
        selectedID = inc.id || selectedID;
        var owner = inc.mailbox || inc.domain || inc.account || keySummary(inc.correlation_key) || 'unknown';
        var html = '';
        html += '<div class="row g-3 mb-3">';
        var incSourceIP = incidentSourceIP(inc);
        html += statBlock('Status', inc.status);
        html += statBlock('Severity', inc.severity || 'UNKNOWN');
        html += statBlock('Owner', owner);
        html += statBlock('Updated', CSM.fmtDate(inc.updated_at, {tz: true}));
        if (incSourceIP) {
            html += '<div class="col-sm-6 col-lg-3"><div class="subheader">Firewall</div><div class="h3 m-0 text-muted" id="csm-incident-fw-status">Checking...</div><div class="text-muted small font-monospace">' + CSM.esc(incSourceIP) + '</div></div>';
        }
        html += '</div>';
        html += '<div class="timeline-list">';
        var events = (inc.timeline || []).slice().sort(function(a, b) {
            return new Date(b.time).getTime() - new Date(a.time).getTime();
        });
        for (var i = 0; i < events.length; i++) {
            html += eventHTML(events[i]);
        }
        var actions = (inc.actions || []).slice().sort(function(a, b) {
            return new Date(b.time).getTime() - new Date(a.time).getTime();
        });
        for (var j = 0; j < actions.length; j++) {
            html += actionHTML(actions[j]);
        }
        html += '</div>';
        var footer = '';
        footer += statusButton(inc, 'open', 'rotate-clockwise');
        footer += statusButton(inc, 'contained', 'shield-check');
        footer += statusButton(inc, 'resolved', 'circle-check');
        footer += statusButton(inc, 'dismissed', 'circle-x');
        CSM.detailPanel.open({
            title: labelize(inc.kind),
            bodyHTML: html,
            footerHTML: footer
        });
        CSM.initTimeAgo();
        if (incSourceIP) {
            attachFirewallStatus('csm-incident-fw-status', incSourceIP);
        }
        var panel = CSM.detailPanel.element();
        panel.querySelectorAll('[data-status-target]').forEach(function(btn) {
            btn.addEventListener('click', function() {
                setIncidentStatus(inc.id, this.getAttribute('data-status-target'));
            });
        });
    }

    function statusButton(inc, status, icon) {
        var disabled = inc.status === status ? ' disabled' : '';
        return '<button class="btn btn-outline-secondary btn-sm" data-status-target="' + CSM.attr(status) + '"' + disabled + ' title="Mark ' + CSM.attr(status) + '" aria-label="Mark ' + CSM.attr(status) + '">' +
            '<i class="ti ti-' + CSM.attr(icon) + '"></i></button>';
    }

    function setIncidentStatus(id, status) {
        CSM.post('/api/v1/incidents/' + encodeURIComponent(id) + '/status', {
            status: status,
            details: 'web-ui'
        }).then(function() {
            CSM.toast('Incident updated', 'success');
            pendingIncidentID = id;
            loadIncidents();
            loadIncidentDetail(id);
        });
    }

    function statBlock(label, value) {
        return '<div class="col-6 col-lg-3"><div class="text-muted small">' + CSM.esc(label) + '</div><div class="fw-semibold text-truncate">' + CSM.esc(value || 'unknown') + '</div></div>';
    }

    function eventHTML(e) {
        var bits = [];
        if (e.pid) bits.push('pid=' + e.pid);
        if (e.uid) bits.push('uid=' + e.uid);
        if (e.process) bits.push(e.process);
        if (e.remote_ip) bits.push(e.remote_ip);
        if (e.path) bits.push(e.path);
        return '<div class="d-flex mb-2 align-items-start">' +
            '<div class="text-nowrap me-3 text-muted small csm-mw-80" data-timestamp="' + CSM.attr(e.time) + '">' + CSM.esc(CSM.timeAgo(e.time)) + '</div>' +
            '<div class="me-2"><span class="badge bg-azure-lt">Finding</span></div>' +
            '<div class="csm-break-word"><div class="fw-semibold">' + CSM.esc(e.check || e.kind || 'finding') + '</div>' +
            '<div>' + CSM.esc(e.message || '') + '</div>' +
            (bits.length ? '<div class="text-muted small mt-1">' + CSM.esc(bits.join(', ')) + '</div>' : '') +
            '</div></div>';
    }

    function actionHTML(a) {
        return '<div class="d-flex mb-2 align-items-start">' +
            '<div class="text-nowrap me-3 text-muted small csm-mw-80" data-timestamp="' + CSM.attr(a.time) + '">' + CSM.esc(CSM.timeAgo(a.time)) + '</div>' +
            '<div class="me-2"><span class="badge bg-green-lt">Action</span></div>' +
            '<div class="csm-break-word"><div class="fw-semibold">' + CSM.esc(a.action || 'action') + '</div>' +
            '<div>' + CSM.esc(a.result || '') + '</div>' +
            (a.details ? '<div class="text-muted small mt-1">' + CSM.esc(a.details) + '</div>' : '') +
            '</div></div>';
    }

    function keySummary(key) {
        if (!key) return '';
        return key.mailbox || key.domain || key.account || key.remote_ip || (key.pid ? 'pid=' + key.pid : '') || (key.uid ? 'uid=' + key.uid : '');
    }

    function labelize(s) {
        return String(s || 'incident').replace(/_/g, ' ').replace(/\b\w/g, function(ch) { return ch.toUpperCase(); });
    }

    function loadTimeline() {
        var query = document.getElementById('incident-query').value.trim();
        if (!query) return;
        var hours = currentHours();
        var isIP = CSM.validateIP(query);
        var url = '/api/v1/incident?hours=' + hours;
        if (isIP) { url += '&ip=' + encodeURIComponent(query); }
        else { url += '&account=' + encodeURIComponent(query); }

        var container = document.getElementById('incident-content');
        container.innerHTML = '<div class="card-body text-center text-muted py-4"><span class="spinner-border spinner-border-sm"></span> Searching...</div>';

        CSM.get(url)
            .then(function(data) { renderTimeline(data); })
            .catch(function() { CSM.loadError(container, loadTimeline); });
    }

    function renderTimeline(data) {
        var container = document.getElementById('incident-content');
        var events = data.events || [];
        if (events.length === 0) {
            container.innerHTML = '<div class="card-body text-center text-muted py-4">No events found for this query.</div>';
            return;
        }

        var html = '<div class="card-body">';
        html += '<div class="text-muted small mb-3">' + events.length + ' events found</div>';
        html += '<button class="btn btn-ghost-secondary btn-sm mb-3" id="incident-export"><i class="ti ti-download"></i>&nbsp;Export CSV</button>';
        html += '<div class="timeline-list">';

        for (var i = 0; i < events.length; i++) {
            var e = events[i];
            var sevClass = CSM.sevMap[e.severity] ? CSM.sevMap[e.severity].cls : 'info';
            var sevLabel = CSM.sevMap[e.severity] ? CSM.sevMap[e.severity].label : 'INFO';
            var typeLabel = e.type === 'finding' ? 'Finding' : e.type === 'action' ? 'Action' : 'Event';
            var ago = CSM.timeAgo(e.timestamp);

            html += '<div class="d-flex mb-2 align-items-start">';
            html += '<div class="text-nowrap me-3 text-muted small csm-mw-80" data-timestamp="' + CSM.esc(e.timestamp) + '">' + CSM.esc(ago) + '</div>';
            html += '<div class="me-2"><span class="badge badge-' + sevClass + '">' + sevLabel + '</span></div>';
            html += '<div class="me-2"><span class="badge bg-azure-lt">' + CSM.esc(typeLabel) + '</span></div>';
            html += '<div class="csm-break-word">' + CSM.esc(e.summary);
            if (e.details) {
                html += '<div class="text-muted small mt-1 csm-detail">' + CSM.esc(e.details) + '</div>';
            }
            html += '</div></div>';
        }

        html += '</div></div>';
        container.innerHTML = html;
        CSM.initTimeAgo();

        var exportBtn = document.getElementById('incident-export');
        if (exportBtn) {
            exportBtn.addEventListener('click', function() {
                var lines = ['Timestamp,Severity,Type,Summary,Details'];
                for (var j = 0; j < events.length; j++) {
                    var ev = events[j];
                    lines.push([
                        '"' + (ev.timestamp || '').replace(/"/g, '""') + '"',
                        '"' + ((CSM.sevMap[ev.severity] ? CSM.sevMap[ev.severity].label : 'WARNING')).replace(/"/g, '""') + '"',
                        '"' + (ev.type || '').replace(/"/g, '""') + '"',
                        '"' + (ev.summary || '').replace(/"/g, '""') + '"',
                        '"' + (ev.details || '').replace(/"/g, '""') + '"'
                    ].join(','));
                }
                var blob = new Blob([lines.join('\n')], {type: 'text/csv'});
                var url = URL.createObjectURL(blob);
                var a = document.createElement('a');
                a.href = url; a.download = 'csm-incident-' + new Date().toISOString().slice(0,10) + '.csv';
                document.body.appendChild(a); a.click(); document.body.removeChild(a);
                URL.revokeObjectURL(url);
            });
        }
    }

    document.getElementById('incidents-tab').addEventListener('click', function() { switchTab('incidents'); });
    document.getElementById('timeline-tab').addEventListener('click', function() { switchTab('timeline'); });
    var groupedTabBtn = document.getElementById('grouped-tab');
    if (groupedTabBtn) groupedTabBtn.addEventListener('click', function() { switchTab('grouped'); });
    var groupedRefresh = document.getElementById('grouped-refresh-btn');
    if (groupedRefresh) groupedRefresh.addEventListener('click', loadGroups);
    var groupedStatus = document.getElementById('grouped-status-filter');
    if (groupedStatus) groupedStatus.addEventListener('change', function() { groupedPageOffset = 0; loadGroups(); });
    var groupedKind = document.getElementById('grouped-kind-filter');
    if (groupedKind) groupedKind.addEventListener('change', function() { groupedPageOffset = 0; loadGroups(); });
    var groupedPageSize = document.getElementById('grouped-page-size');
    if (groupedPageSize) groupedPageSize.addEventListener('change', function() { groupedPageOffset = 0; loadGroups(); });
    var gpf = document.getElementById('grouped-page-first');
    if (gpf) gpf.addEventListener('click', function() { setGroupedPageOffset(0); });
    var gpp = document.getElementById('grouped-page-prev');
    if (gpp) gpp.addEventListener('click', function() { setGroupedPageOffset(groupedPageOffset - currentGroupedPageSize()); });
    var gpn = document.getElementById('grouped-page-next');
    if (gpn) gpn.addEventListener('click', function() { setGroupedPageOffset(groupedPageOffset + currentGroupedPageSize()); });
    var gpl = document.getElementById('grouped-page-last');
    if (gpl) gpl.addEventListener('click', function() { setGroupedPageOffset(lastGroupedPageOffset()); });
    document.getElementById('incidents-refresh-btn').addEventListener('click', loadIncidents);
    document.getElementById('incident-status-filter').addEventListener('change', function() {
        selectedID = '';
        pageOffset = 0;
        loadIncidents();
    });
    var pageSizeSel = document.getElementById('incident-page-size');
    if (pageSizeSel) {
        pageSizeSel.addEventListener('change', function() {
            pageOffset = 0;
            loadIncidents();
        });
    }
    var pf = document.getElementById('incidents-page-first');
    if (pf) pf.addEventListener('click', function() { setPageOffset(0); });
    var pp = document.getElementById('incidents-page-prev');
    if (pp) pp.addEventListener('click', function() { setPageOffset(pageOffset - currentPageSize()); });
    var pn = document.getElementById('incidents-page-next');
    if (pn) pn.addEventListener('click', function() { setPageOffset(pageOffset + currentPageSize()); });
    var pl = document.getElementById('incidents-page-last');
    if (pl) pl.addEventListener('click', function() { setPageOffset(lastPageOffset()); });
    document.getElementById('incident-search-btn').addEventListener('click', loadTimeline);
    document.getElementById('incident-query').addEventListener('keydown', function(e) {
        if (e.key === 'Enter') loadTimeline();
    });
    document.querySelectorAll('.incident-hours-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            document.querySelectorAll('.incident-hours-btn').forEach(function(b) { b.classList.remove('active'); });
            this.classList.add('active');
            if (document.getElementById('incident-query').value.trim()) loadTimeline();
        });
    });

    var params = new URLSearchParams(window.location.search);
    var preIP = params.get('ip');
    var preAccount = params.get('account');
    if (preIP || preAccount) {
        switchTab('timeline');
        document.getElementById('incident-query').value = preIP || preAccount;
        loadTimeline();
    } else {
        pendingIncidentID = incidentIDFromHash();
        selectedID = pendingIncidentID;
        loadIncidents();
    }

    window.addEventListener('hashchange', function() {
        var id = incidentIDFromHash();
        if (!id) {
            selectedID = '';
            CSM.detailPanel.close();
            renderIncidentList();
            return;
        }
        switchTab('incidents');
        openIncident(id, false);
    });
})();
