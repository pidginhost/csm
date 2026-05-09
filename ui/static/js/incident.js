// CSM incidents
(function() {
    'use strict';

    var sevClasses = {
        WARNING: 'warning',
        HIGH: 'danger',
        CRITICAL: 'dark'
    };
    var statusClasses = {
        open: 'danger',
        contained: 'warning',
        resolved: 'success',
        dismissed: 'secondary'
    };
    var incidents = [];
    var selectedID = '';
    var pageOffset = 0;
    var pageTotal = 0;

    function currentHours() {
        var active = document.querySelector('.incident-hours-btn.active');
        return active ? active.getAttribute('data-hours') : '72';
    }

    function switchTab(name) {
        var incidentsTab = document.getElementById('incidents-tab');
        var timelineTab = document.getElementById('timeline-tab');
        var incidentsPanel = document.getElementById('incidents-panel');
        var timelinePanel = document.getElementById('timeline-panel');
        var showIncidents = name === 'incidents';

        incidentsTab.classList.toggle('active', showIncidents);
        incidentsTab.setAttribute('aria-selected', showIncidents ? 'true' : 'false');
        timelineTab.classList.toggle('active', !showIncidents);
        timelineTab.setAttribute('aria-selected', showIncidents ? 'false' : 'true');
        incidentsPanel.classList.toggle('d-none', !showIncidents);
        timelinePanel.classList.toggle('d-none', showIncidents);
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
            document.getElementById('incident-detail').classList.add('d-none');
            return;
        }

        var html = '<div class="table-responsive"><table class="table table-vcenter card-table">';
        html += '<thead><tr><th>Status</th><th>Severity</th><th>Kind</th><th>Owner</th><th>Findings</th><th>Updated</th></tr></thead><tbody>';
        for (var i = 0; i < rows.length; i++) {
            var inc = rows[i];
            var owner = inc.mailbox || inc.domain || inc.account || keySummary(inc.correlation_key) || 'unknown';
            var active = inc.id === selectedID ? ' class="table-active"' : '';
            html += '<tr data-incident-id="' + CSM.attr(inc.id) + '"' + active + '>';
            html += '<td><span class="badge bg-' + (statusClasses[inc.status] || 'secondary') + '-lt">' + CSM.esc(inc.status) + '</span></td>';
            html += '<td><span class="badge bg-' + (sevClasses[inc.severity] || 'secondary') + '-lt">' + CSM.esc(inc.severity || 'UNKNOWN') + '</span></td>';
            html += '<td>' + CSM.esc(labelize(inc.kind)) + '</td>';
            html += '<td><span class="text-truncate d-inline-block" style="max-width:260px">' + CSM.esc(owner) + '</span></td>';
            html += '<td>' + ((inc.findings || []).length) + '</td>';
            html += '<td class="text-muted text-nowrap" data-timestamp="' + CSM.attr(inc.updated_at) + '">' + CSM.esc(CSM.timeAgo(inc.updated_at)) + '</td>';
            html += '</tr>';
        }
        html += '</tbody></table></div>';
        container.innerHTML = html;
        CSM.initTimeAgo();

        var trs = container.querySelectorAll('tr[data-incident-id]');
        trs.forEach(function(tr) {
            tr.addEventListener('click', function() {
                selectedID = this.getAttribute('data-incident-id');
                renderIncidentList();
                loadIncidentDetail(selectedID);
            });
        });

        if (!selectedID || !rows.some(function(inc) { return inc.id === selectedID; })) {
            selectedID = rows[0].id;
            loadIncidentDetail(selectedID);
        }
    }

    function loadIncidentDetail(id) {
        var detail = document.getElementById('incident-detail');
        detail.classList.remove('d-none');
        CSM.loading(detail);
        CSM.get('/api/v1/incidents/' + encodeURIComponent(id))
            .then(function(inc) { renderIncidentDetail(inc); })
            .catch(function() { CSM.loadError(detail, function() { loadIncidentDetail(id); }); });
    }

    function renderIncidentDetail(inc) {
        var detail = document.getElementById('incident-detail');
        var owner = inc.mailbox || inc.domain || inc.account || keySummary(inc.correlation_key) || 'unknown';
        var html = '<div class="card-header">';
        html += '<h3 class="card-title"><i class="ti ti-timeline-event"></i>&nbsp;' + CSM.esc(labelize(inc.kind)) + '</h3>';
        html += '<div class="card-actions d-flex gap-2 flex-wrap">';
        html += statusButton(inc, 'open', 'rotate-clockwise');
        html += statusButton(inc, 'contained', 'shield-check');
        html += statusButton(inc, 'resolved', 'circle-check');
        html += statusButton(inc, 'dismissed', 'circle-x');
        html += '</div></div>';
        html += '<div class="card-body">';
        html += '<div class="row g-3 mb-3">';
        html += statBlock('Status', inc.status);
        html += statBlock('Severity', inc.severity || 'UNKNOWN');
        html += statBlock('Owner', owner);
        html += statBlock('Updated', CSM.fmtDate(inc.updated_at, {tz: true}));
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
        html += '</div></div>';
        detail.innerHTML = html;
        CSM.initTimeAgo();
        detail.querySelectorAll('[data-status-target]').forEach(function(btn) {
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
            '<div class="text-nowrap me-3 text-muted small" style="min-width:80px" data-timestamp="' + CSM.attr(e.time) + '">' + CSM.esc(CSM.timeAgo(e.time)) + '</div>' +
            '<div class="me-2"><span class="badge bg-azure-lt">Finding</span></div>' +
            '<div style="word-break:break-word"><div class="fw-semibold">' + CSM.esc(e.check || e.kind || 'finding') + '</div>' +
            '<div>' + CSM.esc(e.message || '') + '</div>' +
            (bits.length ? '<div class="text-muted small mt-1">' + CSM.esc(bits.join(', ')) + '</div>' : '') +
            '</div></div>';
    }

    function actionHTML(a) {
        return '<div class="d-flex mb-2 align-items-start">' +
            '<div class="text-nowrap me-3 text-muted small" style="min-width:80px" data-timestamp="' + CSM.attr(a.time) + '">' + CSM.esc(CSM.timeAgo(a.time)) + '</div>' +
            '<div class="me-2"><span class="badge bg-green-lt">Action</span></div>' +
            '<div style="word-break:break-word"><div class="fw-semibold">' + CSM.esc(a.action || 'action') + '</div>' +
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
        var isIP = CSM.validateIP(query) || query.indexOf(':') >= 0;
        var url = '/api/v1/incident?hours=' + hours;
        if (isIP) { url += '&ip=' + encodeURIComponent(query); }
        else { url += '&account=' + encodeURIComponent(query); }

        var container = document.getElementById('incident-content');
        container.innerHTML = '<div class="card-body text-center text-muted py-4"><span class="spinner-border spinner-border-sm"></span> Searching...</div>';

        fetch(CSM.apiUrl(url), { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
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
            html += '<div class="text-nowrap me-3 text-muted small" style="min-width:80px" data-timestamp="' + CSM.esc(e.timestamp) + '">' + CSM.esc(ago) + '</div>';
            html += '<div class="me-2"><span class="badge badge-' + sevClass + '">' + sevLabel + '</span></div>';
            html += '<div class="me-2"><span class="badge bg-azure-lt">' + CSM.esc(typeLabel) + '</span></div>';
            html += '<div style="word-break:break-word">' + CSM.esc(e.summary);
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
        loadIncidents();
    }
})();
