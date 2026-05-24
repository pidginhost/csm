// CSM Account detail page — tab-based loading
(function() {
    'use strict';
    var params = new URLSearchParams(window.location.search);
    var name = params.get('name');
    if (!name) return;

    var tabs = document.querySelectorAll('#account-tabs [data-tab]');
    var content = document.getElementById('account-tab-content');
    var cachedData = null;
    var currentTab = 'findings';
    var tabTables = {};

    var sevLabels = { 2: 'CRITICAL', 1: 'HIGH', 0: 'WARNING' };
    var sevClasses = { 2: 'critical', 1: 'high', 0: 'warning' };

    function showSpinner() {
        content.innerHTML = '<div class="card-body text-center text-muted py-4"><span class="spinner-border spinner-border-sm"></span> Loading...</div>';
    }

    function setActiveTab(tab) {
        tabs.forEach(function(t) {
            t.classList.toggle('active', t.dataset.tab === tab);
            t.setAttribute('aria-selected', t.dataset.tab === tab ? 'true' : 'false');
        });
    }

    function loadTab(tab) {
        currentTab = tab;
        setActiveTab(tab);

        if (cachedData) {
            renderTabContent(tab, cachedData);
            return;
        }

        showSpinner();
        CSM.fetch('/api/v1/account?name=' + encodeURIComponent(name))
            .then(function(data) {
                if (data.error) {
                    content.innerHTML = '<div class="alert alert-danger">' + CSM.esc(data.error) + '</div>';
                    return;
                }
                cachedData = data;
                renderTabContent(tab, data);
            })
            .catch(function(err) {
                content.innerHTML = '<div class="card-body text-center text-danger py-4">Failed to load: ' + CSM.esc(err.message || 'Unknown error') + '</div>';
            });
    }

    function renderTabContent(tab, data) {
        if (tab === 'findings') {
            renderFindings(data.findings || []);
        } else if (tab === 'quarantine') {
            renderQuarantine(data.quarantined || []);
        } else if (tab === 'history') {
            renderHistory(data.history || []);
        }
    }

    function _buildFindingsToolbar(checkTypes) {
        var bar = '<div class="csm-toolbar">';
        bar += '<input type="text" id="account-findings-search" class="form-control form-control-sm csm-toolbar__search" placeholder="Search findings..." aria-label="Search findings">';
        bar += '<select id="account-findings-sev" class="form-select form-select-sm csm-toolbar__filter" aria-label="Filter by severity">';
        bar += '<option value="">All severities</option>';
        bar += '<option value="2">Critical</option>';
        bar += '<option value="1">High</option>';
        bar += '<option value="0">Warning</option>';
        bar += '</select>';
        bar += '<select id="account-findings-check" class="form-select form-select-sm csm-toolbar__filter" aria-label="Filter by check">';
        bar += '<option value="">All checks</option>';
        for (var i = 0; i < checkTypes.length; i++) {
            bar += '<option value="' + CSM.attr(checkTypes[i]) + '">' + CSM.esc(checkTypes[i]) + '</option>';
        }
        bar += '</select>';
        bar += '</div>';
        return bar;
    }

    function _localDateMillis(value, endExclusive) {
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

    function _filteredRowsForTab(tab, rows) {
        rows = rows || [];
        var table = tabTables[tab];
        if (!table || !table.filteredRows) return rows;
        var out = [];
        for (var i = 0; i < table.filteredRows.length; i++) {
            var raw = table.filteredRows[i].row.getAttribute('data-index');
            var idx = parseInt(raw, 10);
            if (isFinite(idx) && idx >= 0 && idx < rows.length) out.push(rows[idx]);
        }
        return out;
    }

    function renderFindings(findings) {
        tabTables.findings = null;
        var checkTypes = {};
        findings.forEach(function(f) { if (f.check) checkTypes[f.check] = true; });
        var checkList = Object.keys(checkTypes).sort();
        var html = '<div class="card mb-3"><div class="card-header"><h3 class="card-title">Active Findings (' + findings.length + ')</h3></div>';
        html += _buildFindingsToolbar(checkList);
        if (findings.length > 0) {
            html += '<div class="table-responsive"><table class="table table-vcenter card-table table-sm" id="account-findings-table"><thead><tr><th>Severity</th><th>Check</th><th>Message</th></tr></thead><tbody>';
            for (var i = 0; i < findings.length; i++) {
                var f = findings[i];
                html += '<tr data-index="' + i + '" data-severity="' + String(f.severity || 0) + '" data-check="' + CSM.attr(f.check || '') + '">';
                html += '<td data-sort="' + Number(f.severity || 0) + '"><span class="badge badge-' + (sevClasses[f.severity] || 'warning') + '">' + (sevLabels[f.severity] || 'WARNING') + '</span></td>';
                html += '<td><code>' + CSM.esc(f.check) + '</code></td><td>' + CSM.esc(f.message) + '</td></tr>';
            }
            html += '</tbody></table></div>';
        } else {
            html += '<div class="card-body text-center text-muted py-3">No active findings for this account.</div>';
        }
        html += '</div>';
        content.innerHTML = html;
        if (findings.length > 0) {
            tabTables.findings = new CSM.Table({
                tableId: 'account-findings-table',
                perPage: 25,
                searchId: 'account-findings-search',
                sortable: true,
                stateKey: 'csm-account-findings',
                filters: [
                    { id: 'account-findings-sev',   attr: 'data-severity' },
                    { id: 'account-findings-check', attr: 'data-check' }
                ]
            });
        }
    }

    function renderQuarantine(quarantined) {
        tabTables.quarantine = null;
        var html = '<div class="card mb-3"><div class="card-header"><h3 class="card-title">Quarantined Files (' + quarantined.length + ')</h3></div>';
        html += '<div class="csm-toolbar"><input type="text" id="account-quarantine-search" class="form-control form-control-sm csm-toolbar__search" placeholder="Search by path..." aria-label="Search quarantined files"></div>';
        if (quarantined.length > 0) {
            html += '<div class="table-responsive"><table class="table table-vcenter card-table table-sm" id="account-quarantine-table"><thead><tr><th>Path</th><th>Size</th><th>Reason</th></tr></thead><tbody>';
            for (var q = 0; q < quarantined.length; q++) {
                var size = Number(quarantined[q].size || 0);
                html += '<tr data-index="' + q + '" data-path="' + CSM.attr(quarantined[q].original_path || '') + '"><td><code>' + CSM.esc(quarantined[q].original_path) + '</code></td>';
                html += '<td data-sort="' + size + '">' + CSM.formatSize(quarantined[q].size) + '</td>';
                html += '<td class="small">' + CSM.esc(quarantined[q].reason) + '</td></tr>';
            }
            html += '</tbody></table></div>';
        } else {
            html += '<div class="card-body text-center text-muted py-3">No quarantined files.</div>';
        }
        html += '</div>';
        content.innerHTML = html;
        if (quarantined.length > 0) {
            tabTables.quarantine = new CSM.Table({
                tableId: 'account-quarantine-table',
                perPage: 25,
                searchId: 'account-quarantine-search',
                searchAttr: 'data-path',
                sortable: true,
                stateKey: 'csm-account-quarantine'
            });
        }
    }

    function _buildHistoryToolbar() {
        var bar = '<div class="csm-toolbar">';
        bar += '<input type="text" id="account-history-search" class="form-control form-control-sm csm-toolbar__search" placeholder="Search history..." aria-label="Search history">';
        bar += '<select id="account-history-sev" class="form-select form-select-sm csm-toolbar__filter" aria-label="Filter by severity">';
        bar += '<option value="">All severities</option>';
        bar += '<option value="2">Critical</option>';
        bar += '<option value="1">High</option>';
        bar += '<option value="0">Warning</option>';
        bar += '</select>';
        bar += '<input type="date" id="account-history-from" class="form-control form-control-sm csm-toolbar__filter" aria-label="From date">';
        bar += '<input type="date" id="account-history-to" class="form-control form-control-sm csm-toolbar__filter" aria-label="To date">';
        bar += '</div>';
        return bar;
    }

    function renderHistory(history) {
        tabTables.history = null;
        var html = '<div class="card mb-3"><div class="card-header"><h3 class="card-title">Recent History (' + history.length + ')</h3></div>';
        html += _buildHistoryToolbar();
        if (history.length > 0) {
            html += '<div class="table-responsive"><table class="table table-vcenter card-table table-sm" id="account-history-table"><thead><tr><th>Severity</th><th>Check</th><th>Message</th><th>Time</th></tr></thead><tbody>';
            for (var h = 0; h < history.length; h++) {
                var e = history[h];
                html += '<tr data-index="' + h + '" data-severity="' + String(e.severity || 0) + '" data-timestamp="' + CSM.attr(e.timestamp || '') + '">';
                html += '<td data-sort="' + Number(e.severity || 0) + '"><span class="badge badge-' + (sevClasses[e.severity] || 'warning') + '">' + (sevLabels[e.severity] || 'WARNING') + '</span></td>';
                html += '<td><code>' + CSM.esc(e.check) + '</code></td><td>' + CSM.esc(e.message) + '</td>';
                html += '<td class="text-nowrap"><span class="text-muted small" data-timestamp="' + CSM.esc(e.timestamp) + '">' + CSM.esc(CSM.timeAgo(e.timestamp)) + '</span></td></tr>';
            }
            html += '</tbody></table></div>';
        } else {
            html += '<div class="card-body text-center text-muted py-3">No history entries.</div>';
        }
        html += '</div>';
        content.innerHTML = html;
        if (history.length > 0) {
            var fromEl = document.getElementById('account-history-from');
            var toEl = document.getElementById('account-history-to');
            function _inRange(row) {
                var raw = row.getAttribute('data-timestamp') || '';
                if (!raw) return true;
                var ts = new Date(raw.replace(/^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})/, '$1T$2')).getTime();
                if (isNaN(ts)) return true;
                var from = fromEl ? _localDateMillis(fromEl.value, false) : null;
                var to = toEl ? _localDateMillis(toEl.value, true) : null;
                if (from !== null && ts < from) return false;
                if (to !== null && ts >= to) return false;
                return true;
            }
            var historyTable = new CSM.Table({
                tableId: 'account-history-table',
                perPage: 25,
                searchId: 'account-history-search',
                sortable: true,
                stateKey: 'csm-account-history',
                filters: [{ id: 'account-history-sev', attr: 'data-severity' }],
                rowFilter: _inRange
            });
            tabTables.history = historyTable;
            function _onDate() { if (historyTable) { historyTable.currentPage = 1; historyTable.applyFilters(); } }
            if (fromEl) fromEl.addEventListener('change', _onDate);
            if (toEl) toEl.addEventListener('change', _onDate);
        }
    }

    tabs.forEach(function(t) {
        t.addEventListener('click', function() { loadTab(t.dataset.tab); });
    });

    // WEB_ROADMAP P2.4: export the active tab's rows via the shared
    // CSM.exportTable helper. Columns are tab-scoped because each tab
    // has a different shape.
    var _accountExportCols = {
        findings: [
            {key: 'severity', label: 'Severity'},
            {key: 'check',    label: 'Check'},
            {key: 'message',  label: 'Message'}
        ],
        quarantine: [
            {key: 'original_path', label: 'Path'},
            {key: 'size',          label: 'Size'},
            {key: 'reason',        label: 'Reason'}
        ],
        history: [
            {key: 'severity',  label: 'Severity'},
            {key: 'check',     label: 'Check'},
            {key: 'message',   label: 'Message'},
            {key: 'timestamp', label: 'Time'}
        ]
    };
    document.querySelectorAll('[data-export]').forEach(function(el) {
        el.addEventListener('click', function(e) {
            e.preventDefault();
            if (!cachedData) { CSM.toast('Account data still loading', 'warning'); return; }
            var rows = [];
            if (currentTab === 'findings') {
                rows = _filteredRowsForTab('findings', cachedData.findings || []).map(function(f) {
                    return {
                        severity: sevLabels[f.severity] || 'WARNING',
                        check:    f.check || '',
                        message:  f.message || ''
                    };
                });
            } else if (currentTab === 'quarantine') {
                rows = _filteredRowsForTab('quarantine', cachedData.quarantined || []);
            } else if (currentTab === 'history') {
                rows = _filteredRowsForTab('history', cachedData.history || []).map(function(h) {
                    return {
                        severity:  sevLabels[h.severity] || 'WARNING',
                        check:     h.check || '',
                        message:   h.message || '',
                        timestamp: h.timestamp || ''
                    };
                });
            }
            CSM.exportTable(rows, _accountExportCols[currentTab] || [], this.getAttribute('data-export'), 'csm-account-' + currentTab);
        });
    });

    loadTab('findings');
})();
