// CSM Audit Log page

var actionBadges = {
    block_ip:          'bg-red',
    unblock_ip:        'bg-green',
    dismiss:           'bg-yellow',
    fix:               'bg-blue',
    whitelist_ip:      'bg-teal',
    clear_ip:          'bg-cyan',
    restore:           'bg-orange',
    temp_whitelist_ip: 'bg-purple'
};

function loadAudit() {
    CSM.get('/api/v1/audit').then(function(entries){
        var el = document.getElementById('audit-content');
        // Update card title with count
        var title = document.querySelector('.card-title');
        if (title) title.innerHTML = '<i class="ti ti-clipboard-list"></i>&nbsp;Audit Log (' + (entries ? entries.length : 0) + ')';
        if (!entries || entries.length === 0) {
            el.innerHTML = '<div class="card-body text-center text-muted py-4"><i class="ti ti-clipboard-check"></i> No audit entries yet.</div>';
            return;
        }
        var html = '<div class="table-responsive"><table class="table table-vcenter card-table" id="audit-table"><thead><tr><th>Time</th><th>Action</th><th>Target</th><th>Details</th><th>Admin IP</th></tr></thead><tbody>';
        for (var i = 0; i < entries.length; i++) {
            var e = entries[i];
            var badgeClass = actionBadges[e.action] || 'bg-secondary';
            html += '<tr data-action="' + CSM.attr(e.action || '') + '" data-timestamp="' + CSM.attr(e.timestamp || '') + '">';
            html += '<td class="text-nowrap"><span class="text-muted small" data-timestamp="' + CSM.esc(e.timestamp) + '">' + CSM.esc(CSM.timeAgo(e.timestamp)) + '</span></td>';
            html += '<td><span class="badge ' + badgeClass + '">' + CSM.esc(e.action) + '</span></td>';
            html += '<td><code>' + CSM.esc(e.target) + '</code></td>';
            html += '<td class="small">' + CSM.esc(e.details || '') + '</td>';
            html += '<td class="font-monospace small">' + CSM.esc(e.source_ip || '') + '</td>';
            html += '</tr>';
        }
        html += '</tbody></table></div>';
        el.innerHTML = html;
        // WEB_ROADMAP P3.1: action dropdown and date-range inputs are
        // filtered via CSM.Table\'s filter array and a row-level
        // predicate respectively. Row markup carries data-action and
        // data-timestamp so both filters work without extra DOM lookups.
        var _auditFromInput = document.getElementById('audit-from');
        var _auditToInput = document.getElementById('audit-to');
        function _auditDateInRange(row) {
            var raw = row.getAttribute('data-timestamp') || '';
            if (!raw) return true;
            var ts = new Date(raw.replace(/^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})/, '$1T$2')).getTime();
            if (isNaN(ts)) return true;
            var from = _auditFromInput && _auditFromInput.value ? new Date(_auditFromInput.value + 'T00:00:00').getTime() : null;
            var to = _auditToInput && _auditToInput.value ? new Date(_auditToInput.value + 'T23:59:59').getTime() : null;
            if (from !== null && ts < from) return false;
            if (to !== null && ts > to) return false;
            return true;
        }
        var _auditTable = new CSM.Table({
            tableId: 'audit-table',
            perPage: 25,
            searchId: 'audit-search',
            sortable: true,
            stateKey: 'csm-audit-table',
            mobileRowCard: true,
            filters: [{ id: 'audit-action-filter', attr: 'data-action' }],
            rowFilter: _auditDateInRange
        });
        function _auditDateChange() {
            if (_auditTable && typeof _auditTable.applyFilters === 'function') {
                _auditTable.applyFilters();
            }
        }
        if (_auditFromInput) _auditFromInput.addEventListener('change', _auditDateChange);
        if (_auditToInput) _auditToInput.addEventListener('change', _auditDateChange);
        // WEB_ROADMAP P2.1: persist audit-search + filters to URL.
        CSM.urlState.bind({ inputs: {
            q: document.getElementById('audit-search'),
            action: document.getElementById('audit-action-filter'),
            from: _auditFromInput,
            to: _auditToInput
        } });
    }).catch(function(){ CSM.loadError(document.getElementById('audit-content'), loadAudit); });
}

loadAudit();

// Export audit rows via shared CSM.exportTable (WEB_ROADMAP P2.4).
var _auditExportCols = [
    {key: 'time',     label: 'Time'},
    {key: 'action',   label: 'Action'},
    {key: 'target',   label: 'Target'},
    {key: 'details',  label: 'Details'},
    {key: 'admin_ip', label: 'Admin IP'}
];

function _auditExportRows() {
    var rows = document.querySelectorAll('#audit-table tbody tr');
    var out = [];
    rows.forEach(function(r) {
        if (r.style.display === 'none') return;
        var cells = r.querySelectorAll('td');
        if (cells.length < 5) return;
        out.push({
            time:     cells[0].textContent.trim(),
            action:   cells[1].textContent.trim(),
            target:   cells[2].textContent.trim(),
            details:  cells[3].textContent.trim(),
            admin_ip: cells[4].textContent.trim()
        });
    });
    return out;
}

document.querySelectorAll('[data-export]').forEach(function(el) {
    el.addEventListener('click', function(e) {
        e.preventDefault();
        CSM.exportTable(_auditExportRows(), _auditExportCols, this.getAttribute('data-export'), 'csm-audit');
    });
});
