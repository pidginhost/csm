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

var _auditTable = null;
var _auditURLUnbind = null;
var _auditDateUnbind = null;

function resetAuditTable() {
    if (_auditTable && typeof _auditTable.destroy === 'function') _auditTable.destroy();
    _auditTable = null;
    if (_auditURLUnbind) {
        _auditURLUnbind();
        _auditURLUnbind = null;
    }
    if (_auditDateUnbind) {
        _auditDateUnbind();
        _auditDateUnbind = null;
    }
    var controls = document.getElementById('audit-table-controls');
    if (controls) controls.remove();
}

function auditActionLabel(action) {
    return String(action || '').replace(/[_-]+/g, ' ').replace(/\b\w/g, function(ch) {
        return ch.toUpperCase();
    });
}

function populateAuditActionFilter(entries) {
    var select = document.getElementById('audit-action-filter');
    if (!select) return;
    var current = CSM.urlState.get('action') || select.value || '';
    var seen = {};
    for (var i = 0; i < select.options.length; i++) {
        seen[select.options[i].value] = true;
    }
    function addOption(action) {
        action = String(action || '');
        if (!action || seen[action]) return;
        seen[action] = true;
        var opt = document.createElement('option');
        opt.value = action;
        opt.textContent = auditActionLabel(action);
        select.appendChild(opt);
    }
    for (var j = 0; j < (entries || []).length; j++) {
        addOption(entries[j].action);
    }
    addOption(current);
}

function auditURLInputs(fromInput, toInput) {
    return {
        q: document.getElementById('audit-search'),
        action: document.getElementById('audit-action-filter'),
        from: fromInput,
        to: toInput
    };
}

function auditLocalDateMillis(value, endExclusive) {
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

function loadAudit() {
    CSM.get('/api/v1/audit').then(function(entries){
        var el = document.getElementById('audit-content');
        var _auditFromInput = document.getElementById('audit-from');
        var _auditToInput = document.getElementById('audit-to');
        resetAuditTable();
        // Update card title with count
        var title = document.querySelector('.card-title');
        if (title) title.innerHTML = '<i class="ti ti-clipboard-list"></i>&nbsp;Audit Log (' + (entries ? entries.length : 0) + ')';
        if (!entries || entries.length === 0) {
            populateAuditActionFilter(entries);
            _auditURLUnbind = CSM.urlState.bind({ inputs: auditURLInputs(_auditFromInput, _auditToInput) });
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
        populateAuditActionFilter(entries);
        // WEB_ROADMAP P3.1: action dropdown and date-range inputs are
        // filtered via CSM.Table\'s filter array and a row-level
        // predicate respectively. Row markup carries data-action and
        // data-timestamp so both filters work without extra DOM lookups.
        function _auditDateInRange(row) {
            var raw = row.getAttribute('data-timestamp') || '';
            if (!raw) return true;
            var ts = CSM.parseTimestamp(raw);
            if (isNaN(ts)) return true;
            var from = _auditFromInput ? auditLocalDateMillis(_auditFromInput.value, false) : null;
            var to = _auditToInput ? auditLocalDateMillis(_auditToInput.value, true) : null;
            if (from !== null && ts < from) return false;
            if (to !== null && ts >= to) return false;
            return true;
        }
        _auditTable = new CSM.Table({
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
                _auditTable.currentPage = 1;
                _auditTable.applyFilters();
            }
        }
        if (_auditFromInput) _auditFromInput.addEventListener('change', _auditDateChange);
        if (_auditToInput) _auditToInput.addEventListener('change', _auditDateChange);
        _auditDateUnbind = function() {
            if (_auditFromInput) _auditFromInput.removeEventListener('change', _auditDateChange);
            if (_auditToInput) _auditToInput.removeEventListener('change', _auditDateChange);
        };
        // WEB_ROADMAP P2.1: persist audit-search + filters to URL.
        _auditURLUnbind = CSM.urlState.bind({ inputs: auditURLInputs(_auditFromInput, _auditToInput) });
    }).catch(function(){ CSM.loadError(document.getElementById('audit-content'), loadAudit); });
}

loadAudit();
if (CSM.refresh && typeof CSM.refresh.onRefresh === 'function') {
    CSM.refresh.onRefresh(loadAudit);
}

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
