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
    fetch(CSM.apiUrl('/api/v1/audit'), {credentials:'same-origin'}).then(function(r){return r.json()}).then(function(entries){
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
            html += '<tr>';
            html += '<td class="text-nowrap"><span class="text-muted small" data-timestamp="' + CSM.esc(e.timestamp) + '">' + CSM.esc(CSM.timeAgo(e.timestamp)) + '</span></td>';
            html += '<td><span class="badge ' + badgeClass + '">' + CSM.esc(e.action) + '</span></td>';
            html += '<td><code>' + CSM.esc(e.target) + '</code></td>';
            html += '<td class="small">' + CSM.esc(e.details || '') + '</td>';
            html += '<td class="font-monospace small">' + CSM.esc(e.source_ip || '') + '</td>';
            html += '</tr>';
        }
        html += '</tbody></table></div>';
        el.innerHTML = html;
        new CSM.Table({ tableId: 'audit-table', perPage: 25, searchId: 'audit-search', sortable: true, stateKey: 'csm-audit-table' });
    }).catch(function(){ CSM.loadError(document.getElementById('audit-content'), loadAudit); });
}

loadAudit();

var auditExportBtn = document.getElementById('audit-export-csv');
if (auditExportBtn) {
    auditExportBtn.addEventListener('click', function() {
        var rows = document.querySelectorAll('#audit-table tbody tr');
        if (!rows.length) { CSM.toast('No data to export', 'warning'); return; }
        var lines = ['Time,Action,Target,Details,Admin IP'];
        rows.forEach(function(r) {
            if (r.style.display === 'none') return;
            var cells = r.querySelectorAll('td');
            if (cells.length < 5) return;
            lines.push([
                '"' + (cells[0].textContent.trim()).replace(/"/g, '""') + '"',
                '"' + (cells[1].textContent.trim()).replace(/"/g, '""') + '"',
                '"' + (cells[2].textContent.trim()).replace(/"/g, '""') + '"',
                '"' + (cells[3].textContent.trim()).replace(/"/g, '""') + '"',
                '"' + (cells[4].textContent.trim()).replace(/"/g, '""') + '"'
            ].join(','));
        });
        var blob = new Blob([lines.join('\n')], {type: 'text/csv'});
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url; a.download = 'csm-audit-' + new Date().toISOString().slice(0,10) + '.csv';
        document.body.appendChild(a); a.click(); document.body.removeChild(a);
        URL.revokeObjectURL(url);
    });
}
