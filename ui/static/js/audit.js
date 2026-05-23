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
        new CSM.Table({ tableId: 'audit-table', perPage: 25, searchId: 'audit-search', sortable: true, stateKey: 'csm-audit-table', mobileRowCard: true });
    }).catch(function(){ CSM.loadError(document.getElementById('audit-content'), loadAudit); });
}

loadAudit();

function exportAuditRows() {
    var rows = document.querySelectorAll('#audit-table tbody tr');
    var headers = ['Time', 'Action', 'Target', 'Details', 'Admin IP'];
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
    return { headers: headers, rows: out };
}

function downloadBlob(content, mime, ext) {
    var blob = new Blob([content], {type: mime});
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'csm-audit-' + new Date().toISOString().slice(0,10) + '.' + ext;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

document.querySelectorAll('[data-export]').forEach(function(el) {
    el.addEventListener('click', function(e) {
        e.preventDefault();
        var format = this.getAttribute('data-export');
        var data = exportAuditRows();
        if (!data.rows.length) { CSM.toast('No data to export', 'warning'); return; }
        if (format === 'csv') {
            var lines = [data.headers.join(',')];
            data.rows.forEach(function(r) {
                lines.push([r.time, r.action, r.target, r.details, r.admin_ip].map(function(v) {
                    return '"' + String(v).replace(/"/g, '""') + '"';
                }).join(','));
            });
            downloadBlob(lines.join('\n'), 'text/csv', 'csv');
        } else if (format === 'json') {
            downloadBlob(JSON.stringify(data.rows, null, 2), 'application/json', 'json');
        }
    });
});
