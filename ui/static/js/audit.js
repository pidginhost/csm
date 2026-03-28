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
    fetch('/api/v1/audit', {credentials:'same-origin'}).then(function(r){return r.json()}).then(function(entries){
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
            html += '<td class="text-nowrap" title="' + CSM.esc(e.timestamp) + '"><span class="text-muted small">' + CSM.esc(CSM.timeAgo(e.timestamp)) + '</span></td>';
            html += '<td><span class="badge ' + badgeClass + '">' + CSM.esc(e.action) + '</span></td>';
            html += '<td><code>' + CSM.esc(e.target) + '</code></td>';
            html += '<td class="small">' + CSM.esc(e.details || '') + '</td>';
            html += '<td class="font-monospace small">' + CSM.esc(e.source_ip || '') + '</td>';
            html += '</tr>';
        }
        html += '</tbody></table></div>';
        el.innerHTML = html;
        new CSM.Table({ tableId: 'audit-table', perPage: 25, searchId: 'audit-search', sortable: true });
    }).catch(function(){
        document.getElementById('audit-content').innerHTML = '<div class="card-body text-center text-danger py-4">Error loading audit log.</div>';
    });
}

loadAudit();
