// CSM Account detail page
(function() {
    'use strict';
    var params = new URLSearchParams(window.location.search);
    var name = params.get('name');
    if (!name) {
        document.getElementById('account-page').innerHTML = '<div class="alert alert-warning">No account specified. Use ?name=username</div>';
        return;
    }

    fetch(CSM.apiUrl('/api/v1/account?name=' + encodeURIComponent(name)), { credentials: 'same-origin' })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.error) { document.getElementById('account-page').innerHTML = '<div class="alert alert-danger">' + CSM.esc(data.error) + '</div>'; return; }
            renderAccount(data);
        })
        .catch(function() { CSM.loadError(document.getElementById('account-page'), function() { location.reload(); }); });

    function renderAccount(data) {
        var container = document.getElementById('account-page');
        var sevLabels = { 2: 'CRITICAL', 1: 'HIGH', 0: 'WARNING' };
        var sevClasses = { 2: 'critical', 1: 'high', 0: 'warning' };

        var html = '';
        // Header
        html += '<div class="page-header mb-3"><div class="row align-items-center">';
        html += '<div class="col"><h2 class="page-title">Account: <code>' + CSM.esc(data.account) + '</code></h2></div>';
        html += '<div class="col-auto"><a href="' + CSM.esc(data.whm_url) + '" target="_blank" class="btn btn-outline-primary btn-sm"><i class="ti ti-external-link"></i>&nbsp;View in WHM</a></div>';
        html += '</div></div>';

        // Findings
        var findings = data.findings || [];
        html += '<div class="card mb-3"><div class="card-header"><h3 class="card-title">Active Findings (' + findings.length + ')</h3></div>';
        if (findings.length > 0) {
            html += '<div class="table-responsive"><table class="table table-vcenter card-table table-sm"><thead><tr><th>Severity</th><th>Check</th><th>Message</th></tr></thead><tbody>';
            for (var i = 0; i < findings.length; i++) {
                var f = findings[i];
                html += '<tr><td><span class="badge badge-' + (sevClasses[f.severity] || 'warning') + '">' + (sevLabels[f.severity] || 'WARNING') + '</span></td>';
                html += '<td><code>' + CSM.esc(f.check) + '</code></td><td>' + CSM.esc(f.message) + '</td></tr>';
            }
            html += '</tbody></table></div>';
        } else {
            html += '<div class="card-body text-center text-muted py-3">No active findings for this account.</div>';
        }
        html += '</div>';

        // Quarantined files
        var quarantined = data.quarantined || [];
        html += '<div class="card mb-3"><div class="card-header"><h3 class="card-title">Quarantined Files (' + quarantined.length + ')</h3></div>';
        if (quarantined.length > 0) {
            html += '<div class="table-responsive"><table class="table table-vcenter card-table table-sm"><thead><tr><th>Path</th><th>Size</th><th>Reason</th></tr></thead><tbody>';
            for (var q = 0; q < quarantined.length; q++) {
                html += '<tr><td><code>' + CSM.esc(quarantined[q].original_path) + '</code></td>';
                html += '<td>' + CSM.formatSize(quarantined[q].size) + '</td>';
                html += '<td class="small">' + CSM.esc(quarantined[q].reason) + '</td></tr>';
            }
            html += '</tbody></table></div>';
        } else {
            html += '<div class="card-body text-center text-muted py-3">No quarantined files.</div>';
        }
        html += '</div>';

        // History
        var history = data.history || [];
        html += '<div class="card mb-3"><div class="card-header"><h3 class="card-title">Recent History (' + history.length + ')</h3></div>';
        if (history.length > 0) {
            html += '<div class="table-responsive"><table class="table table-vcenter card-table table-sm"><thead><tr><th>Severity</th><th>Check</th><th>Message</th><th>Time</th></tr></thead><tbody>';
            for (var h = 0; h < history.length; h++) {
                var e = history[h];
                html += '<tr><td><span class="badge badge-' + (sevClasses[e.severity] || 'warning') + '">' + (sevLabels[e.severity] || 'WARNING') + '</span></td>';
                html += '<td><code>' + CSM.esc(e.check) + '</code></td><td>' + CSM.esc(e.message) + '</td>';
                html += '<td class="text-nowrap"><span class="text-muted small" data-timestamp="' + CSM.esc(e.timestamp) + '">' + CSM.esc(CSM.timeAgo(e.timestamp)) + '</span></td></tr>';
            }
            html += '</tbody></table></div>';
        } else {
            html += '<div class="card-body text-center text-muted py-3">No history entries.</div>';
        }
        html += '</div>';

        container.innerHTML = html;
    }
})();
