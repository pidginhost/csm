// CSM Account detail page — tab-based loading
(function() {
    'use strict';
    var params = new URLSearchParams(window.location.search);
    var name = params.get('name');
    if (!name) return;

    var tabs = document.querySelectorAll('#account-tabs [data-tab]');
    var content = document.getElementById('account-tab-content');
    var cachedData = null;

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

    function renderFindings(findings) {
        var html = '<div class="card mb-3"><div class="card-header"><h3 class="card-title">Active Findings (' + findings.length + ')</h3></div>';
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
        content.innerHTML = html;
    }

    function renderQuarantine(quarantined) {
        var html = '<div class="card mb-3"><div class="card-header"><h3 class="card-title">Quarantined Files (' + quarantined.length + ')</h3></div>';
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
        content.innerHTML = html;
    }

    function renderHistory(history) {
        var html = '<div class="card mb-3"><div class="card-header"><h3 class="card-title">Recent History (' + history.length + ')</h3></div>';
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
        content.innerHTML = html;
    }

    tabs.forEach(function(t) {
        t.addEventListener('click', function() { loadTab(t.dataset.tab); });
    });

    loadTab('findings');
})();
