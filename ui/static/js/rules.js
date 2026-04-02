// CSM Rules page

var fmtSize = CSM.formatSize;

function loadStatus() {
    fetch('/api/v1/rules/status', {credentials: 'same-origin'}).then(function(r) { return r.json(); }).then(function(data) {
        document.getElementById('stat-yaml').textContent = data.yaml_rules || 0;
        document.getElementById('stat-yara').textContent = data.yara_available ? (data.yara_rules || 0) : 'N/A';
        if (!data.yara_available) {
            document.getElementById('stat-yara').title = 'Binary compiled without YARA-X support (build tag: yara)';
        }
        document.getElementById('stat-version').textContent = data.yaml_version || '—';
        document.getElementById('stat-autoupdate').textContent = data.auto_update ? 'Enabled' : 'Disabled';
        if (data.rules_dir) {
            document.getElementById('rules-dir').textContent = 'Rules directory: ' + data.rules_dir;
        }
    }).catch(function() { CSM.loadError(document.getElementById('stat-yaml').closest('.card') || document.getElementById('stat-yaml').parentElement, loadStatus); });
}

function loadFiles() {
    fetch('/api/v1/rules/list', {credentials: 'same-origin'}).then(function(r) { return r.json(); }).then(function(data) {
        var tbody = document.getElementById('rules-tbody');
        if (!data || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="3" class="text-center text-muted">No rule files found</td></tr>';
            return;
        }
        var html = '';
        for (var i = 0; i < data.length; i++) {
            var f = data[i];
            var typeBadge = f.type === 'yara'
                ? '<span class="badge bg-purple-lt">YARA</span>'
                : '<span class="badge bg-blue-lt">YAML</span>';
            html += '<tr>';
            html += '<td><code class="font-monospace">' + CSM.esc(f.name) + '</code></td>';
            html += '<td>' + typeBadge + '</td>';
            html += '<td class="text-muted">' + fmtSize(f.size) + '</td>';
            html += '</tr>';
        }
        tbody.innerHTML = html;
        new CSM.Table({ tableId: 'rules-table', sortable: true });
    }).catch(function() { CSM.loadError(document.getElementById('rules-tbody').parentElement.parentElement.parentElement, loadFiles); });
}

document.getElementById('btn-reload').addEventListener('click', function() {
    CSM.confirm('Reload all rules?\n\nThis will re-read all YAML and YARA rule files from the rules directory.').then(function() {
        var btn = document.getElementById('btn-reload');
        btn.disabled = true;
        btn.innerHTML = '<i class="ti ti-loader"></i>&nbsp;Reloading...';
        CSM.post('/api/v1/rules/reload', {}).then(function(data) {
            btn.disabled = false;
            btn.innerHTML = '<i class="ti ti-refresh"></i>&nbsp;Reload Rules';
            if (data.errors && data.errors.length > 0) {
                CSM.toast('Reload completed with errors:\n' + data.errors.join('\n'), 'error');
            } else {
                CSM.toast('Rules reloaded successfully.\nYAML: ' + data.yaml_rules + ' rules, YARA: ' + data.yara_rules + ' files', 'success');
            }
            loadStatus();
            loadFiles();
        }).catch(function(e) {
            btn.disabled = false;
            btn.innerHTML = '<i class="ti ti-refresh"></i>&nbsp;Reload Rules';
            CSM.toast('Reload failed: ' + e, 'error');
        });
    }).catch(function() {});
});

document.getElementById('btn-test-alert').addEventListener('click', function() {
    var btn = this;
    btn.disabled = true;
    btn.innerHTML = '<i class="ti ti-loader"></i>&nbsp;Sending...';
    CSM.post('/api/v1/test-alert', {}).then(function(data) {
        btn.disabled = false;
        btn.innerHTML = '<i class="ti ti-bell-ringing"></i>&nbsp;Send Test Alert';
        if (data.status === 'sent') {
            CSM.toast('Test alert sent successfully', 'success');
        } else {
            CSM.toast('Failed: ' + (data.error || 'unknown error'), 'error');
        }
    }).catch(function(e) {
        btn.disabled = false;
        btn.innerHTML = '<i class="ti ti-bell-ringing"></i>&nbsp;Send Test Alert';
        CSM.toast('Error: ' + e, 'error');
    });
});

function loadSuppressions() {
    fetch('/api/v1/suppressions', {credentials: 'same-origin'}).then(function(r) { return r.json(); }).then(function(data) {
        var container = document.getElementById('suppressions-content');
        if (!data || data.length === 0) {
            container.innerHTML = '<div class="card-body text-center text-muted py-4">No suppression rules configured.</div>';
            return;
        }
        var html = '<div class="table-responsive"><table class="table table-vcenter card-table table-sm">';
        html += '<thead><tr><th>Check</th><th>Path Pattern</th><th>Reason</th><th>Created</th><th>Actions</th></tr></thead><tbody>';
        for (var i = 0; i < data.length; i++) {
            var s = data[i];
            var created = s.created_at ? new Date(s.created_at).toLocaleString() : '—';
            html += '<tr>';
            html += '<td><code>' + CSM.esc(s.check) + '</code></td>';
            html += '<td class="font-monospace small">' + CSM.esc(s.path_pattern || '(all)') + '</td>';
            html += '<td class="text-muted">' + CSM.esc(s.reason || '') + '</td>';
            html += '<td class="text-nowrap small">' + CSM.esc(created) + '</td>';
            html += '<td><button class="btn btn-ghost-danger btn-sm delete-suppression-btn" data-id="' + CSM.esc(s.id) + '"><i class="ti ti-trash"></i></button></td>';
            html += '</tr>';
        }
        html += '</tbody></table></div>';
        container.innerHTML = html;

        // Bind delete buttons
        container.querySelectorAll('.delete-suppression-btn').forEach(function(btn) {
            btn.addEventListener('click', function() {
                var id = this.getAttribute('data-id');
                CSM.confirm('Remove this suppression rule?').then(function() {
                    fetch('/api/v1/suppressions', {
                        method: 'DELETE',
                        credentials: 'same-origin',
                        headers: {
                            'Content-Type': 'application/json',
                            'X-CSRF-Token': CSM.csrfToken
                        },
                        body: JSON.stringify({id: id})
                    }).then(function(r) { return r.json(); }).then(function(data) {
                        if (data.status === 'deleted') {
                            CSM.toast('Suppression rule removed', 'success');
                            loadSuppressions();
                        } else {
                            CSM.toast('Failed: ' + (data.error || 'unknown'), 'error');
                        }
                    }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
                }).catch(function() {});
            });
        });
    }).catch(function(e) { console.error('suppressions:', e); });
}

var importFile = document.getElementById('import-file');
if (importFile) {
    importFile.addEventListener('change', function() {
        var file = this.files[0];
        if (!file) return;
        var reader = new FileReader();
        reader.onload = function(e) {
            try {
                var data = JSON.parse(e.target.result);
                CSM.post('/api/v1/import', data).then(function(result) {
                    CSM.toast('Import complete: ' + (result.summary || 'done'), 'success');
                    loadSuppressions();
                }).catch(function(err) { CSM.toast('Import failed: ' + err, 'error'); });
            } catch(ex) {
                CSM.toast('Invalid JSON file', 'error');
            }
        };
        reader.readAsText(file);
        this.value = '';
    });
}

// Create suppression rule from form
document.getElementById('suppression-form').addEventListener('submit', function(e) {
    e.preventDefault();
    var check = document.getElementById('suppress-check').value.trim();
    if (!check) return;
    var pathPattern = document.getElementById('suppress-path').value.trim();
    var reason = document.getElementById('suppress-reason').value.trim();
    CSM.post('/api/v1/suppressions', {
        check: check,
        path_pattern: pathPattern,
        reason: reason || 'Created from Rules page'
    }).then(function(data) {
        if (data.status === 'created') {
            CSM.toast('Suppression rule created', 'success');
            document.getElementById('suppress-check').value = '';
            document.getElementById('suppress-path').value = '';
            document.getElementById('suppress-reason').value = '';
            loadSuppressions();
        } else {
            CSM.toast('Failed: ' + (data.error || 'unknown'), 'error');
        }
    }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
});

// Populate check-type datalist from active findings
function loadCheckTypes() {
    fetch('/api/v1/findings', {credentials: 'same-origin'}).then(function(r) { return r.json(); }).then(function(findings) {
        var types = {};
        for (var i = 0; i < findings.length; i++) {
            if (findings[i].check) types[findings[i].check] = true;
        }
        var dl = document.getElementById('check-types');
        if (!dl) return;
        dl.innerHTML = '';
        Object.keys(types).sort().forEach(function(t) {
            var opt = document.createElement('option');
            opt.value = t;
            dl.appendChild(opt);
        });
    }).catch(function() {});
}

// --- ModSecurity escalation exclusions ---
var _modsecRules = [];

function loadModSecEscalation() {
    fetch(CSM.apiUrl('/api/v1/rules/modsec-escalation'), {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
        .then(function(data) {
            _modsecRules = data.rules || [];
            renderModSecEscalation();
        })
        .catch(function() {});
}

function renderModSecEscalation() {
    var container = document.getElementById('modsec-escalation-list');
    if (!container) return;
    if (_modsecRules.length === 0) {
        container.innerHTML = '<div class="text-muted small">No rules excluded — all CSM rules (900000-900999) will escalate to firewall blocks.</div>';
        return;
    }
    var html = '<table class="table table-sm table-vcenter"><thead><tr><th>Rule ID</th><th>Action</th></tr></thead><tbody>';
    _modsecRules.sort();
    for (var i = 0; i < _modsecRules.length; i++) {
        html += '<tr><td><code>' + _modsecRules[i] + '</code></td>' +
            '<td><button class="btn btn-ghost-danger btn-sm modsec-remove-btn" data-id="' + _modsecRules[i] + '"><i class="ti ti-trash"></i></button></td></tr>';
    }
    html += '</tbody></table>';
    container.innerHTML = html;

    container.querySelectorAll('.modsec-remove-btn').forEach(function(btn) {
        btn.addEventListener('click', function() {
            var id = parseInt(this.getAttribute('data-id'), 10);
            _modsecRules = _modsecRules.filter(function(r) { return r !== id; });
            saveModSecEscalation();
        });
    });
}

function saveModSecEscalation() {
    CSM.post('/api/v1/rules/modsec-escalation', {rules: _modsecRules}).then(function(data) {
        if (data.ok) {
            CSM.toast('ModSecurity escalation rules updated', 'success');
            renderModSecEscalation();
        }
    }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
}

var modsecForm = document.getElementById('modsec-escalation-form');
if (modsecForm) {
    modsecForm.addEventListener('submit', function(e) {
        e.preventDefault();
        var input = document.getElementById('modsec-rule-id');
        var id = parseInt(input.value, 10);
        if (isNaN(id) || id < 900000 || id > 900999) {
            CSM.toast('Rule ID must be between 900000 and 900999', 'warning');
            return;
        }
        if (_modsecRules.indexOf(id) >= 0) {
            CSM.toast('Rule ' + id + ' is already excluded', 'warning');
            return;
        }
        _modsecRules.push(id);
        input.value = '';
        saveModSecEscalation();
    });
}

loadStatus();
loadFiles();
loadSuppressions();
loadCheckTypes();
loadModSecEscalation();
