// CSM Rules page

var fmtSize = CSM.formatSize;

function loadStatus() {
    var stats = document.getElementById('stat-yaml').closest('.row');
    CSM.get('/api/v1/rules/status').then(function(data) {
        CSM.clearLoadError(stats);
        document.getElementById('stat-yaml').textContent = data.yaml_rules || 0;
        document.getElementById('stat-yara').textContent = data.yara_available ? (data.yara_rules || 0) : 'N/A';
        if (!data.yara_available) {
            document.getElementById('stat-yara').title = 'Binary compiled without YARA-X support (build tag: yara)';
        }
        document.getElementById('stat-version').textContent = data.yaml_version || '-';
        document.getElementById('stat-autoupdate').textContent = data.auto_update ? 'Enabled' : 'Disabled';
        if (data.rules_dir) {
            document.getElementById('rules-dir').textContent = 'Rules directory: ' + data.rules_dir;
        }
    }).catch(function(err) { CSM.loadError(stats, loadStatus, { title: 'Failed to load rule status', error: err }); });
}

function loadFiles() {
    CSM.get('/api/v1/rules/list').then(function(data) {
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
            var size = Number(f.size || 0);
            if (!isFinite(size)) size = 0;
            html += '<tr data-type="' + CSM.attr(f.type || 'yaml') + '">';
            html += '<td><code class="font-monospace">' + CSM.esc(f.name) + '</code></td>';
            html += '<td>' + typeBadge + '</td>';
            html += '<td class="text-muted" data-sort="' + size + '">' + fmtSize(f.size) + '</td>';
            html += '</tr>';
        }
        tbody.innerHTML = html;
        new CSM.Table({
            tableId: 'rules-table',
            sortable: true,
            searchId: 'rule-files-search',
            countTargetId: 'rule-files-count',
            stateKey: 'csm-rule-files-table',
            filters: [
                { id: 'rule-files-type-filter', attr: 'data-type' }
            ],
            emptyState: {
                icon: 'list-search',
                title: 'No files match',
                reason: 'Try clearing the search or type filter.'
            }
        });
    }).catch(function(err) { CSM.loadError(document.getElementById('rules-tbody'), loadFiles, { title: 'Failed to load rule files', error: err }); });
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
            CSM.toast('Reload failed: ' + CSM.errorText(e), 'error');
        });
    }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
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
        CSM.toast(CSM.errorText(e), 'error');
    });
});

function loadSuppressions() {
    CSM.get('/api/v1/suppressions').then(function(data) {
        var container = document.getElementById('suppressions-content');
        if (!data || data.length === 0) {
            container.innerHTML = '<div class="card-body text-center text-muted py-4">No suppression rules configured.</div>';
            return;
        }
        var html = '<div class="table-responsive"><table class="table table-vcenter card-table table-sm">';
        html += '<thead><tr><th>Check</th><th>Path Pattern</th><th>Reason</th><th>Created</th><th>Actions</th></tr></thead><tbody>';
        for (var i = 0; i < data.length; i++) {
            var s = data[i];
            var created = CSM.fmtDate(s.created_at);
            html += '<tr>';
            html += '<td><code>' + CSM.esc(s.check) + '</code></td>';
            html += '<td class="font-monospace small">' + CSM.esc(s.path_pattern || '(all)') + '</td>';
            html += '<td class="text-muted">' + CSM.esc(s.reason || '') + '</td>';
            html += '<td class="text-nowrap small">' + CSM.esc(created) + '</td>';
            html += '<td><button class="btn btn-ghost-danger btn-sm delete-suppression-btn" data-id="' + CSM.esc(s.id) + '" aria-label="Delete the ' + CSM.attr(s.check) + ' suppression rule" title="Delete rule"><i class="ti ti-trash" aria-hidden="true"></i></button></td>';
            html += '</tr>';
        }
        html += '</tbody></table></div>';
        container.innerHTML = html;

        // Bind delete buttons
        container.querySelectorAll('.delete-suppression-btn').forEach(function(btn) {
            btn.addEventListener('click', function() {
                var id = this.getAttribute('data-id');
                CSM.confirm('Remove this suppression rule?').then(function() {
                    CSM.delete('/api/v1/suppressions', {id: id}).then(function(data) {
                        if (data.status === 'deleted') {
                            CSM.toast('Suppression rule removed', 'success');
                            loadSuppressions();
                        } else {
                            CSM.toast('Failed: ' + (data.error || 'unknown'), 'error');
                        }
                    }).catch(function(e) { CSM.toast(CSM.errorText(e), 'error'); });
                }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
            });
        });
    }).catch(function(e) { console.error('suppressions:', e); });
}

var importFile = document.getElementById('import-file');
if (importFile) {
    importFile.addEventListener('change', function() {
        var input = this;
        var file = input.files[0];
        if (!file) return;
        var label = input.closest('label');
        var labelText = label ? label.querySelector('[data-import-label-text]') : null;
        var labelIcon = label ? label.querySelector('[data-import-label-icon]') : null;
        var origText = labelText ? labelText.textContent : 'Import State';
        var origIcon = labelIcon ? labelIcon.className : '';
        if (label) {
            label.classList.add('disabled');
            label.setAttribute('aria-busy', 'true');
            label.setAttribute('aria-disabled', 'true');
            input.disabled = true;
            if (labelIcon) labelIcon.className = 'ti ti-loader';
            if (labelText) labelText.textContent = 'Importing...';
        }
        function restore() {
            if (!label) return;
            label.classList.remove('disabled');
            label.removeAttribute('aria-busy');
            label.removeAttribute('aria-disabled');
            input.disabled = false;
            if (labelIcon) labelIcon.className = origIcon || 'ti ti-upload';
            if (labelText) labelText.textContent = origText || 'Import State';
        }
        var reader = new FileReader();
        reader.onerror = function() {
            CSM.toast('Could not read file', 'error');
            restore();
        };
        reader.onload = function(e) {
            try {
                var data = JSON.parse(e.target.result);
                CSM.post('/api/v1/import', data).then(function(result) {
                    CSM.toast('Import complete: ' + (result.summary || 'done'), 'success');
                    loadSuppressions();
                }).catch(function(err) {
                    CSM.toast('Import failed: ' + CSM.errorText(err), 'error');
                }).finally(restore);
            } catch(ex) {
                CSM.toast('Invalid JSON file', 'error');
                restore();
            }
        };
        try {
            reader.readAsText(file);
        } catch(ex) {
            CSM.toast('Could not read file', 'error');
            restore();
        } finally {
            input.value = '';
        }
    });
}

// Create suppression rule from form
document.getElementById('suppression-form').addEventListener('submit', function(e) {
    e.preventDefault();
    var check = document.getElementById('suppress-check').value.trim();
    if (!check) return;
    var allPaths = document.getElementById('suppress-all-paths');
    var body = CSM.suppressionRequest(check, allPaths.checked ? 'all' : 'path',
        document.getElementById('suppress-path').value,
        document.getElementById('suppress-reason').value,
        'Created from Rules page');
    if (body.error) {
        CSM.toast(body.error, 'error');
        return;
    }
    CSM.post('/api/v1/suppressions', body).then(function(resp) {
        CSM.suppressionSaved(resp);
        document.getElementById('suppress-check').value = '';
        document.getElementById('suppress-path').value = '';
        document.getElementById('suppress-reason').value = '';
        allPaths.checked = false;
        loadSuppressions();
    }).catch(function(err) {
        CSM.toast('Suppression not saved: ' + (err && err.message ? err.message : 'request failed'), 'error');
    });
});

// Populate check-type datalist from active findings
function loadCheckTypes() {
    CSM.get('/api/v1/findings', { silent: true }).then(function(findings) {
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
    }).catch(function(err) { console.error('loadCheckTypes:', err); });
}

loadStatus();
loadFiles();
loadSuppressions();
loadCheckTypes();
if (CSM.refresh) CSM.refresh.onRefresh(function() {
    loadStatus();
    loadFiles();
    loadSuppressions();
});
