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
    }).catch(function(e) { console.error('rules status:', e); });
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
    }).catch(function(e) { console.error('rules list:', e); });
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

loadStatus();
loadFiles();
