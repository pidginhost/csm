// CSM Cleanup History page
(function() {
    'use strict';

    // File backups, pre-clean backups included, are listed on the
    // Quarantine page; this page keeps the DB object backups.
    var formatSize = CSM.formatSize;

    // Thin alias preserved so the rest of the file reads naturally; routes
    // through the shared CSM.get so timeouts and error toasts stay uniform.
    function getJSON(url) {
        return CSM.get(url);
    }

    function removeEl(id) {
        var el = document.getElementById(id);
        if (el && el.parentNode) el.parentNode.removeChild(el);
    }

    function loadDBBackups() {
        getJSON('/api/v1/db-object-backups').then(function(data) {
            var items = data.items;
            var el = document.getElementById('cleanup-db-content');
            var title = document.getElementById('cleanup-db-title');
            removeEl('cleanup-db-table-controls');
            if (title) title.innerHTML = '<i class="ti ti-database"></i>&nbsp;DB Object Backups (' + (items ? items.length : 0) + ')';
            if (!items || items.length === 0) {
                el.innerHTML = '<div class="card-body text-center text-muted py-4"><i class="ti ti-circle-check"></i> No DB object backups.</div>';
                return;
            }
            var html = '<div class="table-responsive"><table class="table table-vcenter card-table" id="cleanup-db-table"><thead><tr>' +
                '<th>Account</th><th>Schema</th><th>Type</th><th>Name</th><th>Dropped</th><th>By</th><th>Size</th><th>Status</th><th>Actions</th>' +
                '</tr></thead><tbody>';
            for (var i = 0; i < items.length; i++) {
                var b = items[i];
                var status = b.restored ? '<span class="badge bg-success-lt">Restored</span>' : '<span class="badge bg-warning-lt">Backup retained</span>';
                var restoreDisabled = b.restored ? ' disabled title="Already restored"' : '';
                var bodyBytes = Number(b.body_bytes || 0);
                if (!isFinite(bodyBytes)) bodyBytes = 0;
                html += '<tr>' +
                    '<td><code>' + CSM.esc(b.account) + '</code></td>' +
                    '<td><code>' + CSM.esc(b.schema) + '</code></td>' +
                    '<td><span class="badge bg-azure-lt">' + CSM.esc(b.kind) + '</span></td>' +
                    '<td><code>' + CSM.esc(b.name) + '</code></td>' +
                    '<td data-timestamp="' + CSM.esc(b.dropped_at || '') + '" class="text-nowrap small">' + CSM.fmtDate(b.dropped_at) + '</td>' +
                    '<td>' + CSM.esc(b.dropped_by || '') + '</td>' +
                    '<td data-sort="' + bodyBytes + '">' + formatSize(b.body_bytes) + '</td>' +
                    '<td>' + status + (b.restored_at ? '<div class="text-muted small">' + CSM.esc(CSM.fmtDate(b.restored_at)) + '</div>' : '') + '</td>' +
                    '<td class="text-nowrap">' +
                    '<button class="btn btn-sm btn-ghost-secondary me-1 cleanup-db-view" data-key="' + CSM.esc(b.key) + '"><i class="ti ti-eye"></i>&nbsp;View</button>' +
                    '<button class="btn btn-sm btn-warning cleanup-db-restore" data-key="' + CSM.esc(b.key) + '"' + restoreDisabled + '><i class="ti ti-restore"></i>&nbsp;Restore</button>' +
                    '</td></tr>';
            }
            html += '</tbody></table></div>';
            el.innerHTML = html;
            new CSM.Table({ tableId: 'cleanup-db-table', perPage: 25, searchId: 'cleanup-db-search', sortable: true, stateKey: 'csm-cleanup-db-table' });
            bindDBBackupActions(el);
        }).catch(function(err) {
            CSM.loadError(document.getElementById('cleanup-db-content'), loadDBBackups, { title: 'Failed to load database backups', error: err });
        });
    }

    function bindDBBackupActions(el) {
        el.querySelectorAll('.cleanup-db-view').forEach(function(btn) {
            btn.addEventListener('click', function() {
                viewDBBackup(this.getAttribute('data-key'));
            });
        });
        el.querySelectorAll('.cleanup-db-restore').forEach(function(btn) {
            btn.addEventListener('click', function() {
                restoreDBBackup(this.getAttribute('data-key'));
            });
        });
    }

    function viewDBBackup(key) {
        getJSON('/api/v1/db-object-backup-preview?key=' + encodeURIComponent(key)).then(function(data) {
            var title = data.kind + ' ' + data.schema + '.' + data.name;
            var info = data.truncated ? 'first 8KB of ' + formatSize(data.total_size) : formatSize(data.total_size);
            CSM.filePreview(title, info, data.preview || '');
        }).catch(function(e) {
            CSM.toast('Preview failed: ' + e.message, 'error');
        });
    }

    function restoreDBBackup(key) {
        CSM.confirm('Restore this DB object from backup?').then(function() {
            CSM.post('/api/v1/db-object-backup-restore', { key: key }).then(function(data) {
                CSM.toast(data.message || 'DB object restored', 'success');
                loadDBBackups();
            }).catch(function(e) {
                CSM.toast('Restore failed: ' + e.message, 'error');
            });
        }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
    }

    loadDBBackups();
    if (CSM.refresh) CSM.refresh.onRefresh(loadDBBackups);
})();
