// CSM Cleanup History page
(function() {
    'use strict';

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

    function kindLabel(kind) {
        if (kind === 'pre_clean') return 'Pre-clean backup';
        return 'Quarantine';
    }

    function stateBadge(state) {
        var label = 'Review';
        var cls = 'bg-secondary-lt';
        if (state === 'original_missing') {
            label = 'Original missing';
            cls = 'bg-warning-lt';
        } else if (state === 'live_differs') {
            label = 'Live differs';
            cls = 'bg-orange-lt';
        } else if (state === 'original_not_file') {
            label = 'Original not file';
            cls = 'bg-warning-lt';
        } else if (state === 'archive_missing' || state === 'archive_not_file') {
            label = 'Archive issue';
            cls = 'bg-danger-lt';
        } else if (state === 'unknown') {
            label = 'Unknown';
            cls = 'bg-secondary-lt';
        }
        return '<span class="badge ' + cls + '">' + label + '</span>';
    }

    function showPreview(title, subhead, preview) {
        var modal = document.getElementById('csm-confirm-modal');
        var dialog = modal ? modal.querySelector('.modal-dialog') : null;
        var body = document.getElementById('csm-confirm-body');
        var okBtn = document.getElementById('csm-confirm-ok');
        var cancelBtn = document.getElementById('csm-confirm-cancel');
        if (!modal || !body || !dialog || !okBtn || !cancelBtn) return;

        dialog.classList.remove('modal-sm');
        dialog.classList.add('modal-lg');
        body.textContent = '';
        body.style.whiteSpace = 'normal';

        var header = document.createElement('div');
        header.className = 'mb-2';
        var strong = document.createElement('strong');
        strong.textContent = title;
        header.appendChild(strong);
        if (subhead) {
            var meta = document.createElement('div');
            meta.className = 'text-muted small';
            meta.textContent = subhead;
            header.appendChild(meta);
        }
        body.appendChild(header);

        var pre = document.createElement('pre');
        pre.style.cssText = 'max-height:60vh;overflow:auto;padding:12px;border-radius:4px;font-size:0.75rem;white-space:pre-wrap;word-break:break-all;border:1px solid var(--csm-border);background:var(--csm-bg-card);color:var(--csm-text)';
        pre.textContent = preview || '(empty)';
        body.appendChild(pre);

        okBtn.textContent = 'Close';
        cancelBtn.style.display = 'none';

        function cleanup() {
            dialog.classList.remove('modal-lg');
            dialog.classList.add('modal-sm');
            body.style.whiteSpace = '';
            okBtn.textContent = 'OK';
            cancelBtn.style.display = '';
            okBtn.removeEventListener('click', close);
            modal.removeEventListener('hidden.bs.modal', cleanup);
        }
        function close() {
            if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
                bootstrap.Modal.getOrCreateInstance(modal).hide();
            } else {
                modal.classList.remove('show');
                modal.style.display = 'none';
                cleanup();
            }
        }

        okBtn.addEventListener('click', close);
        modal.addEventListener('hidden.bs.modal', cleanup, { once: true });
        if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
            bootstrap.Modal.getOrCreateInstance(modal).show();
        } else {
            modal.classList.add('show');
            modal.style.display = 'block';
        }
    }

    function loadFileBackups() {
        return getJSON('/api/v1/quarantine').then(function(files) {
            var el = document.getElementById('cleanup-files-content');
            var title = document.getElementById('cleanup-files-title');
            removeEl('cleanup-files-table-controls');
            if (title) title.innerHTML = '<i class="ti ti-file-zip"></i>&nbsp;File Backups (' + (files ? files.length : 0) + ')';
            if (!files || files.length === 0) {
                el.innerHTML = '<div class="card-body text-center text-muted py-4"><i class="ti ti-circle-check"></i> No file backups.</div>';
                updateFileBulkButtons();
                return;
            }
            var html = '<div class="table-responsive"><table class="table table-vcenter card-table" id="cleanup-files-table"><thead><tr>' +
                '<th><input type="checkbox" class="form-check-input" id="cleanup-files-select-all"></th>' +
                '<th>Type</th><th>Original Path</th><th>Size</th><th>Archived</th><th>State</th><th>Reason</th><th>Actions</th></tr></thead><tbody>';
            for (var i = 0; i < files.length; i++) {
                var f = files[i];
                html += '<tr>' +
                    '<td><input type="checkbox" class="form-check-input cleanup-file-cb" data-id="' + CSM.esc(f.id) + '"></td>' +
                    '<td><span class="badge bg-azure-lt">' + CSM.esc(kindLabel(f.kind)) + '</span></td>' +
                    '<td><code>' + CSM.esc(f.original_path) + '</code></td>' +
                    '<td data-sort="' + (f.size || 0) + '">' + formatSize(f.size || 0) + '</td>' +
                    '<td data-timestamp="' + CSM.esc(f.quarantined_at || '') + '" class="text-nowrap small">' + CSM.fmtDate(f.quarantined_at) + '</td>' +
                    '<td>' + stateBadge(f.live_state) + '</td>' +
                    '<td class="small text-wrap csm-tw-320">' + CSM.esc(f.reason || '') + '</td>' +
                    '<td class="text-nowrap">' +
                    '<button class="btn btn-sm btn-ghost-secondary me-1 cleanup-file-view" data-id="' + CSM.esc(f.id) + '" data-path="' + CSM.esc(f.original_path) + '"><i class="ti ti-eye"></i>&nbsp;View</button>' +
                    '<button class="btn btn-sm btn-warning cleanup-file-restore" data-id="' + CSM.esc(f.id) + '"><i class="ti ti-restore"></i>&nbsp;Restore</button>' +
                    '</td></tr>';
            }
            html += '</tbody></table></div>';
            el.innerHTML = html;
            new CSM.Table({ tableId: 'cleanup-files-table', perPage: 25, searchId: 'cleanup-files-search', sortable: true, stateKey: 'csm-cleanup-files-table' });
            bindFileBackupActions(el);
        }).catch(function() {
            CSM.loadError(document.getElementById('cleanup-files-content'), loadFileBackups);
        });
    }

    function bindFileBackupActions(el) {
        var selectAll = document.getElementById('cleanup-files-select-all');
        if (selectAll) {
            selectAll.addEventListener('change', function() {
                el.querySelectorAll('.cleanup-file-cb').forEach(function(cb) { cb.checked = selectAll.checked; });
                updateFileBulkButtons();
            });
        }
        el.querySelectorAll('.cleanup-file-cb').forEach(function(cb) {
            cb.addEventListener('change', updateFileBulkButtons);
        });
        el.querySelectorAll('.cleanup-file-view').forEach(function(btn) {
            btn.addEventListener('click', function() {
                viewFileBackup(this.getAttribute('data-id'), this.getAttribute('data-path'));
            });
        });
        el.querySelectorAll('.cleanup-file-restore').forEach(function(btn) {
            btn.addEventListener('click', function() {
                restoreFileBackup(this.getAttribute('data-id'));
            });
        });
    }

    function updateFileBulkButtons() {
        var checked = document.querySelectorAll('.cleanup-file-cb:checked');
        var restoreBtn = document.getElementById('cleanup-files-restore-btn');
        var deleteBtn = document.getElementById('cleanup-files-delete-btn');
        if (restoreBtn) {
            restoreBtn.classList.toggle('d-none', checked.length === 0);
            restoreBtn.innerHTML = '<i class="ti ti-restore"></i>&nbsp;Restore ' + checked.length;
        }
        if (deleteBtn) {
            deleteBtn.classList.toggle('d-none', checked.length === 0);
            deleteBtn.innerHTML = '<i class="ti ti-trash"></i>&nbsp;Delete ' + checked.length;
        }
    }

    function viewFileBackup(id, path) {
        getJSON('/api/v1/quarantine-preview?id=' + encodeURIComponent(id)).then(function(data) {
            var info = data.truncated ? 'first 8KB of ' + formatSize(data.total_size) : formatSize(data.total_size || 0);
            showPreview(path, info, data.preview || '');
        }).catch(function(e) {
            CSM.toast('Preview failed: ' + e.message, 'error');
        });
    }

    function restoreFileBackup(id) {
        CSM.confirm('Restore this file backup? A re-scan is recommended after restore.').then(function() {
            CSM.post('/api/v1/quarantine-restore', { id: id }).then(function(data) {
                CSM.toast('Restored: ' + data.path, 'success');
                loadFileBackups();
            }).catch(function(e) {
                CSM.toast('Restore failed: ' + e.message, 'error');
            });
        }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
    }

    function selectedFileIDs() {
        var ids = [];
        document.querySelectorAll('.cleanup-file-cb:checked').forEach(function(cb) {
            ids.push(cb.getAttribute('data-id'));
        });
        return ids;
    }

    function withFileBulkButtons(activeID, busyHTML, fn) {
        var buttonIDs = ['cleanup-files-restore-btn', 'cleanup-files-delete-btn'];
        var states = [];
        var activeBtn = document.getElementById(activeID);
        if (activeBtn && activeBtn.disabled) return Promise.resolve();
        buttonIDs.forEach(function(id) {
            var btn = document.getElementById(id);
            if (!btn) return;
            states.push({ btn: btn, disabled: btn.disabled, html: btn.innerHTML });
            btn.disabled = true;
        });
        if (activeBtn) activeBtn.innerHTML = busyHTML;
        return Promise.resolve().then(fn).finally(function() {
            states.forEach(function(state) {
                state.btn.disabled = state.disabled;
                state.btn.innerHTML = state.html;
            });
            updateFileBulkButtons();
        });
    }

    function restoreSelectedFileBackups() {
        var ids = selectedFileIDs();
        if (ids.length === 0) return;
        CSM.confirm('Restore ' + ids.length + ' file backup(s)? A re-scan is recommended after restore.').then(function() {
            withFileBulkButtons('cleanup-files-restore-btn', '<i class="ti ti-restore"></i>&nbsp;Restoring...', function() {
                var chain = Promise.resolve();
                var succeeded = 0;
                var failed = 0;
                ids.forEach(function(id) {
                    chain = chain.then(function() {
                        return CSM.post('/api/v1/quarantine-restore', { id: id })
                            .then(function() { succeeded++; })
                            .catch(function() { failed++; });
                    });
                });
                return chain.then(function() {
                    CSM.toast('Restored ' + succeeded + ' of ' + (succeeded + failed), failed ? 'warning' : 'success');
                    return loadFileBackups();
                });
            });
        }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
    }

    function deleteSelectedFileBackups() {
        var ids = selectedFileIDs();
        if (ids.length === 0) return;
        CSM.confirm('Permanently delete ' + ids.length + ' file backup(s)?').then(function() {
            withFileBulkButtons('cleanup-files-delete-btn', '<i class="ti ti-trash"></i>&nbsp;Deleting...', function() {
                return CSM.post('/api/v1/quarantine/bulk-delete', { ids: ids }).then(function(data) {
                    CSM.toast('Deleted ' + data.count + ' file backup(s)', 'success');
                    return loadFileBackups();
                }).catch(function(e) {
                    CSM.toast('Delete failed: ' + e.message, 'error');
                });
            });
        }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
    }

    function loadDBBackups() {
        getJSON('/api/v1/db-object-backups').then(function(items) {
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
                html += '<tr>' +
                    '<td><code>' + CSM.esc(b.account) + '</code></td>' +
                    '<td><code>' + CSM.esc(b.schema) + '</code></td>' +
                    '<td><span class="badge bg-azure-lt">' + CSM.esc(b.kind) + '</span></td>' +
                    '<td><code>' + CSM.esc(b.name) + '</code></td>' +
                    '<td data-timestamp="' + CSM.esc(b.dropped_at || '') + '" class="text-nowrap small">' + CSM.fmtDate(b.dropped_at) + '</td>' +
                    '<td>' + CSM.esc(b.dropped_by || '') + '</td>' +
                    '<td data-sort="' + (b.body_bytes || 0) + '">' + formatSize(b.body_bytes || 0) + '</td>' +
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
        }).catch(function() {
            CSM.loadError(document.getElementById('cleanup-db-content'), loadDBBackups);
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
            var info = data.truncated ? 'first 8KB of ' + formatSize(data.total_size) : formatSize(data.total_size || 0);
            showPreview(title, info, data.preview || '');
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

    var restoreSelectedBtn = document.getElementById('cleanup-files-restore-btn');
    if (restoreSelectedBtn) restoreSelectedBtn.addEventListener('click', restoreSelectedFileBackups);
    var deleteSelectedBtn = document.getElementById('cleanup-files-delete-btn');
    if (deleteSelectedBtn) deleteSelectedBtn.addEventListener('click', deleteSelectedFileBackups);

    loadFileBackups();
    loadDBBackups();
})();
