// CSM Quarantine page

function loadQuarantine() {
    fetch(CSM.apiUrl('/api/v1/quarantine'), {credentials:'same-origin'}).then(function(r){return r.json()}).then(function(files){
        var el = document.getElementById('quarantine-content');
        var title = document.querySelector('.card-title');
        if (title) title.innerHTML = '<i class="ti ti-lock"></i>&nbsp;Quarantined Files (' + (files ? files.length : 0) + ')';
        if (!files || files.length === 0) { el.innerHTML = '<div class="card-body text-center text-muted py-4"><i class="ti ti-circle-check"></i> No quarantined files.</div>'; return; }
        var html = '<div class="table-responsive"><table class="table table-vcenter card-table" id="quarantine-table"><thead><tr><th><input type="checkbox" class="form-check-input" id="q-select-all"></th><th>Original Path</th><th>Size</th><th>Quarantined</th><th>Reason</th><th>Action</th></tr></thead><tbody>';
        for (var i = 0; i < files.length; i++) {
            var f = files[i];
            html += '<tr><td><input type="checkbox" class="form-check-input q-cb" data-id="'+CSM.esc(f.id)+'"></td><td><code>'+CSM.esc(f.original_path)+'</code></td><td>'+formatSize(f.size)+'</td><td class="text-nowrap"><span class="text-muted small">'+CSM.esc(f.quarantined_at)+'</span></td><td class="small">'+CSM.esc(f.reason)+'</td><td><button class="btn btn-sm btn-ghost-secondary me-1 view-btn" data-id="'+CSM.esc(f.id)+'" data-path="'+CSM.esc(f.original_path)+'">View</button><button class="btn btn-sm btn-warning restore-btn" data-id="'+CSM.esc(f.id)+'">Restore</button></td></tr>';
        }
        html += '</tbody></table></div>';
        el.innerHTML = html;
        // Initialize table component after DOM is ready
        new CSM.Table({ tableId: 'quarantine-table', perPage: 25, searchId: 'quarantine-search', sortable: true, stateKey: 'csm-quarantine-table' });
        // Bind restore and view buttons after DOM insertion
        el.querySelectorAll('.restore-btn').forEach(function(btn) {
            btn.addEventListener('click', function() { restoreFile(this.getAttribute('data-id')); });
        });
        el.querySelectorAll('.view-btn').forEach(function(btn) {
            btn.addEventListener('click', function() { viewFile(this.getAttribute('data-id'), this.getAttribute('data-path')); });
        });
        // Bulk restore: select-all and per-row checkboxes
        var selectAll = document.getElementById('q-select-all');
        if (selectAll) {
            selectAll.addEventListener('change', function() {
                var checked = this.checked;
                el.querySelectorAll('.q-cb').forEach(function(cb) { cb.checked = checked; });
                updateBulkRestore();
            });
        }
        el.querySelectorAll('.q-cb').forEach(function(cb) {
            cb.addEventListener('change', updateBulkRestore);
        });
    }).catch(function(){ CSM.loadError(document.getElementById('quarantine-content'), loadQuarantine); });
}
function restoreFile(id) {
    CSM.confirm('Restore this file? A re-scan is recommended after restore.').then(function() {
        CSM.post('/api/v1/quarantine-restore', {id: id}).then(function(data){
            if (data.error) { CSM.toast('Error: ' + data.error, 'error'); }
            else { CSM.toast('Restored: ' + data.path, 'success'); }
            loadQuarantine();
        }).catch(function(e){ CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
}
function viewFile(id, path) {
    fetch(CSM.apiUrl('/api/v1/quarantine-preview?id=' + encodeURIComponent(id)), { credentials: 'same-origin' })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.error) { CSM.toast('Error: ' + data.error, 'error'); return; }
            var info = data.truncated ? ' (first 8KB of ' + formatSize(data.total_size) + ')' : '';
            var preview = data.preview || '(empty file)';

            var modal = document.getElementById('csm-confirm-modal');
            var dialog = modal ? modal.querySelector('.modal-dialog') : null;
            var body = document.getElementById('csm-confirm-body');
            var okBtn = document.getElementById('csm-confirm-ok');
            var cancelBtn = document.getElementById('csm-confirm-cancel');
            if (!modal || !body || !dialog) return;

            // Make modal large for file preview
            dialog.classList.remove('modal-sm');
            dialog.classList.add('modal-lg');

            // Build preview content
            body.textContent = '';
            body.style.whiteSpace = 'normal';
            var header = document.createElement('div');
            header.style.cssText = 'margin-bottom:8px';
            var strong = document.createElement('strong');
            strong.textContent = path;
            header.appendChild(strong);
            if (info) {
                var infoSpan = document.createElement('span');
                infoSpan.className = 'text-muted small ms-2';
                infoSpan.textContent = info;
                header.appendChild(infoSpan);
            }
            body.appendChild(header);

            var pre = document.createElement('pre');
            pre.style.cssText = 'max-height:60vh;overflow:auto;padding:12px;border-radius:4px;font-size:0.75rem;white-space:pre-wrap;word-break:break-all;border:1px solid var(--csm-border);background:var(--csm-bg-card);color:var(--csm-text)';
            pre.textContent = preview;
            body.appendChild(pre);

            if (okBtn) okBtn.textContent = 'Close';
            if (cancelBtn) cancelBtn.style.display = 'none';

            modal.classList.add('show');
            modal.style.display = 'block';
            modal.setAttribute('aria-hidden', 'false');
            var backdrop = document.createElement('div');
            backdrop.className = 'modal-backdrop fade show';
            document.body.appendChild(backdrop);

            function closeModal() {
                modal.classList.remove('show');
                modal.style.display = 'none';
                modal.setAttribute('aria-hidden', 'true');
                // Restore modal to default small size
                dialog.classList.remove('modal-lg');
                dialog.classList.add('modal-sm');
                body.style.whiteSpace = '';
                if (okBtn) { okBtn.textContent = 'OK'; okBtn.removeEventListener('click', closeModal); }
                if (cancelBtn) cancelBtn.style.display = '';
                if (backdrop.parentNode) backdrop.parentNode.removeChild(backdrop);
            }
            if (okBtn) okBtn.addEventListener('click', closeModal);
            backdrop.addEventListener('click', closeModal);
        })
        .catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
}
var formatSize = CSM.formatSize;

function updateBulkRestore() {
    var checked = document.querySelectorAll('.q-cb:checked');
    var btn = document.getElementById('bulk-restore-btn');
    if (btn) {
        btn.classList.toggle('d-none', checked.length === 0);
        btn.textContent = 'Restore ' + checked.length + ' file(s)';
    }
    var delBtn = document.getElementById('bulk-delete-btn');
    if (delBtn) {
        delBtn.classList.toggle('d-none', checked.length === 0);
        delBtn.textContent = 'Delete ' + checked.length + ' file(s)';
    }
}

var bulkRestoreBtn = document.getElementById('bulk-restore-btn');
if (bulkRestoreBtn) {
    bulkRestoreBtn.addEventListener('click', function() {
        var checked = document.querySelectorAll('.q-cb:checked');
        if (checked.length === 0) return;
        var ids = [];
        checked.forEach(function(cb) { ids.push(cb.dataset.id); });
        CSM.confirm('Restore ' + ids.length + ' file(s)? A re-scan is recommended after restore.').then(function() {
            var succeeded = 0, failed = 0;
            var chain = Promise.resolve();
            ids.forEach(function(id) {
                chain = chain.then(function() {
                    return CSM.post('/api/v1/quarantine-restore', {id: id})
                        .then(function() { succeeded++; })
                        .catch(function() { failed++; });
                });
            });
            chain.then(function() {
                CSM.toast('Restored ' + succeeded + ' of ' + (succeeded + failed) + ' file(s)', failed > 0 ? 'warning' : 'success');
                loadQuarantine();
            });
        }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
    });
}

var bulkDeleteBtn = document.getElementById('bulk-delete-btn');
if (bulkDeleteBtn) {
    bulkDeleteBtn.addEventListener('click', function() {
        var checked = document.querySelectorAll('.q-cb:checked');
        if (checked.length === 0) return;
        var ids = [];
        checked.forEach(function(cb) { ids.push(cb.dataset.id); });
        CSM.confirm('Permanently delete ' + ids.length + ' quarantined file(s)?').then(function() {
            CSM.post('/api/v1/quarantine/bulk-delete', { ids: ids }).then(function(data) {
                CSM.toast('Deleted ' + data.count + ' file(s)', 'success');
                loadQuarantine();
            }).catch(function(err) { CSM.toast(err.message || 'Delete failed', 'error'); });
        }).catch(function() { /* cancelled */ });
    });
}

loadQuarantine();
