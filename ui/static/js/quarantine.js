// CSM Quarantine page

function loadQuarantine() {
    fetch('/api/v1/quarantine', {credentials:'same-origin'}).then(function(r){return r.json()}).then(function(files){
        var el = document.getElementById('quarantine-content');
        var title = document.querySelector('.card-title');
        if (title) title.innerHTML = '<i class="ti ti-lock"></i>&nbsp;Quarantined Files (' + (files ? files.length : 0) + ')';
        if (!files || files.length === 0) { el.innerHTML = '<div class="card-body text-center text-muted py-4"><i class="ti ti-circle-check"></i> No quarantined files.</div>'; return; }
        var html = '<div class="table-responsive"><table class="table table-vcenter card-table" id="quarantine-table"><thead><tr><th>Original Path</th><th>Size</th><th>Quarantined</th><th>Reason</th><th>Action</th></tr></thead><tbody>';
        for (var i = 0; i < files.length; i++) {
            var f = files[i];
            html += '<tr><td><code>'+CSM.esc(f.original_path)+'</code></td><td>'+formatSize(f.size)+'</td><td class="text-nowrap"><span class="text-muted small">'+CSM.esc(f.quarantined_at)+'</span></td><td class="small">'+CSM.esc(f.reason)+'</td><td><button class="btn btn-sm btn-ghost-secondary me-1 view-btn" data-id="'+CSM.esc(f.id)+'" data-path="'+CSM.esc(f.original_path)+'">View</button><button class="btn btn-sm btn-warning restore-btn" data-id="'+CSM.esc(f.id)+'">Restore</button></td></tr>';
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
    }).catch(function(){ CSM.loadError(document.getElementById('quarantine-content'), loadQuarantine); });
}
function restoreFile(id) {
    CSM.confirm('Restore this file? A re-scan is recommended after restore.').then(function() {
        CSM.post('/api/v1/quarantine-restore', {id: id}).then(function(data){
            if (data.error) { CSM.toast('Error: ' + data.error, 'error'); }
            else { CSM.toast('Restored: ' + data.path, 'success'); }
            loadQuarantine();
        }).catch(function(e){ CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(){});
}
function viewFile(id, path) {
    fetch(CSM.apiUrl('/api/v1/quarantine-preview?id=' + encodeURIComponent(id)), { credentials: 'same-origin' })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            if (data.error) { CSM.toast('Error: ' + data.error, 'error'); return; }
            var title = CSM.esc(path);
            var info = data.truncated ? ' (first 8KB of ' + CSM.formatSize(data.total_size) + ')' : '';
            var body = document.getElementById('csm-confirm-body');
            var modal = document.getElementById('csm-confirm-modal');
            if (body && modal) {
                // Close any existing modal first to prevent backdrop leak
                var existingBackdrop = document.querySelector('.modal-backdrop');
                if (existingBackdrop) existingBackdrop.remove();
                if (modal.classList.contains('show')) {
                    modal.classList.remove('show');
                    modal.style.display = 'none';
                }

                body.innerHTML = '<div style="margin-bottom:8px"><strong>' + title + '</strong><span class="text-muted small">' + info + '</span></div>' +
                    '<pre style="max-height:400px;overflow:auto;background:var(--tblr-bg-surface);padding:8px;border-radius:4px;font-size:0.75rem;white-space:pre-wrap;word-break:break-all">' + CSM.esc(data.preview) + '</pre>';
                var ok = document.getElementById('csm-confirm-ok');
                var cancel = document.getElementById('csm-confirm-cancel');
                if (ok) ok.textContent = 'Close';
                if (cancel) cancel.style.display = 'none';
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
                    if (ok) { ok.textContent = 'OK'; ok.removeEventListener('click', closeModal); }
                    if (cancel) cancel.style.display = '';
                    backdrop.remove();
                }
                if (ok) ok.addEventListener('click', closeModal);
            }
        })
        .catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
}
var formatSize = CSM.formatSize;
loadQuarantine();
