// CSM Quarantine page

function loadQuarantine() {
    fetch('/api/v1/quarantine', {credentials:'same-origin'}).then(function(r){return r.json()}).then(function(files){
        var el = document.getElementById('quarantine-content');
        if (!files || files.length === 0) { el.innerHTML = '<div class="card-body text-center text-muted py-4"><i class="ti ti-circle-check"></i> No quarantined files.</div>'; return; }
        var html = '<div class="table-responsive"><table class="table table-vcenter card-table" id="quarantine-table"><thead><tr><th>Original Path</th><th>Size</th><th>Quarantined</th><th>Reason</th><th>Action</th></tr></thead><tbody>';
        for (var i = 0; i < files.length; i++) {
            var f = files[i];
            html += '<tr><td><code>'+CSM.esc(f.original_path)+'</code></td><td>'+formatSize(f.size)+'</td><td class="text-nowrap"><span class="text-muted small">'+CSM.esc(f.quarantined_at)+'</span></td><td class="small">'+CSM.esc(f.reason)+'</td><td><button class="btn btn-sm btn-warning restore-btn" data-id="'+CSM.esc(f.id)+'">Restore</button></td></tr>';
        }
        html += '</tbody></table></div>';
        el.innerHTML = html;
        // Initialize table component after DOM is ready
        new CSM.Table({ tableId: 'quarantine-table', perPage: 25, searchId: 'quarantine-search', sortable: true });
        // Bind restore buttons after DOM insertion
        el.querySelectorAll('.restore-btn').forEach(function(btn) {
            btn.addEventListener('click', function() { restoreFile(this.getAttribute('data-id')); });
        });
    }).catch(function(){ document.getElementById('quarantine-content').innerHTML = '<div class="card-body text-center text-danger py-4">Error loading data.</div>'; });
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
function formatSize(b){if(b<1024)return b+'B';if(b<1048576)return(b/1024).toFixed(1)+'KB';return(b/1048576).toFixed(1)+'MB';}
loadQuarantine();
