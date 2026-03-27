// CSM Blocked IPs page
var esc = CSM.esc;

function loadBlocked() {
    fetch('/api/v1/blocked-ips', {credentials:'same-origin'}).then(function(r){return r.json()}).then(function(ips){
        var el = document.getElementById('blocked-content');
        if (!ips || ips.length === 0) { el.innerHTML = '<div class="card-body text-center text-muted py-4"><i class="ti ti-circle-check"></i> No blocked IPs.</div>'; return; }
        var html = '<div class="table-responsive"><table class="table table-vcenter card-table" id="blocked-table"><thead><tr><th style="width:30px"><input type="checkbox" class="form-check-input" id="select-all-blocked"></th><th>IP</th><th>Reason</th><th>Blocked</th><th>Expires</th><th>Action</th></tr></thead><tbody>';
        for (var i = 0; i < ips.length; i++) {
            var ip = ips[i];
            html += '<tr><td><input type="checkbox" class="form-check-input blocked-cb" data-ip="'+esc(ip.ip)+'"></td><td><code>'+esc(ip.ip)+'</code></td><td class="small">'+esc(ip.reason)+'</td><td class="text-nowrap small text-muted">'+esc(ip.blocked_at)+'</td><td>'+esc(ip.expires_in)+'</td><td><button class="btn btn-sm btn-success unblock-btn" data-ip="'+esc(ip.ip)+'">Unblock</button></td></tr>';
        }
        html += '</tbody></table></div>';
        el.innerHTML = html;
        new CSM.Table({ tableId: 'blocked-table', perPage: 25, searchId: 'blocked-search', sortable: true });
        // Bind dynamic elements after insertion
        var selAll = document.getElementById('select-all-blocked');
        if (selAll) selAll.addEventListener('change', toggleAllBlocked);
        el.querySelectorAll('.blocked-cb').forEach(function(cb) { cb.addEventListener('change', updateUnblockCount); });
        el.querySelectorAll('.unblock-btn').forEach(function(btn) {
            btn.addEventListener('click', function() { unblockIP(this.getAttribute('data-ip')); });
        });
    }).catch(function(){ document.getElementById('blocked-content').innerHTML = '<div class="card-body text-center text-danger py-4">Error loading data.</div>'; });
}
function unblockIP(ip) {
    if (!confirm('Unblock ' + ip + '?')) return;
    CSM.post('/api/v1/unblock-ip', {ip: ip}).then(function(data){
        showStatus(data.error || 'Unblocked: ' + ip, !data.error); loadBlocked();
    }).catch(function(e){ showStatus('Error: ' + e, false); });
}
document.getElementById('block-form').addEventListener('submit', function(e) {
    e.preventDefault();
    var ip = document.getElementById('block-ip').value.trim();
    var reason = document.getElementById('block-reason').value.trim() || 'Blocked via CSM Web UI';
    if (!ip) return;
    if (!confirm('Block IP ' + ip + '?')) return;
    CSM.post('/api/v1/block-ip', {ip: ip, reason: reason}).then(function(data){
        showStatus(data.error || 'Blocked: ' + ip, !data.error);
        document.getElementById('block-ip').value = ''; document.getElementById('block-reason').value = '';
        loadBlocked();
    }).catch(function(e){ showStatus('Error: ' + e, false); });
});
function showStatus(msg, ok) {
    var el = document.getElementById('block-status');
    el.textContent = msg; el.className = 'mt-2 small ' + (ok ? 'text-success' : 'text-danger');
    setTimeout(function(){ el.textContent = ''; }, 5000);
}
function toggleAllBlocked() {
    var checked = document.getElementById('select-all-blocked').checked;
    document.querySelectorAll('.blocked-cb').forEach(function(cb){ cb.checked = checked; });
    updateUnblockCount();
}
function updateUnblockCount() {
    var count = document.querySelectorAll('.blocked-cb:checked').length;
    document.getElementById('unblock-count').textContent = count;
    document.getElementById('bulk-unblock').classList.toggle('d-none', count === 0);
}
function bulkUnblock() {
    var cbs = document.querySelectorAll('.blocked-cb:checked');
    var ips = [];
    cbs.forEach(function(cb){ ips.push(cb.getAttribute('data-ip')); });
    if (ips.length === 0) return;
    if (!confirm('Unblock ' + ips.length + ' IP(s)?')) return;
    var done = 0, failed = 0;
    ips.forEach(function(ip) {
        CSM.post('/api/v1/unblock-ip', {ip: ip}).then(function(data){
            done++; if (data.error) failed++;
            if (done === ips.length) { showStatus('Unblocked ' + (done-failed) + '/' + ips.length + ' IPs', failed === 0); loadBlocked(); }
        }).catch(function(){ done++; failed++;
            if (done === ips.length) { showStatus('Unblocked ' + (done-failed) + '/' + ips.length + ' IPs', false); loadBlocked(); }
        });
    });
}
var _bulkUnblockBtn = document.getElementById('bulk-unblock-btn');
if (_bulkUnblockBtn) _bulkUnblockBtn.addEventListener('click', bulkUnblock);
loadBlocked();
