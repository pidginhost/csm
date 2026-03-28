// CSM Firewall page

function loadStatus(){
    fetch('/api/v1/firewall/status',{credentials:'same-origin'}).then(function(r){return r.json()}).then(function(d){
        document.getElementById('fw-enabled').innerHTML = d.enabled ? '<span class="text-success">ACTIVE</span>' : '<span class="text-muted">DISABLED</span>';
        document.getElementById('fw-blocked').textContent = d.blocked_count;
        document.getElementById('fw-subnets').textContent = d.blocked_net_count;
        document.getElementById('fw-allowed').textContent = d.allowed_count;
        function portList(ports){return '<code class="small">'+(ports||[]).join(', ')+'</code>';}
        var t1 = '<tr><td class="text-muted">TCP In</td><td>'+portList(d.tcp_in)+'</td></tr>';
        t1 += '<tr><td class="text-muted">TCP Out</td><td>'+portList(d.tcp_out)+'</td></tr>';
        t1 += '<tr><td class="text-muted">UDP In</td><td>'+portList(d.udp_in)+'</td></tr>';
        t1 += '<tr><td class="text-muted">UDP Out</td><td>'+portList(d.udp_out)+'</td></tr>';
        t1 += '<tr><td class="text-muted">Restricted</td><td><code class="small">'+CSM.esc((d.restricted_tcp||[]).join(', '))+'</code></td></tr>';
        t1 += '<tr><td class="text-muted">Passive FTP</td><td><code>'+d.passive_ftp[0]+'-'+d.passive_ftp[1]+'</code></td></tr>';
        var infraList = (d.infra_ips||[]);
        t1 += '<tr><td class="text-muted">Infra IPs</td><td>'+( infraList.length > 0 ? '<code class="small">'+CSM.esc(infraList.join(', '))+'</code>' : '<span class="text-danger">none configured</span>')+'</td></tr>';
        document.getElementById('fw-config-table').innerHTML = t1;
        var t2 = '<tr><td class="text-muted">Conn Rate</td><td>'+d.conn_rate_limit+'/min per IP</td></tr>';
        t2 += '<tr><td class="text-muted">Conn Limit</td><td>'+(d.conn_limit||'disabled')+'</td></tr>';
        t2 += '<tr><td class="text-muted">SYN Flood</td><td>'+(d.syn_flood_protection?'<span class="text-success">on</span>':'off')+'</td></tr>';
        t2 += '<tr><td class="text-muted">UDP Flood</td><td>'+(d.udp_flood?'<span class="text-success">on</span>':'off')+'</td></tr>';
        t2 += '<tr><td class="text-muted">SMTP Block</td><td>'+(d.smtp_block?'<span class="text-success">on</span>':'off')+'</td></tr>';
        t2 += '<tr><td class="text-muted">IPv6</td><td>'+(d.ipv6?'<span class="text-success">on</span>':'off')+'</td></tr>';
        t2 += '<tr><td class="text-muted">Drop Logging</td><td>'+(d.log_dropped?'on':'off')+'</td></tr>';
        t2 += '<tr><td class="text-muted">Deny Limit</td><td>'+(d.deny_ip_limit||'unlimited')+'</td></tr>';
        document.getElementById('fw-config-table2').innerHTML = t2;
    }).catch(function(){ document.getElementById('fw-config-table').innerHTML = '<tr><td colspan="2" class="text-danger">Error loading status.</td></tr>'; });
}

function loadSubnets(){
    fetch('/api/v1/firewall/subnets',{credentials:'same-origin'}).then(function(r){return r.json()}).then(function(subs){
        var el = document.getElementById('subnet-content');
        if(!subs||subs.length===0){el.innerHTML='<div class="card-body text-center text-muted py-3">No blocked subnets.</div>';return;}
        var h='<div class="table-responsive"><table class="table table-vcenter card-table"><thead><tr><th>CIDR</th><th>Reason</th><th>Blocked</th><th>Action</th></tr></thead><tbody>';
        for(var i=0;i<subs.length;i++){
            h+='<tr><td><code>'+CSM.esc(subs[i].cidr)+'</code></td><td class="small">'+CSM.esc(subs[i].reason)+'</td><td class="small text-muted">'+CSM.esc(subs[i].time_ago)+'</td><td><button class="btn btn-sm btn-success remove-subnet-btn" data-cidr="'+CSM.esc(subs[i].cidr)+'">Remove</button></td></tr>';
        }
        h+='</tbody></table></div>';
        el.innerHTML=h;
        // Bind remove buttons after DOM insertion
        el.querySelectorAll('.remove-subnet-btn').forEach(function(btn) {
            btn.addEventListener('click', function() { removeSubnet(this.getAttribute('data-cidr')); });
        });
    }).catch(function(){ document.getElementById('subnet-content').innerHTML = '<div class="card-body text-center text-danger py-3">Error loading subnets.</div>'; });
}

function loadAudit(){
    fetch('/api/v1/firewall/audit?limit=50',{credentials:'same-origin'}).then(function(r){return r.json()}).then(function(entries){
        var el = document.getElementById('audit-content');
        if(!entries||entries.length===0){el.innerHTML='<div class="card-body text-center text-muted py-3">No audit entries.</div>';return;}
        var h='<div class="table-responsive"><table class="table table-vcenter card-table table-sm"><thead><tr><th>Time</th><th>Action</th><th>IP/CIDR</th><th>Reason</th></tr></thead><tbody>';
        for(var i=entries.length-1;i>=0;i--){
            var e=entries[i];
            var cls='';
            if(e.action.indexOf('block')>=0) cls='text-danger';
            else if(e.action.indexOf('allow')>=0) cls='text-success';
            else if(e.action==='flush') cls='text-warning';
            h+='<tr><td class="text-nowrap small text-muted">'+CSM.esc(e.time_ago)+'</td><td class="'+cls+'">'+CSM.esc(e.action)+'</td><td><code>'+CSM.esc(e.ip)+'</code></td><td class="small">'+CSM.esc(e.reason)+'</td></tr>';
        }
        h+='</tbody></table></div>';
        el.innerHTML=h;
    }).catch(function(){ document.getElementById('audit-content').innerHTML = '<div class="card-body text-center text-danger py-3">Error loading audit log.</div>'; });
}

function removeSubnet(cidr){
    CSM.confirm('Remove subnet block '+cidr+'?').then(function(){
        CSM.post('/api/v1/firewall/remove-subnet',{cidr:cidr}).then(function(){loadSubnets();loadStatus();loadAudit();}).catch(function(e){ CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(){});
}

document.getElementById('subnet-form').addEventListener('submit',function(e){
    e.preventDefault();
    var cidr=document.getElementById('subnet-cidr').value.trim();
    var reason=document.getElementById('subnet-reason').value.trim()||'Blocked via CSM Web UI';
    if(!cidr)return;
    CSM.confirm('Block subnet '+cidr+'?').then(function(){
        CSM.post('/api/v1/firewall/deny-subnet',{cidr:cidr,reason:reason}).then(function(){
            document.getElementById('subnet-cidr').value='';
            document.getElementById('subnet-reason').value='';
            loadSubnets();loadStatus();loadAudit();
        }).catch(function(e){ CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(){});
});

function loadBlocked(){
    fetch('/api/v1/blocked-ips',{credentials:'same-origin'}).then(function(r){return r.json()}).then(function(ips){
        var el=document.getElementById('blocked-content');
        if(!ips||ips.length===0){el.innerHTML='<div class="card-body text-center text-muted py-3">No blocked IPs.</div>';return;}
        var h='<div class="table-responsive"><table class="table table-vcenter card-table table-sm" id="blocked-table"><thead><tr>';
        h+='<th><input type="checkbox" class="form-check-input" id="blocked-select-all"></th>';
        h+='<th>IP</th><th>Reason</th><th>Expires</th><th>Action</th></tr></thead><tbody>';
        for(var i=0;i<ips.length;i++){
            h+='<tr><td><input type="checkbox" class="form-check-input blocked-cb" data-ip="'+CSM.esc(ips[i].ip)+'"></td>';
            h+='<td><code>'+CSM.esc(ips[i].ip)+'</code></td><td class="small">'+CSM.esc(ips[i].reason)+'</td><td class="small text-muted">'+CSM.esc(ips[i].expires_in)+'</td><td><button class="btn btn-sm btn-ghost-success fw-unblock-btn" data-ip="'+CSM.esc(ips[i].ip)+'">Unblock</button></td></tr>';
        }
        h+='</tbody></table></div>';
        el.innerHTML=h;
        if(typeof CSM!=='undefined'&&CSM.Table) new CSM.Table({tableId:'blocked-table',perPage:25,searchId:'blocked-search',sortable:true});
        // Bind unblock buttons
        el.querySelectorAll('.fw-unblock-btn').forEach(function(btn) {
            btn.addEventListener('click', function() { unblockIP(this.getAttribute('data-ip')); });
        });
        // Select all checkbox
        var selectAll = document.getElementById('blocked-select-all');
        if (selectAll) {
            selectAll.addEventListener('change', function() {
                var checked = this.checked;
                el.querySelectorAll('.blocked-cb').forEach(function(cb) { cb.checked = checked; });
                updateBulkUnblock();
            });
        }
        el.querySelectorAll('.blocked-cb').forEach(function(cb) {
            cb.addEventListener('change', updateBulkUnblock);
        });
    }).catch(function(){ document.getElementById('blocked-content').innerHTML = '<div class="card-body text-center text-danger py-3">Error loading blocked IPs.</div>'; });
}

function updateBulkUnblock() {
    var checked = document.querySelectorAll('.blocked-cb:checked');
    var btn = document.getElementById('bulk-unblock-btn');
    if (btn) {
        btn.classList.toggle('d-none', checked.length === 0);
        btn.textContent = 'Unblock ' + checked.length + ' IPs';
    }
}

function bulkUnblock() {
    var checked = document.querySelectorAll('.blocked-cb:checked');
    if (checked.length === 0) return;
    var ips = [];
    checked.forEach(function(cb) { ips.push(cb.dataset.ip); });
    CSM.confirm('Unblock ' + ips.length + ' IPs?').then(function() {
        CSM.post('/api/v1/unblock-bulk', { ips: ips }).then(function(data) {
            CSM.toast('Unblocked ' + (data.succeeded || 0) + ' of ' + (data.total || 0) + ' IPs', 'success');
            loadBlocked(); loadStatus(); loadAudit();
        }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
    }).catch(function() {});
}
function unblockIP(ip){
    CSM.confirm('Unblock '+ip+'?').then(function(){
        CSM.post('/api/v1/unblock-ip',{ip:ip}).then(function(){loadBlocked();loadStatus();loadAudit();}).catch(function(e){ CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(){});
}
document.getElementById('block-form').addEventListener('submit',function(e){
    e.preventDefault();
    var ip=document.getElementById('block-ip').value.trim();
    var reason=document.getElementById('block-reason').value.trim()||'Blocked via CSM Web UI';
    if(!ip)return;
    CSM.confirm('Block IP '+ip+'?').then(function(){
        CSM.post('/api/v1/block-ip',{ip:ip,reason:reason}).then(function(){
            document.getElementById('block-ip').value='';
            document.getElementById('block-reason').value='';
            loadBlocked();loadStatus();loadAudit();
        }).catch(function(e){ CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(){});
});

loadStatus();loadSubnets();loadBlocked();loadAudit();
