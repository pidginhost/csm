// CSM Firewall page

function loadStatus(){
    fetch(CSM.apiUrl('/api/v1/firewall/status'),{credentials:'same-origin'}).then(function(r){return r.json()}).then(function(d){
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
        var passiveFtp = d.passive_ftp && d.passive_ftp.length >= 2 ? d.passive_ftp[0]+'-'+d.passive_ftp[1] : 'not configured';
        t1 += '<tr><td class="text-muted">Passive FTP</td><td><code>'+passiveFtp+'</code></td></tr>';
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
    }).catch(function(){ CSM.loadError(document.getElementById('fw-config'), loadStatus); });
}

function loadSubnets(){
    fetch(CSM.apiUrl('/api/v1/firewall/subnets'),{credentials:'same-origin'}).then(function(r){return r.json()}).then(function(subs){
        var el = document.getElementById('subnet-content');
        if(!subs||subs.length===0){el.innerHTML='<div class="card-body text-center text-muted py-3">No blocked subnets.</div>';return;}
        var h='<div class="table-responsive"><table class="table table-vcenter card-table" id="subnets-table"><thead><tr><th>CIDR</th><th>Location</th><th>Reason</th><th>Blocked</th><th>Action</th></tr></thead><tbody>';
        for(var i=0;i<subs.length;i++){
            // Use the network base address (strip /mask) for GeoIP lookup
            var baseIP = subs[i].cidr.replace(/\/.*/, '');
            h+='<tr><td><code class="csm-copy" title="Click to copy">'+CSM.esc(subs[i].cidr)+'</code></td><td class="small text-muted text-nowrap geo-cell" data-ip="'+CSM.esc(baseIP)+'"></td><td class="small">'+CSM.esc(subs[i].reason)+'</td><td class="small text-muted">'+CSM.esc(subs[i].time_ago)+'</td><td><button class="btn btn-sm btn-ghost-secondary remove-subnet-btn" data-cidr="'+CSM.esc(subs[i].cidr)+'" title="Remove subnet block from firewall">Remove</button></td></tr>';
        }
        h+='</tbody></table></div>';
        el.innerHTML=h;
        new CSM.Table({ tableId: 'subnets-table', sortable: true });
        enrichBlockedGeoIP(el);
        el.querySelectorAll('.remove-subnet-btn').forEach(function(btn) {
            btn.addEventListener('click', function() { removeSubnet(this.getAttribute('data-cidr')); });
        });
    }).catch(function(){ CSM.loadError(document.getElementById('subnet-content'), loadSubnets); });
}

function removeSubnet(cidr){
    CSM.confirm('Remove subnet block '+cidr+'?').then(function(){
        CSM.post('/api/v1/firewall/remove-subnet',{cidr:cidr}).then(function(){loadSubnets();loadStatus();}).catch(function(e){ CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
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
            loadSubnets();loadStatus();
        }).catch(function(e){ CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
});

function loadBlocked(){
    fetch(CSM.apiUrl('/api/v1/blocked-ips'),{credentials:'same-origin'}).then(function(r){return r.json()}).then(function(ips){
        var el=document.getElementById('blocked-content');
        if(!ips||ips.length===0){el.innerHTML='<div class="card-body text-center text-muted py-3">No blocked IPs.</div>';return;}
        var h='<div class="table-responsive"><table class="table table-vcenter card-table table-sm" id="blocked-table"><thead><tr>';
        h+='<th><input type="checkbox" class="form-check-input" id="blocked-select-all"></th>';
        h+='<th>IP</th><th>Location</th><th>Reason</th><th>Expires</th><th>Action</th></tr></thead><tbody>';
        for(var i=0;i<ips.length;i++){
            h+='<tr><td><input type="checkbox" class="form-check-input blocked-cb" data-ip="'+CSM.esc(ips[i].ip)+'"></td>';
            h+='<td><code class="csm-copy" title="Click to copy">'+CSM.esc(ips[i].ip)+'</code></td><td class="small text-muted text-nowrap geo-cell" data-ip="'+CSM.esc(ips[i].ip)+'"></td><td class="small">'+CSM.esc(ips[i].reason)+'</td><td class="small text-muted">'+CSM.esc(ips[i].expires_in)+'</td><td><button class="btn btn-sm btn-ghost-secondary fw-unblock-btn" data-ip="'+CSM.esc(ips[i].ip)+'" title="Remove firewall block for this IP">Unblock</button></td></tr>';
        }
        h+='</tbody></table></div>';
        el.innerHTML=h;
        if(typeof CSM!=='undefined'&&CSM.Table) new CSM.Table({tableId:'blocked-table',perPage:25,searchId:'blocked-search',sortable:true});
        enrichBlockedGeoIP(el);
        el.querySelectorAll('.fw-unblock-btn').forEach(function(btn) {
            btn.addEventListener('click', function() { unblockIP(this.getAttribute('data-ip')); });
        });
        var selectAll = document.getElementById('blocked-select-all');
        if (selectAll) {
            selectAll.addEventListener('change', function() {
                var checked = this.checked;
                el.querySelectorAll('.blocked-cb').forEach(function(cb) {
                    if (cb.closest('tr').style.display !== 'none') cb.checked = checked;
                });
                updateBulkUnblock();
            });
        }
        el.querySelectorAll('.blocked-cb').forEach(function(cb) {
            cb.addEventListener('change', updateBulkUnblock);
        });
    }).catch(function(){ CSM.loadError(document.getElementById('blocked-content'), loadBlocked); });
}

function getVisibleChecked() {
    var all = document.querySelectorAll('.blocked-cb:checked');
    var visible = [];
    all.forEach(function(cb) {
        if (cb.closest('tr').style.display !== 'none') visible.push(cb);
    });
    return visible;
}

function updateBulkUnblock() {
    var checked = getVisibleChecked();
    var btn = document.getElementById('bulk-unblock-btn');
    if (btn) {
        btn.classList.toggle('d-none', checked.length === 0);
        btn.textContent = 'Unblock ' + checked.length + ' IPs';
    }
}

function bulkUnblock() {
    var checked = getVisibleChecked();
    if (checked.length === 0) return;
    var ips = [];
    checked.forEach(function(cb) { ips.push(cb.dataset.ip); });
    CSM.confirm('Unblock ' + ips.length + ' IPs?').then(function() {
        CSM.post('/api/v1/unblock-bulk', { ips: ips }).then(function(data) {
            CSM.toast('Unblocked ' + (data.succeeded || 0) + ' of ' + (data.total || 0) + ' IPs', 'success');
            loadBlocked(); loadStatus();
        }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
}

function unblockIP(ip){
    CSM.confirm('Unblock '+ip+'?').then(function(){
        CSM.post('/api/v1/unblock-ip',{ip:ip}).then(function(){loadBlocked();loadStatus();}).catch(function(e){ CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
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
            loadBlocked();loadStatus();
        }).catch(function(e){ CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
});

// --- Whitelist management ---
function loadWhitelist(){
    fetch(CSM.apiUrl('/api/v1/threat/whitelist'),{credentials:'same-origin'}).then(function(r){return r.json()}).then(function(ips){
        var el=document.getElementById('whitelist-content');
        if(!ips||ips.length===0){el.innerHTML='<div class="card-body text-center text-muted py-3">No whitelisted IPs.</div>';return;}
        var h='<div class="table-responsive"><table class="table table-vcenter card-table table-sm" id="whitelist-table"><thead><tr><th>IP</th><th>Action</th></tr></thead><tbody>';
        for(var i=0;i<ips.length;i++){
            var wl = ips[i];
            var ip = typeof wl === 'string' ? wl : wl.ip;
            var typeInfo = '';
            if (wl.permanent) typeInfo = '<span class="badge bg-green-lt ms-2">Permanent</span>';
            else if (wl.expires_at) typeInfo = '<span class="badge bg-yellow-lt ms-2">Expires ' + CSM.fmtDate(wl.expires_at) + '</span>';
            h+='<tr><td><code>'+CSM.esc(ip)+'</code>' + typeInfo + '</td><td><button class="btn btn-sm btn-ghost-secondary wl-remove-btn" data-ip="'+CSM.esc(ip)+'" title="Remove IP from whitelist">Remove</button></td></tr>';
        }
        h+='</tbody></table></div>';
        el.innerHTML=h;
        new CSM.Table({ tableId: 'whitelist-table', sortable: true });
        el.querySelectorAll('.wl-remove-btn').forEach(function(btn){
            btn.addEventListener('click',function(){ removeWhitelist(this.getAttribute('data-ip')); });
        });
    }).catch(function(){ CSM.loadError(document.getElementById('whitelist-content'), loadWhitelist); });
}

function removeWhitelist(ip){
    CSM.confirm('Remove '+ip+' from whitelist?').then(function(){
        CSM.post('/api/v1/threat/unwhitelist-ip',{ip:ip}).then(function(){
            CSM.toast('Removed from whitelist','success');
            loadWhitelist();loadStatus();
        }).catch(function(e){ CSM.toast('Error: '+e,'error'); });
    }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
}

document.getElementById('whitelist-form').addEventListener('submit',function(e){
    e.preventDefault();
    var ip=document.getElementById('whitelist-ip').value.trim();
    if(!ip)return;
    CSM.confirm('Whitelist '+ip+'?\n\nThis will unblock the IP and prevent future auto-blocking.').then(function(){
        CSM.post('/api/v1/threat/whitelist-ip',{ip:ip}).then(function(){
            document.getElementById('whitelist-ip').value='';
            CSM.toast('IP whitelisted','success');
            loadWhitelist();loadBlocked();loadStatus();
        }).catch(function(e){ CSM.toast('Error: '+e,'error'); });
    }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
});

// --- GeoIP enrichment (batch) ---
function enrichBlockedGeoIP(container) {
    var cells = container.querySelectorAll('.geo-cell');
    if (cells.length === 0) return;

    var ips = [];
    var cellMap = {};
    for (var i = 0; i < cells.length; i++) {
        var ip = cells[i].dataset.ip;
        if (ip) {
            ips.push(ip);
            cellMap[ip] = cellMap[ip] || [];
            cellMap[ip].push(cells[i]);
        }
    }
    if (ips.length === 0) return;

    CSM.post(CSM.apiUrl('/api/v1/geoip/batch'), { ips: ips })
        .then(function(data) {
            var results = data.results || {};
            for (var ip in results) {
                var geo = results[ip];
                var html = '-';
                if (!geo.error && geo.country) {
                    html = CSM.countryFlag(geo.country) + ' ' + CSM.esc(geo.country);
                    if (geo.as_org) html += ' <span class="text-muted small">' + CSM.esc(geo.as_org) + '</span>';
                }
                var targets = cellMap[ip] || [];
                for (var j = 0; j < targets.length; j++) {
                    targets[j].innerHTML = html;
                }
            }
        })
        .catch(function() {
            // Fallback: per-IP requests on batch failure
            enrichBlockedGeoIPFallback(cells);
        });
}

function enrichBlockedGeoIPFallback(cells) {
    var idx = 0;
    function next() {
        if (idx >= cells.length) return;
        var cell = cells[idx++];
        var ip = cell.dataset.ip;
        if (!ip) { next(); return; }
        fetch(CSM.apiUrl('/api/v1/geoip?ip=' + encodeURIComponent(ip)), { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(geo) {
                var html = '-';
                if (geo.country) {
                    html = CSM.countryFlag(geo.country) + ' ' + CSM.esc(geo.country);
                    if (geo.as_org) html += ' <span class="text-muted small">' + CSM.esc(geo.as_org) + '</span>';
                }
                cell.innerHTML = html;
            })
            .catch(function() { cell.textContent = '-'; })
            .finally(function() { setTimeout(next, 50); });
    }
    for (var c = 0; c < 3 && c < cells.length; c++) { next(); }
}

// Bind bulk unblock button (replaces inline onclick for CSP compliance)
var bulkUnblockBtn = document.getElementById('bulk-unblock-btn');
if (bulkUnblockBtn) bulkUnblockBtn.addEventListener('click', bulkUnblock);

loadStatus();loadSubnets();loadBlocked();loadWhitelist();
