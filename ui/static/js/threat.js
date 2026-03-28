// CSM Threat Intelligence page

var fmtDate = CSM.fmtDate;

function countryFlag(code){
    if(!code||code.length!==2)return '';
    return String.fromCodePoint.apply(null,[].map.call(code.toUpperCase(),function(c){return 127397+c.charCodeAt(0);}));
}

function verdictBadge(v,score){
    var cls = v==='blocked'?'bg-secondary':v==='malicious'?'bg-danger':v==='suspicious'?'bg-warning':'bg-success';
    return '<span class="badge '+cls+'">'+score+'/100</span>';
}

function typeBadges(counts){
    if(!counts)return '—';
    var html='';
    var order=['brute_force','webshell','phishing','c2','waf_block','spam','cpanel_login','file_upload','recon','other'];
    var colors={brute_force:'blue',webshell:'red',phishing:'orange',c2:'purple',waf_block:'cyan',spam:'yellow',cpanel_login:'teal',file_upload:'pink',recon:'lime',other:'secondary'};
    for(var i=0;i<order.length;i++){
        var t=order[i];
        if(counts[t]&&counts[t]>0){
            html+='<span class="badge bg-'+( colors[t]||'secondary')+'-lt me-1">'+t.replace('_',' ')+': '+counts[t]+'</span>';
        }
    }
    return html||'—';
}

// Load stats
fetch('/api/v1/threat/stats',{credentials:'same-origin'}).then(function(r){return r.json()}).then(function(data){
    document.getElementById('stat-total-ips').textContent=data.total_ips||0;
    document.getElementById('stat-24h').textContent=data.last_24h_events||0;
    document.getElementById('stat-7d').textContent=data.last_7d_events||0;
    document.getElementById('stat-blocked').textContent=data.blocked_ips||0;

    // Attack types chart (horizontal bars using inline SVG)
    var typesDiv=document.getElementById('chart-types');
    var byType=data.by_type||{};
    var types=Object.keys(byType).sort(function(a,b){return byType[b]-byType[a]});
    if(types.length===0){typesDiv.innerHTML='<p class="text-muted">No attack data yet</p>';return;}
    var maxVal=byType[types[0]]||1;
    var html='<table class="table table-sm mb-0">';
    for(var i=0;i<types.length;i++){
        var t=types[i], v=byType[t];
        var pct=Math.round(v/maxVal*100);
        html+='<tr><td style="width:120px" class="text-nowrap small">'+CSM.esc(t.replace(/_/g,' '))+'</td>';
        html+='<td><div class="progress progress-sm"><div class="progress-bar bg-primary" style="width:'+pct+'%"></div></div></td>';
        html+='<td style="width:50px" class="text-end small font-monospace">'+v+'</td></tr>';
    }
    html+='</table>';
    typesDiv.innerHTML=html;

    // Hourly chart (simple SVG bars)
    var hourlyDiv=document.getElementById('chart-hourly');
    var buckets=data.hourly_buckets||[];
    if(buckets.length===0){hourlyDiv.innerHTML='<p class="text-muted">No recent data</p>';return;}
    var maxH=Math.max.apply(null,buckets)||1;
    var svgW=hourlyDiv.offsetWidth||500,svgH=180,barW=Math.floor((svgW-20)/24),pad=2;
    var svg='<svg width="'+svgW+'" height="'+svgH+'" style="display:block">';
    for(var h=0;h<24;h++){
        var barH=Math.round(buckets[h]/maxH*(svgH-30));
        var x=10+h*barW;
        var y=svgH-25-barH;
        svg+='<rect x="'+x+'" y="'+y+'" width="'+(barW-pad)+'" height="'+barH+'" fill="var(--tblr-primary)" rx="2">';
        svg+='<title>'+(24-h)+'h ago: '+buckets[h]+' events</title></rect>';
    }
    svg+='<text x="10" y="'+(svgH-5)+'" font-size="11" fill="var(--tblr-muted)">24h ago</text>';
    svg+='<text x="'+(svgW-40)+'" y="'+(svgH-5)+'" font-size="11" fill="var(--tblr-muted)">Now</text>';
    svg+='</svg>';
    hourlyDiv.innerHTML=svg;
}).catch(function(e){console.error('threat stats:',e)});

// Load top attackers
fetch('/api/v1/threat/top-attackers?limit=50',{credentials:'same-origin'}).then(function(r){return r.json()}).then(function(data){
    var tbody=document.getElementById('attackers-tbody');
    if(!data||data.length===0){tbody.innerHTML='<tr><td colspan="9" class="text-center text-muted">No attack data recorded yet</td></tr>';return;}
    var html='';
    for(var i=0;i<data.length;i++){
        var r=data[i];
        var statusBadge=r.currently_blocked?'<span class="badge bg-secondary">Blocked</span>':
                        r.in_threat_db?'<span class="badge bg-danger-lt">Threat DB</span>':'';
        html+='<tr class="ip-row" style="cursor:pointer" data-ip="'+CSM.esc(r.ip)+'">';
        html+='<td><code class="font-monospace">'+CSM.esc(r.ip)+'</code></td>';
        html+='<td class="text-nowrap">'+(r.country?countryFlag(r.country)+' '+CSM.esc(r.country):'')+(r.as_org?' <span class="text-muted small">'+CSM.esc(r.as_org)+'</span>':'')+'</td>';
        html+='<td>'+verdictBadge(r.verdict,r.unified_score)+'</td>';
        html+='<td>'+r.event_count+'</td>';
        html+='<td>'+typeBadges(r.attack_counts)+'</td>';
        html+='<td>'+(r.accounts?Object.keys(r.accounts).length:0)+'</td>';
        html+='<td class="text-nowrap small">'+fmtDate(r.first_seen)+'</td>';
        html+='<td class="text-nowrap small">'+fmtDate(r.last_seen)+'</td>';
        html+='<td>'+statusBadge+'</td>';
        html+='</tr>';
    }
    tbody.innerHTML=html;
    // Click row to lookup
    document.querySelectorAll('.ip-row').forEach(function(row){
        row.addEventListener('click',function(){
            document.getElementById('lookup-ip').value=this.getAttribute('data-ip');
            document.getElementById('lookup-form').dispatchEvent(new Event('submit'));
        });
    });
}).catch(function(e){console.error('top attackers:',e)});

// IP Lookup
document.getElementById('lookup-form').addEventListener('submit',function(e){
    e.preventDefault();
    var ip=document.getElementById('lookup-ip').value.trim();
    if(!ip)return;
    var status=document.getElementById('lookup-status');
    var result=document.getElementById('lookup-result');
    status.textContent='Looking up...';status.className='text-muted small';
    result.classList.add('d-none');

    Promise.all([
        fetch('/api/v1/threat/ip?ip='+encodeURIComponent(ip),{credentials:'same-origin'}).then(function(r){return r.json()}),
        fetch('/api/v1/threat/events?ip='+encodeURIComponent(ip)+'&limit=20',{credentials:'same-origin'}).then(function(r){return r.json()})
    ]).then(function(results){
        var intel=results[0], events=results[1];
        if(intel.error){status.textContent=intel.error;status.className='text-danger small';return;}
        status.textContent='';
        result.classList.remove('d-none');

        var html='<div class="row mb-3">';
        // Score card
        html+='<div class="col-md-3"><div class="card"><div class="card-body text-center">';
        html+='<div class="subheader">Unified Score</div>';
        html+='<div class="h1 mb-1">'+verdictBadge(intel.verdict,intel.unified_score)+'</div>';
        html+='<div class="text-muted small">'+CSM.esc(intel.verdict)+'</div>';
        html+='</div></div></div>';
        // Details
        html+='<div class="col-md-9"><div class="card"><div class="card-body"><table class="table table-sm mb-0">';
        html+='<tr><td class="text-muted" style="width:160px">Local Score</td><td>'+intel.local_score+'/100</td></tr>';
        if(intel.country)html+='<tr><td class="text-muted">Country</td><td>'+countryFlag(intel.country)+' <strong>'+CSM.esc(intel.country)+'</strong>'+(intel.country_name?' — '+CSM.esc(intel.country_name):'')+(intel.city?', '+CSM.esc(intel.city):'')+'</td></tr>';
        if(intel.as_org)html+='<tr><td class="text-muted">ISP / ASN</td><td>'+CSM.esc(intel.as_org)+(intel.asn?' <span class="text-muted">(AS'+intel.asn+')</span>':'')+'</td></tr>';
        if(intel.network)html+='<tr><td class="text-muted">Network</td><td><code>'+CSM.esc(intel.network)+'</code></td></tr>';
        html+='<tr><td class="text-muted">AbuseIPDB Score</td><td>'+(intel.abuse_score>=0?intel.abuse_score+'/100':'Not cached')+'</td></tr>';
        if(intel.abuse_category)html+='<tr><td class="text-muted">AbuseIPDB Category</td><td>'+CSM.esc(intel.abuse_category)+'</td></tr>';
        html+='<tr><td class="text-muted">In Threat DB</td><td>'+(intel.in_threat_db?'<span class="badge bg-danger">Yes</span> ('+CSM.esc(intel.threat_db_source)+')':'No')+'</td></tr>';
        if(intel.currently_blocked){
            var blockType=intel.block_permanent?'<span class="badge bg-dark">Permanent</span>':'<span class="badge bg-warning">Temporary</span>';
            html+='<tr><td class="text-muted">Block Status</td><td><span class="badge bg-secondary">Blocked</span> '+blockType+'</td></tr>';
            if(intel.block_reason)html+='<tr><td class="text-muted">Block Reason</td><td class="small">'+CSM.esc(intel.block_reason)+'</td></tr>';
            if(intel.blocked_at)html+='<tr><td class="text-muted">Blocked At</td><td>'+fmtDate(intel.blocked_at)+'</td></tr>';
            if(intel.block_expires_at && !intel.block_permanent)html+='<tr><td class="text-muted">Expires At</td><td>'+fmtDate(intel.block_expires_at)+'</td></tr>';
        } else {
            html+='<tr><td class="text-muted">Block Status</td><td>Not blocked</td></tr>';
        }
        if(intel.attack_record){
            var rec=intel.attack_record;
            html+='<tr><td class="text-muted">Events</td><td>'+rec.event_count+'</td></tr>';
            html+='<tr><td class="text-muted">Attack Types</td><td>'+typeBadges(rec.attack_counts)+'</td></tr>';
            html+='<tr><td class="text-muted">Accounts Targeted</td><td>'+(rec.accounts?Object.keys(rec.accounts).join(', '):'—')+'</td></tr>';
            html+='<tr><td class="text-muted">First Seen</td><td>'+fmtDate(rec.first_seen)+'</td></tr>';
            html+='<tr><td class="text-muted">Last Seen</td><td>'+fmtDate(rec.last_seen)+'</td></tr>';
        }
        html+='</table>';
        html+='<div class="mt-3 d-flex gap-2 flex-wrap">';
        html+='<button class="btn btn-outline-primary btn-sm clear-ip-btn" data-ip="'+CSM.esc(intel.ip)+'"><i class="ti ti-eraser"></i>&nbsp;Unblock &amp; Clear</button>';
        html+='<button class="btn btn-outline-warning btn-sm temp-wl-btn" data-ip="'+CSM.esc(intel.ip)+'"><i class="ti ti-clock"></i>&nbsp;Temp Whitelist (24h)</button>';
        html+='<button class="btn btn-success btn-sm perm-wl-btn" data-ip="'+CSM.esc(intel.ip)+'"><i class="ti ti-shield-check"></i>&nbsp;Permanent Whitelist</button>';
        html+='</div>';
        html+='</div></div></div>';
        html+='</div>';

        // Events timeline
        if(events&&events.length>0){
            html+='<div class="card mt-2"><div class="card-header"><h3 class="card-title">Recent Events</h3></div>';
            html+='<div class="table-responsive"><table class="table table-sm table-vcenter card-table">';
            html+='<thead><tr><th>Time</th><th>Type</th><th>Check</th><th>Account</th><th>Message</th></tr></thead><tbody>';
            for(var i=0;i<events.length;i++){
                var ev=events[i];
                html+='<tr><td class="text-nowrap small">'+fmtDate(ev.ts)+'</td>';
                html+='<td><span class="badge bg-azure-lt">'+CSM.esc((ev.type||'').replace(/_/g,' '))+'</span></td>';
                html+='<td><code class="small">'+CSM.esc(ev.check)+'</code></td>';
                html+='<td>'+CSM.esc(ev.account||'—')+'</td>';
                html+='<td class="small">'+CSM.esc(ev.msg||'')+'</td></tr>';
            }
            html+='</tbody></table></div></div>';
        }

        result.innerHTML=html;
        // Bind action buttons after DOM insertion
        var clearBtn=result.querySelector('.clear-ip-btn');
        if(clearBtn) clearBtn.addEventListener('click',function(){clearIP(this.getAttribute('data-ip'));});
        var tempBtn=result.querySelector('.temp-wl-btn');
        if(tempBtn) tempBtn.addEventListener('click',function(){tempWhitelistIP(this.getAttribute('data-ip'));});
        var permBtn=result.querySelector('.perm-wl-btn');
        if(permBtn) permBtn.addEventListener('click',function(){whitelistIP(this.getAttribute('data-ip'));});
    }).catch(function(e){status.textContent='Error: '+e;status.className='text-danger small'});
});

// --- Whitelist management ---
function loadWhitelist() {
    fetch('/api/v1/threat/whitelist',{credentials:'same-origin'}).then(function(r){return r.json()}).then(function(entries){
        var tbody=document.getElementById('wl-tbody');
        if(!entries||entries.length===0){
            tbody.innerHTML='<tr><td colspan="3" class="text-center text-muted">No whitelisted IPs</td></tr>';
            return;
        }
        var html='';
        for(var i=0;i<entries.length;i++){
            var e=entries[i];
            var typeBadge=e.permanent?'<span class="badge bg-success-lt">Permanent</span>':
                '<span class="badge bg-warning-lt">Expires '+fmtDate(e.expires_at)+'</span>';
            html+='<tr><td><code class="font-monospace">'+CSM.esc(e.ip)+'</code></td>';
            html+='<td>'+typeBadge+'</td>';
            html+='<td><button class="btn btn-ghost-danger btn-sm remove-wl-btn" data-ip="'+CSM.esc(e.ip)+'"><i class="ti ti-x"></i>&nbsp;Remove</button></td></tr>';
        }
        tbody.innerHTML=html;
        // Bind remove buttons after DOM insertion
        tbody.querySelectorAll('.remove-wl-btn').forEach(function(btn){
            btn.addEventListener('click',function(){removeWhitelist(this.getAttribute('data-ip'));});
        });
    }).catch(function(){});
}
loadWhitelist();

document.getElementById('add-wl-form').addEventListener('submit',function(e){
    e.preventDefault();
    var ip=document.getElementById('add-wl-ip').value.trim();
    if(!ip)return;
    whitelistIP(ip);
});

function removeWhitelist(ip) {
    CSM.confirm('Remove '+ip+' from whitelist?\n\nThis IP will be subject to threat detection and auto-blocking again.').then(function() {
        CSM.post('/api/v1/threat/unwhitelist-ip',{ip:ip}).then(function(data){
            if(data.error){CSM.toast('Error: '+data.error,'error');return;}
            loadWhitelist();
        }).catch(function(e){CSM.toast('Error: '+e,'error')});
    }).catch(function() {});
}

function clearIP(ip) {
    CSM.confirm('Unblock & Clear '+ip+'?\n\nThis will unblock and remove from all databases, but will NOT whitelist.\nThe IP can be re-blocked if it triggers detections again.\n\nUse this for dynamic IP customers.').then(function() {
        CSM.post('/api/v1/threat/clear-ip',{ip:ip}).then(function(data){
            if(data.error){CSM.toast('Error: '+data.error,'error');return;}
            CSM.toast('IP '+ip+' cleared.\n\nActions: '+(data.actions||[]).join(', '),'success');
            document.getElementById('lookup-form').dispatchEvent(new Event('submit'));
        }).catch(function(e){CSM.toast('Error: '+e,'error')});
    }).catch(function() {});
}

function tempWhitelistIP(ip) {
    CSM.prompt('Temp whitelist '+ip+' for how many hours?','24').then(function(hours) {
        hours=parseInt(hours,10);
        if(isNaN(hours)||hours<1){CSM.toast('Invalid number of hours','warning');return;}
        CSM.post('/api/v1/threat/temp-whitelist-ip',{ip:ip,hours:hours}).then(function(data){
            if(data.error){CSM.toast('Error: '+data.error,'error');return;}
            CSM.toast('IP '+ip+' temp-whitelisted for '+data.hours+'h.\n\nActions: '+(data.actions||[]).join(', '),'success');
            loadWhitelist();
            document.getElementById('lookup-form').dispatchEvent(new Event('submit'));
        }).catch(function(e){CSM.toast('Error: '+e,'error')});
    }).catch(function() {});
}

function whitelistIP(ip) {
    CSM.confirm('Permanently whitelist '+ip+'?\n\nUse this only for static IPs (offices, dedicated servers).\nFor dynamic IPs, use "Temp Whitelist" instead.\n\nThis will:\n- Unblock from firewall\n- Add to permanent allow list\n- Remove from all threat databases\n- Never flag this IP again').then(function() {
        CSM.post('/api/v1/threat/whitelist-ip',{ip:ip}).then(function(data){
            if(data.error){CSM.toast('Error: '+data.error,'error');return;}
            CSM.toast('IP '+ip+' permanently whitelisted.\n\nActions: '+(data.actions||[]).join(', '),'success');
            loadWhitelist();
            document.getElementById('lookup-form').dispatchEvent(new Event('submit'));
        }).catch(function(e){CSM.toast('Error: '+e,'error')});
    }).catch(function() {});
}
