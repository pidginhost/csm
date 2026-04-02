(function(){
'use strict';

function loadStats(){
    fetch(CSM.apiUrl('/api/v1/modsec/stats'),{credentials:'same-origin'})
        .then(function(r){return r.json()})
        .then(function(d){
            document.getElementById('stat-total').textContent=d.total||0;
            document.getElementById('stat-ips').textContent=d.unique_ips||0;
            document.getElementById('stat-escalated').textContent=d.escalated||0;
            document.getElementById('stat-top-rule').textContent=d.top_rule||'--';
        })
        .catch(function(){});
}

function loadBlocked(){
    fetch(CSM.apiUrl('/api/v1/modsec/blocks'),{credentials:'same-origin'})
        .then(function(r){return r.json()})
        .then(function(blocks){
            if(!blocks||blocks.length===0){
                document.getElementById('modsec-content').innerHTML='<div class="card-body text-center text-muted py-3">No ModSecurity blocks in the last 24 hours</div>';
                return;
            }
            var h='<div class="table-responsive"><table class="table table-vcenter card-table table-sm" id="modsec-table">';
            h+='<thead><tr>';
            h+='<th>IP</th><th>Location</th><th>Rule</th><th>Description</th><th>Domains</th><th>Hits</th><th>Last Seen</th><th>Status</th>';
            h+='</tr></thead><tbody>';
            for(var i=0;i<blocks.length;i++){
                var b=blocks[i];
                var statusBadge=b.escalated?'<span class="badge bg-red">Firewall Blocked</span>':'<span class="badge bg-yellow">ModSec Only</span>';
                h+='<tr>';
                h+='<td><code>'+CSM.esc(b.ip)+'</code></td>';
                h+='<td class="geo-cell" data-ip="'+CSM.esc(b.ip)+'"><span class="text-muted">--</span></td>';
                h+='<td><code>'+CSM.esc(b.rule_id)+'</code></td>';
                h+='<td>'+CSM.esc(b.description)+'</td>';
                h+='<td>'+CSM.esc(b.domains)+'</td>';
                h+='<td><strong>'+b.hits+'</strong></td>';
                h+='<td>'+CSM.esc(b.last_seen)+'</td>';
                h+='<td>'+statusBadge+'</td>';
                h+='</tr>';
            }
            h+='</tbody></table></div>';
            document.getElementById('modsec-content').innerHTML=h;
            new CSM.Table({tableId:'modsec-table',perPage:25,searchId:'modsec-search',sortable:true});
            enrichGeoIP(document.getElementById('modsec-content'));
        })
        .catch(function(e){
            document.getElementById('modsec-content').innerHTML='<div class="card-body text-center text-danger py-3">Failed to load: '+CSM.esc(e.message||'unknown error')+'</div>';
        });
}

function loadEvents(){
    fetch(CSM.apiUrl('/api/v1/modsec/events?limit=100'),{credentials:'same-origin'})
        .then(function(r){return r.json()})
        .then(function(events){
            if(!events||events.length===0){
                document.getElementById('modsec-events').innerHTML='<div class="card-body text-center text-muted py-3">No recent events</div>';
                return;
            }
            var h='<div class="table-responsive"><table class="table table-vcenter card-table table-sm" id="events-table">';
            h+='<thead><tr>';
            h+='<th>Time</th><th>IP</th><th>Rule</th><th>Domain</th><th>URI</th><th>Severity</th>';
            h+='</tr></thead><tbody>';
            for(var i=0;i<events.length;i++){
                var e=events[i];
                var sevClass=e.severity==='CRITICAL'?'bg-red':e.severity==='HIGH'?'bg-orange':'bg-yellow';
                h+='<tr>';
                h+='<td class="text-nowrap">'+CSM.esc(e.time)+'</td>';
                h+='<td><code>'+CSM.esc(e.ip)+'</code></td>';
                h+='<td><code>'+CSM.esc(e.rule_id)+'</code></td>';
                h+='<td>'+CSM.esc(e.hostname)+'</td>';
                h+='<td><code>'+CSM.esc(e.uri)+'</code></td>';
                h+='<td><span class="badge '+sevClass+'">'+CSM.esc(e.severity)+'</span></td>';
                h+='</tr>';
            }
            h+='</tbody></table></div>';
            document.getElementById('modsec-events').innerHTML=h;
            new CSM.Table({tableId:'events-table',perPage:25,sortable:true});
        })
        .catch(function(e){
            document.getElementById('modsec-events').innerHTML='<div class="card-body text-center text-danger py-3">Failed to load events</div>';
        });
}

function enrichGeoIP(container){
    var cells=container.querySelectorAll('.geo-cell');
    if(cells.length===0) return;
    var ips=[];
    for(var i=0;i<cells.length;i++) ips.push(cells[i].dataset.ip);
    CSM.post(CSM.apiUrl('/api/v1/geoip/batch'),{ips:ips})
        .then(function(data){
            var results=data.results||{};
            for(var j=0;j<cells.length;j++){
                var ip=cells[j].dataset.ip;
                if(results[ip]){
                    var g=results[ip];
                    cells[j].innerHTML=CSM.countryFlag(g.country)+' '+CSM.esc(g.country);
                    if(g.org) cells[j].innerHTML+='<br><small class="text-muted">'+CSM.esc(g.org)+'</small>';
                }
            }
        })
        .catch(function(){});
}

loadStats();
loadBlocked();
loadEvents();
setInterval(loadStats,30000);
})();
