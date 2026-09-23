// CSM Threat Intelligence page

var fmtDate = CSM.fmtDate;

var _threatAttackerData = [];

// loadThreatStats/loadTopAttackers re-run after a bulk block/whitelist so the
// page updates in place instead of a full reload that would lose the operator's
// attackers-table scroll, filters, and selection. The table is module-scoped so
// a re-render can tear down the previous instance, and the date-filter and URL
// bindings are wired once to avoid stacking listeners across re-renders.
var _attackersTable = null;
var _attackerBulk = null;
var _attackerURLUnbind = null;
var _attackerDateListenersBound = false;
var _attackersLoadSeq = 0;
var _threatStatsLoadSeq = 0;

var countryFlag = CSM.countryFlag;

function verdictBadge(v,score){
    var cls = v==='blocked'?'bg-secondary':v==='malicious'?'bg-danger':v==='suspicious'?'bg-warning':'bg-success';
    return '<span class="badge '+cls+'">'+score+'/100</span>';
}

var _checkNames = (typeof CSM_CONFIG !== 'undefined' && CSM_CONFIG.checkNames) || {};

// blockStatusRows renders the Block Status rows of the IP lookup card. An IP
// that is no longer blocked but still carries permanent threat evidence keeps
// scoring 100 and gets flagged again on its next sighting, so the card says so
// instead of showing a bare "Not blocked" next to "In Threat DB: Yes".
function blockStatusRows(intel){
    var html='';
    if(intel.currently_blocked){
        var blockType=intel.block_permanent?'<span class="badge bg-dark">Permanent</span>':'<span class="badge bg-warning">Temporary</span>';
        html+='<tr><td class="text-muted">Block Status</td><td><span class="badge bg-secondary">Blocked</span> '+blockType+'</td></tr>';
        if(intel.block_reason)html+='<tr><td class="text-muted">Block Reason</td><td class="small">'+CSM.esc(intel.block_reason)+'</td></tr>';
        if(intel.blocked_at)html+='<tr><td class="text-muted">Blocked At</td><td>'+fmtDate(intel.blocked_at)+'</td></tr>';
        if(intel.block_expires_at && !intel.block_permanent)html+='<tr><td class="text-muted">Expires At</td><td>'+fmtDate(intel.block_expires_at)+'</td></tr>';
        return html;
    }
    var note='Not blocked';
    if(intel.in_threat_db && intel.threat_db_permanent){
        note='Not blocked (permanent threat entry: flagged again on next sighting)';
    } else if(intel.in_threat_db && intel.threat_db_expires_at){
        note='Not blocked (threat entry until '+fmtDate(intel.threat_db_expires_at)+')';
    } else if(intel.in_threat_db){
        note='Not blocked (listed by a threat feed)';
    }
    return html+'<tr><td class="text-muted">Block Status</td><td>'+CSM.esc(note)+'</td></tr>';
}

// accountHTML links a targeted account to its page; other values stay text.
function accountHTML(name){
    var url=CSM.accountURL(name);
    return url?'<a href="'+CSM.attr(url)+'">'+CSM.esc(name)+'</a>':CSM.esc(name);
}

function typeBadges(counts){
    if(!counts)return '-';
    var html='';
    var order=['brute_force','webshell','phishing','c2','waf_block','spam','cpanel_login','file_upload','auth_success','recon','other'];
    var colors={brute_force:'blue',webshell:'red',phishing:'orange',c2:'purple',waf_block:'cyan',spam:'yellow',cpanel_login:'teal',file_upload:'pink',auth_success:'secondary',recon:'lime',other:'secondary'};
    for(var i=0;i<order.length;i++){
        var t=order[i];
        if(counts[t]&&counts[t]>0){
            var label = _checkNames[t] || t.replace('_',' ');
            html+='<span class="badge bg-'+( colors[t]||'secondary')+'-lt me-1">'+label+': '+counts[t]+'</span>';
        }
    }
    return html||'-';
}

function attackerURLInputs(countrySel, fromEl, toEl) {
    return {
        q: document.getElementById('attackers-search'),
        country: countrySel,
        verdict: document.getElementById('attackers-verdict'),
        from: fromEl,
        to: toEl
    };
}

// Re-binding URL state on every re-render would stack listeners, so drop the
// previous binding first (CSM.urlState.bind returns its own unbind).
function _bindAttackerURLState(countrySel, fromEl, toEl) {
    if (_attackerURLUnbind) _attackerURLUnbind();
    _attackerURLUnbind = CSM.urlState.bind({ inputs: attackerURLInputs(countrySel, fromEl, toEl) });
}

// Date inputs live outside the table body, so their change listeners survive a
// re-render; bind them once and let the latched table reference do the filter.
function _bindAttackerDateFilters(fromEl, toEl) {
    if (_attackerDateListenersBound) return;
    function onDate() { if (_attackersTable) { _attackersTable.currentPage = 1; _attackersTable.applyFilters(); } }
    if (fromEl) fromEl.addEventListener('change', onDate);
    if (toEl) toEl.addEventListener('change', onDate);
    _attackerDateListenersBound = true;
}

function resetAttackerSelection() {
    attackerBulk().clear();
}

function resetThreatHourlyChart(message) {
    if (window._csmThreatHourlyChart) {
        window._csmThreatHourlyChart.destroy();
        window._csmThreatHourlyChart = null;
    }
    var hourlyDiv = document.getElementById('chart-hourly');
    if (hourlyDiv) hourlyDiv.textContent = message || '';
}

function populateAttackerCountryFilter(rows) {
    var countrySel = document.getElementById('attackers-country');
    if (!countrySel) return null;
    var countries = Object.create(null);
    for (var ci = 0; ci < (rows || []).length; ci++) {
        var c = (rows[ci].country || '').toUpperCase();
        if (c) countries[c] = true;
    }
    var selected = CSM.urlState.get('country') || countrySel.value || '';
    while (countrySel.options.length > 1) countrySel.remove(1);
    var added = Object.create(null);
    function addCountry(c) {
        c = String(c || '');
        if (!c || added[c]) return;
        added[c] = true;
        var opt = document.createElement('option');
        opt.value = c;
        opt.textContent = c;
        countrySel.appendChild(opt);
    }
    Object.keys(countries).sort().forEach(addCountry);
    addCountry(selected);
    return countrySel;
}

function getJSONAllowError(url) {
    return CSM.get(url, { allowNonOK: true, silent: true });
}

// Load stats
function loadThreatStats() {
    var seq = ++_threatStatsLoadSeq;
    CSM.get('/api/v1/threat/stats').then(function(data){
    if (seq !== _threatStatsLoadSeq) return;
    document.getElementById('stat-total-ips').textContent=data.total_ips||0;
    document.getElementById('stat-24h').textContent=data.last_24h_events||0;
    document.getElementById('stat-7d').textContent=data.last_7d_events||0;
    document.getElementById('stat-blocked').textContent=data.blocked_ips||0;

    // Attack types chart (horizontal bars using inline SVG)
    var typesDiv=document.getElementById('chart-types');
    var byType=data.by_type||{};
    var types=Object.keys(byType).sort(function(a,b){return byType[b]-byType[a]});
    if(types.length===0){
        typesDiv.innerHTML='<p class="text-muted">No attack data yet</p>';
    } else {
        var maxVal=byType[types[0]]||1;
        var html='<table class="table table-sm mb-0">';
        for(var i=0;i<types.length;i++){
            var t=types[i], v=byType[t];
            var pct=Math.round(v/maxVal*100);
            html+='<tr><td class="csm-w-120 text-nowrap small">'+CSM.esc(t.replace(/_/g,' '))+'</td>';
            html+='<td><div class="progress progress-sm"><div class="progress-bar bg-primary csm-progress-zero" role="progressbar" aria-valuemin="0" aria-valuemax="100" data-csm-progress="'+CSM.attr(pct)+'"></div></div></td>';
            html+='<td class="csm-w-50 text-end small font-monospace">'+v+'</td></tr>';
        }
        html+='</table>';
        typesDiv.innerHTML=html;
        CSM.applyProgressBars(typesDiv);
    }

    // Hourly chart (Chart.js)
    var hourlyDiv=document.getElementById('chart-hourly');
    var buckets=data.hourly_buckets||[];
    if(buckets.length===0){resetThreatHourlyChart('No recent data');return;}
    // Replace div with canvas if needed
    var canvas=hourlyDiv.querySelector('canvas');
    if(!canvas){
        hourlyDiv.textContent='';
        canvas=document.createElement('canvas');
        hourlyDiv.appendChild(canvas);
    }
    if(window._csmThreatHourlyChart && window._csmThreatHourlyChart.canvas !== canvas){
        window._csmThreatHourlyChart.destroy();
        window._csmThreatHourlyChart=null;
    }
    // Bucket index 0 is the oldest hour, index N-1 is the current hour.
    // Label each bar with how many hours ago it covers: "23h" at the left
    // edge down to "now" at the right.
    var labels=[];
    for(var h=0;h<buckets.length;h++){
        var hoursAgo=buckets.length-1-h;
        labels.push(hoursAgo===0?'now':hoursAgo+'h');
    }
    var isDark=document.documentElement.classList.contains('theme-dark');
    var gridColor=isDark?'rgba(45,58,78,0.6)':'rgba(230,232,235,0.8)';
    if(window._csmThreatHourlyChart){
        window._csmThreatHourlyChart.data.labels=labels;
        window._csmThreatHourlyChart.data.datasets[0].data=buckets;
        window._csmThreatHourlyChart.update();
    } else {
        window._csmThreatHourlyChart=new Chart(canvas,{
            type:'bar',
            data:{
                labels:labels,
                datasets:[{
                    label:'Events',
                    data:buckets,
                    backgroundColor:isDark?'rgba(66,153,225,0.7)':'rgba(66,153,225,0.6)',
                    borderColor:'#4299e1',
                    borderWidth:1,
                    borderRadius:2
                }]
            },
            options:{
                responsive:true,
                maintainAspectRatio:false,
                plugins:{
                    legend:{display:false},
                    tooltip:{
                        backgroundColor:isDark?'#1e293b':'#fff',
                        titleColor:isDark?'#c8d3e0':'#1a2234',
                        bodyColor:isDark?'#c8d3e0':'#1a2234',
                        borderColor:isDark?'#2d3a4e':'#e6e8eb',
                        borderWidth:1,
                        callbacks:{
                            title:function(items){
                                var lbl=items[0].label;
                                return lbl==='now'?'this hour':lbl+' ago';
                            },
                            label:function(ctx){return ctx.parsed.y+' events';}
                        }
                    }
                },
                scales:{
                    x:{
                        grid:{display:false},
                        ticks:{
                            maxRotation:0,
                            // Anchor the stride on the right edge so "now" is always
                            // labelled, then every 4th older hour walking leftward.
                            // Using the live ticks array keeps this correct across
                            // re-renders when the bucket count changes.
                            callback:function(v,i,ticks){
                                var fromEnd=(ticks.length-1)-i;
                                return fromEnd%4===0?this.getLabelForValue(v):'';
                            }
                        }
                    },
                    y:{beginAtZero:true,grid:{color:gridColor},ticks:{precision:0}}
                }
            }
        });
    }
}).catch(function(err){ if (seq !== _threatStatsLoadSeq) return; console.error('threat stats:', err); CSM.loadError(document.getElementById('chart-types'), function(){ location.reload(); }); });
}

// Load top attackers
function loadTopAttackers() {
    var seq = ++_attackersLoadSeq;
    if (_attackersTable) { _attackersTable.destroy(); _attackersTable = null; }
    resetAttackerSelection();
    CSM.get('/api/v1/threat/top-attackers?limit=50').then(function(data){
    if (seq !== _attackersLoadSeq) return;
    var tbody=document.getElementById('attackers-tbody');
    var fromEl = document.getElementById('attackers-from');
    var toEl = document.getElementById('attackers-to');
    var countrySel = populateAttackerCountryFilter(data || []);
    if(!data||data.length===0){
        _threatAttackerData = [];
        tbody.innerHTML='<tr><td colspan="11" class="text-center text-muted">No attack data recorded yet</td></tr>';
        _bindAttackerURLState(countrySel, fromEl, toEl);
        resetAttackerSelection();
        return;
    }
    _threatAttackerData = data.map(function(r) {
        return { ip: r.ip, hits: r.event_count, score: r.unified_score, country: r.country || '', blocked: r.currently_blocked ? 'Yes' : 'No' };
    });
    var html='';
    for(var i=0;i<data.length;i++){
        var r=data[i];
        var statusBadge=r.currently_blocked?'<span class="badge bg-danger text-white">Blocked</span>':
                        r.in_threat_db?'<span class="badge bg-warning text-dark">Threat DB</span>':
                        '<span class="text-muted">\u2014</span>';
        html+='<tr class="ip-row feed-item" data-ip="'+CSM.esc(r.ip)+'" data-country="'+CSM.attr((r.country||'').toUpperCase())+'" data-verdict="'+CSM.attr((r.verdict||'').toLowerCase())+'" data-last-seen="'+CSM.attr(r.last_seen||'')+'">';
        html+='<td><input type="checkbox" class="form-check-input bulk-ip-cb" data-ip="'+CSM.esc(r.ip)+'"></td>';
        html+='<td><code class="font-monospace csm-copy" title="Click to copy">'+CSM.esc(r.ip)+'</code></td>';
        html+='<td class="text-nowrap">'+(r.country?countryFlag(r.country)+' '+CSM.esc(r.country):'')+(r.as_org?' <span class="text-muted small">'+CSM.esc(r.as_org)+'</span>':'')+'</td>';
        html+='<td>'+verdictBadge(r.verdict,r.unified_score)+'</td>';
        html+='<td>'+r.event_count+'</td>';
        html+='<td>'+typeBadges(r.attack_counts)+'</td>';
        html+='<td>'+(r.accounts?Object.keys(r.accounts).length:0)+'</td>';
        html+='<td class="text-nowrap small">'+fmtDate(r.first_seen)+'</td>';
        html+='<td class="text-nowrap small">'+fmtDate(r.last_seen)+'</td>';
        html+='<td>'+statusBadge+'</td>';
        html+='<td class="text-nowrap">';
        if(!r.currently_blocked){
            html+='<button class="btn btn-ghost-danger btn-sm quick-block-btn" data-ip="'+CSM.esc(r.ip)+'" title="Block 24h"><i class="ti ti-shield-lock"></i></button>';
        }
        html+='<button class="btn btn-ghost-danger btn-sm quick-block-perm-btn" data-ip="'+CSM.esc(r.ip)+'" title="Block permanently"><i class="ti ti-lock"></i></button>';
        html+='<button class="btn btn-ghost-success btn-sm quick-wl-btn" data-ip="'+CSM.esc(r.ip)+'" title="Whitelist"><i class="ti ti-shield-check"></i></button>';
        html+='</td>';
        html+='</tr>';
    }
    tbody.innerHTML=html;
    function _attackerInRange(row) {
        var raw = row.getAttribute('data-last-seen') || '';
        if (!raw) return true;
        var ts = CSM.parseTimestamp(raw);
        if (isNaN(ts)) return true;
        var from = fromEl ? CSM.prefs.dayBoundary(fromEl.value, false) : null;
        var to = toEl ? CSM.prefs.dayBoundary(toEl.value, true) : null;
        if (from !== null && ts < from) return false;
        if (to !== null && ts >= to) return false;
        return true;
    }
    _attackersTable = new CSM.Table({
        tableId: 'attackers-table',
        perPage: 25,
        searchId: 'attackers-search',
        sortable: true,
        stateKey: 'csm-threat-attackers',
        mobileRowCard: true,
        filters: [
            { id: 'attackers-country', attr: 'data-country' },
            { id: 'attackers-verdict', attr: 'data-verdict' }
        ],
        rowFilter: _attackerInRange,
        // Paging and filtering hide rows; recount what bulk actions will reach.
        onRender: updateBulkButtons
    });
    _bindAttackerDateFilters(fromEl, toEl);
    // WEB_ROADMAP P2.1 / P3.5: persist all filter state to URL.
    _bindAttackerURLState(countrySel, fromEl, toEl);
    // Click row to lookup
    document.querySelectorAll('.ip-row').forEach(function(row){
        row.addEventListener('click',function(){
            document.getElementById('tr-lookup-ip').value=this.getAttribute('data-ip');
            document.getElementById('tr-lookup-form').dispatchEvent(new Event('submit'));
        });
    });
    // Inline action buttons
    document.querySelectorAll('.quick-block-btn').forEach(function(btn){
        btn.addEventListener('click',function(e){
            e.stopPropagation();
            blockIP(this.getAttribute('data-ip'),false);
        });
    });
    document.querySelectorAll('.quick-block-perm-btn').forEach(function(btn){
        btn.addEventListener('click',function(e){
            e.stopPropagation();
            blockIP(this.getAttribute('data-ip'),true);
        });
    });
    document.querySelectorAll('.quick-wl-btn').forEach(function(btn){
        btn.addEventListener('click',function(e){
            e.stopPropagation();
            whitelistIP(this.getAttribute('data-ip'));
        });
    });
    // Bulk selection: a checkbox click must not also trigger the row lookup.
    document.querySelectorAll('.bulk-ip-cb').forEach(function(cb){
        cb.addEventListener('click', function(e) { e.stopPropagation(); });
    });
    resetAttackerSelection();
}).catch(function(err){ if (seq !== _attackersLoadSeq) return; console.error('top-attackers:', err); CSM.loadError(document.getElementById('attackers-tbody').parentElement.parentElement.parentElement, function(){ location.reload(); }); });
}

// Initial load (re-run in place after bulk block/whitelist).
loadThreatStats();
loadTopAttackers();

// IP Lookup
document.getElementById('tr-lookup-form').addEventListener('submit',function(e){
    e.preventDefault();
    var ip=document.getElementById('tr-lookup-ip').value.trim();
    if(!ip)return;
    var status=document.getElementById('lookup-status');
    var result=document.getElementById('tr-lookup-result');
    status.textContent='Looking up...';status.className='text-muted small';
    result.classList.add('d-none');

    Promise.all([
        getJSONAllowError('/api/v1/threat/ip?ip='+encodeURIComponent(ip)),
        getJSONAllowError('/api/v1/threat/events?ip='+encodeURIComponent(ip)+'&limit=20')
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
        html+='<tr><td class="text-muted csm-w-160">Local Score</td><td>'+intel.local_score+'/100</td></tr>';
        if(intel.country)html+='<tr><td class="text-muted">Country</td><td>'+countryFlag(intel.country)+' <strong>'+CSM.esc(intel.country)+'</strong>'+(intel.country_name?' - '+CSM.esc(intel.country_name):'')+(intel.city?', '+CSM.esc(intel.city):'')+'</td></tr>';
        if(intel.as_org)html+='<tr><td class="text-muted">ISP / ASN</td><td>'+CSM.esc(intel.as_org)+(intel.asn?' <span class="text-muted">(AS'+intel.asn+')</span>':'')+'</td></tr>';
        if(intel.network)html+='<tr><td class="text-muted" title="The routed prefix this address belongs to, from GeoIP. Blocks and threat entries apply to the address itself.">GeoIP prefix</td><td><code>'+CSM.esc(intel.network)+'</code></td></tr>';
        html+='<tr><td class="text-muted">AbuseIPDB Score</td><td>'+(intel.abuse_score>=0?intel.abuse_score+'/100':'Not cached')+'</td></tr>';
        if(intel.abuse_category)html+='<tr><td class="text-muted">AbuseIPDB Category</td><td>'+CSM.esc(intel.abuse_category)+'</td></tr>';
        html+='<tr><td class="text-muted">In Threat DB</td><td>'+(intel.in_threat_db?'<span class="badge bg-danger">Yes</span> ('+CSM.esc(intel.threat_db_source)+')':'No')+'</td></tr>';
        html+=blockStatusRows(intel);
        if(intel.attack_record){
            var rec=intel.attack_record;
            html+='<tr><td class="text-muted">Events</td><td>'+rec.event_count+'</td></tr>';
            html+='<tr><td class="text-muted">Attack Types</td><td>'+typeBadges(rec.attack_counts)+'</td></tr>';
            html+='<tr><td class="text-muted">Accounts Targeted</td><td>'+(rec.accounts?Object.keys(rec.accounts).map(accountHTML).join(', '):'-')+'</td></tr>';
            html+='<tr><td class="text-muted">First Seen</td><td>'+fmtDate(rec.first_seen)+'</td></tr>';
            html+='<tr><td class="text-muted">Last Seen</td><td>'+fmtDate(rec.last_seen)+'</td></tr>';
        }
        html+='</table>';
        html+='<div class="mt-3 d-flex gap-2 flex-wrap">';
        if(!intel.currently_blocked){
            html+='<button class="btn btn-danger btn-sm block-ip-btn" data-ip="'+CSM.esc(intel.ip)+'" title="Block this IP in the firewall for 24 hours"><i class="ti ti-shield-lock"></i>&nbsp;Block (24h)</button>';
        }
        if(!intel.currently_blocked || !intel.block_permanent){
            html+='<button class="btn btn-outline-danger btn-sm block-ip-perm-btn" data-ip="'+CSM.esc(intel.ip)+'" title="Block this IP in the firewall with no expiry and keep it in the threat database"><i class="ti ti-lock"></i>&nbsp;Block permanently</button>';
        }
        html+='<button class="btn btn-outline-primary btn-sm clear-ip-btn" data-ip="'+CSM.esc(intel.ip)+'" title="Unblock IP and remove from all threat databases"><i class="ti ti-eraser"></i>&nbsp;Unblock &amp; Clear</button>';
        html+='<button class="btn btn-outline-warning btn-sm temp-wl-btn" data-ip="'+CSM.esc(intel.ip)+'" title="Temporarily allow this IP for a set number of hours"><i class="ti ti-clock"></i>&nbsp;Temp Whitelist (24h)</button>';
        html+='<button class="btn btn-success btn-sm perm-wl-btn" data-ip="'+CSM.esc(intel.ip)+'" title="Permanently allow this IP - never block or flag it again"><i class="ti ti-shield-check"></i>&nbsp;Permanent Whitelist</button>';
        html+='<a class="btn btn-ghost-secondary btn-sm" href="/firewall?ip='+encodeURIComponent(intel.ip)+'" title="Firewall state and actions for this IP"><i class="ti ti-firewall-check"></i>&nbsp;Firewall</a>';
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
                html+='<td>'+CSM.esc(ev.account||'-')+'</td>';
                html+='<td class="small">'+CSM.esc(ev.msg||'')+'</td></tr>';
            }
            html+='</tbody></table></div></div>';
        }

        result.innerHTML=html;
        // Bind action buttons after DOM insertion
        var blockBtn=result.querySelector('.block-ip-btn');
        if(blockBtn) blockBtn.addEventListener('click',function(){blockIP(this.getAttribute('data-ip'),false);});
        var blockPermBtn=result.querySelector('.block-ip-perm-btn');
        if(blockPermBtn) blockPermBtn.addEventListener('click',function(){blockIP(this.getAttribute('data-ip'),true);});
        var clearBtn=result.querySelector('.clear-ip-btn');
        if(clearBtn) clearBtn.addEventListener('click',function(){clearIP(this.getAttribute('data-ip'));});
        var tempBtn=result.querySelector('.temp-wl-btn');
        if(tempBtn) tempBtn.addEventListener('click',function(){tempWhitelistIP(this.getAttribute('data-ip'));});
        var permBtn=result.querySelector('.perm-wl-btn');
        if(permBtn) permBtn.addEventListener('click',function(){whitelistIP(this.getAttribute('data-ip'));});
    }).catch(function(e){status.textContent='Error: '+e;status.className='text-danger small'});
});

// blockIP blocks for 24 hours by default. A permanent block is a separate,
// explicitly confirmed operator action: it never expires in the firewall and
// keeps the IP in the threat database for good.
function blockIP(ip, permanent) {
    var url=permanent?'/api/v1/threat/block-ip-permanent':'/api/v1/threat/block-ip';
    var question=permanent?
        'Block '+ip+' permanently?\n\nThe firewall block never expires and the IP stays in the threat database until you clear it.':
        'Block '+ip+' for 24 hours?\n\nThis will block the IP in the firewall and add it to the threat database for the same 24 hours.';
    var done=permanent?'IP '+ip+' blocked permanently.':'IP '+ip+' blocked for 24h.';
    return CSM.confirm(question, { danger: true, okLabel: 'Block' }).then(function() {
        return CSM.post(url,{ip:ip}).then(function(data){
            if(data.error){CSM.toast('Error: '+data.error,'error');return;}
            CSM.toast(done+'\n\nActions: '+(data.actions||[]).join(', '),'success');
            document.getElementById('tr-lookup-form').dispatchEvent(new Event('submit'));
        }).catch(function(e){CSM.toast('Error: '+e,'error')});
    }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
}

function clearIP(ip) {
    CSM.confirm('Unblock & Clear '+ip+'?\n\nThis will unblock and remove from all databases, but will NOT whitelist.\nThe IP can be re-blocked if it triggers detections again.\n\nUse this for dynamic IP customers.').then(function() {
        CSM.post('/api/v1/threat/clear-ip',{ip:ip}).then(function(data){
            if(data.error){CSM.toast('Error: '+data.error,'error');return;}
            CSM.toast('IP '+ip+' cleared.\n\nActions: '+(data.actions||[]).join(', '),'success');
            document.getElementById('tr-lookup-form').dispatchEvent(new Event('submit'));
        }).catch(function(e){CSM.toast('Error: '+e,'error')});
    }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
}

function tempWhitelistIP(ip) {
    CSM.prompt('Temp whitelist '+ip+' for how many hours?','24').then(function(hours) {
        hours=parseInt(hours,10);
        if(isNaN(hours)||hours<1){CSM.toast('Invalid number of hours','warning');return;}
        CSM.post('/api/v1/threat/temp-whitelist-ip',{ip:ip,hours:hours}).then(function(data){
            if(data.error){CSM.toast('Error: '+data.error,'error');return;}
            CSM.toast('IP '+ip+' temp-whitelisted for '+data.hours+'h.\n\nActions: '+(data.actions||[]).join(', '),'success');
            document.getElementById('tr-lookup-form').dispatchEvent(new Event('submit'));
        }).catch(function(e){CSM.toast('Error: '+e,'error')});
    }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
}

function whitelistIP(ip) {
    CSM.confirm('Permanently whitelist '+ip+'?\n\nUse this only for static IPs (offices, dedicated servers).\nFor dynamic IPs, use "Temp Whitelist" instead.\n\nThis will:\n- Unblock from firewall\n- Add to permanent allow list\n- Remove from all threat databases\n- Never flag this IP again', { danger: true, okLabel: 'Whitelist' }).then(function() {
        CSM.post('/api/v1/threat/whitelist-ip',{ip:ip}).then(function(data){
            if(data.error){CSM.toast('Error: '+data.error,'error');return;}
            CSM.toast('IP '+ip+' permanently whitelisted.\n\nActions: '+(data.actions||[]).join(', '),'success');
            document.getElementById('tr-lookup-form').dispatchEvent(new Event('submit'));
        }).catch(function(e){CSM.toast('Error: '+e,'error')});
    }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
}

// Other pages link here with ?ip= to look one address up.
(function() {
    var ip = (new URLSearchParams(window.location.search).get('ip') || '').trim();
    if (!ip || !(isValidIPv4(ip) || isValidIPv6(ip))) return;
    document.getElementById('tr-lookup-ip').value = ip;
    document.getElementById('tr-lookup-form').dispatchEvent(new Event('submit'));
})();

// --- Bulk operations ---
// CSM.bulk limits select-all and every bulk action to rows the table shows,
// so a permanent block or whitelist never reaches rows on other pages or
// hidden by a filter.
function attackerBulk() {
    if (!_attackerBulk) {
        _attackerBulk = CSM.bulk({
            rowCheckboxSelector: '.bulk-ip-cb',
            selectAllEl: document.getElementById('select-all-attackers'),
            valueAttr: 'data-ip',
            buttons: [
                { el: document.getElementById('bulk-block-btn'), labelTemplate: 'Block 24h ({n})' },
                { el: document.getElementById('bulk-block-perm-btn'), labelTemplate: 'Block Permanently ({n})' },
                { el: document.getElementById('bulk-whitelist-btn'), labelTemplate: 'Whitelist Selected ({n})' }
            ]
        });
    }
    return _attackerBulk;
}

function getSelectedIPs() {
    return attackerBulk().selectedValues();
}

function updateBulkButtons() {
    attackerBulk().refresh();
}

// Bulk block. The permanent variant is its own button and its own confirm so
// a 24h block is never turned into a permanent one by a stray click.
function bulkBlock(permanent) {
    var ips = getSelectedIPs();
    if (ips.length === 0) return Promise.resolve();
    if (ips.length > CSM.THREAT_BULK_MAX) {
        CSM.toast('Too many IPs selected (' + ips.length + '); the bulk limit is ' + CSM.THREAT_BULK_MAX + '. Narrow the selection and repeat.', 'error');
        return Promise.resolve();
    }
    var question = permanent ?
        'Block ' + ips.length + ' IP(s) permanently?\n\nThe firewall blocks never expire and the IPs stay in the threat database until you clear them.' :
        'Block ' + ips.length + ' IP(s) for 24 hours?\n\nThis will block them in the firewall and add them to the threat database for the same 24 hours. Permanent and longer blocks are skipped; unblock them explicitly before changing their lifetime.';
    var label = permanent ? 'Permanently blocked ' : 'Blocked ';
    return CSM.confirm(question, { danger: true, okLabel: 'Block' }).then(function() {
        return CSM.post('/api/v1/threat/bulk-action', { ips: ips, action: permanent ? 'block_permanent' : 'block' }).then(function(data) {
            if (data.error) { CSM.toast('Error: ' + data.error, 'error'); return; }
            if (data.count > 0) CSM.toast(data.count + ' IP(s) blocked successfully', 'success');
            if (data.warnings && data.warnings.length) CSM.toast(data.warnings.join('\n'), 'warning');
            if (data.undo_token) CSM.undo.offer({ token: data.undo_token, label: label + data.count + ' IP(s)' });
            loadThreatStats();
            loadTopAttackers();
        }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
}

document.getElementById('bulk-block-btn').addEventListener('click', function() {
    bulkBlock(false);
});

document.getElementById('bulk-block-perm-btn').addEventListener('click', function() {
    bulkBlock(true);
});

// Bulk whitelist
document.getElementById('bulk-whitelist-btn').addEventListener('click', function() {
    var ips = getSelectedIPs();
    if (ips.length === 0) return;
    if (ips.length > CSM.THREAT_BULK_MAX) {
        CSM.toast('Too many IPs selected (' + ips.length + '); the bulk limit is ' + CSM.THREAT_BULK_MAX + '. Narrow the selection and repeat.', 'error');
        return;
    }
    CSM.confirm('Permanently whitelist ' + ips.length + ' IP(s)?\n\nThis will unblock from firewall, add to allow list, and remove from all threat databases.', { danger: true, okLabel: 'Whitelist' }).then(function() {
        CSM.post('/api/v1/threat/bulk-action', { ips: ips, action: 'whitelist' }).then(function(data) {
            if (data.error) { CSM.toast('Error: ' + data.error, 'error'); return; }
            CSM.toast(data.count + ' IP(s) whitelisted successfully', 'success');
            if (data.undo_token) CSM.undo.offer({ token: data.undo_token, label: 'Whitelisted ' + data.count + ' IP(s)' });
            loadThreatStats();
            loadTopAttackers();
        }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
});

// --- Export handlers ---
(function() {
    var cols = [
        {key:'ip', label:'IP'},
        {key:'hits', label:'Hits'},
        {key:'score', label:'Score'},
        {key:'country', label:'Country'},
        {key:'blocked', label:'Blocked'}
    ];
    document.querySelectorAll('[data-export]').forEach(function(el) {
        el.addEventListener('click', function(e) {
            e.preventDefault();
            CSM.exportTable(_threatAttackerData, cols, this.getAttribute('data-export'), 'csm-threat-attackers');
        });
    });
})();

// --- Theme reactivity: update chart colors when dark/light mode toggles ---
function updateChartTheme() {
    var isDark = document.documentElement.classList.contains('theme-dark');
    var gridColor = isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)';
    var textColor = isDark ? '#94a3b8' : '#64748b';
    Chart.defaults.color = textColor;
    Chart.defaults.borderColor = gridColor;
    Object.values(Chart.instances).forEach(function(chart) {
        if (chart.options.scales) {
            Object.keys(chart.options.scales).forEach(function(axis) {
                if (chart.options.scales[axis].grid) chart.options.scales[axis].grid.color = gridColor;
                if (chart.options.scales[axis].ticks) chart.options.scales[axis].ticks.color = textColor;
            });
        }
        chart.update('none');
    });
}

new MutationObserver(function(mutations) {
    mutations.forEach(function(m) { if (m.attributeName === 'class') updateChartTheme(); });
}).observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
