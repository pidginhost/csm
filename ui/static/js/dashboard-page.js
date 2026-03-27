// CSM Dashboard page — timeline chart rendering and feed interactions

// --- Timeline chart (reads data from #timeline-chart data-bars attribute) ---
(function(){
    var container = document.getElementById('timeline-chart');
    if (!container) return;
    var raw = container.getAttribute('data-bars');
    if (!raw) return;
    var srcBars;
    try { srcBars = JSON.parse(raw); } catch(e) { return; }
    // Map Go struct fields (Hour, Critical, High, Warning, Total) to short names
    var bars = [];
    for (var i = 0; i < srcBars.length; i++) {
        var s = srcBars[i];
        bars.push({h: s.Hour, c: s.Critical, hi: s.High, w: s.Warning, t: s.Total});
    }

    var vW = 1400, vH = 160;
    var padL = 38, padR = 8, padT = 8, padB = 22;
    var chartW = vW - padL - padR;
    var chartH = vH - padT - padB;
    var barW = chartW / 24;
    var barPad = Math.max(1, barW * 0.12);

    var maxVal = 1;
    for (var i = 0; i < bars.length; i++) { if (bars[i].t > maxVal) maxVal = bars[i].t; }
    var gridLines = 4;
    var step = Math.ceil(maxVal / gridLines);
    if (step === 0) step = 1;
    maxVal = step * gridLines;

    var isDark = document.documentElement.classList.contains('theme-dark');
    var gridColor = isDark ? '#2d3a4e' : '#e6e8eb';
    var textColor = isDark ? '#6b7a8d' : '#9da9b5';

    var svg = '<svg viewBox="0 0 '+vW+' '+vH+'" preserveAspectRatio="xMidYMid meet" style="display:block;width:100%;height:auto">';

    for (var g = 0; g <= gridLines; g++) {
        var val = step * g;
        var y = padT + chartH - (val / maxVal * chartH);
        svg += '<line x1="'+padL+'" y1="'+y+'" x2="'+(vW-padR)+'" y2="'+y+'" stroke="'+gridColor+'" stroke-width="0.5"/>';
        svg += '<text x="'+(padL-6)+'" y="'+(y+3.5)+'" text-anchor="end" fill="'+textColor+'" font-size="9">'+val+'</text>';
    }

    for (var i = 0; i < bars.length; i++) {
        var b = bars[i];
        var x = padL + i * barW + barPad;
        var bw = barW - barPad * 2;
        if (bw < 3) bw = 3;
        var baseY = padT + chartH;
        var tip = b.h+': '+b.t+' findings ('+b.c+'C / '+b.hi+'H / '+b.w+'W)';

        if (b.w > 0) {
            var wH = b.w / maxVal * chartH;
            svg += '<rect x="'+x+'" y="'+(baseY-wH)+'" width="'+bw+'" height="'+wH+'" fill="#f59f00" rx="1.5" class="timeline-bar"><title>'+tip+'</title></rect>';
            baseY -= wH;
        }
        if (b.hi > 0) {
            var hH = b.hi / maxVal * chartH;
            svg += '<rect x="'+x+'" y="'+(baseY-hH)+'" width="'+bw+'" height="'+hH+'" fill="#f76707" rx="1.5" class="timeline-bar"><title>'+tip+'</title></rect>';
            baseY -= hH;
        }
        if (b.c > 0) {
            var cH = b.c / maxVal * chartH;
            svg += '<rect x="'+x+'" y="'+(baseY-cH)+'" width="'+bw+'" height="'+cH+'" fill="#d63939" rx="1.5" class="timeline-bar"><title>'+tip+'</title></rect>';
        }

        if (i % 3 === 0) {
            svg += '<text x="'+(padL+i*barW+barW/2)+'" y="'+(vH-4)+'" text-anchor="middle" fill="'+textColor+'" font-size="9">'+b.h+'</text>';
        }
    }

    svg += '<line x1="'+padL+'" y1="'+(padT+chartH)+'" x2="'+(vW-padR)+'" y2="'+(padT+chartH)+'" stroke="'+gridColor+'" stroke-width="0.5"/>';
    svg += '</svg>';
    container.innerHTML = svg;
})();

// --- Feed item expand/collapse ---
document.querySelectorAll('.feed-item').forEach(function(item) {
    item.addEventListener('click', function(e) {
        // Don't toggle if clicking a button
        if (e.target.closest('button')) return;
        var d = this.querySelector('.detail');
        if (d) d.classList.toggle('d-none');
    });
});

// --- Fix from feed button ---
function fixFromFeed(btn) {
    var check = btn.getAttribute('data-check');
    var message = btn.getAttribute('data-message');
    var desc = btn.getAttribute('data-fixdesc');
    if (!confirm('Apply fix?\n\n' + desc)) return;
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
    CSM.post('/api/v1/fix', {check: check, message: message}).then(function(data) {
        if (data.success) {
            btn.innerHTML = '<i class="ti ti-check"></i>';
            btn.className = 'btn btn-success btn-sm';
            btn.closest('.list-group-item').style.opacity = '0.3';
        } else {
            alert('Fix failed: ' + (data.error || 'unknown'));
            btn.disabled = false;
            btn.innerHTML = '<i class="ti ti-tool"></i>';
        }
    }).catch(function(e) {
        alert('Error: ' + e);
        btn.disabled = false;
        btn.innerHTML = '<i class="ti ti-tool"></i>';
    });
}

document.querySelectorAll('.feed-fix-btn').forEach(function(btn) {
    btn.addEventListener('click', function(e) {
        e.stopPropagation();
        fixFromFeed(this);
    });
});
