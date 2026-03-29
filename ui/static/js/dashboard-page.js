// CSM Dashboard page — timeline chart, attack-type chart, live feed, blocked IP stats

// --- Timeline chart (reads data from #timeline-chart data-bars attribute) ---
(function(){
    var container = document.getElementById('timeline-chart');
    if (!container) return;
    var raw = container.getAttribute('data-bars');
    if (!raw) return;
    var srcBars;
    try { srcBars = JSON.parse(raw); } catch(e) { return; }
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

    // Invisible hover zones for each bar column, plus visible stacked bars
    for (var i = 0; i < bars.length; i++) {
        var b = bars[i];
        var x = padL + i * barW + barPad;
        var bw = barW - barPad * 2;
        if (bw < 3) bw = 3;
        var baseY = padT + chartH;

        if (b.w > 0) {
            var wH = b.w / maxVal * chartH;
            svg += '<rect x="'+x+'" y="'+(baseY-wH)+'" width="'+bw+'" height="'+wH+'" fill="#f59f00" rx="1.5" class="timeline-bar"/>';
            baseY -= wH;
        }
        if (b.hi > 0) {
            var hH = b.hi / maxVal * chartH;
            svg += '<rect x="'+x+'" y="'+(baseY-hH)+'" width="'+bw+'" height="'+hH+'" fill="#f76707" rx="1.5" class="timeline-bar"/>';
            baseY -= hH;
        }
        if (b.c > 0) {
            var cH = b.c / maxVal * chartH;
            svg += '<rect x="'+x+'" y="'+(baseY-cH)+'" width="'+bw+'" height="'+cH+'" fill="#d63939" rx="1.5" class="timeline-bar"/>';
        }

        // Invisible hit area for tooltip
        svg += '<rect x="'+(padL + i * barW)+'" y="'+padT+'" width="'+barW+'" height="'+chartH+'" fill="transparent" class="timeline-hover" data-idx="'+i+'"/>';

        if (i % 3 === 0) {
            svg += '<text x="'+(padL+i*barW+barW/2)+'" y="'+(vH-4)+'" text-anchor="middle" fill="'+textColor+'" font-size="9">'+b.h+'</text>';
        }
    }

    svg += '<line x1="'+padL+'" y1="'+(padT+chartH)+'" x2="'+(vW-padR)+'" y2="'+(padT+chartH)+'" stroke="'+gridColor+'" stroke-width="0.5"/>';
    svg += '</svg>';
    container.innerHTML = svg;

    // Tooltip behavior
    var tooltip = document.getElementById('timeline-tooltip');
    if (tooltip) {
        var svgEl = container.querySelector('svg');
        container.parentElement.addEventListener('mousemove', function(e) {
            var hoverEl = document.elementFromPoint(e.clientX, e.clientY);
            if (!hoverEl || !hoverEl.classList.contains('timeline-hover')) {
                tooltip.classList.remove('visible');
                return;
            }
            var idx = parseInt(hoverEl.getAttribute('data-idx'), 10);
            if (isNaN(idx) || idx < 0 || idx >= bars.length) {
                tooltip.classList.remove('visible');
                return;
            }
            var b = bars[idx];
            tooltip.textContent = b.h + ' \u2014 ' + b.t + ' total (' + b.c + ' crit, ' + b.hi + ' high, ' + b.w + ' warn)';

            // Position the tooltip above the hovered bar
            var parentRect = container.parentElement.getBoundingClientRect();
            tooltip.style.left = (e.clientX - parentRect.left) + 'px';
            tooltip.style.top = (e.clientY - parentRect.top - 10) + 'px';
            tooltip.classList.add('visible');
        });

        container.parentElement.addEventListener('mouseleave', function() {
            tooltip.classList.remove('visible');
        });
    }

    // Store bars globally so other code can reference them
    window._csmTimelineBars = bars;
})();

// --- Top Attack Types bar chart ---
(function(){
    var colors = {
        brute_force:  '#d63939',
        waf_block:    '#f76707',
        webshell:     '#a855f7',
        phishing:     '#e64980',
        c2:           '#ae3ec9',
        recon:        '#4299e1',
        spam:         '#f59f00',
        cpanel_login: '#f76707',
        file_upload:  '#0ca678',
        reputation:   '#e8590c',
        other:        '#6b7a8d'
    };

    var labels = {
        brute_force:  'Brute Force',
        waf_block:    'WAF Block',
        webshell:     'Webshell',
        phishing:     'Phishing',
        c2:           'C2 / Callback',
        recon:        'Recon / Scan',
        spam:         'Spam',
        cpanel_login: 'cPanel Login',
        file_upload:  'File Upload',
        reputation:   'Known Malicious IP',
        other:        'Other'
    };

    function renderAttackTypesChart() {
        var container = document.getElementById('attack-types-chart');
        if (!container) return;

        fetch(CSM.apiUrl('/api/v1/threat/stats'), { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                var byType = data.by_type || {};
                // Sort by count descending, take top 8
                var entries = [];
                for (var key in byType) {
                    if (byType.hasOwnProperty(key)) {
                        entries.push({ type: key, count: byType[key] });
                    }
                }
                entries.sort(function(a, b) { return b.count - a.count; });
                entries = entries.slice(0, 8);

                if (entries.length === 0) {
                    container.innerHTML = '<div class="text-muted text-center py-3">No attack data yet</div>';
                    return;
                }

                var maxCount = entries[0].count || 1;
                var html = '';
                for (var i = 0; i < entries.length; i++) {
                    var e = entries[i];
                    var label = labels[e.type] || e.type;
                    var color = colors[e.type] || '#6b7a8d';
                    var pct = Math.round((e.count / maxCount) * 100);
                    html += '<div class="bar-chart-row">' +
                        '<div class="bar-chart-label" title="' + CSM.esc(label) + '">' + CSM.esc(label) + '</div>' +
                        '<div class="bar-chart-track"><div class="bar-chart-fill" style="width:' + pct + '%;background:' + color + '"></div></div>' +
                        '<div class="bar-chart-value">' + e.count + '</div>' +
                        '</div>';
                }
                container.innerHTML = html;
            })
            .catch(function() {
                container.innerHTML = '<div class="text-muted text-center py-3">Could not load attack data</div>';
            });
    }

    renderAttackTypesChart();
    setInterval(renderAttackTypesChart, 60000);
})();

// --- Live Feed: enhance new entries with highlight animation and relative time ---
(function(){
    var feed = document.getElementById('live-feed-entries');
    if (!feed) return;

    // Override: observe new children being added to the feed by dashboard.js
    // and enhance them with highlight animation + relative time
    var _feedProcessing = false;
    var feedObserver = new MutationObserver(function(mutations) {
        if (_feedProcessing) return; // prevent re-entry from our own DOM changes
        _feedProcessing = true;
        for (var m = 0; m < mutations.length; m++) {
            var added = mutations[m].addedNodes;
            for (var n = 0; n < added.length; n++) {
                var node = added[n];
                if (node.nodeType !== 1 || !node.classList.contains('list-group-item')) continue;
                node.classList.add('feed-highlight');
                addRelativeTime(node);
                attachFeedItemListeners(node);
            }
        }
        // Enforce max 10 visible items — disconnect observer first to avoid cascade
        while (feed.children.length > 10) {
            feed.removeChild(feed.lastChild);
        }
        _feedProcessing = false;
    });
    feedObserver.observe(feed, { childList: true });

    function addRelativeTime(item) {
        var row = item.querySelector('.row');
        if (!row) return;
        // Check if already has a relative time element
        if (item.querySelector('.feed-relative-time')) return;
        var span = document.createElement('div');
        span.className = 'col-auto feed-relative-time';
        span.innerHTML = '<span class="text-muted small">just now</span>';
        span.setAttribute('data-ts', Date.now().toString());
        row.appendChild(span);
    }

    // Periodically update relative times
    setInterval(function() {
        var items = feed.querySelectorAll('.feed-relative-time');
        var now = Date.now();
        for (var i = 0; i < items.length; i++) {
            var ts = parseInt(items[i].getAttribute('data-ts'), 10);
            if (isNaN(ts)) continue;
            var diff = Math.floor((now - ts) / 1000);
            var text;
            if (diff < 5) {
                text = 'just now';
            } else if (diff < 60) {
                text = diff + 's ago';
            } else if (diff < 3600) {
                text = Math.floor(diff / 60) + 'm ago';
            } else {
                text = Math.floor(diff / 3600) + 'h ago';
            }
            var span = items[i].querySelector('span');
            if (span) span.textContent = text;
        }
    }, 5000);
})();

// --- Feed item expand/collapse ---
function attachFeedItemListeners(item) {
    item.style.cursor = 'pointer';
    item.addEventListener('click', function(e) {
        if (e.target.closest('button')) return;
        var d = this.querySelector('.detail');
        if (d) d.classList.toggle('d-none');
    });
    var fixBtn = item.querySelector('.feed-fix-btn');
    if (fixBtn) {
        fixBtn.addEventListener('click', function(e) {
            e.stopPropagation();
            fixFromFeed(this);
        });
    }
}

document.querySelectorAll('.feed-item').forEach(function(item) {
    attachFeedItemListeners(item);
});

// --- Fix from feed button ---
function fixFromFeed(btn) {
    var check = btn.getAttribute('data-check');
    var message = btn.getAttribute('data-message');
    var desc = btn.getAttribute('data-fixdesc');
    CSM.confirm('Apply fix?\n\n' + desc).then(function() {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
        CSM.post('/api/v1/fix', {check: check, message: message}).then(function(data) {
            if (data.success) {
                btn.innerHTML = '<i class="ti ti-check"></i>';
                btn.className = 'btn btn-success btn-sm';
                btn.closest('.list-group-item').style.opacity = '0.3';
                CSM.toast('Fix applied successfully', 'success');
            } else {
                CSM.toast('Fix failed: ' + (data.error || 'unknown'), 'error');
                btn.disabled = false;
                btn.innerHTML = '<i class="ti ti-tool"></i>';
            }
        }).catch(function(e) {
            CSM.toast('Error: ' + e, 'error');
            btn.disabled = false;
            btn.innerHTML = '<i class="ti ti-tool"></i>';
        });
    }).catch(function() { /* cancelled */ });
}

// --- 30-Day Trend Chart ---
(function(){
    function loadTrend() {
        fetch(CSM.apiUrl('/api/v1/stats/trend'), { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(days) {
                var container = document.getElementById('trend-chart');
                if (!container || !days || !days.length) return;
                var maxVal = 1;
                days.forEach(function(d) { if (d.total > maxVal) maxVal = d.total; });
                var w = container.clientWidth || 800;
                var barW = Math.floor((w - 60) / days.length) - 2;
                if (barW < 4) barW = 4;
                var h = 120;
                var padL = 30, padB = 18;
                var chartH = h - padB;

                var isDark = document.documentElement.classList.contains('theme-dark');
                var textColor = isDark ? '#6b7a8d' : '#9da9b5';

                var svg = '<svg width="' + w + '" height="' + h + '">';
                days.forEach(function(d, i) {
                    var x = padL + i * (barW + 2);
                    var barH = Math.max(1, Math.round(d.total / maxVal * (chartH - 4)));
                    var color = d.critical > 0 ? '#d63939' : d.high > 0 ? '#f76707' : d.total > 0 ? '#f59f00' : '#2d3a4e';
                    svg += '<rect x="' + x + '" y="' + (chartH - barH) + '" width="' + barW + '" height="' + barH + '" fill="' + color + '" rx="1.5">';
                    svg += '<title>' + d.date + ': ' + d.total + ' (' + d.critical + ' crit, ' + d.high + ' high, ' + d.warning + ' warn)</title></rect>';
                    if (i % 7 === 0) {
                        svg += '<text x="' + (x + barW/2) + '" y="' + (h - 2) + '" text-anchor="middle" fill="' + textColor + '" style="font-size:9px">' + d.date.slice(5) + '</text>';
                    }
                });
                svg += '</svg>';
                container.innerHTML = svg;
            })
            .catch(function() {
                var c = document.getElementById('trend-chart');
                if (c) c.innerHTML = '<div class="text-muted text-center py-3">Could not load trend data</div>';
            });
    }
    loadTrend();
})();
