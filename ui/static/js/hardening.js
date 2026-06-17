(function() {
    var categoryNames = {
        ssh: 'SSH', php: 'PHP', webserver: 'Web Server', mail: 'Mail',
        cpanel: 'cPanel / WHM', os: 'OS Hardening', firewall: 'Firewall'
    };
    var categoryIcons = {
        ssh: 'ti-terminal-2', php: 'ti-brand-php', webserver: 'ti-world',
        mail: 'ti-mail', cpanel: 'ti-server', os: 'ti-cpu', firewall: 'ti-firewall'
    };
    // Status icons use innerHTML but only with hardcoded icon markup (no user data)
    var statusIcons = {
        pass: '<span class="text-success"><i class="ti ti-circle-check"></i></span>',
        warn: '<span class="text-warning"><i class="ti ti-alert-triangle"></i></span>',
        fail: '<span class="text-danger"><i class="ti ti-circle-x"></i></span>'
    };

    function renderReport(report) {
        if (!report || !report.results || report.results.length === 0) {
            document.getElementById('empty-state').classList.remove('d-none');
            document.getElementById('score-card').classList.add('d-none');
            document.getElementById('categories-container').textContent = '';
            return;
        }
        document.getElementById('empty-state').classList.add('d-none');
        document.getElementById('score-card').classList.remove('d-none');

        // Stored reports should carry score/total, but derive them from rows
        // when either field is missing so incomplete payloads remain useful.
        var rawTotal = Number(report.total);
        var total = report.total != null && isFinite(rawTotal) && rawTotal > 0 ? Math.floor(rawTotal) : report.results.length;
        var rawScore = Number(report.score);
        var score = report.score != null && isFinite(rawScore) && rawScore >= 0 ? Math.floor(rawScore) : 0;
        if (report.score == null || !isFinite(rawScore) || rawScore < 0) {
            for (var si = 0; si < report.results.length; si++) {
                if (report.results[si].status === 'pass') score++;
            }
        }
        var pct = total > 0 ? Math.round((score / total) * 100) : 0;
        document.getElementById('score-text').textContent = score + ' / ' + total + ' checks passed';
        var bar = document.getElementById('score-bar');
        CSM.setProgressBar(bar, pct);
        bar.className = 'progress-bar';
        if (total === 0) bar.classList.add('bg-secondary');
        else if (pct >= 80) bar.classList.add('bg-success');
        else if (pct >= 60) bar.classList.add('bg-warning');
        else bar.classList.add('bg-danger');

        var typeLabel = { cpanel: 'cPanel', cloudlinux: 'CloudLinux + cPanel', bare: 'Bare Server' };
        document.getElementById('score-server-type').textContent = '(' + (typeLabel[report.server_type] || report.server_type) + ')';
        if (report.timestamp) {
            document.getElementById('audit-timestamp').textContent = 'Last run: ' + new Date(report.timestamp).toLocaleString();
        }

        var cats = {};
        var catOrder = ['ssh', 'php', 'webserver', 'mail', 'cpanel', 'os', 'firewall'];
        for (var i = 0; i < report.results.length; i++) {
            var r = report.results[i];
            if (!cats[r.category]) cats[r.category] = [];
            cats[r.category].push(r);
        }

        // Build category cards using DOM methods for safety, with innerHTML only
        // for structural markup where all dynamic values are CSM.esc()'d
        var container = document.getElementById('categories-container');
        container.textContent = ''; // clear

        for (var ci = 0; ci < catOrder.length; ci++) {
            var cat = catOrder[ci];
            var items = cats[cat];
            if (!items) continue;

            var passed = 0, warned = 0, failed = 0;
            for (var j = 0; j < items.length; j++) {
                if (items[j].status === 'pass') passed++;
                else if (items[j].status === 'warn') warned++;
                else failed++;
            }

            var badgeClass = 'bg-success', badgeText = 'All passed';
            if (failed > 0) { badgeClass = 'bg-danger'; badgeText = failed + ' failed'; }
            else if (warned > 0) { badgeClass = 'bg-warning'; badgeText = warned + ' warning' + (warned > 1 ? 's' : ''); }

            var card = document.createElement('div');
            card.className = 'card mb-2';
            var collapseId = 'cat-' + cat;

            var header = document.createElement('div');
            header.className = 'card-header cursor-pointer';
            header.setAttribute('data-bs-toggle', 'collapse');
            header.setAttribute('data-bs-target', '#' + collapseId);
            var headerInner = document.createElement('div');
            headerInner.className = 'd-flex align-items-center w-100';
            var iconEl = document.createElement('i');
            iconEl.className = 'ti ' + (categoryIcons[cat] || 'ti-circle') + ' me-2';
            var nameEl = document.createElement('strong');
            nameEl.textContent = categoryNames[cat] || cat;
            var badge = document.createElement('span');
            badge.className = 'badge ' + badgeClass + ' ms-auto';
            badge.textContent = badgeText;
            headerInner.appendChild(iconEl);
            headerInner.appendChild(nameEl);
            headerInner.appendChild(badge);
            header.appendChild(headerInner);
            card.appendChild(header);

            var collapse = document.createElement('div');
            collapse.className = 'collapse' + (failed > 0 ? ' show' : '');
            collapse.id = collapseId;
            var tableWrap = document.createElement('div');
            tableWrap.className = 'table-responsive';
            var table = document.createElement('table');
            table.className = 'table table-vcenter card-table';
            var tbody = document.createElement('tbody');

            for (var k = 0; k < items.length; k++) {
                var item = items[k];
                var tr = document.createElement('tr');
                var tdIcon = document.createElement('td');
                tdIcon.className = 'w-1';
                // Safe: statusIcons contains only hardcoded icon HTML, no user data
                tdIcon.innerHTML = statusIcons[item.status] || '';
                var tdContent = document.createElement('td');
                var strong = document.createElement('strong');
                strong.textContent = item.title;
                var br = document.createElement('br');
                var msgSpan = document.createElement('span');
                msgSpan.className = 'text-muted';
                msgSpan.textContent = item.message;
                tdContent.appendChild(strong);
                tdContent.appendChild(br);
                tdContent.appendChild(msgSpan);
                tr.appendChild(tdIcon);
                tr.appendChild(tdContent);
                tbody.appendChild(tr);

                if (item.fix && item.status !== 'pass') {
                    var fixTr = document.createElement('tr');
                    var fixTdEmpty = document.createElement('td');
                    var fixTd = document.createElement('td');
                    fixTd.className = 'text-muted small';
                    fixTd.style.paddingTop = '0';
                    fixTd.style.borderTop = '0';
                    var fixIcon = document.createElement('i');
                    fixIcon.className = 'ti ti-tool me-1';
                    fixTd.appendChild(fixIcon);
                    fixTd.appendChild(document.createTextNode(item.fix));
                    fixTr.appendChild(fixTdEmpty);
                    fixTr.appendChild(fixTd);
                    tbody.appendChild(fixTr);
                }
            }

            table.appendChild(tbody);
            tableWrap.appendChild(table);
            collapse.appendChild(tableWrap);
            card.appendChild(collapse);
            container.appendChild(card);
        }
    }

    function loadReport() {
        // silent:true so CSM.request does not toast; the page owns its own
        // messaging. The empty-state ("no audit run yet") stays visible as the
        // recovery path, but a swallowed failure would read as "nothing has run"
        // rather than "the load failed", so surface it.
        CSM.get('/api/v1/hardening', { silent: true })
            .then(renderReport)
            .catch(function(err) {
                var msg = 'Failed to load hardening report';
                if (err && err.message) msg += ': ' + err.message;
                CSM.toast(msg, 'error');
            });
    }

    function runAudit() {
        var btn = document.getElementById('btn-run-audit');
        btn.disabled = true;
        // Safe: hardcoded spinner HTML, no user data
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Running...';
        CSM.post('/api/v1/hardening/run', {})
            .then(function(report) {
                renderReport(report);
                btn.disabled = false;
                btn.innerHTML = '<i class="ti ti-player-play"></i>&nbsp;Run Audit';
            })
            .catch(function(err) {
                btn.disabled = false;
                btn.innerHTML = '<i class="ti ti-player-play"></i>&nbsp;Run Audit';
                if (typeof CSM.toast === 'function') CSM.toast(err.message || 'Audit failed', 'error');
            });
    }

    document.getElementById('btn-run-audit').addEventListener('click', runAudit);

    // WEB_ROADMAP P2.4: shared exporter for the current audit report.
    var _hardeningExportRows = [];
    var _hardeningExportCols = [
        {key: 'category', label: 'Category'},
        {key: 'status',   label: 'Status'},
        {key: 'title',    label: 'Check'},
        {key: 'message',  label: 'Message'},
        {key: 'fix',      label: 'Suggested Fix'}
    ];
    var origRenderReport = renderReport;
    renderReport = function(report) {
        origRenderReport(report);
        _hardeningExportRows = ((report && report.results) || []).map(function(r) {
            return {
                category: categoryNames[r.category] || r.category || '',
                status:   r.status || '',
                title:    r.title || '',
                message:  r.message || '',
                fix:      r.fix || ''
            };
        });
    };
    document.querySelectorAll('[data-export]').forEach(function(el) {
        el.addEventListener('click', function(e) {
            e.preventDefault();
            CSM.exportTable(_hardeningExportRows, _hardeningExportCols, this.getAttribute('data-export'), 'csm-hardening');
        });
    });

    loadReport();
})();
