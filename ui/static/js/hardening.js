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
            document.getElementById('empty-state').style.display = '';
            document.getElementById('score-card').style.display = 'none';
            document.getElementById('categories-container').textContent = '';
            return;
        }
        document.getElementById('empty-state').style.display = 'none';
        document.getElementById('score-card').style.display = '';

        var pct = Math.round((report.score / report.total) * 100);
        document.getElementById('score-text').textContent = report.score + ' / ' + report.total + ' checks passed';
        var bar = document.getElementById('score-bar');
        bar.style.width = pct + '%';
        bar.className = 'progress-bar';
        if (pct >= 80) bar.classList.add('bg-success');
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
        fetch(CSM.apiUrl('/api/v1/hardening'), { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(renderReport)
            .catch(function() {});
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
                if (typeof CSM.toast === 'function') CSM.toast(err.message || 'Audit failed', 'danger');
            });
    }

    document.getElementById('btn-run-audit').addEventListener('click', runAudit);
    loadReport();
})();
