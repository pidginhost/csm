(function() {
    var categoryNames = {
        ssh: 'SSH', php: 'PHP', webserver: 'Web Server', mail: 'Mail',
        cpanel: 'cPanel / WHM', os: 'OS Hardening', firewall: 'Firewall'
    };
    var categoryIcons = {
        ssh: 'ti-terminal-2', php: 'ti-brand-php', webserver: 'ti-world',
        mail: 'ti-mail', cpanel: 'ti-server', os: 'ti-cpu', firewall: 'ti-firewall-check'
    };
    // Status icons use innerHTML but only with hardcoded icon markup (no user data)
    var statusIcons = {
        pass: '<span class="text-success"><i class="ti ti-circle-check"></i></span>',
        warn: '<span class="text-warning"><i class="ti ti-alert-triangle"></i></span>',
        fail: '<span class="text-danger"><i class="ti ti-circle-x"></i></span>'
    };

    // Outcome of the last "Apply fixes" per section, shown above that
    // section's checks after the recheck re-renders the page.
    var lastApply = {};
    var applying = false;

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
            document.getElementById('audit-timestamp').textContent = 'Last run: ' + CSM.fmtDate(report.timestamp, { tz: true });
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

            var passed = 0, warned = 0, failed = 0, fixable = 0;
            for (var j = 0; j < items.length; j++) {
                if (items[j].status === 'pass') passed++;
                else if (items[j].status === 'warn') warned++;
                else failed++;
                if (items[j].status !== 'pass' && items[j].auto_fix) fixable++;
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
            if (fixable > 0) {
                var fixBadge = document.createElement('span');
                fixBadge.className = 'badge bg-azure-lt ms-2';
                fixBadge.textContent = fixable + ' auto-fixable';
                headerInner.appendChild(fixBadge);
            }
            header.appendChild(headerInner);
            card.appendChild(header);

            var collapse = document.createElement('div');
            collapse.className = 'collapse' + (failed > 0 || lastApply[cat] ? ' show' : '');
            collapse.id = collapseId;
            if (lastApply[cat]) collapse.appendChild(renderApplyOutcome(lastApply[cat]));
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

                if (item.auto_fix && item.status !== 'pass') {
                    var autoTr = document.createElement('tr');
                    var autoTdEmpty = document.createElement('td');
                    var autoTd = document.createElement('td');
                    autoTd.className = 'small';
                    autoTd.style.paddingTop = '0';
                    autoTd.style.borderTop = '0';
                    var label = document.createElement('label');
                    label.className = 'form-check mb-0';
                    var cb = document.createElement('input');
                    cb.type = 'checkbox';
                    cb.className = 'form-check-input';
                    // A fix that can disrupt a working host starts unticked.
                    cb.checked = !item.auto_fix_caution;
                    cb.setAttribute('data-fix-cat', cat);
                    cb.setAttribute('data-fix-name', item.name);
                    cb.setAttribute('data-fix-desc', item.auto_fix);
                    var labelText = document.createElement('span');
                    labelText.className = 'form-check-label';
                    var autoStrong = document.createElement('strong');
                    autoStrong.textContent = 'Auto-fix: ';
                    labelText.appendChild(autoStrong);
                    labelText.appendChild(document.createTextNode(item.auto_fix));
                    if (item.auto_fix_caution) {
                        var caution = document.createElement('div');
                        caution.className = 'text-warning';
                        caution.textContent = 'Can break: ' + item.auto_fix_caution;
                        labelText.appendChild(caution);
                    }
                    label.appendChild(cb);
                    label.appendChild(labelText);
                    autoTd.appendChild(label);
                    autoTr.appendChild(autoTdEmpty);
                    autoTr.appendChild(autoTd);
                    tbody.appendChild(autoTr);
                }
            }

            table.appendChild(tbody);
            tableWrap.appendChild(table);
            collapse.appendChild(tableWrap);
            if (fixable > 0) {
                var footer = document.createElement('div');
                footer.className = 'card-footer d-flex align-items-center flex-wrap gap-2';
                var applyBtn = document.createElement('button');
                applyBtn.type = 'button';
                applyBtn.className = 'btn btn-primary btn-sm';
                applyBtn.setAttribute('data-apply-cat', cat);
                applyBtn.disabled = applying;
                var applyIcon = document.createElement('i');
                applyIcon.className = 'ti ti-tool';
                applyBtn.appendChild(applyIcon);
                applyBtn.appendChild(document.createTextNode('\u00a0Apply selected fixes'));
                applyBtn.addEventListener('click', applySection);
                var note = document.createElement('span');
                note.className = 'text-muted small';
                note.textContent = 'CSM changes only the checked items, then re-runs the audit.';
                footer.appendChild(applyBtn);
                footer.appendChild(note);
                collapse.appendChild(footer);
            }
            card.appendChild(collapse);
            container.appendChild(card);
        }
    }

    // Lists what the last apply did in a section: applied, failed, skipped.
    function renderApplyOutcome(outcome) {
        var box = document.createElement('div');
        var anyFailed = outcome.some(function(o) { return o.status === 'failed'; });
        box.className = 'alert m-3 ' + (anyFailed ? 'alert-warning' : 'alert-success');
        box.setAttribute('role', 'status');
        var title = document.createElement('div');
        title.className = 'fw-bold mb-1';
        title.textContent = 'Last apply (audit re-run afterwards)';
        box.appendChild(title);
        var list = document.createElement('ul');
        list.className = 'mb-0';
        for (var i = 0; i < outcome.length; i++) {
            var o = outcome[i];
            var li = document.createElement('li');
            var st = document.createElement('strong');
            st.className = o.status === 'applied' ? 'text-success' : (o.status === 'failed' ? 'text-danger' : 'text-muted');
            st.textContent = o.status;
            li.appendChild(st);
            li.appendChild(document.createTextNode(' ' + (o.title || o.name) + ': ' + (o.message || '')));
            list.appendChild(li);
        }
        box.appendChild(list);
        return box;
    }

    function setApplyBusy(busy) {
        applying = busy;
        document.querySelectorAll('[data-apply-cat]').forEach(function(b) { b.disabled = busy; });
        document.getElementById('btn-run-audit').disabled = busy;
    }

    function applySection(e) {
        var cat = e.currentTarget.getAttribute('data-apply-cat');
        var names = [], descs = [];
        document.querySelectorAll('input[data-fix-cat]').forEach(function(cb) {
            if (cb.getAttribute('data-fix-cat') !== cat || !cb.checked) return;
            names.push(cb.getAttribute('data-fix-name'));
            descs.push('- ' + cb.getAttribute('data-fix-desc'));
        });
        var section = categoryNames[cat] || cat;
        if (names.length === 0) {
            CSM.toast('Check at least one fix to apply in ' + section + '.', 'warning');
            return;
        }
        var msg = 'Apply ' + names.length + ' fix' + (names.length > 1 ? 'es' : '') + ' in ' + section + '?\n\n' +
            descs.join('\n') + '\n\nCSM changes this server now, then re-runs the audit.';
        CSM.confirm(msg, { okLabel: 'Apply' }).then(function() {
            var btn = document.querySelector('[data-apply-cat="' + cat + '"]');
            setApplyBusy(true);
            if (btn) {
                // Safe: hardcoded spinner HTML, no user data
                btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Applying...';
            }
            CSM.post('/api/v1/hardening/apply', { category: cat, names: names }, { timeoutMs: 0 })
                .then(function(resp) {
                    var outcome = (resp && resp.applied) || [];
                    lastApply = {};
                    lastApply[cat] = outcome;
                    applying = false;
                    renderReport(resp);
                    setApplyBusy(false);
                    var ok = 0, bad = 0;
                    outcome.forEach(function(o) { if (o.status === 'applied') ok++; else if (o.status === 'failed') bad++; });
                    CSM.toast(section + ': ' + ok + ' applied' + (bad ? ', ' + bad + ' failed' : '') + '. Audit re-run.', bad ? 'warning' : 'success');
                })
                .catch(function(err) {
                    setApplyBusy(false);
                    if (btn) {
                        btn.textContent = '';
                        var ic = document.createElement('i');
                        ic.className = 'ti ti-tool';
                        btn.appendChild(ic);
                        btn.appendChild(document.createTextNode('\u00a0Apply selected fixes'));
                    }
                    CSM.toast((err && err.message) || 'Applying fixes failed', 'error');
                    // A failed worker may have changed some files; the server
                    // re-ran the audit, so show that report.
                    if (err && err.status === 500) {
                        lastApply = {};
                        if (err.body && err.body.report) {
                            renderReport(err.body.report);
                        } else {
                            setApplyBusy(true);
                            loadReport().finally(function() { setApplyBusy(false); });
                        }
                    }
                });
        }, function() {});
    }

    function loadReport() {
        // silent:true so CSM.request does not toast; the failure shows in
        // place of the report. The "no audit results" message is hidden with
        // it, or a failed load would read as "nothing has run".
        return CSM.get('/api/v1/hardening', { silent: true })
            .then(renderReport)
            .catch(function(err) {
                document.getElementById('empty-state').classList.add('d-none');
                CSM.loadError(document.getElementById('categories-container'), loadReport, { title: 'Failed to load hardening report', error: err });
            });
    }

    function runAudit() {
        var btn = document.getElementById('btn-run-audit');
        btn.disabled = true;
        // Safe: hardcoded spinner HTML, no user data
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Running...';
        CSM.post('/api/v1/hardening/run', {})
            .then(function(report) {
                lastApply = {};
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
        {key: 'fix',      label: 'Suggested Fix'},
        {key: 'auto_fix', label: 'Auto-fix'}
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
                fix:      r.fix || '',
                auto_fix: r.auto_fix || ''
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
    // Refresh re-reads the stored report; it does not run a new audit.
    if (CSM.refresh) CSM.refresh.onRefresh(loadReport);
})();
