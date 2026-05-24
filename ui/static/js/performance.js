// CSM Performance Dashboard
(function() {
    'use strict';

    var _fallbackNames = {
        'perf_load': 'Load',
        'perf_php_processes': 'PHP Processes',
        'perf_memory': 'Memory',
        'perf_php_handler': 'PHP Handler',
        'perf_mysql_config': 'MySQL Config',
        'perf_redis_config': 'Redis Config',
        'perf_error_logs': 'Error Logs',
        'perf_wp_config': 'WP Config',
        'perf_wp_transients': 'WP Transients',
        'perf_wp_cron': 'WP Cron'
    };
    var CHECK_NAMES = (typeof CSM_CONFIG !== 'undefined' && CSM_CONFIG.checkNames) || _fallbackNames;

    function sevClass(sev) {
        if (sev >= 2) return 'danger';
        if (sev >= 1) return 'warning';
        return 'info';
    }

    function sevLabel(sev) {
        if (sev >= 2) return 'CRITICAL';
        if (sev >= 1) return 'HIGH';
        return 'WARNING';
    }

    // colorClass returns a Bootstrap text color class based on thresholds.
    // val >= yellow => 'text-danger', val >= green => 'text-warning', else 'text-success'
    function colorClass(val, green, yellow) {
        if (val >= yellow) return 'text-danger';
        if (val >= green) return 'text-warning';
        return 'text-success';
    }

    // Pull a file path out of a perf finding when the check has a
    // remediation. Returns null when the check cannot be fixed from the
    // UI; the caller hides the Actions dropdown in that case.
    function describePerfAction(f) {
        if (!f) return null;
        if (f.check === 'perf_error_logs') {
            var prefix = 'Bloated error_log: ';
            var msg = f.message || '';
            if (msg.indexOf(prefix) !== 0) return null;
            var path = msg.slice(prefix.length).trim();
            if (!path) return null;
            return {
                endpoint: '/api/v1/perf/fix-error-log',
                path: path,
                key: f.key || '',
                label: 'Empty log file',
                bulkLabel: 'Empty all bloated logs',
                icon: 'ti-eraser',
                confirm: 'Truncate ' + path + ' to zero bytes? The file stays in place so PHP keeps writing to it.'
            };
        }
        if (f.check === 'perf_wp_config' && (f.message || '').indexOf('display_errors enabled') === 0) {
            var details = f.details || '';
            var match = /File:\s*([^,]+),\s*Value:\s*On/i.exec(details);
            if (!match) return null;
            var p = match[1].trim();
            if (!p) return null;
            return {
                endpoint: '/api/v1/perf/fix-display-errors',
                path: p,
                key: f.key || '',
                label: 'Disable display_errors',
                bulkLabel: 'Disable display_errors in all configs',
                icon: 'ti-shield-off',
                confirm: 'Comment the display_errors line in ' + p + ' and append an Off override at end of file?'
            };
        }
        return null;
    }

    // Per-row direct action button. Each perf finding currently has at
    // most one supported remediation; a dropdown wrapper buys nothing
    // here, so render a plain button labeled with the action verb.
    function buildActionButton(action) {
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-sm btn-outline-secondary';
        var icon = document.createElement('i');
        icon.className = 'ti ' + action.icon + ' me-1';
        btn.appendChild(icon);
        btn.appendChild(document.createTextNode(action.label));
        btn.addEventListener('click', function() {
            runPerfAction(action, btn);
        });
        return btn;
    }

    function runPerfAction(action, originBtn) {
        CSM.confirm(action.confirm).then(function() {
            originBtn.classList.add('disabled');
            CSM.post(action.endpoint, { path: action.path, key: action.key || '' }).then(function(data) {
                if (data && data.success) {
                    CSM.toast(data.description || 'Fix applied', 'success');
                    update();
                } else {
                    CSM.toast((data && data.error) || 'Fix failed', 'error');
                    originBtn.classList.remove('disabled');
                }
            }).catch(function(err) {
                CSM.toast('Error: ' + err, 'error');
                originBtn.classList.remove('disabled');
            });
        }).catch(function() { /* cancelled */ });
    }

    // Bulk groups: collect every remediable finding into per-endpoint
    // buckets so the header offers one click to fix all of them. Sequential
    // POSTs keep the firewall/audit log readable and let a partial failure
    // report the count cleanly without rolling back applied edits.
    function buildBulkGroups(findings) {
        var groups = {};
        for (var i = 0; i < findings.length; i++) {
            var a = describePerfAction(findings[i]);
            if (!a) continue;
            var key = a.endpoint;
            if (!groups[key]) {
                groups[key] = { endpoint: a.endpoint, label: a.bulkLabel || a.label, icon: a.icon, items: [] };
            }
            groups[key].items.push({ path: a.path, key: a.key || '' });
        }
        return groups;
    }

    function renderBulkActions(findings) {
        var holder = document.getElementById('perf-bulk-actions');
        if (!holder) return;
        holder.textContent = '';
        var groups = buildBulkGroups(findings);
        var keys = Object.keys(groups);
        if (keys.length === 0) return;

        var wrap = document.createElement('div');
        wrap.className = 'dropdown';
        var toggle = document.createElement('button');
        toggle.type = 'button';
        toggle.className = 'btn btn-sm btn-outline-secondary dropdown-toggle';
        toggle.setAttribute('data-bs-toggle', 'dropdown');
        toggle.setAttribute('aria-expanded', 'false');
        var ti = document.createElement('i');
        ti.className = 'ti ti-tools me-1';
        toggle.appendChild(ti);
        toggle.appendChild(document.createTextNode('Bulk fix'));
        var menu = document.createElement('div');
        menu.className = 'dropdown-menu dropdown-menu-end';
        for (var i = 0; i < keys.length; i++) {
            (function(g) {
                var link = document.createElement('a');
                link.className = 'dropdown-item';
                link.href = '#';
                var ic = document.createElement('i');
                ic.className = 'ti ' + g.icon + ' me-2';
                link.appendChild(ic);
                link.appendChild(document.createTextNode(g.label + ' (' + g.items.length + ')'));
                link.addEventListener('click', function(e) {
                    e.preventDefault();
                    runBulkPerfAction(g, link);
                });
                menu.appendChild(link);
            })(groups[keys[i]]);
        }
        wrap.appendChild(toggle);
        wrap.appendChild(menu);
        holder.appendChild(wrap);
    }

    function runBulkPerfAction(group, originLink) {
        var n = group.items.length;
        var msg = 'Apply "' + group.label + '" to ' + n + ' finding' + (n === 1 ? '' : 's') + '?';
        CSM.confirm(msg).then(function() {
            originLink.classList.add('disabled');
            var ok = 0, failed = 0, errs = [];
            function next(i) {
                if (i >= group.items.length) {
                    if (failed === 0) {
                        CSM.toast('Fixed ' + ok + ' of ' + group.items.length, 'success');
                    } else if (ok === 0) {
                        CSM.toast('All ' + failed + ' failed: ' + errs.slice(0, 2).join('; '), 'error');
                    } else {
                        CSM.toast('Fixed ' + ok + ', failed ' + failed + ' (' + errs.slice(0, 2).join('; ') + ')', 'warning');
                    }
                    originLink.classList.remove('disabled');
                    update();
                    return;
                }
                var it = group.items[i];
                CSM.post(group.endpoint, { path: it.path, key: it.key }).then(function(data) {
                    if (data && data.success) ok++;
                    else { failed++; if (data && data.error) errs.push(data.error); }
                    next(i + 1);
                }).catch(function(e) {
                    failed++;
                    errs.push(String(e));
                    next(i + 1);
                });
            }
            next(0);
        }).catch(function() { /* cancelled */ });
    }

    function update() {
        CSM.get('/api/v1/performance')
            .then(function(data) {
                var m = data.metrics || {};
                var findings = data.findings || [];
                var cores = m.cpu_cores || 1;

                // --- Load Average ---
                var loadEl = document.getElementById('stat-load');
                var loadDetailEl = document.getElementById('stat-load-detail');
                if (loadEl) {
                    var load1 = m.load_avg ? m.load_avg[0] : 0;
                    loadEl.textContent = load1.toFixed(2);
                    loadEl.className = 'h1 mb-0 ' + colorClass(load1, cores, cores * 2);
                }
                if (loadDetailEl && m.load_avg) {
                    loadDetailEl.textContent = m.load_avg[0].toFixed(2) + ' / ' +
                        m.load_avg[1].toFixed(2) + ' / ' +
                        m.load_avg[2].toFixed(2);
                }

                // --- CPU Cores ---
                var coresEl = document.getElementById('stat-cores');
                if (coresEl) {
                    coresEl.textContent = cores;
                    coresEl.className = 'h1 mb-0';
                }

                // --- RAM ---
                var ramEl = document.getElementById('stat-ram');
                var ramBarEl = document.getElementById('stat-ram-bar');
                if (ramEl && m.mem_total_mb) {
                    var usedMB = m.mem_used_mb || 0;
                    var totalMB = m.mem_total_mb || 1;
                    var ramPct = Math.round(usedMB / totalMB * 100);
                    ramEl.textContent = usedMB + ' / ' + totalMB + ' MB';
                    ramEl.className = 'h1 mb-0 ' + colorClass(ramPct, 70, 90);
                    if (ramBarEl) {
                        CSM.setProgressBar(ramBarEl, ramPct);
                        ramBarEl.className = 'progress-bar ' + (ramPct >= 90 ? 'bg-danger' : ramPct >= 75 ? 'bg-warning' : 'bg-success');
                    }
                }

                // --- PHP Processes ---
                var phpEl = document.getElementById('stat-php');
                if (phpEl) {
                    var phpTotal = m.php_procs_total || 0;
                    phpEl.textContent = phpTotal;
                    phpEl.className = 'h1 mb-0 ' + colorClass(phpTotal, cores * 2, cores * 4);
                }

                // --- MySQL ---
                // Both fields are null when the mysql client lookup failed
                // (no ~/.my.cnf, no socket auth, mysqld absent). Render "n/a"
                // for the missing piece so operators do not read it as 0.
                var mysqlEl = document.getElementById('stat-mysql');
                if (mysqlEl) {
                    var memText = (typeof m.mysql_mem_mb === 'number') ? m.mysql_mem_mb + ' MB' : 'n/a';
                    var connText = (typeof m.mysql_conns === 'number') ? m.mysql_conns + ' conn' : 'n/a';
                    mysqlEl.textContent = memText + ' / ' + connText;
                    mysqlEl.className = 'h1 mb-0';
                }

                // --- Redis ---
                var redisEl = document.getElementById('stat-redis');
                if (redisEl) {
                    var redisMem = m.redis_mem_mb || 0;
                    var redisMax = m.redis_maxmem_mb || 0;
                    if (redisMax === 0) {
                        redisEl.textContent = redisMem + ' MB / no limit';
                        redisEl.className = 'h1 mb-0 ' + (redisMem > 0 ? 'text-danger' : '');
                    } else {
                        redisEl.textContent = redisMem + ' / ' + redisMax + ' MB';
                        redisEl.className = 'h1 mb-0 ' + colorClass(redisMem, redisMax * 0.75, redisMax * 0.9);
                    }
                }

                // --- PHP Consumers Table ---
                var tbody = document.getElementById('php-consumers');
                if (tbody) {
                    tbody.textContent = '';
                    var consumers = m.top_php_users || [];
                    var maxCount = consumers.length > 0 ? consumers[0].count : 1;
                    if (consumers.length === 0) {
                        var emptyTr = document.createElement('tr');
                        var emptyTd = document.createElement('td');
                        emptyTd.colSpan = 3;
                        emptyTd.className = 'text-center text-muted py-3';
                        emptyTd.textContent = 'No PHP processes';
                        emptyTr.appendChild(emptyTd);
                        tbody.appendChild(emptyTr);
                    } else {
                        for (var i = 0; i < consumers.length; i++) {
                            var c = consumers[i];
                            var pct = Math.round(c.count / maxCount * 100);

                            var tr = document.createElement('tr');

                            var tdUser = document.createElement('td');
                            var code = document.createElement('code');
                            code.textContent = c.user;
                            tdUser.appendChild(code);
                            tr.appendChild(tdUser);

                            var tdCount = document.createElement('td');
                            tdCount.textContent = c.count;
                            tr.appendChild(tdCount);

                            var tdBar = document.createElement('td');
                            tdBar.style.width = '40%';
                            var progWrap = document.createElement('div');
                            progWrap.className = 'progress progress-sm';
                            var progBar = document.createElement('div');
                            progBar.className = 'progress-bar bg-primary';
                            CSM.setProgressBar(progBar, pct);
                            progWrap.appendChild(progBar);
                            tdBar.appendChild(progWrap);
                            tr.appendChild(tdBar);

                            tbody.appendChild(tr);
                        }
                    }
                }

                // --- Performance Findings ---
                var findingsEl = document.getElementById('perf-findings');
                if (findingsEl) {
                    findingsEl.textContent = '';
                    if (findings.length === 0) {
                        var noItem = document.createElement('div');
                        noItem.className = 'list-group-item text-muted';
                        noItem.textContent = 'No performance findings';
                        findingsEl.appendChild(noItem);
                    } else {
                        for (var j = 0; j < findings.length; j++) {
                            var f = findings[j];
                            var sc = sevClass(f.severity);
                            var sl = sevLabel(f.severity);
                            var checkName = CHECK_NAMES[f.check] || f.check;

                            var item = document.createElement('div');
                            item.className = 'list-group-item';

                            var header = document.createElement('div');
                            header.className = 'd-flex align-items-center gap-2 mb-1';

                            var badge = document.createElement('span');
                            badge.className = 'badge bg-' + sc;
                            badge.textContent = sl;
                            header.appendChild(badge);

                            var name = document.createElement('strong');
                            name.textContent = checkName;
                            header.appendChild(name);

                            // Actions dropdown (right-aligned). Only rendered
                            // when the finding carries a path we know how to
                            // remediate; perf checks without a path or with
                            // an unsupported file type stay informational.
                            var action = describePerfAction(f);
                            if (action) {
                                var spacer = document.createElement('div');
                                spacer.className = 'ms-auto';
                                header.appendChild(spacer);
                                header.appendChild(buildActionButton(action));
                            }

                            item.appendChild(header);

                            var msgDiv = document.createElement('div');
                            msgDiv.className = 'small';
                            msgDiv.textContent = f.message;
                            item.appendChild(msgDiv);

                            if (f.details) {
                                var detailsDiv = document.createElement('div');
                                detailsDiv.className = 'small text-muted mt-1 csm-detail';
                                detailsDiv.textContent = f.details;
                                item.appendChild(detailsDiv);
                            }

                            findingsEl.appendChild(item);
                        }
                    }
                    renderBulkActions(findings);
                }
            })
            .catch(function(err) {
                console.error('performance update:', err);
            });
    }

    update();
    var _perfInterval = setInterval(update, 10000);
    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            clearInterval(_perfInterval);
        } else {
            update();
            _perfInterval = setInterval(update, 10000);
        }
    });
})();
