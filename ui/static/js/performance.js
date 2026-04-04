// CSM Performance Dashboard
(function() {
    'use strict';

    var CHECK_NAMES = {
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

    function update() {
        fetch(CSM.apiUrl('/api/v1/performance'), { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
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
                        ramBarEl.style.width = ramPct + '%';
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
                var mysqlEl = document.getElementById('stat-mysql');
                if (mysqlEl) {
                    var mysqlMem = m.mysql_mem_mb || 0;
                    var mysqlConns = m.mysql_conns || 0;
                    mysqlEl.textContent = mysqlMem + ' MB / ' + mysqlConns + ' conn';
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
                            progBar.style.width = pct + '%';
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

                            item.appendChild(header);

                            var msgDiv = document.createElement('div');
                            msgDiv.className = 'small';
                            msgDiv.textContent = f.message;
                            item.appendChild(msgDiv);

                            if (f.details) {
                                var detailsDiv = document.createElement('div');
                                detailsDiv.className = 'small text-muted mt-1';
                                detailsDiv.style.whiteSpace = 'pre-wrap';
                                detailsDiv.textContent = f.details;
                                item.appendChild(detailsDiv);
                            }

                            findingsEl.appendChild(item);
                        }
                    }
                }
            })
            .catch(function(err) {
                console.error('performance update:', err);
            });
    }

    update();
    setInterval(update, 10000);
})();
