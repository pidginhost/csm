// CSM Findings page

// --- Table init with search + check type filter ---
var findingsTable;
if (document.getElementById('findings-table')) {
    findingsTable = new CSM.Table({
        tableId: 'findings-table',
        perPage: 25,
        search: true,
        searchId: 'findings-search',
        sortable: true,
        filters: [{ id: 'check-filter', attr: 'data-check' }],
        stateKey: 'csm-findings-table'
    });
}

function changePerPage() {
    var pp = parseInt(document.getElementById('per-page').value, 10);
    if (findingsTable) {
        findingsTable.perPage = pp || 0;
        findingsTable.currentPage = 1;
        findingsTable.render();
    }
}
var perPageEl = document.getElementById('per-page');
if (perPageEl) perPageEl.addEventListener('change', changePerPage);

// --- Selection management ---
function getVisibleRows() {
    return Array.from(document.querySelectorAll('.finding-row')).filter(function(r) {
        return r.style.display !== 'none';
    });
}

function getSelectedRows() {
    return getVisibleRows().filter(function(r) {
        var cb = r.querySelector('.row-checkbox');
        return cb && cb.checked;
    });
}

function toggleSelectAll() {
    var checked = document.getElementById('select-all').checked;
    getVisibleRows().forEach(function(r) {
        var cb = r.querySelector('.row-checkbox');
        if (cb) cb.checked = checked;
    });
    updateSelection();
}

function updateSelection() {
    var selected = getSelectedRows();
    var count = selected.length;
    document.getElementById('selected-count').textContent = count;
    document.getElementById('bulk-actions').classList.toggle('d-none', count === 0);
    // Show Fix button only if any selected row is fixable
    var hasFixable = selected.some(function(r) { return r.getAttribute('data-hasFix') === 'true'; });
    document.getElementById('bulk-fix-btn').classList.toggle('d-none', !hasFixable);
}

// Reset select-all when filter changes
var checkFilterEl = document.getElementById('check-filter');
if (checkFilterEl) checkFilterEl.addEventListener('change', function() {
    var selectAll = document.getElementById('select-all');
    if (selectAll) selectAll.checked = false;
    document.querySelectorAll('.row-checkbox').forEach(function(cb) { cb.checked = false; });
    updateSelection();
});

// --- Single actions ---
function fixOne(btn) {
    var row = btn.closest('tr');
    var desc = row.getAttribute('data-fixdesc');
    CSM.confirm('Apply fix?\n\n' + desc).then(function() {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
        CSM.post('/api/v1/fix', {
            check: row.getAttribute('data-check'),
            message: row.getAttribute('data-message')
        }).then(function(data) {
            if (data.success) {
                row.style.opacity = '0.3';
                btn.innerHTML = '<i class="ti ti-check"></i>';
                btn.className = 'btn btn-success btn-sm me-1';
                setTimeout(function() { location.reload(); }, 1000);
            } else {
                CSM.toast('Fix failed: ' + (data.error || 'unknown'), 'error');
                btn.disabled = false;
                btn.innerHTML = '<i class="ti ti-tool"></i>';
            }
        }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); btn.disabled = false; btn.innerHTML = '<i class="ti ti-tool"></i>'; });
    }).catch(function() {});
}

function dismissOne(key) {
    CSM.confirm('Dismiss this finding?').then(function() {
        CSM.post('/api/v1/dismiss', {key: key}).then(function() { location.reload(); }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
    }).catch(function() {});
}

// --- Bulk actions ---
function bulkAction(action) {
    var selected = getSelectedRows();
    if (selected.length === 0) return;

    var items = selected.map(function(row) {
        return {
            check: row.getAttribute('data-check'),
            message: row.getAttribute('data-message'),
            fixable: row.getAttribute('data-hasFix') === 'true'
        };
    });

    if (action === 'fix') {
        var fixable = items.filter(function(i) { return i.fixable; });
        if (fixable.length === 0) { CSM.toast('None of the selected findings have automated fixes.', 'warning'); return; }
        CSM.confirm('Fix ' + fixable.length + ' finding(s)?\n\nThis will apply automated fixes (chmod, quarantine, etc.) to the selected items.').then(function() {
            var fixItems = fixable.map(function(i) { return { check: i.check, message: i.message, details: '' }; });
            CSM.post('/api/v1/fix-bulk', fixItems).then(function(data) {
                CSM.toast('Fixed ' + data.succeeded + ' of ' + data.total + (data.failed > 0 ? ' (' + data.failed + ' failed)' : ''), 'success');
                location.reload();
            }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
        }).catch(function() {});

    } else if (action === 'dismiss') {
        CSM.confirm('Dismiss ' + items.length + ' finding(s)?').then(function() {
            var promises = items.map(function(i) {
                return CSM.post('/api/v1/dismiss', { key: i.check + ':' + i.message });
            });
            Promise.all(promises).then(function() { location.reload(); }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
        }).catch(function() {});

    } else if (action === 'quarantine') {
        CSM.confirm('Quarantine ' + items.length + ' file(s)?\n\nFiles will be moved to /opt/csm/quarantine/').then(function() {
            var quarItems = items.map(function(i) { return { check: i.check, message: i.message, details: '' }; });
            CSM.post('/api/v1/fix-bulk', quarItems).then(function(data) {
                CSM.toast('Quarantined ' + data.succeeded + ' of ' + data.total, 'success');
                location.reload();
            }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
        }).catch(function() {});
    }
}

// --- Scan account ---
document.getElementById('scan-form').addEventListener('submit', function(e) {
    e.preventDefault();
    var account = document.getElementById('scan-account').value.trim();
    if (!account) return;
    var btn = document.getElementById('scan-btn');
    var status = document.getElementById('scan-status').querySelector('span');
    var results = document.getElementById('scan-results');
    var tbody = document.getElementById('scan-tbody');
    btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Scanning...';
    status.textContent = ''; results.classList.add('d-none'); tbody.innerHTML = '';
    CSM.post('/api/v1/scan-account', {account: account}).then(function(data) {
        btn.disabled = false; btn.innerHTML = '<i class="ti ti-radar-2"></i>&nbsp;Scan';
        if (data.error) { status.textContent = data.error; status.className = 'text-danger small'; return; }
        if (!data.count) { status.textContent = account + ' is clean (' + data.elapsed + ')'; status.className = 'text-success small'; return; }
        status.textContent = data.count + ' finding(s) in ' + data.elapsed; status.className = 'text-danger small';
        results.classList.remove('d-none');
        var fixableChecks = {'world_writable_php':1,'group_writable_php':1,'webshell':1,'new_webshell_file':1,'obfuscated_php':1,'php_dropper':1,'suspicious_php_content':1,'new_php_in_languages':1,'new_php_in_upgrade':1,'phishing_page':1,'phishing_directory':1,'backdoor_binary':1,'new_executable_in_config':1};
        (data.findings||[]).forEach(function(f) {
            var sev = f.severity===2?'critical':f.severity===1?'high':'warning';
            var label = f.severity===2?'CRITICAL':f.severity===1?'HIGH':'WARNING';
            var tr = document.createElement('tr');
            var actionHtml = '';
            if (fixableChecks[f.check]) {
                actionHtml = '<button class="btn btn-warning btn-sm scan-fix-btn" data-check="'+esc(f.check)+'" data-message="'+esc(f.message)+'"><i class="ti ti-tool"></i>&nbsp;Fix</button>';
            }
            tr.innerHTML = '<td><span class="badge badge-'+sev+'">'+label+'</span></td><td><code>'+esc(f.check)+'</code></td><td>'+esc(f.message)+'</td><td>'+actionHtml+'</td>';
            tbody.appendChild(tr);
        });
        // Bind fix buttons on scan results
        document.querySelectorAll('.scan-fix-btn').forEach(function(btn) {
            btn.addEventListener('click', function() {
                var check = this.getAttribute('data-check');
                var message = this.getAttribute('data-message');
                var self = this;
                CSM.confirm('Apply fix for ' + check + '?').then(function() {
                    self.disabled = true;
                    self.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
                    CSM.post('/api/v1/fix', {check: check, message: message}).then(function(d) {
                        if (d.success) { self.innerHTML = '<i class="ti ti-check"></i>'; self.className = 'btn btn-success btn-sm'; }
                        else { CSM.toast('Failed: ' + (d.error||''), 'error'); self.disabled = false; self.innerHTML = '<i class="ti ti-tool"></i>&nbsp;Fix'; }
                    }).catch(function(e) { CSM.toast('Error: '+e, 'error'); self.disabled=false; self.innerHTML='<i class="ti ti-tool"></i>&nbsp;Fix'; });
                }).catch(function() {});
            });
        });
    }).catch(function(e) { btn.disabled=false; btn.innerHTML='<i class="ti ti-radar-2"></i>&nbsp;Scan'; status.textContent='Error: '+e; status.className='text-danger small'; });
});

// Load account list for autocomplete dropdown
fetch('/api/v1/accounts', {credentials:'same-origin'}).then(function(r){return r.json()}).then(function(accounts) {
    var dl = document.getElementById('account-list');
    (accounts||[]).forEach(function(a) {
        var opt = document.createElement('option');
        opt.value = a;
        dl.appendChild(opt);
    });
}).catch(function(){});

// Bind select-all checkbox
var _selectAll = document.getElementById('select-all');
if (_selectAll) _selectAll.addEventListener('change', toggleSelectAll);

// Bind row checkboxes
document.querySelectorAll('.row-checkbox').forEach(function(cb) {
    cb.addEventListener('change', updateSelection);
});

// Bind bulk action buttons
var _bulkFixBtn = document.getElementById('bulk-fix-btn');
if (_bulkFixBtn) _bulkFixBtn.addEventListener('click', function() { bulkAction('fix'); });
var _bulkDismissBtn = document.getElementById('bulk-dismiss-btn');
if (_bulkDismissBtn) _bulkDismissBtn.addEventListener('click', function() { bulkAction('dismiss'); });

// --- Findings grouping ---
(function() {
    var groupByEl = document.getElementById('group-by');
    if (!groupByEl) return;

    // Inject CSS for group headers
    var style = document.createElement('style');
    style.textContent =
        '.csm-group-header { cursor: pointer; user-select: none; }' +
        '.csm-group-header td { background-color: rgba(0,0,0,0.03); font-weight: 600; padding: 8px 12px !important; }' +
        '.theme-dark .csm-group-header td { background-color: rgba(255,255,255,0.04); }' +
        '.csm-group-header .csm-group-arrow { display: inline-block; transition: transform 0.2s; margin-right: 6px; }' +
        '.csm-group-header.collapsed .csm-group-arrow { transform: rotate(-90deg); }';
    document.head.appendChild(style);

    function extractAccount(row) {
        var msg = row.getAttribute('data-message') || '';
        var match = msg.match(/\/home\/([^\/\s]+)\//);
        return match ? match[1] : '(unknown)';
    }

    function getGroupKey(row, mode) {
        if (mode === 'account') return extractAccount(row);
        if (mode === 'check') return row.getAttribute('data-check') || '(unknown)';
        return null;
    }

    function removeGroupHeaders() {
        var headers = document.querySelectorAll('.csm-group-header');
        for (var i = 0; i < headers.length; i++) {
            headers[i].remove();
        }
    }

    var _savedPerPage = null;

    function applyGrouping() {
        var mode = groupByEl.value;
        removeGroupHeaders();

        // Show all finding rows (remove group-hidden state)
        document.querySelectorAll('.finding-row').forEach(function(r) {
            r.removeAttribute('data-csm-group');
            r.classList.remove('csm-group-hidden');
        });

        if (mode === 'none') {
            // Restore original perPage and re-render
            if (findingsTable && _savedPerPage !== null) {
                findingsTable.perPage = _savedPerPage;
                _savedPerPage = null;
            }
            if (findingsTable) findingsTable.applyFilters();
            return;
        }

        // When grouping, show all rows (disable pagination)
        if (findingsTable) {
            if (_savedPerPage === null) {
                _savedPerPage = findingsTable.perPage;
            }
            findingsTable.perPage = 0;
            findingsTable.applyFilters();
        }

        var tbody = document.getElementById('findings-tbody');
        if (!tbody) return;

        // Get all filtered rows (all visible since pagination is disabled)
        var visibleRows = Array.from(tbody.querySelectorAll('.finding-row')).filter(function(r) {
            return r.style.display !== 'none';
        });

        // Build groups
        var groups = {};
        var groupOrder = [];
        visibleRows.forEach(function(row) {
            var key = getGroupKey(row, mode);
            if (!groups[key]) {
                groups[key] = [];
                groupOrder.push(key);
            }
            groups[key].push(row);
            row.setAttribute('data-csm-group', key);
        });

        // Sort group names
        groupOrder.sort();

        // Get number of columns from thead
        var colCount = 6;
        var theadRow = document.querySelector('#findings-table thead tr');
        if (theadRow) colCount = theadRow.children.length;

        // Insert group headers and reorder rows
        groupOrder.forEach(function(key) {
            var headerRow = document.createElement('tr');
            headerRow.className = 'csm-group-header';
            headerRow.setAttribute('data-csm-group-key', key);
            var td = document.createElement('td');
            td.colSpan = colCount;
            td.innerHTML = '<span class="csm-group-arrow">&#9660;</span>' +
                CSM.esc(key) + ' <span class="text-muted small">(' + groups[key].length + ' finding' + (groups[key].length !== 1 ? 's' : '') + ')</span>';
            headerRow.appendChild(td);

            // Append header and then all group rows in order
            tbody.appendChild(headerRow);
            groups[key].forEach(function(row) {
                tbody.appendChild(row);
            });

            // Click to collapse/expand
            headerRow.addEventListener('click', function() {
                var isCollapsed = headerRow.classList.toggle('collapsed');
                groups[key].forEach(function(row) {
                    row.style.display = isCollapsed ? 'none' : '';
                });
            });
        });
    }

    groupByEl.addEventListener('change', applyGrouping);

    // Re-apply grouping when table filters change
    var checkFilter = document.getElementById('check-filter');
    if (checkFilter) {
        checkFilter.addEventListener('change', function() {
            setTimeout(applyGrouping, 50);
        });
    }
    var searchEl = document.getElementById('findings-search');
    if (searchEl) {
        searchEl.addEventListener('input', function() {
            if (groupByEl.value !== 'none') {
                setTimeout(applyGrouping, 50);
            }
        });
    }
})();

// Build action buttons from data attributes (avoids Go template escaping issues)
document.querySelectorAll('.finding-row').forEach(function(row) {
    var cell = row.querySelector('.action-cell');
    if (!cell) return;
    var hasFix = row.getAttribute('data-hasFix') === 'true';
    var html = '';
    if (hasFix) {
        html += '<button class="btn btn-warning btn-sm me-1 fix-btn" title="' + esc(row.getAttribute('data-fixdesc') || '') + '"><i class="ti ti-tool"></i></button>';
    }
    html += '<button class="btn btn-ghost-secondary btn-sm dismiss-btn"><i class="ti ti-x"></i></button>';
    cell.innerHTML = html;

    var fixBtn = cell.querySelector('.fix-btn');
    if (fixBtn) fixBtn.addEventListener('click', function() { fixOne(this); });
    var dismissBtn = cell.querySelector('.dismiss-btn');
    if (dismissBtn) dismissBtn.addEventListener('click', function() {
        dismissOne(row.getAttribute('data-check') + ':' + row.getAttribute('data-message'));
    });
});
