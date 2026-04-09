// CSM Findings page - Client-side rendered via /api/v1/findings/enriched

(function() {
'use strict';

// --- State ---
var findingsTable = null;

// --- Fetch and render findings from enriched API ---
function loadFindings() {
    fetch(CSM.apiUrl('/api/v1/findings/enriched'), { credentials: 'same-origin' })
        .then(function(r) {
            if (!r.ok) throw new Error('HTTP ' + r.status);
            return r.json();
        })
        .then(function(data) {
            if (data.error) throw new Error(data.error);
            renderFindings(data);
        })
        .catch(function(err) {
            var loading = document.getElementById('findings-loading');
            if (loading) loading.classList.add('d-none');
            var card = document.getElementById('findings-card');
            if (!card) return;
            // Show error with retry - insert into card rather than replacing it
            var errDiv = document.getElementById('findings-error');
            if (!errDiv) {
                errDiv = document.createElement('div');
                errDiv.id = 'findings-error';
                errDiv.className = 'card-body text-center py-4';
                card.appendChild(errDiv);
            }
            errDiv.innerHTML = '<div class="text-danger"><i class="ti ti-alert-triangle"></i> Failed to load findings: ' +
                CSM.esc(err.message || 'unknown error') + '</div>' +
                '<button class="btn btn-sm btn-primary mt-2" id="findings-retry">Retry</button>';
            document.getElementById('findings-retry').addEventListener('click', function() {
                errDiv.remove();
                var newLoading = document.getElementById('findings-loading');
                if (newLoading) newLoading.classList.remove('d-none');
                loadFindings();
            });
        });
}

function renderFindings(data) {
    var findings = data.findings || [];
    var checkTypes = data.check_types || [];
    var accounts = data.accounts || [];
    var total = data.total || 0;

    // Hide loading spinner
    document.getElementById('findings-loading').classList.add('d-none');

    // Update header count and severity badges
    var countEl = document.getElementById('findings-count');
    if (countEl) countEl.textContent = '(' + total + ')';

    var badgesEl = document.getElementById('severity-badges');
    if (badgesEl) {
        var badgeHtml = '';
        if (data.critical_count) badgeHtml += '<span class="badge badge-critical">' + data.critical_count + ' critical</span> ';
        if (data.high_count) badgeHtml += '<span class="badge badge-high">' + data.high_count + ' high</span> ';
        if (data.warning_count) badgeHtml += '<span class="badge badge-warning">' + data.warning_count + ' warning</span> ';
        badgesEl.innerHTML = badgeHtml;
    }

    // Populate check type filter dropdown
    var checkFilter = document.getElementById('check-filter');
    if (checkFilter) {
        for (var i = 0; i < checkTypes.length; i++) {
            var opt = document.createElement('option');
            opt.value = checkTypes[i];
            opt.textContent = checkTypes[i];
            checkFilter.appendChild(opt);
        }
    }

    // Populate account filter datalist
    var filterDl = document.getElementById('account-filter-list');
    if (filterDl) {
        for (var j = 0; j < accounts.length; j++) {
            var opt2 = document.createElement('option');
            opt2.value = accounts[j];
            filterDl.appendChild(opt2);
        }
    }

    // Start auto-refresh polling regardless of whether we have findings
    initAutoRefresh(findings);

    if (findings.length === 0) {
        document.getElementById('findings-empty').classList.remove('d-none');
        return;
    }

    // Render table rows
    var tbody = document.getElementById('findings-tbody');
    var html = '';
    for (var k = 0; k < findings.length; k++) {
        var f = findings[k];
        html += '<tr class="finding-row feed-item"' +
            ' data-key="' + CSM.esc(f.key || (f.check + ':' + f.message)) + '"' +
            ' data-check="' + CSM.esc(f.check) + '"' +
            ' data-message="' + CSM.esc(f.message) + '"' +
            ' data-filepath="' + CSM.esc(f.file_path || '') + '"' +
            ' data-account="' + CSM.esc(f.account || '') + '"' +
            ' data-hasFix="' + (f.has_fix ? 'true' : 'false') + '"' +
            ' data-fixdesc="' + CSM.esc(f.fix_desc || '') + '">' +
            '<td><input type="checkbox" class="form-check-input row-checkbox"></td>' +
            '<td><span class="badge badge-' + CSM.esc(f.sev_class) + '">' + CSM.esc(f.severity) + '</span></td>' +
            '<td><code>' + CSM.esc(f.check) + '</code></td>' +
            '<td class="text-secondary" style="word-break:break-all">' + CSM.esc(f.message) + '</td>' +
            '<td class="text-nowrap"><span class="font-monospace small" data-timestamp="' + CSM.esc(f.first_seen) + '">' + CSM.fmtDate(f.first_seen) + '</span></td>' +
            '<td class="text-nowrap"><span class="font-monospace small" data-timestamp="' + CSM.esc(f.last_seen) + '">' + CSM.fmtDate(f.last_seen) + '</span></td>' +
            '<td class="text-nowrap action-cell"></td>' +
            '</tr>';
    }
    tbody.innerHTML = html;

    // Show the table wrapper
    document.getElementById('findings-table-wrap').classList.remove('d-none');

    // Build action buttons for each row
    var rows = tbody.querySelectorAll('.finding-row');
    for (var r = 0; r < rows.length; r++) {
        buildActionButtons(rows[r]);
    }

    // Bind row checkboxes
    var checkboxes = tbody.querySelectorAll('.row-checkbox');
    for (var c = 0; c < checkboxes.length; c++) {
        checkboxes[c].addEventListener('change', updateSelection);
    }

    // Bind click-to-expand on rows
    for (var rx = 0; rx < rows.length; rx++) {
        rows[rx].addEventListener('click', function(e) {
            if (e.target.closest('button') || e.target.closest('input')) return;
            toggleFindingDetail(this);
        });
    }

    // Initialize CSM.Table after rows are in the DOM
    findingsTable = new CSM.Table({
        tableId: 'findings-table',
        perPage: 25,
        search: true,
        searchId: 'findings-search',
        sortable: true,
        filters: [
            { id: 'check-filter', attr: 'data-check' },
            { id: 'account-filter', attr: 'data-account' }
        ],
        stateKey: 'csm-findings-table',
        onRender: function() { updateSelection(); }
    });

    // Restore filter state from URL params (after table init)
    restoreURLParams();
}

// --- Build action buttons for a row ---
function buildActionButtons(row) {
    var cell = row.querySelector('.action-cell');
    if (!cell) return;
    var hasFix = row.getAttribute('data-hasFix') === 'true';
    var btnHtml = '';
    if (hasFix) {
        btnHtml += '<button class="btn btn-warning btn-sm me-1 fix-btn" title="Apply automated fix for this finding" aria-label="Fix finding"><i class="ti ti-tool"></i></button>';
    }
    btnHtml += '<button class="btn btn-ghost-secondary btn-sm me-1 dismiss-btn" title="Dismiss this finding (can be restored)" aria-label="Dismiss finding"><i class="ti ti-x"></i></button>';
    btnHtml += '<button class="btn btn-ghost-secondary btn-sm suppress-btn" title="Create a suppression rule to hide similar findings" aria-label="Suppress finding"><i class="ti ti-eye-off"></i></button>';
    cell.innerHTML = btnHtml;

    var fixBtn = cell.querySelector('.fix-btn');
    if (fixBtn) fixBtn.addEventListener('click', function() { fixOne(this); });
    var dismissBtn = cell.querySelector('.dismiss-btn');
    if (dismissBtn) dismissBtn.addEventListener('click', function() {
        dismissOne(row.getAttribute('data-key') || (row.getAttribute('data-check') + ':' + row.getAttribute('data-message')));
    });
    var suppressBtn = cell.querySelector('.suppress-btn');
    if (suppressBtn) suppressBtn.addEventListener('click', function() {
        suppressFinding(row.getAttribute('data-check'), row.getAttribute('data-message'), row.getAttribute('data-filepath'));
    });
}

// --- URL param restore ---
function restoreURLParams() {
    var params = new URLSearchParams(window.location.search);
    var checkParam = params.get('check');
    var searchParam = params.get('search');
    var accountParam = params.get('account');
    var groupParam = params.get('group');
    var perPageParam = params.get('perPage');
    if (checkParam) {
        var filter = document.getElementById('check-filter');
        if (filter) { filter.value = checkParam; filter.dispatchEvent(new Event('change')); }
    }
    if (accountParam) {
        var filter2 = document.getElementById('account-filter');
        if (filter2) { filter2.value = accountParam; filter2.dispatchEvent(new Event('input')); }
    }
    if (searchParam) {
        var search = document.getElementById('findings-search');
        if (search) { search.value = searchParam; search.dispatchEvent(new Event('input')); }
    }
    if (groupParam) {
        var groupEl = document.getElementById('group-by');
        if (groupEl) { groupEl.value = groupParam; groupEl.dispatchEvent(new Event('change')); }
    }
    if (perPageParam) {
        var ppEl = document.getElementById('per-page');
        if (ppEl) { ppEl.value = perPageParam; ppEl.dispatchEvent(new Event('change')); }
    }
}

// --- Sync active-tab filter state to URL ---
function syncFindingsURL() {
    // Only sync when active tab is shown (don't overwrite history tab params)
    var activeTab = document.querySelector('#tab-active.active');
    if (!activeTab) return;
    var checkVal = (document.getElementById('check-filter') || {}).value || '';
    var searchVal = (document.getElementById('findings-search') || {}).value || '';
    var accountVal = (document.getElementById('account-filter') || {}).value || '';
    var groupVal = (document.getElementById('group-by') || {}).value || '';
    var perPageVal = (document.getElementById('per-page') || {}).value || '';
    CSM.urlState.set({
        check: checkVal !== 'all' ? checkVal : '',
        search: searchVal,
        account: accountVal,
        group: groupVal !== 'none' ? groupVal : '',
        perPage: perPageVal !== '25' ? perPageVal : ''
    });
}

// --- Collapsible scan section ---
(function() {
    var header = document.getElementById('scan-header');
    var body = document.getElementById('scan-body');
    var icon = document.getElementById('scan-collapse-icon');
    if (!header || !body || !icon) return;

    var STORAGE_KEY = 'csm-scan-collapsed';

    function collapse() {
        body.style.maxHeight = body.scrollHeight + 'px';
        body.offsetHeight; // force reflow
        body.classList.add('collapsed');
        body.style.maxHeight = '0';
        icon.classList.add('collapsed');
        header.setAttribute('aria-expanded', 'false');
        localStorage.setItem(STORAGE_KEY, '1');
    }

    function expand() {
        body.classList.remove('collapsed');
        body.style.maxHeight = body.scrollHeight + 'px';
        icon.classList.remove('collapsed');
        header.setAttribute('aria-expanded', 'true');
        localStorage.setItem(STORAGE_KEY, '0');
        var cleanup = function() {
            body.style.maxHeight = '';
            body.removeEventListener('transitionend', cleanup);
        };
        body.addEventListener('transitionend', cleanup);
    }

    header.addEventListener('click', function() {
        if (body.classList.contains('collapsed')) {
            expand();
        } else {
            collapse();
        }
    });

    // Restore state - default collapsed
    if (localStorage.getItem(STORAGE_KEY) !== '0') {
        body.classList.add('collapsed');
        body.style.maxHeight = '0';
        icon.classList.add('collapsed');
        header.setAttribute('aria-expanded', 'false');
    }
})();

// --- Sticky header shadow on scroll ---
(function() {
    var cardHeader = document.querySelector('#findings-card > .card-header');
    if (!cardHeader) return;

    var sentinel = document.createElement('div');
    sentinel.className = 'csm-sticky-sentinel';
    sentinel.style.height = '1px';
    sentinel.style.marginBottom = '-1px';
    cardHeader.parentNode.insertBefore(sentinel, cardHeader);

    var observer = new IntersectionObserver(function(entries) {
        cardHeader.classList.toggle('csm-stuck', !entries[0].isIntersecting);
    }, { threshold: [1] });
    observer.observe(sentinel);
})();

// --- Tab URL sync: remove tab param when Active tab is shown ---
(function() {
    var activeTabLink = document.querySelector('[href="#tab-active"]');
    if (activeTabLink) {
        activeTabLink.addEventListener('shown.bs.tab', function() {
            var params = new URLSearchParams(window.location.search);
            params.delete('tab');
            params.delete('from'); params.delete('to');
            params.delete('severity'); params.delete('hsearch'); params.delete('hpage');
            var qs = params.toString();
            history.replaceState(null, '', '/findings' + (qs ? '?' + qs : ''));
        });
    }
})();

// --- Per-page selector ---
var perPageEl = document.getElementById('per-page');
if (perPageEl) perPageEl.addEventListener('change', function() {
    var pp = parseInt(this.value, 10);
    if (findingsTable) {
        findingsTable.perPage = pp || 0;
        findingsTable.currentPage = 1;
        findingsTable.render();
        findingsTable._saveState();
    }
    syncFindingsURL();
});

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
    var countEl = document.getElementById('selected-count');
    if (countEl) countEl.textContent = count;
    var bulkEl = document.getElementById('bulk-actions');
    if (bulkEl) bulkEl.classList.toggle('d-none', count === 0);
    // Show Fix button only if any selected row is fixable
    var hasFixable = selected.some(function(r) { return r.getAttribute('data-hasFix') === 'true'; });
    var fixBtn = document.getElementById('bulk-fix-btn');
    if (fixBtn) fixBtn.classList.toggle('d-none', !hasFixable);
}

// Warn before navigating away with active selections
window.addEventListener('beforeunload', function(e) {
    if (getSelectedRows().length > 0) {
        e.preventDefault();
        e.returnValue = '';
    }
});

// Reset select-all when check filter changes
var checkFilterEl = document.getElementById('check-filter');
if (checkFilterEl) checkFilterEl.addEventListener('change', function() {
    var selectAll = document.getElementById('select-all');
    if (selectAll) selectAll.checked = false;
    document.querySelectorAll('.row-checkbox').forEach(function(cb) { cb.checked = false; });
    updateSelection();
    syncFindingsURL();
});

// Account filter - bind 'input' to trigger table filtering
var accountFilterEl = document.getElementById('account-filter');
if (accountFilterEl) accountFilterEl.addEventListener('input', function() {
    if (findingsTable) {
        findingsTable.filterValues['account-filter'] = this.value;
        findingsTable.currentPage = 1;
        findingsTable.applyFilters();
    }
    var selectAll = document.getElementById('select-all');
    if (selectAll) selectAll.checked = false;
    document.querySelectorAll('.row-checkbox').forEach(function(cb) { cb.checked = false; });
    updateSelection();
    syncFindingsURL();
});

// Clear selections before reload so beforeunload guard does not block
function clearAndReload() {
    document.querySelectorAll('.row-checkbox').forEach(function(cb) { cb.checked = false; });
    var sa = document.getElementById('select-all');
    if (sa) sa.checked = false;
    location.reload();
}

// --- Single actions ---
function fixOne(btn) {
    var row = btn.closest('tr');
    var desc = row.getAttribute('data-fixdesc');
    CSM.confirm('Apply fix?\n\n' + desc).then(function() {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
        CSM.post('/api/v1/fix', {
            check: row.getAttribute('data-check'),
            message: row.getAttribute('data-message'),
            file_path: row.getAttribute('data-filepath') || ''
        }).then(function(data) {
            if (data.success) {
                row.style.opacity = '0.3';
                btn.innerHTML = '<i class="ti ti-check"></i>';
                btn.className = 'btn btn-success btn-sm me-1';
                setTimeout(clearAndReload, 1000);
            } else {
                CSM.toast('Fix failed: ' + (data.error || 'unknown'), 'error');
                btn.disabled = false;
                btn.innerHTML = '<i class="ti ti-tool"></i>';
            }
        }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); btn.disabled = false; btn.innerHTML = '<i class="ti ti-tool"></i>'; });
    }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
}

function dismissOne(key) {
    CSM.confirm('Dismiss this finding?').then(function() {
        CSM.post('/api/v1/dismiss', {key: key}).then(function() { clearAndReload(); }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
}

function suppressFinding(check, message, filePath) {
    // Pre-fill with file path if available, suggest wildcard for directory
    var defaultPath = '';
    if (filePath) {
        defaultPath = filePath;
    } else {
        // Try to extract path from message (e.g. "YARA rule match: /home/user/file.php")
        var m = message.match(/:\s*(\/\S+)/);
        if (m) defaultPath = m[1];
    }
    CSM.prompt('Reason for suppression (optional):', '').then(function(reason) {
        CSM.prompt('Path pattern to match (optional, e.g. /home/user/site/*):', defaultPath).then(function(pathPattern) {
            CSM.post('/api/v1/suppressions', {
                check: check,
                path_pattern: pathPattern,
                reason: reason || 'Suppressed from findings page'
            }).then(function(data) {
                if (data.status === 'created') {
                    CSM.toast('Suppression rule created', 'success');
                    clearAndReload();
                } else {
                    CSM.toast('Failed: ' + (data.error || 'unknown'), 'error');
                }
            }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
        }).catch(function() { /* cancelled */ });
    }).catch(function() { /* cancelled */ });
}

// --- Bulk actions ---
function bulkAction(action) {
    var selected = getSelectedRows();
    if (selected.length === 0) return;

    var items = selected.map(function(row) {
        return {
            key: row.getAttribute('data-key') || '',
            check: row.getAttribute('data-check'),
            message: row.getAttribute('data-message'),
            file_path: row.getAttribute('data-filepath') || '',
            fixable: row.getAttribute('data-hasFix') === 'true'
        };
    });

    if (action === 'fix') {
        var fixable = items.filter(function(i) { return i.fixable; });
        if (fixable.length === 0) { CSM.toast('None of the selected findings have automated fixes.', 'warning'); return; }
        CSM.confirm('Fix ' + fixable.length + ' finding(s)?\n\nThis will apply automated fixes (chmod, quarantine, etc.) to the selected items.').then(function() {
            var fixItems = fixable.map(function(i) { return { check: i.check, message: i.message, details: '', file_path: i.file_path }; });
            CSM.post('/api/v1/fix-bulk', fixItems).then(function(data) {
                CSM.toast('Fixed ' + data.succeeded + ' of ' + data.total + (data.failed > 0 ? ' (' + data.failed + ' failed)' : ''), 'success');
                clearAndReload();
            }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
        }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });

    } else if (action === 'dismiss') {
        CSM.confirm('Dismiss ' + items.length + ' finding(s)?').then(function() {
            var succeeded = 0, failed = 0;
            var chain = Promise.resolve();
            items.forEach(function(i) {
                chain = chain.then(function() {
                    return CSM.post('/api/v1/dismiss', { key: i.key || (i.check + ':' + i.message) })
                        .then(function() { succeeded++; })
                        .catch(function() { failed++; });
                });
            });
            chain.then(function() {
                if (failed > 0) {
                    CSM.toast('Dismissed ' + succeeded + ' of ' + (succeeded + failed) + ' (' + failed + ' failed)', 'warning');
                }
                clearAndReload();
            });
        }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });

    } else if (action === 'quarantine') {
        CSM.confirm('Quarantine ' + items.length + ' file(s)?\n\nFiles will be moved to /opt/csm/quarantine/').then(function() {
            var quarItems = items.map(function(i) { return { check: i.check, message: i.message, details: '', file_path: i.file_path }; });
            CSM.post('/api/v1/fix-bulk', quarItems).then(function(data) {
                CSM.toast('Quarantined ' + data.succeeded + ' of ' + data.total, 'success');
                clearAndReload();
            }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
        }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
    }
}

// --- Scan account ---
document.getElementById('scan-form').addEventListener('submit', function(e) {
    e.preventDefault();
    var account = document.getElementById('scan-account').value.trim();
    if (!account) return;
    var btn = document.getElementById('scan-btn');
    var status = document.getElementById('scan-status').querySelector('span');
    btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Scanning...';
    status.textContent = '';
    // Elapsed timer
    var scanStart = Date.now();
    var timerInterval = setInterval(function() {
        var secs = Math.floor((Date.now() - scanStart) / 1000);
        status.textContent = 'Scanning ' + account + '... ' + secs + 's';
        status.className = 'text-muted small';
    }, 1000);
    CSM.post('/api/v1/scan-account', {account: account}).then(function(data) {
        clearInterval(timerInterval);
        btn.disabled = false; btn.innerHTML = '<i class="ti ti-radar-2"></i>&nbsp;Scan';
        if (data.error) { status.textContent = data.error; status.className = 'text-danger small'; return; }
        if (!data.count) { status.textContent = account + ' is clean (' + data.elapsed + ')'; status.className = 'text-success small'; return; }
        // Redirect to filtered view for the scanned account
        window.location.href = '/findings?account=' + encodeURIComponent(account);
    }).catch(function(e) { clearInterval(timerInterval); btn.disabled=false; btn.innerHTML='<i class="ti ti-radar-2"></i>&nbsp;Scan'; status.textContent='Error: '+e; status.className='text-danger small'; });
});

// Load account list for scan autocomplete dropdown
fetch(CSM.apiUrl('/api/v1/accounts'), {credentials:'same-origin'}).then(function(r){return r.json()}).then(function(accounts) {
    var dl = document.getElementById('account-list');
    (accounts||[]).forEach(function(a) {
        var opt = document.createElement('option');
        opt.value = a;
        dl.appendChild(opt);
    });
}).catch(function(err){ console.error('loadAccounts:', err); });

// Bind select-all checkbox
var _selectAll = document.getElementById('select-all');
if (_selectAll) _selectAll.addEventListener('change', toggleSelectAll);

// Bind bulk action buttons
var _bulkFixBtn = document.getElementById('bulk-fix-btn');
if (_bulkFixBtn) _bulkFixBtn.addEventListener('click', function() { bulkAction('fix'); });
var _bulkDismissBtn = document.getElementById('bulk-dismiss-btn');
if (_bulkDismissBtn) _bulkDismissBtn.addEventListener('click', function() { bulkAction('dismiss'); });

// Sync search input to URL (debounced to avoid excessive URL updates while typing)
var _findingsSearchEl = document.getElementById('findings-search');
if (_findingsSearchEl) _findingsSearchEl.addEventListener('input', CSM.debounce(function() {
    syncFindingsURL();
}, 300));

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
        // Prefer data-account attribute (set from API response)
        var acct = row.getAttribute('data-account');
        if (acct) return acct;
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
        var colCount = 7;
        var theadRow = document.querySelector('#findings-table thead tr');
        if (theadRow) colCount = theadRow.children.length;

        // Insert group headers and reorder rows
        groupOrder.forEach(function(key) {
            var headerRow = document.createElement('tr');
            headerRow.className = 'csm-group-header';
            headerRow.setAttribute('data-csm-group-key', key);
            headerRow.setAttribute('aria-expanded', 'true');
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
                headerRow.setAttribute('aria-expanded', isCollapsed ? 'false' : 'true');
                groups[key].forEach(function(row) {
                    row.style.display = isCollapsed ? 'none' : '';
                });
            });
        });
    }

    groupByEl.addEventListener('change', function() {
        applyGrouping();
        syncFindingsURL();
    });

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
    var accountFilter2 = document.getElementById('account-filter');
    if (accountFilter2) {
        accountFilter2.addEventListener('input', function() {
            if (groupByEl.value !== 'none') {
                setTimeout(applyGrouping, 50);
            }
        });
    }
})();

// --- Click-to-expand finding detail (remediation action tracking) ---
function toggleFindingDetail(row) {
    var existing = row.nextElementSibling;
    if (existing && existing.classList.contains('finding-detail-row')) {
        existing.remove();
        return;
    }
    // Remove any other open detail rows
    document.querySelectorAll('.finding-detail-row').forEach(function(r) { r.remove(); });

    var check = row.dataset.check;
    var message = row.dataset.message;
    var detailRow = document.createElement('tr');
    detailRow.className = 'finding-detail-row';
    var td = document.createElement('td');
    td.colSpan = row.children.length || 7;
    td.innerHTML = '<div class="p-2 text-muted small"><span class="spinner-border spinner-border-sm"></span> Loading...</div>';
    detailRow.appendChild(td);
    row.after(detailRow);

    fetch(CSM.apiUrl('/api/v1/finding-detail?check=' + encodeURIComponent(check) + '&message=' + encodeURIComponent(message)), { credentials: 'same-origin' })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var html = '<div class="p-3 bg-dark-lt" style="font-size:0.8rem">';
            // Timeline info
            if (data.first_seen) {
                html += '<div class="mb-2"><strong>First seen:</strong> ' + CSM.fmtDate(data.first_seen) + ' &mdash; <strong>Last seen:</strong> ' + CSM.fmtDate(data.last_seen) + '</div>';
            }
            // Actions taken
            var actions = data.actions || [];
            if (actions.length > 0) {
                html += '<div class="mb-2"><strong>Actions taken (' + actions.length + '):</strong>';
                html += '<ul class="mb-0 mt-1">';
                for (var i = 0; i < Math.min(actions.length, 10); i++) {
                    var a = actions[i];
                    html += '<li>' + CSM.esc(a.action) + ' &mdash; ' + CSM.esc(a.target || '') + ' <span class="text-muted">(' + CSM.fmtDate(a.timestamp || '') + ')</span></li>';
                }
                if (actions.length > 10) html += '<li class="text-muted">...and ' + (actions.length - 10) + ' more</li>';
                html += '</ul></div>';
            } else {
                html += '<div class="mb-2 text-muted">No recorded actions for this finding.</div>';
            }
            // Related findings count
            var related = data.related || [];
            if (related.length > 0) {
                html += '<div><strong>Historical occurrences:</strong> ' + related.length + ' times in history</div>';
            }
            html += '</div>';
            td.innerHTML = html;
        })
        .catch(function(err) { console.error('findingDetail:', err); td.innerHTML = '<div class="p-2 text-danger small">Failed to load details.</div>'; });
}

// --- Export findings (CSV / JSON) via CSM.exportTable ---
var _findingsExportCols = [
    {key:'severity', label:'Severity'},
    {key:'check', label:'Check'},
    {key:'account', label:'Account'},
    {key:'message', label:'Message'},
    {key:'first_seen', label:'First Seen'},
    {key:'last_seen', label:'Last Seen'}
];

function getExportData() {
    var rows = getVisibleRows();
    return rows.map(function(r) {
        return {
            severity: r.querySelector('.badge') ? r.querySelector('.badge').textContent.trim() : '',
            check: r.getAttribute('data-check') || '',
            account: r.getAttribute('data-account') || '',
            message: r.getAttribute('data-message') || '',
            first_seen: r.cells[4] ? r.cells[4].textContent.trim() : '',
            last_seen: r.cells[5] ? r.cells[5].textContent.trim() : ''
        };
    });
}

var csvBtn = document.getElementById('export-csv');
if (csvBtn) csvBtn.addEventListener('click', function(e) { e.preventDefault(); CSM.exportTable(getExportData(), _findingsExportCols, 'csv', 'csm-findings'); });
var jsonBtn = document.getElementById('export-json');
if (jsonBtn) jsonBtn.addEventListener('click', function(e) { e.preventDefault(); CSM.exportTable(getExportData(), _findingsExportCols, 'json', 'csm-findings'); });

// --- Auto-refresh: poll for new findings every 15 seconds ---
var _findingsPoller = null;

function initAutoRefresh(initialFindings) {
    var currentKeys = {};
    for (var i = 0; i < initialFindings.length; i++) {
        var f = initialFindings[i];
        currentKeys[f.check + ':' + f.message] = true;
    }
    var currentCount = initialFindings.length;

    // Stop any previous poller
    if (_findingsPoller) { _findingsPoller.stop(); _findingsPoller = null; }

    _findingsPoller = CSM.poll('/api/v1/findings', 15000, function(err, data) {
        if (err) { console.error('findings auto-refresh:', err); return; }
        if (!data) return;
        var changed = data.length !== currentCount;
        if (!changed) {
            for (var j = 0; j < data.length; j++) {
                var key = data[j].check + ':' + data[j].message;
                if (!currentKeys[key]) { changed = true; break; }
            }
        }
        if (changed) {
            var banner = document.getElementById('refresh-banner');
            if (banner) banner.classList.remove('d-none');
        }
    });
}

window.addEventListener('beforeunload', function() {
    if (_findingsPoller) { _findingsPoller.stop(); _findingsPoller = null; }
});

// Bind refresh button (replaces inline onclick for CSP compliance)
var refreshBtn = document.getElementById('refresh-page-btn');
if (refreshBtn) refreshBtn.addEventListener('click', function(e) { e.preventDefault(); location.reload(); });

// --- Kick off ---
loadFindings();

})();
