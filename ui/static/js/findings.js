// CSM Findings page - Client-side rendered via /api/v1/findings/enriched

(function() {
'use strict';

// --- State ---
var findingsTable = null;
var _findingsLoadSeq = 0;
// Set by the grouping section. Every table render re-appends the filtered
// rows, so grouping is laid out again after each render, whatever caused it.
var _layoutFindingGroups = null;

// Numeric severity rank for column sorting (mirrors the webui severityRank).
// Derived from the already-promoted label so a dedup severity bump sorts right.
function severityRank(label) {
    if (label === 'CRITICAL') return 3;
    if (label === 'HIGH') return 2;
    if (label === 'WARNING') return 1;
    return 0;
}

// --- Fetch and render findings from enriched API ---
function loadFindings() {
    var seq = ++_findingsLoadSeq;
    CSM.get('/api/v1/findings/enriched')
        .then(function(data) {
            if (seq !== _findingsLoadSeq) return;
            if (data.error) throw new Error(data.error);
            renderFindings(data);
        })
        .catch(function(err) {
            if (seq !== _findingsLoadSeq) return;
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

    // renderFindings runs on first load and again after every in-place action
    // refresh, so it must be idempotent: drop the previous table (and its
    // listeners/controls), clear a prior error or a stale "new findings" banner,
    // and rebuild the filter option lists from scratch rather than appending.
    if (findingsTable) { findingsTable.destroy(); findingsTable = null; }
    var prevError = document.getElementById('findings-error');
    if (prevError) prevError.remove();
    var refreshBanner = document.getElementById('refresh-banner');
    if (refreshBanner) refreshBanner.classList.add('d-none');
    // The header select-all persists across renders; the rebuilt rows are all
    // unchecked, so reset it to match.
    var selectAll = document.getElementById('select-all');
    if (selectAll) { selectAll.checked = false; selectAll.indeterminate = false; }
    var tbody = document.getElementById('findings-tbody');

    // Update header count and severity badges
    var countEl = document.getElementById('findings-count');
    if (countEl) countEl.textContent = total + ' active';

    var badgesEl = document.getElementById('severity-badges');
    if (badgesEl) {
        var badgeHtml = '';
        if (data.critical_count) badgeHtml += '<span class="badge badge-critical">' + data.critical_count + ' critical</span> ';
        if (data.high_count) badgeHtml += '<span class="badge badge-high">' + data.high_count + ' high</span> ';
        if (data.warning_count) badgeHtml += '<span class="badge badge-warning">' + data.warning_count + ' warning</span> ';
        badgesEl.innerHTML = badgeHtml;
    }

    // Populate check type filter dropdown. Drop options past the static
    // "All Types" first entry so a re-render does not stack duplicates.
    var checkFilter = document.getElementById('check-filter');
    if (checkFilter) {
        while (checkFilter.options.length > 1) checkFilter.remove(1);
        for (var i = 0; i < checkTypes.length; i++) {
            var opt = document.createElement('option');
            opt.value = checkTypes[i];
            opt.textContent = checkTypes[i];
            checkFilter.appendChild(opt);
        }
    }

    // Populate account filter datalist (fully dynamic; clear before rebuild).
    var filterDl = document.getElementById('account-filter-list');
    if (filterDl) {
        filterDl.replaceChildren();
        for (var j = 0; j < accounts.length; j++) {
            var opt2 = document.createElement('option');
            opt2.value = accounts[j];
            filterDl.appendChild(opt2);
        }
    }

    // Start auto-refresh polling regardless of whether we have findings
    initAutoRefresh(data.version);

    if (findings.length === 0) {
        if (tbody) tbody.innerHTML = '';
        document.getElementById('findings-empty').classList.remove('d-none');
        document.getElementById('findings-table-wrap').classList.add('d-none');
        updateSelection();
        return;
    }
    // Non-empty: a prior render may have shown the empty state.
    document.getElementById('findings-empty').classList.add('d-none');

    // Render table rows
    var html = '';
    for (var k = 0; k < findings.length; k++) {
        var f = findings[k];
        html += '<tr class="finding-row feed-item"' +
            ' data-key="' + CSM.esc(f.key || (f.check + ':' + f.message)) + '"' +
            ' data-check="' + CSM.esc(f.check) + '"' +
            ' data-message="' + CSM.esc(f.message) + '"' +
            ' data-details="' + CSM.esc(f.details || '') + '"' +
            ' data-filepath="' + CSM.esc(f.file_path || '') + '"' +
            ' data-account="' + CSM.esc(f.account || '') + '"' +
            ' data-hasFix="' + (f.has_fix ? 'true' : 'false') + '"' +
            ' data-hasVerify="' + (f.has_verify ? 'true' : 'false') + '"' +
            ' data-fixdesc="' + CSM.esc(f.fix_desc || '') + '">' +
            '<td><input type="checkbox" class="form-check-input row-checkbox"></td>' +
            '<td data-sort="' + severityRank(f.severity) + '"><span class="badge badge-' + CSM.esc(f.sev_class) + '">' + CSM.esc(f.severity) + '</span></td>' +
            '<td><code>' + CSM.esc(f.check) + '</code></td>' +
            '<td class="text-secondary csm-break-all">' + CSM.esc(f.message) + '</td>' +
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
        onRender: function() {
            if (_layoutFindingGroups) _layoutFindingGroups();
            updateSelection();
        }
    });

    // Restore filter state from URL params (after table init)
    restoreURLParams();
}

// --- Build action buttons for a row ---
function buildActionButtons(row) {
    var cell = row.querySelector('.action-cell');
    if (!cell) return;
    var hasFix = row.getAttribute('data-hasFix') === 'true';
    var hasVerify = row.getAttribute('data-hasVerify') === 'true';
    var btnHtml = '';
    if (hasFix) {
        btnHtml += '<button class="btn btn-warning btn-sm me-1 fix-btn" title="Apply automated fix for this finding" aria-label="Fix finding"><i class="ti ti-tool"></i></button>';
    }
    if (hasVerify) {
        btnHtml += '<button class="btn btn-ghost-secondary btn-sm me-1 verify-btn" title="Re-check whether this finding is still present" aria-label="Re-check finding"><i class="ti ti-refresh"></i></button>';
    }
    btnHtml += '<button class="btn btn-ghost-secondary btn-sm me-1 dismiss-btn" title="Dismiss: stop alerts for this finding while it stays unchanged. A later scan can list it again; use Suppress to hide it for good." aria-label="Dismiss finding"><i class="ti ti-x"></i></button>';
    btnHtml += '<button class="btn btn-ghost-secondary btn-sm suppress-btn" title="Create a suppression rule to hide similar findings" aria-label="Suppress finding"><i class="ti ti-eye-off"></i></button>';
    cell.innerHTML = btnHtml;

    var fixBtn = cell.querySelector('.fix-btn');
    if (fixBtn) fixBtn.addEventListener('click', function() { fixOne(this); });
    var verifyBtn = cell.querySelector('.verify-btn');
    if (verifyBtn) verifyBtn.addEventListener('click', function() { verifyOne(this); });
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

// (Collapsible scan section removed in phase 4: scan moved to modal.)

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
    var bulkBar = document.getElementById('findings-bulk-bar');
    if (bulkBar) bulkBar.hidden = (count === 0);
    // Show Fix button only if any selected row is fixable.
    var hasFixable = selected.some(function(r) { return r.getAttribute('data-hasFix') === 'true'; });
    var fixBtn = document.getElementById('bulk-fix-btn');
    if (fixBtn) fixBtn.classList.toggle('d-none', !hasFixable);
}

function clearAllSelections() {
    document.querySelectorAll('.row-checkbox').forEach(function(cb) { cb.checked = false; });
    var sa = document.getElementById('select-all');
    if (sa) sa.checked = false;
    updateSelection();
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

// Re-fetch and re-render the findings list in place after an action. This
// keeps the operator's filters, search, grouping, page size, and scroll
// position instead of throwing them away with a full page reload mid-triage.
// renderFindings rebuilds the rows (and their unchecked checkboxes), so the
// selection clears on its own.
function refreshFindings() {
    loadFindings();
}

// --- Single actions ---
function fixOne(btn) {
    var row = btn.closest('tr');
    var desc = row.getAttribute('data-fixdesc');
    CSM.confirm('Apply fix?\n\n' + desc).then(function() {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
        CSM.post('/api/v1/fix', {
            key: row.getAttribute('data-key') || '',
            check: row.getAttribute('data-check'),
            message: row.getAttribute('data-message'),
            details: row.getAttribute('data-details') || '',
            file_path: row.getAttribute('data-filepath') || ''
        }).then(function(data) {
            if (data.success) {
                row.style.opacity = '0.3';
                btn.innerHTML = '<i class="ti ti-check"></i>';
                btn.className = 'btn btn-success btn-sm me-1';
                setTimeout(refreshFindings, 1000);
            } else {
                CSM.toast('Fix failed: ' + (data.error || 'unknown'), 'error');
                btn.disabled = false;
                btn.innerHTML = '<i class="ti ti-tool"></i>';
            }
        }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); btn.disabled = false; btn.innerHTML = '<i class="ti ti-tool"></i>'; });
    }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
}

// Re-check whether a finding's condition still holds. Resolves on the server
// against the live filesystem; a resolved finding is dismissed there and
// removed here, while an unresolved or non-verifiable finding stays put with an
// explanatory toast.
function verifyOne(btn) {
    var row = btn.closest('tr');
    btn.disabled = true;
    var orig = btn.innerHTML;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
    CSM.post('/api/v1/verify-finding', {
        key: row.getAttribute('data-key') || '',
        check: row.getAttribute('data-check'),
        message: row.getAttribute('data-message'),
        details: row.getAttribute('data-details') || '',
        file_path: row.getAttribute('data-filepath') || ''
    }).then(function(data) {
        if (data.resolved) {
            row.style.opacity = '0.3';
            CSM.toast('Resolved: ' + (data.detail || 'finding cleared'), 'success');
            setTimeout(refreshFindings, 1000);
        } else if (data.severity_change === 'demoted') {
            // Never cleared, only ranked lower. The applied outcome is
            // separate from the verifier verdict because a concurrent scan
            // can replace the stored snapshot before this mutation lands.
            CSM.toast('Demoted: ' + (data.detail || 'remediation unconfirmed'), 'warning');
            setTimeout(refreshFindings, 1000);
        } else if (data.severity_change === 'restored') {
            CSM.toast('Restored: ' + (data.detail || 'finding needs review'), 'warning');
            setTimeout(refreshFindings, 1000);
        } else if (data.demote) {
            CSM.toast('Severity unchanged: ' + (data.detail || 'reload and retry'), 'info');
            btn.disabled = false;
            btn.innerHTML = orig;
            setTimeout(refreshFindings, 1000);
        } else if (data.checked) {
            CSM.toast('Still present: ' + (data.detail || ''), 'warning');
            btn.disabled = false;
            btn.innerHTML = orig;
            // A re-check can also restore a severity an earlier demotion
            // lowered, so refresh rather than leaving a stale row.
            setTimeout(refreshFindings, 1000);
        } else {
            CSM.toast('Cannot auto-verify: ' + (data.detail || ''), 'info');
            btn.disabled = false;
            btn.innerHTML = orig;
            // An inconclusive re-check still reverses an earlier demotion, so
            // the severity can rise here too.
            setTimeout(refreshFindings, 1000);
        }
    }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); btn.disabled = false; btn.innerHTML = orig; });
}

// Dismissal marks the finding as known: it stops alerting while its details
// stay the same, but a later scan that still reports it lists it again. The
// only way back is the short undo window, so the wording says so.
var DISMISS_EXPLAINED = 'Dismissed findings stop alerting while they stay unchanged. A later scan that still finds them lists them again; use Suppress to hide them for good. You can undo for 30 seconds.';

function offerDismissUndo(data, label) {
    if (data && data.undo_token && CSM.undo) CSM.undo.offer({ token: data.undo_token, label: label });
}

function dismissOne(key) {
    CSM.confirm('Dismiss this finding?\n\n' + DISMISS_EXPLAINED).then(function() {
        CSM.post('/api/v1/dismiss', {key: key}).then(function(data) {
            offerDismissUndo(data, 'Dismissed 1 finding');
            refreshFindings();
        }).catch(function(e) { CSM.toast('Dismiss failed: ' + (e && e.message ? e.message : 'request failed'), 'error'); });
    }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
}

// --- Suppress dialog ---
// A suppression without a path pattern hides every finding of the check and
// stops its remediation, so that scope is a separate, explicit choice in one
// dialog that says what the rule will cover before it is saved.
// suppressDefaultPattern pre-fills the finding's own file. The pattern is a
// glob, so characters the server's matcher treats as syntax are escaped to
// match that file literally.
function suppressDefaultPattern(message, filePath) {
    var path = filePath;
    if (!path) {
        // e.g. "YARA rule match: /home/user/file.php"
        var m = (message || '').match(/:\s*(\/\S+)/);
        path = m ? m[1] : '';
    }
    return path.replace(/[\\*?[\]]/g, '\\$&');
}

function suppressDialogScope() {
    return document.getElementById('suppress-finding-scope-all').checked ? 'all' : 'path';
}

function updateSuppressDialog() {
    var check = document.getElementById('suppress-finding-check').textContent;
    var pattern = document.getElementById('suppress-finding-pattern').value;
    var scope = suppressDialogScope();
    document.getElementById('suppress-finding-summary').textContent = CSM.suppressionSummary(check, scope, pattern);
    document.getElementById('suppress-finding-submit').disabled = !!CSM.suppressionRequest(check, scope, pattern, '').error;
}

var _suppressDialogBound = false;
var _suppressInFlight = false;
function bindSuppressDialog() {
    if (_suppressDialogBound) return;
    _suppressDialogBound = true;
    var pattern = document.getElementById('suppress-finding-pattern');
    pattern.addEventListener('input', function() {
        document.getElementById('suppress-finding-scope-path').checked = true;
        document.getElementById('suppress-finding-scope-all').checked = false;
        updateSuppressDialog();
    });
    document.getElementById('suppress-finding-scope-path').addEventListener('change', updateSuppressDialog);
    document.getElementById('suppress-finding-scope-all').addEventListener('change', updateSuppressDialog);
    document.getElementById('suppress-finding-form').addEventListener('submit', function(e) {
        e.preventDefault();
        if (_suppressInFlight) return;
        var check = document.getElementById('suppress-finding-check').textContent;
        var body = CSM.suppressionRequest(check, suppressDialogScope(),
            document.getElementById('suppress-finding-pattern').value,
            document.getElementById('suppress-finding-reason').value,
            'Suppressed from findings page');
        if (body.error) {
            CSM.toast(body.error, 'error');
            return;
        }
        _suppressInFlight = true;
        CSM.post('/api/v1/suppressions', body).then(function(resp) {
            bootstrap.Modal.getOrCreateInstance(document.getElementById('suppress-finding-modal')).hide();
            CSM.suppressionSaved(resp);
            refreshFindings();
        }).catch(function(err) {
            CSM.toast('Suppression not saved: ' + (err && err.message ? err.message : 'request failed'), 'error');
        }).then(function() {
            _suppressInFlight = false;
        });
    });
}

function suppressFinding(check, message, filePath) {
    bindSuppressDialog();
    document.getElementById('suppress-finding-check').textContent = check;
    document.getElementById('suppress-finding-pattern').value = suppressDefaultPattern(message, filePath);
    document.getElementById('suppress-finding-reason').value = '';
    document.getElementById('suppress-finding-scope-path').checked = true;
    document.getElementById('suppress-finding-scope-all').checked = false;
    updateSuppressDialog();
    bootstrap.Modal.getOrCreateInstance(document.getElementById('suppress-finding-modal')).show();
}

// --- Bulk actions ---
function bulkFixPayload(items) {
    var payload = items.map(function(i) {
        return { key: i.key, check: i.check, message: i.message, details: i.details, file_path: i.file_path };
    });
    // The endpoint bounds bytes, not item count; finding details may be large
    // and non-ASCII text takes more than one byte per character.
    if (new Blob([JSON.stringify(payload)]).size > CSM.FIX_BULK_BODY_MAX) {
        CSM.toast('Selection is too large for one request. Select fewer findings and repeat.', 'error');
        return null;
    }
    return payload;
}

function bulkAction(action) {
    var selected = getSelectedRows();
    if (selected.length === 0) return;

    var items = selected.map(function(row) {
        return {
            key: row.getAttribute('data-key') || '',
            check: row.getAttribute('data-check'),
            message: row.getAttribute('data-message'),
            details: row.getAttribute('data-details') || '',
            file_path: row.getAttribute('data-filepath') || '',
            fixable: row.getAttribute('data-hasFix') === 'true'
        };
    });

    if (action === 'fix') {
        var fixable = items.filter(function(i) { return i.fixable; });
        if (fixable.length === 0) { CSM.toast('None of the selected findings have automated fixes.', 'warning'); return; }
        var fixItems = bulkFixPayload(fixable);
        if (!fixItems) return;
        CSM.confirm('Fix ' + fixable.length + ' finding(s)?\n\nThis will apply automated fixes (chmod, quarantine, etc.) to the selected items.').then(function() {
            CSM.post('/api/v1/fix-bulk', fixItems).then(function(data) {
                CSM.toast('Fixed ' + data.succeeded + ' of ' + data.total + (data.failed > 0 ? ' (' + data.failed + ' failed)' : ''), 'success');
                refreshFindings();
            }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
        }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });

    } else if (action === 'dismiss') {
        // One request is one undo entry, so a selection over the server
        // limit is narrowed instead of being split into several.
        if (items.length > CSM.DISMISS_BULK_MAX) {
            CSM.toast('Too many findings selected (' + items.length + '); the bulk dismiss limit is ' + CSM.DISMISS_BULK_MAX + '. Narrow the selection and repeat.', 'error');
            return;
        }
        var keys = items.map(function(i) { return i.key || (i.check + ':' + i.message); });
        CSM.confirm('Dismiss ' + items.length + ' finding(s)?\n\n' + DISMISS_EXPLAINED).then(function() {
            return CSM.post('/api/v1/dismiss', { keys: keys }).then(function(data) {
                offerDismissUndo(data, 'Dismissed ' + (data.count || keys.length) + ' finding(s)');
                refreshFindings();
            }).catch(function(e) { CSM.toast('Dismiss failed: ' + (e && e.message ? e.message : 'request failed'), 'error'); });
        }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
    }
}

// --- Scan account ---
document.getElementById('scan-form').addEventListener('submit', function(e) {
    e.preventDefault();
    var account = document.getElementById('scan-account').value.trim();
    if (!account) return;
    var btn = document.getElementById('scan-btn');
    var status = document.getElementById('scan-status');
    btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Scanning...';
    status.textContent = '';
    status.className = 'mt-3 small text-muted';
    // Elapsed timer
    var scanStart = Date.now();
    var timerInterval = setInterval(function() {
        var secs = Math.floor((Date.now() - scanStart) / 1000);
        status.textContent = 'Scanning ' + account + '... ' + secs + 's';
        status.className = 'mt-3 small text-muted';
    }, 1000);
    CSM.post('/api/v1/scan-account', {account: account}).then(function(data) {
        clearInterval(timerInterval);
        btn.disabled = false; btn.innerHTML = '<i class="ti ti-radar-2"></i>&nbsp;Scan';
        if (data.error) { status.textContent = data.error; status.className = 'mt-3 small text-danger'; return; }
        if (!data.count) { status.textContent = account + ' is clean (' + data.elapsed + ')'; status.className = 'mt-3 small text-success'; return; }
        // Redirect to filtered view for the scanned account
        window.location.href = '/findings?account=' + encodeURIComponent(account);
    }).catch(function(e) { clearInterval(timerInterval); btn.disabled=false; btn.innerHTML='<i class="ti ti-radar-2"></i>&nbsp;Scan'; status.textContent='Error: '+e; status.className='mt-3 small text-danger'; });
});

// Load account list for scan autocomplete dropdown
CSM.get('/api/v1/accounts', { silent: true }).then(function(accounts) {
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
var _bulkCancelBtn = document.getElementById('bulk-cancel-btn');
if (_bulkCancelBtn) _bulkCancelBtn.addEventListener('click', clearAllSelections);

// Sync search input to URL (debounced to avoid excessive URL updates while typing)
var _findingsSearchEl = document.getElementById('findings-search');
if (_findingsSearchEl) _findingsSearchEl.addEventListener('input', CSM.debounce(function() {
    syncFindingsURL();
}, 300));

// --- Findings grouping ---
(function() {
    var groupByEl = document.getElementById('group-by');
    if (!groupByEl) return;
    var groupModeButtons = document.querySelectorAll('[data-group-mode]');

    function syncGroupModeButtons() {
        var mode = groupByEl.value || 'none';
        groupModeButtons.forEach(function(btn) {
            var active = btn.getAttribute('data-group-mode') === mode;
            btn.classList.toggle('active', active);
            btn.setAttribute('aria-pressed', active ? 'true' : 'false');
        });
    }

    groupModeButtons.forEach(function(btn) {
        btn.addEventListener('click', function() {
            groupByEl.value = this.getAttribute('data-group-mode') || 'none';
            groupByEl.dispatchEvent(new Event('change'));
        });
    });
    syncGroupModeButtons();

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
    // Collapsed groups are remembered by key so a render caused by a search,
    // sort or refresh keeps them collapsed.
    var _collapsedGroups = {};

    function layoutGroups() {
        var mode = groupByEl.value;
        removeGroupHeaders();
        document.querySelectorAll('.finding-row').forEach(function(r) {
            r.removeAttribute('data-csm-group');
            r.classList.remove('csm-group-hidden');
        });

        if (mode === 'none') {
            if (findingsTable && _savedPerPage !== null) {
                findingsTable.perPage = _savedPerPage;
                _savedPerPage = null;
                findingsTable.applyFilters();
            }
            return;
        }

        // Groups show every matching row, so pagination is off while grouped.
        // Changing perPage renders again, which lays the groups out.
        if (findingsTable && findingsTable.perPage !== 0) {
            if (_savedPerPage === null) _savedPerPage = findingsTable.perPage;
            findingsTable.perPage = 0;
            findingsTable.applyFilters();
            return;
        }

        var tbody = document.getElementById('findings-tbody');
        if (!tbody) return;

        var visibleRows = Array.from(tbody.querySelectorAll('.finding-row')).filter(function(r) {
            return r.style.display !== 'none';
        });

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
        groupOrder.sort();

        var colCount = 7;
        var theadRow = document.querySelector('#findings-table thead tr');
        if (theadRow) colCount = theadRow.children.length;

        groupOrder.forEach(function(key) {
            var collapsed = !!_collapsedGroups[mode + '\u0000' + key];
            var headerRow = document.createElement('tr');
            headerRow.className = 'csm-group-header' + (collapsed ? ' collapsed' : '');
            headerRow.setAttribute('data-csm-group-key', key);
            headerRow.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
            var td = document.createElement('td');
            td.colSpan = colCount;
            td.innerHTML = '<span class="csm-group-arrow">&#9660;</span>' +
                CSM.esc(key) + ' <span class="text-muted small">(' + groups[key].length + ' finding' + (groups[key].length !== 1 ? 's' : '') + ')</span>';
            var accountURL = mode === 'account' ? CSM.accountURL(key) : '';
            if (accountURL) {
                td.innerHTML += ' <a class="ms-2 small" href="' + CSM.attr(accountURL) + '">Account page</a>';
            }
            headerRow.appendChild(td);

            tbody.appendChild(headerRow);
            groups[key].forEach(function(row) {
                if (collapsed) row.style.display = 'none';
                tbody.appendChild(row);
            });

            headerRow.addEventListener('click', function(e) {
                if (e.target.closest('a')) return;
                var isCollapsed = headerRow.classList.toggle('collapsed');
                headerRow.setAttribute('aria-expanded', isCollapsed ? 'false' : 'true');
                if (isCollapsed) _collapsedGroups[mode + '\u0000' + key] = true;
                else delete _collapsedGroups[mode + '\u0000' + key];
                groups[key].forEach(function(row) {
                    row.style.display = isCollapsed ? 'none' : '';
                });
            });
        });
    }

    _layoutFindingGroups = layoutGroups;

    // Filters, search, sorting and paging all go through the table, whose
    // render calls layoutGroups; a mode change just asks for a render.
    groupByEl.addEventListener('change', function() {
        syncGroupModeButtons();
        if (findingsTable) findingsTable.applyFilters();
        else layoutGroups();
        syncFindingsURL();
    });
})();

// --- Open finding detail in shared CSM.detailPanel (replaces inline row expansion) ---
function toggleFindingDetail(row) {
    var check = row.dataset.check;
    var message = row.dataset.message;
    var hasFix = row.getAttribute('data-hasFix') === 'true';
    var key = row.getAttribute('data-key') || (check + ':' + message);
    var filepath = row.getAttribute('data-filepath') || '';
    var account = row.getAttribute('data-account') || '';

    CSM.detailPanel.open({
        title: check,
        bodyHTML: '<div class="text-center text-muted py-4"><span class="spinner-border spinner-border-sm"></span> Loading...</div>'
    });

    CSM.get('/api/v1/finding-detail?check=' + encodeURIComponent(check) + '&message=' + encodeURIComponent(message))
        .then(function(data) {
            var html = '<div class="csm-fs-sm">';
            if (account) {
                var accountURL = CSM.accountURL(account);
                var accountHTML = '<code>' + CSM.esc(account) + '</code>';
                if (accountURL) accountHTML = '<a href="' + CSM.attr(accountURL) + '" title="Open the account page">' + accountHTML + '</a>';
                html += '<div class="mb-2"><strong>Account:</strong> ' + accountHTML + '</div>';
            }
            html += '<div class="mb-2"><strong>Check:</strong> <code>' + CSM.esc(check) + '</code></div>';
            html += '<div class="mb-2"><strong>Message:</strong><br>' + CSM.esc(message) + '</div>';
            if (filepath) html += '<div class="mb-2"><strong>File:</strong> <code class="csm-break-all">' + CSM.esc(filepath) + '</code></div>';
            if (data.first_seen) html += '<div class="mb-2"><strong>First seen:</strong> ' + CSM.esc(CSM.fmtDate(data.first_seen)) + '</div>';
            if (data.last_seen) html += '<div class="mb-2"><strong>Last seen:</strong> ' + CSM.esc(CSM.fmtDate(data.last_seen)) + '</div>';
            var actions = data.actions || [];
            if (actions.length > 0) {
                html += '<div class="mb-2"><strong>Actions taken (' + actions.length + '):</strong><ul class="mb-0 mt-1">';
                for (var i = 0; i < Math.min(actions.length, 10); i++) {
                    var a = actions[i];
                    html += '<li>' + CSM.esc(a.action) + ' -- ' + CSM.esc(a.target || '') +
                        ' <span class="text-muted">(' + CSM.esc(CSM.fmtDate(a.timestamp || '')) + ')</span></li>';
                }
                if (actions.length > 10) html += '<li class="text-muted">...and ' + (actions.length - 10) + ' more</li>';
                html += '</ul></div>';
            } else {
                html += '<div class="mb-2 text-muted">No recorded actions for this finding.</div>';
            }
            var related = data.related || [];
            if (related.length > 0) {
                html += '<div><strong>Historical occurrences:</strong> ' + related.length + '</div>';
            }
            html += '</div>';

            var footer = '';
            if (hasFix) footer += '<button type="button" class="btn btn-warning btn-sm" data-csm-finding-fix>Fix</button>';
            footer += '<button type="button" class="btn btn-ghost-secondary btn-sm" data-csm-finding-dismiss>Dismiss</button>';
            footer += '<button type="button" class="btn btn-ghost-secondary btn-sm" data-csm-finding-suppress>Suppress</button>';

            CSM.detailPanel.open({ title: check, bodyHTML: html, footerHTML: footer });

            var panel = CSM.detailPanel.element();
            if (!panel) return;
            var fixBtn = panel.querySelector('[data-csm-finding-fix]');
            if (fixBtn) fixBtn.addEventListener('click', function() {
                var rowFix = row.querySelector('.fix-btn');
                if (rowFix) rowFix.click();
                CSM.detailPanel.close();
            });
            var dismissBtn = panel.querySelector('[data-csm-finding-dismiss]');
            if (dismissBtn) dismissBtn.addEventListener('click', function() {
                dismissOne(key);
                CSM.detailPanel.close();
            });
            var suppressBtn = panel.querySelector('[data-csm-finding-suppress]');
            if (suppressBtn) suppressBtn.addEventListener('click', function() {
                // The panel traps focus; close it so the dialog owns the keyboard.
                CSM.detailPanel.close();
                suppressFinding(check, message, filepath);
            });
        })
        .catch(function(err) {
            console.error('findingDetail:', err);
            CSM.detailPanel.open({
                title: check,
                bodyHTML: CSM.emptyStateBlock({
                    icon: 'alert-circle',
                    title: 'Failed to load details',
                    reason: 'Try again from the row buttons.'
                })
            });
        });
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

function initAutoRefresh(version) {
    // Stop any previous poller
    if (_findingsPoller) { _findingsPoller.stop(); _findingsPoller = null; }

    // Poll the enriched endpoint that renders the table, for the version of
    // its list only: the server derives it from the same deduped rows, so it
    // moves exactly when the table would change, without sending the list.
    // The raw /api/v1/findings has no IP dedup and fired the banner on every
    // poll whenever any ip_reputation finding existed.
    _findingsPoller = CSM.poll('/api/v1/findings/enriched?fields=version', 15000, function(err, data) {
        if (err) { console.error('findings auto-refresh:', err); return; }
        if (!data || !data.version) return;
        if (data.version !== version) {
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
