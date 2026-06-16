// CSM Quarantine page

var _quarTable = null;
var _quarURLUnbind = null;
var _quarDateListenersBound = false;

// WEB_ROADMAP P3.3: extract /home/<account>/ from the quarantine entry's
// original_path so the account filter dropdown works without a server
// schema change. Returns '' for system paths so they fall under "All".
function _quarAccountFromPath(path) {
    if (!path) return '';
    var m = String(path).match(/^\/home\/([^\/]+)\//);
    return m ? m[1] : '';
}

// Detectors carry a short label as the first colon-delimited segment of
// the reason field (e.g. "YARA rule match: foo", "WordPress upload",
// "ModSec...:"). Use the prefix before the first colon (or the whole
// reason when no colon) as a stable bucket.
function _quarDetectorFromReason(reason) {
    if (!reason) return '';
    var s = String(reason).trim();
    var c = s.indexOf(':');
    return (c > 0 ? s.slice(0, c) : s).trim();
}

function _quarLocalDateMillis(value, endExclusive) {
    if (!value) return null;
    var parts = String(value).match(/^(\d{4})-(\d{2})-(\d{2})$/);
    if (!parts) return null;
    var year = Number(parts[1]);
    var month = Number(parts[2]) - 1;
    var day = Number(parts[3]);
    var d = new Date(year, month, day);
    if (isNaN(d.getTime())) return null;
    if (d.getFullYear() !== year || d.getMonth() !== month || d.getDate() !== day) return null;
    if (endExclusive) d.setDate(d.getDate() + 1);
    return d.getTime();
}

function _quarURLInputs(fromEl, toEl) {
    return {
        q: document.getElementById('quarantine-search'),
        account: document.getElementById('quarantine-account-filter'),
        source: document.getElementById('quarantine-source-filter'),
        from: fromEl,
        to: toEl
    };
}

function _bindQuarURLState(fromEl, toEl) {
    if (_quarURLUnbind) _quarURLUnbind();
    _quarURLUnbind = CSM.urlState.bind({ inputs: _quarURLInputs(fromEl, toEl) });
}

function _resetQuarTable() {
    if (_quarTable) {
        if (typeof _quarTable.destroy === 'function') _quarTable.destroy();
        _quarTable = null;
    }
    var controls = document.getElementById('quarantine-table-controls');
    if (controls) controls.remove();
}

function _bindQuarDateFilters(fromEl, toEl) {
    if (_quarDateListenersBound) return;
    function onDate() {
        if (_quarTable) {
            _quarTable.currentPage = 1;
            _quarTable.applyFilters();
        }
    }
    if (fromEl) fromEl.addEventListener('change', onDate);
    if (toEl) toEl.addEventListener('change', onDate);
    _quarDateListenersBound = true;
}

function _populateQuarFilterOptions(files) {
    var accounts = Object.create(null), detectors = Object.create(null);
    files = files || [];
    for (var i = 0; i < files.length; i++) {
        var a = _quarAccountFromPath(files[i].original_path);
        if (a) accounts[a] = true;
        var d = _quarDetectorFromReason(files[i].reason);
        if (d) detectors[d] = true;
    }
    function fill(id, values) {
        var el = document.getElementById(id);
        if (!el) return;
        var prev = el.value;
        // Drop existing options beyond the "All ..." first one.
        while (el.options.length > 1) el.remove(1);
        Object.keys(values).sort().forEach(function(v) {
            var opt = document.createElement('option');
            opt.value = v;
            opt.textContent = v;
            el.appendChild(opt);
        });
        if (prev) el.value = prev;
    }
    fill('quarantine-account-filter', accounts);
    fill('quarantine-source-filter', detectors);
}

function loadQuarantine() {
    CSM.get('/api/v1/quarantine').then(function(files){
        var el = document.getElementById('quarantine-content');
        var fromEl = document.getElementById('quarantine-from');
        var toEl = document.getElementById('quarantine-to');
        var title = document.querySelector('.card-title');
        if (title) title.innerHTML = '<i class="ti ti-lock"></i>&nbsp;Quarantined Files (' + (files ? files.length : 0) + ')';
        _resetQuarTable();
        _populateQuarFilterOptions(files || []);
        if (!files || files.length === 0) {
            _bindQuarURLState(fromEl, toEl);
            el.innerHTML = '<div class="card-body text-center text-muted py-4"><i class="ti ti-circle-check"></i> No quarantined files.</div>';
            updateBulkRestore();
            return;
        }
        var html = '<div class="table-responsive"><table class="table table-vcenter card-table" id="quarantine-table"><thead><tr><th><input type="checkbox" class="form-check-input" id="q-select-all"></th><th>Original Path</th><th>Size</th><th>Quarantined</th><th>Reason</th><th>Action</th></tr></thead><tbody>';
        for (var i = 0; i < files.length; i++) {
            var f = files[i];
            var acct = _quarAccountFromPath(f.original_path);
            var det = _quarDetectorFromReason(f.reason);
            html += '<tr data-path="' + CSM.attr(f.original_path || '') + '" data-account="' + CSM.attr(acct) + '" data-source="' + CSM.attr(det) + '" data-timestamp="' + CSM.attr(f.quarantined_at || '') + '">';
            html += '<td><input type="checkbox" class="form-check-input q-cb" data-id="'+CSM.esc(f.id)+'"></td><td><code>'+CSM.esc(f.original_path)+'</code></td><td>'+formatSize(f.size)+'</td><td class="text-nowrap"><span class="text-muted small">'+CSM.esc(f.quarantined_at)+'</span></td><td class="small">'+CSM.esc(f.reason)+'</td><td><button class="btn btn-sm btn-ghost-secondary me-1 view-btn" data-id="'+CSM.esc(f.id)+'" data-path="'+CSM.esc(f.original_path)+'">View</button><button class="btn btn-sm btn-warning restore-btn" data-id="'+CSM.esc(f.id)+'">Restore</button></td></tr>';
        }
        html += '</tbody></table></div>';
        el.innerHTML = html;
        function _inRange(row) {
            var raw = row.getAttribute('data-timestamp') || '';
            if (!raw) return true;
            var ts = new Date(raw.replace(/^(\d{4}-\d{2}-\d{2})\s+(\d{2}:\d{2}:\d{2})/, '$1T$2')).getTime();
            if (isNaN(ts)) return true;
            var from = fromEl ? _quarLocalDateMillis(fromEl.value, false) : null;
            var to = toEl ? _quarLocalDateMillis(toEl.value, true) : null;
            if (from !== null && ts < from) return false;
            if (to !== null && ts >= to) return false;
            return true;
        }
        // Initialize table component after DOM is ready
        _quarTable = new CSM.Table({
            tableId: 'quarantine-table',
            perPage: 25,
            searchId: 'quarantine-search',
            searchAttr: 'data-path',
            sortable: true,
            stateKey: 'csm-quarantine-table',
            filters: [
                { id: 'quarantine-account-filter', attr: 'data-account' },
                { id: 'quarantine-source-filter',  attr: 'data-source' }
            ],
            rowFilter: _inRange,
            onRender: function() {
                if (_quarBulk) _quarBulk.refresh();
            }
        });
        _bindQuarDateFilters(fromEl, toEl);
        // WEB_ROADMAP P2.1 / P3.3: persist all filters to URL.
        _bindQuarURLState(fromEl, toEl);
        // Bind restore and view buttons after DOM insertion
        el.querySelectorAll('.restore-btn').forEach(function(btn) {
            btn.addEventListener('click', function() { restoreFile(this.getAttribute('data-id')); });
        });
        el.querySelectorAll('.view-btn').forEach(function(btn) {
            btn.addEventListener('click', function() { viewFile(this.getAttribute('data-id'), this.getAttribute('data-path')); });
        });
        // CSM.bulk owns the select-all and per-row checkbox listeners
        // (re-bind is idempotent via the data-csm-bulk-bound flag).
        updateBulkRestore();
    }).catch(function(){ CSM.loadError(document.getElementById('quarantine-content'), loadQuarantine); });
}
function restoreFile(id) {
    CSM.confirm('Restore this file? A re-scan is recommended after restore.').then(function() {
        CSM.post('/api/v1/quarantine-restore', {id: id}).then(function(data){
            if (data.error) { CSM.toast('Error: ' + data.error, 'error'); }
            else { CSM.toast('Restored: ' + data.path, 'success'); }
            loadQuarantine();
        }).catch(function(e){ CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
}
function viewFile(id, path) {
    CSM.get('/api/v1/quarantine-preview?id=' + encodeURIComponent(id), { allowNonOK: true, silent: true })
        .then(function(data) {
            if (data.error) { CSM.toast('Error: ' + data.error, 'error'); return; }
            var info = data.truncated ? ' (first 8KB of ' + formatSize(data.total_size) + ')' : '';
            var preview = data.preview || '(empty file)';

            var modal = document.getElementById('csm-confirm-modal');
            var dialog = modal ? modal.querySelector('.modal-dialog') : null;
            var body = document.getElementById('csm-confirm-body');
            var okBtn = document.getElementById('csm-confirm-ok');
            var cancelBtn = document.getElementById('csm-confirm-cancel');
            if (!modal || !body || !dialog) return;

            // Make modal large for file preview
            dialog.classList.remove('modal-sm');
            dialog.classList.add('modal-lg');

            // Build preview content
            body.textContent = '';
            body.style.whiteSpace = 'normal';
            var header = document.createElement('div');
            header.style.cssText = 'margin-bottom:8px';
            var strong = document.createElement('strong');
            strong.textContent = path;
            header.appendChild(strong);
            if (info) {
                var infoSpan = document.createElement('span');
                infoSpan.className = 'text-muted small ms-2';
                infoSpan.textContent = info;
                header.appendChild(infoSpan);
            }
            body.appendChild(header);

            var pre = document.createElement('pre');
            pre.style.cssText = 'max-height:60vh;overflow:auto;padding:12px;border-radius:4px;font-size:0.75rem;white-space:pre-wrap;word-break:break-all;border:1px solid var(--csm-border);background:var(--csm-bg-card);color:var(--csm-text)';
            pre.textContent = preview;
            body.appendChild(pre);

            if (okBtn) okBtn.textContent = 'Close';
            if (cancelBtn) cancelBtn.style.display = 'none';

            modal.classList.add('show');
            modal.style.display = 'block';
            modal.setAttribute('aria-hidden', 'false');
            var backdrop = document.createElement('div');
            backdrop.className = 'modal-backdrop fade show';
            document.body.appendChild(backdrop);

            function closeModal() {
                modal.classList.remove('show');
                modal.style.display = 'none';
                modal.setAttribute('aria-hidden', 'true');
                // Restore modal to default small size
                dialog.classList.remove('modal-lg');
                dialog.classList.add('modal-sm');
                body.style.whiteSpace = '';
                if (okBtn) { okBtn.textContent = 'OK'; okBtn.removeEventListener('click', closeModal); }
                if (cancelBtn) cancelBtn.style.display = '';
                if (backdrop.parentNode) backdrop.parentNode.removeChild(backdrop);
            }
            if (okBtn) okBtn.addEventListener('click', closeModal);
            backdrop.addEventListener('click', closeModal);
        })
        .catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
}
var formatSize = CSM.formatSize;

// WEB_ROADMAP P2.5: shared CSM.bulk owns selection state, button
// labels, and the select-all indeterminate. Quarantine just registers
// the two action handlers.
var _quarBulk = null;
function updateBulkRestore() {
    var restoreBtn = document.getElementById('bulk-restore-btn');
    var deleteBtn  = document.getElementById('bulk-delete-btn');
    var selectAll  = document.getElementById('q-select-all');
    if (!_quarBulk && !selectAll && !document.querySelector('.q-cb')) {
        [restoreBtn, deleteBtn].forEach(function(btn) {
            if (!btn) return;
            btn.disabled = true;
            btn.classList.add('d-none');
        });
        return;
    }
    if (_quarBulk) { _quarBulk.refresh(); return; }
    if (!restoreBtn && !deleteBtn) return;
    _quarBulk = CSM.bulk({
        rowCheckboxSelector: '.q-cb',
        selectAllEl: selectAll,
        selectAllSelector: '#q-select-all',
        valueAttr: 'data-id',
        buttons: [
            { el: restoreBtn, labelTemplate: 'Restore {n} file(s)' },
            { el: deleteBtn,  labelTemplate: 'Delete {n} file(s)' }
        ]
    });
}

var bulkRestoreBtn = document.getElementById('bulk-restore-btn');
if (bulkRestoreBtn) {
    bulkRestoreBtn.addEventListener('click', function() {
        if (!_quarBulk) return;
        var ids = _quarBulk.selectedValues();
        if (ids.length === 0) return;
        CSM.confirm('Restore ' + ids.length + ' file(s)? A re-scan is recommended after restore.').then(function() {
            var succeeded = 0, failed = 0;
            var chain = Promise.resolve();
            ids.forEach(function(id) {
                chain = chain.then(function() {
                    return CSM.post('/api/v1/quarantine-restore', {id: id})
                        .then(function() { succeeded++; })
                        .catch(function() { failed++; });
                });
            });
            chain.then(function() {
                CSM.toast('Restored ' + succeeded + ' of ' + (succeeded + failed) + ' file(s)', failed > 0 ? 'warning' : 'success');
                loadQuarantine();
            });
        }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
    });
}

var bulkDeleteBtn = document.getElementById('bulk-delete-btn');
if (bulkDeleteBtn) {
    bulkDeleteBtn.addEventListener('click', function() {
        if (!_quarBulk) return;
        var ids = _quarBulk.selectedValues();
        if (ids.length === 0) return;
        CSM.confirm('Permanently delete ' + ids.length + ' quarantined file(s)?').then(function() {
            CSM.post('/api/v1/quarantine/bulk-delete', { ids: ids }).then(function(data) {
                CSM.toast('Deleted ' + data.count + ' file(s)', 'success');
                loadQuarantine();
            }).catch(function(err) { CSM.toast(err.message || 'Delete failed', 'error'); });
        }).catch(function() { /* cancelled */ });
    });
}

loadQuarantine();
if (CSM.refresh && typeof CSM.refresh.onRefresh === 'function') {
    CSM.refresh.onRefresh(loadQuarantine);
}
