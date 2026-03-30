// CSM History page — API-driven with server-side pagination
(function() {
    'use strict';

    var page = 0;
    var perPage = 50;
    var fromDate = '';
    var toDate = '';
    var searchTerm = '';
    var sevFilter = 'all';

    var sevLabels = { 2: 'CRITICAL', 1: 'HIGH', 0: 'WARNING' };
    var sevClasses = { 2: 'critical', 1: 'high', 0: 'warning' };

    function syncURL() {
        var params = new URLSearchParams();
        if (fromDate) params.set('from', fromDate);
        if (toDate) params.set('to', toDate);
        if (sevFilter !== 'all') params.set('severity', sevFilter);
        if (searchTerm) params.set('search', searchTerm);
        if (page > 0) params.set('page', page);
        var qs = params.toString();
        history.replaceState(null, '', '/history' + (qs ? '?' + qs : ''));
    }

    function loadHistory() {
        var url = '/api/v1/history?limit=' + perPage + '&offset=' + (page * perPage);
        if (fromDate) url += '&from=' + fromDate;
        if (toDate) url += '&to=' + toDate;
        if (sevFilter !== 'all') url += '&severity=' + sevFilter;
        if (searchTerm) url += '&search=' + encodeURIComponent(searchTerm);

        fetch(CSM.apiUrl(url), { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                renderTable(data.findings || [], data.total || 0);
                renderPager(data.total || 0);
            })
            .catch(function() { CSM.loadError(document.getElementById('history-content'), loadHistory); });
        syncURL();
    }

    function renderTable(findings, total) {
        var container = document.getElementById('history-content');
        var countEl = document.getElementById('history-count');
        if (countEl) countEl.textContent = '(' + total + ' total)';

        if (!findings || findings.length === 0) {
            container.innerHTML = '<div class="card-body text-center text-muted py-4">No history entries found.</div>';
            return;
        }

        var html = '<div class="table-responsive"><table class="table table-vcenter card-table" id="history-table"><thead>';
        html += '<tr><th>Severity</th><th>Check</th><th>Message</th><th>Time</th><th></th></tr></thead><tbody>';

        for (var i = 0; i < findings.length; i++) {
            var f = findings[i];
            var sev = f.severity !== undefined ? f.severity : 0;
            var sevClass = sevClasses[sev] || 'warning';
            var sevLabel = sevLabels[sev] || 'WARNING';

            var ts = f.timestamp ? CSM.fmtDate(f.timestamp) : '';
            var ago = f.timestamp ? CSM.timeAgo(f.timestamp) : '';

            html += '<tr class="history-row" data-idx="' + i + '">';
            html += '<td><span class="badge badge-' + sevClass + '">' + sevLabel + '</span></td>';
            html += '<td><code>' + CSM.esc(f.check) + '</code></td>';
            html += '<td>' + CSM.esc(f.message) + '</td>';
            html += '<td class="text-nowrap"><span class="text-muted small" data-timestamp="' + CSM.esc(f.timestamp || '') + '">' + CSM.esc(ago) + '</span></td>';
            var expandBtn = f.details ? '<button class="btn btn-ghost-secondary btn-sm expand-btn" title="Show details"><i class="ti ti-chevron-down"></i></button>' : '';
            html += '<td>' + expandBtn + '</td>';
            html += '</tr>';

            if (f.details) {
                html += '<tr class="details-row" style="display:none">';
                html += '<td colspan="5" style="white-space:pre-wrap;font-size:0.8rem" class="text-muted bg-dark-lt">' + CSM.esc(f.details) + '</td>';
                html += '</tr>';
            }
        }

        html += '</tbody></table></div>';
        container.innerHTML = html;

    }

    function renderPager(total) {
        var pager = document.getElementById('history-pager');
        if (!pager) return;
        var totalPages = Math.ceil(total / perPage);
        if (totalPages <= 1) { pager.innerHTML = ''; return; }

        var html = '<div class="text-muted small">Page ' + (page + 1) + ' of ' + totalPages + '</div><div class="btn-group btn-group-sm">';
        html += '<button class="btn btn-ghost-secondary" ' + (page === 0 ? 'disabled' : '') + ' id="pager-prev">Prev</button>';
        html += '<button class="btn btn-ghost-secondary" ' + (page >= totalPages - 1 ? 'disabled' : '') + ' id="pager-next">Next</button>';
        html += '</div>';
        pager.innerHTML = html;

        var prev = document.getElementById('pager-prev');
        var next = document.getElementById('pager-next');
        if (prev) prev.addEventListener('click', function() { if (page > 0) { page--; loadHistory(); } });
        if (next) next.addEventListener('click', function() { if (page < totalPages - 1) { page++; loadHistory(); } });
    }

    // Date filter
    var filterBtn = document.getElementById('date-filter-btn');
    var clearBtn = document.getElementById('date-clear-btn');
    if (filterBtn) {
        filterBtn.addEventListener('click', function() {
            fromDate = document.getElementById('date-from').value;
            toDate = document.getElementById('date-to').value;
            page = 0;
            if (fromDate || toDate) clearBtn.classList.remove('d-none');
            loadHistory();
        });
    }
    if (clearBtn) {
        clearBtn.addEventListener('click', function() {
            fromDate = ''; toDate = '';
            document.getElementById('date-from').value = '';
            document.getElementById('date-to').value = '';
            clearBtn.classList.add('d-none');
            page = 0;
            loadHistory();
        });
    }

    // Severity filter
    var sevSelect = document.getElementById('sev-filter');
    if (sevSelect) {
        sevSelect.addEventListener('change', function() {
            sevFilter = this.value;
            page = 0;
            loadHistory();
        });
    }

    // Search
    var searchInput = document.getElementById('history-search');
    if (searchInput) {
        var searchTimer;
        searchInput.addEventListener('input', function() {
            clearTimeout(searchTimer);
            searchTerm = this.value;
            page = 0;
            searchTimer = setTimeout(function() { loadHistory(); }, 300);
        });
    }

    // Restore filter state from URL params
    var params = new URLSearchParams(window.location.search);
    if (params.get('from')) { fromDate = params.get('from'); document.getElementById('date-from').value = fromDate; }
    if (params.get('to')) { toDate = params.get('to'); document.getElementById('date-to').value = toDate; }
    if (params.get('severity')) { sevFilter = params.get('severity'); document.getElementById('sev-filter').value = sevFilter; }
    if (params.get('search')) { searchTerm = params.get('search'); document.getElementById('history-search').value = searchTerm; }
    if (params.get('page')) { page = parseInt(params.get('page'), 10) || 0; }
    if (fromDate || toDate) { var clearBtn = document.getElementById('date-clear-btn'); if (clearBtn) clearBtn.classList.remove('d-none'); }

    // Event delegation for history table expand buttons
    var historyContainer = document.getElementById('history-content');
    if (historyContainer) {
        historyContainer.addEventListener('click', function(e) {
            var expandBtn = e.target.closest('.expand-btn');
            if (expandBtn) {
                var row = expandBtn.closest('tr');
                if (row) {
                    var next = row.nextElementSibling;
                    if (next && next.classList.contains('details-row')) {
                        next.style.display = next.style.display === 'none' ? '' : 'none';
                    }
                }
            }
        });
    }

    // Initial load
    loadHistory();
})();
