// CSM History tab - API-driven with server-side pagination
// Loaded inside the Findings page as the "History" tab
(function() {
    'use strict';

    var page = 0;
    var perPage = 50;
    var fromDate = '';
    var toDate = '';
    var searchTerm = '';
    var sevFilter = 'all';
    var historyLoaded = false;

    var sevLabels = {}; for (var sk in CSM.sevMap) sevLabels[sk] = CSM.sevMap[sk].label;
    var sevClasses = {}; for (var sk2 in CSM.sevMap) sevClasses[sk2] = CSM.sevMap[sk2].cls;

    function syncURL() {
        var params = new URLSearchParams(window.location.search);
        // Preserve non-history params (check, search, account from active tab)
        params.set('tab', 'history');
        // Set history-specific params
        if (fromDate) params.set('from', fromDate); else params.delete('from');
        if (toDate) params.set('to', toDate); else params.delete('to');
        if (sevFilter !== 'all') params.set('severity', sevFilter); else params.delete('severity');
        if (searchTerm) params.set('hsearch', searchTerm); else params.delete('hsearch');
        if (page > 0) params.set('hpage', String(page)); else params.delete('hpage');
        var qs = params.toString();
        history.replaceState(null, '', '/findings' + (qs ? '?' + qs : ''));
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
            container.textContent = '';
            var emptyDiv = document.createElement('div');
            emptyDiv.className = 'card-body text-center text-muted py-4';
            emptyDiv.textContent = 'No history entries found.';
            container.appendChild(emptyDiv);
            return;
        }

        // Build table via DOM methods - all user data escaped via CSM.esc()
        var wrap = document.createElement('div');
        wrap.className = 'table-responsive';
        var table = document.createElement('table');
        table.className = 'table table-vcenter card-table';
        table.id = 'history-table';

        var thead = document.createElement('thead');
        var headRow = document.createElement('tr');
        ['Severity', 'Check', 'Message', 'Time', ''].forEach(function(label) {
            var th = document.createElement('th');
            th.textContent = label;
            headRow.appendChild(th);
        });
        thead.appendChild(headRow);
        table.appendChild(thead);

        var tbody = document.createElement('tbody');
        for (var i = 0; i < findings.length; i++) {
            var f = findings[i];
            var sev = f.severity !== undefined ? f.severity : 0;
            var sevClass = sevClasses[sev] || 'warning';
            var sevLabel = sevLabels[sev] || 'WARNING';
            var ago = f.timestamp ? CSM.timeAgo(f.timestamp) : '';

            var tr = document.createElement('tr');
            tr.className = 'history-row';
            tr.setAttribute('data-idx', i);

            // Severity cell
            var tdSev = document.createElement('td');
            var badge = document.createElement('span');
            badge.className = 'badge badge-' + sevClass;
            badge.textContent = sevLabel;
            tdSev.appendChild(badge);
            tr.appendChild(tdSev);

            // Check cell
            var tdCheck = document.createElement('td');
            var code = document.createElement('code');
            code.textContent = f.check;
            tdCheck.appendChild(code);
            tr.appendChild(tdCheck);

            // Message cell
            var tdMsg = document.createElement('td');
            tdMsg.textContent = f.message;
            tr.appendChild(tdMsg);

            // Time cell
            var tdTime = document.createElement('td');
            tdTime.className = 'text-nowrap';
            var timeSpan = document.createElement('span');
            timeSpan.className = 'text-muted small';
            timeSpan.setAttribute('data-timestamp', f.timestamp || '');
            timeSpan.textContent = ago;
            tdTime.appendChild(timeSpan);
            tr.appendChild(tdTime);

            // Expand button cell
            var tdExpand = document.createElement('td');
            if (f.details) {
                var btn = document.createElement('button');
                btn.className = 'btn btn-ghost-secondary btn-sm expand-btn';
                btn.title = 'Expand details';
                btn.setAttribute('aria-label', 'Expand details');
                var icon = document.createElement('i');
                icon.className = 'ti ti-chevron-down';
                btn.appendChild(icon);
                tdExpand.appendChild(btn);
            }
            tr.appendChild(tdExpand);
            tbody.appendChild(tr);

            // Details row (hidden by default)
            if (f.details) {
                var detailTr = document.createElement('tr');
                detailTr.className = 'details-row';
                var detailTd = document.createElement('td');
                detailTd.colSpan = 5;
                detailTd.className = 'text-muted bg-dark-lt csm-detail small';
                detailTd.textContent = f.details;
                detailTr.appendChild(detailTd);
                tbody.appendChild(detailTr);
            }
        }

        table.appendChild(tbody);
        wrap.appendChild(table);
        container.textContent = '';
        container.appendChild(wrap);
    }

    function renderPager(total) {
        var pager = document.getElementById('history-pager');
        if (!pager) return;
        var totalPages = Math.ceil(total / perPage);
        if (totalPages <= 1) { pager.textContent = ''; return; }

        pager.textContent = '';
        var info = document.createElement('div');
        info.className = 'text-muted small';
        info.title = 'Showing ' + perPage + ' entries per page';
        info.textContent = 'Page ' + (page + 1) + ' of ' + totalPages;
        pager.appendChild(info);

        var btnGroup = document.createElement('div');
        btnGroup.className = 'btn-group btn-group-sm';

        var prev = document.createElement('button');
        prev.className = 'btn btn-ghost-secondary';
        prev.id = 'pager-prev';
        prev.title = 'Previous page';
        prev.textContent = 'Prev';
        if (page === 0) prev.disabled = true;
        prev.addEventListener('click', function() { if (page > 0) { page--; loadHistory(); } });
        btnGroup.appendChild(prev);

        var next = document.createElement('button');
        next.className = 'btn btn-ghost-secondary';
        next.id = 'pager-next';
        next.title = 'Next page';
        next.textContent = 'Next';
        if (page >= totalPages - 1) next.disabled = true;
        next.addEventListener('click', function() { if (page < totalPages - 1) { page++; loadHistory(); } });
        btnGroup.appendChild(next);

        pager.appendChild(btnGroup);
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
    if (params.get('hsearch')) { searchTerm = params.get('hsearch'); document.getElementById('history-search').value = searchTerm; }
    if (params.get('hpage')) { page = parseInt(params.get('hpage'), 10) || 0; }
    if (fromDate || toDate) { if (clearBtn) clearBtn.classList.remove('d-none'); }

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
                        var showing = next.style.display === 'none';
                        next.style.display = showing ? '' : 'none';
                        expandBtn.classList.toggle('expanded', showing);
                    }
                }
            }
        });
    }

    // --- Tab-deferred loading ---
    // Only load history data when the History tab is first shown
    function initHistory() {
        if (historyLoaded) return;
        historyLoaded = true;
        loadHistory();
    }

    var historyTabLink = document.querySelector('[href="#tab-history"]');
    if (historyTabLink) {
        historyTabLink.addEventListener('shown.bs.tab', initHistory);
    }

    // If tab=history is in URL, activate the History tab on load
    if (params.get('tab') === 'history') {
        if (historyTabLink) {
            // Use Bootstrap Tab API to switch
            var bsTab = new bootstrap.Tab(historyTabLink);
            bsTab.show();
        }
    }
})();
