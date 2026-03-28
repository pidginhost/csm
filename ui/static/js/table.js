/**
 * CSM.Table — Reusable table component with search, filter, sort, pagination.
 *
 * Usage:
 *   new CSM.Table({
 *     tableId: 'my-table',          // ID of <table> element
 *     perPage: 25,                  // rows per page (default 25)
 *     search: true,                 // enable search (default true)
 *     searchId: 'my-search',        // ID of search <input> (auto-created if missing)
 *     filters: [                    // optional filters
 *       { id: 'sev-filter', column: 0, attr: 'data-sev' }
 *     ],
 *     sortable: true,               // enable column sorting (default true)
 *     detailRows: true,             // rows with class 'details-row' are expandable
 *     controlsId: 'my-controls',    // ID of div for pagination controls (auto-created)
 *     stateKey: 'my-table-state',   // localStorage key for persistent state (optional)
 *   });
 */
var CSM = CSM || {};

CSM.Table = function(opts) {
    this.table = document.getElementById(opts.tableId);
    if (!this.table) return;

    this.tbody = this.table.querySelector('tbody');
    if (!this.tbody) return;

    this.perPage = opts.perPage || 25;
    this.currentPage = 1;
    this.searchText = '';
    this.filterValues = {};
    this.sortColumn = -1;
    this.sortAsc = true;
    this.hasDetailRows = opts.detailRows || false;
    this.filters = opts.filters || [];
    this.stateKey = opts.stateKey || null;
    this.onRender = opts.onRender || null;

    // Collect all data rows (skip detail rows)
    this.allRows = [];
    var rows = this.tbody.querySelectorAll('tr');
    for (var i = 0; i < rows.length; i++) {
        if (!rows[i].classList.contains('details-row')) {
            var detailRow = null;
            if (this.hasDetailRows && rows[i+1] && rows[i+1].classList.contains('details-row')) {
                detailRow = rows[i+1];
            }
            this.allRows.push({ row: rows[i], detail: detailRow, text: rows[i].textContent.toLowerCase() });
        }
    }

    this.filteredRows = this.allRows.slice();

    // Build controls
    this._buildControls(opts);

    // Bind search
    if (opts.search !== false) {
        var searchEl = opts.searchId ? document.getElementById(opts.searchId) : null;
        if (searchEl) {
            var self = this;
            searchEl.addEventListener('input', function() {
                self.searchText = this.value.toLowerCase();
                self.currentPage = 1;
                self.applyFilters();
                self._saveState();
            });
        }
    }

    // Bind filters
    for (var f = 0; f < this.filters.length; f++) {
        (function(filter, tbl) {
            var el = document.getElementById(filter.id);
            if (el) {
                el.addEventListener('change', function() {
                    tbl.filterValues[filter.id] = this.value;
                    tbl.currentPage = 1;
                    tbl.applyFilters();
                });
            }
        })(this.filters[f], this);
    }

    // Bind sortable headers
    if (opts.sortable !== false) {
        var headers = this.table.querySelectorAll('thead th');
        for (var h = 0; h < headers.length; h++) {
            (function(idx, header, tbl) {
                // Skip checkbox and action columns
                if (header.querySelector('input[type="checkbox"]')) return;
                if (header.textContent.trim() === 'Action' || header.textContent.trim() === 'Actions') return;

                header.style.cursor = 'pointer';
                header.title = 'Click to sort';
                header.addEventListener('click', function() {
                    if (tbl.sortColumn === idx) {
                        tbl.sortAsc = !tbl.sortAsc;
                    } else {
                        tbl.sortColumn = idx;
                        tbl.sortAsc = true;
                    }
                    // Update header indicators
                    var allHeaders = tbl.table.querySelectorAll('thead th');
                    for (var j = 0; j < allHeaders.length; j++) {
                        allHeaders[j].classList.remove('sort-asc', 'sort-desc');
                    }
                    header.classList.add(tbl.sortAsc ? 'sort-asc' : 'sort-desc');
                    tbl.applySort();
                    tbl.render();
                    tbl._saveState();
                });
            })(h, headers[h], this);
        }
    }

    // Restore saved state before initial render
    this._restoreState(opts);

    // Initial render
    this.applyFilters();
};

CSM.Table.prototype._buildControls = function(opts) {
    var controlsId = opts.controlsId || opts.tableId + '-controls';
    var controls = document.getElementById(controlsId);
    if (!controls) {
        controls = document.createElement('div');
        controls.id = controlsId;
        controls.className = 'card-footer d-flex justify-content-between align-items-center';
        // Append to card level so controls don't end up inside table-responsive overflow
        var card = this.table.closest('.card');
        (card || this.table.parentNode).appendChild(controls);
    }
    this.controlsEl = controls;
};

CSM.Table.prototype.applyFilters = function() {
    var self = this;
    this.filteredRows = this.allRows.filter(function(item) {
        // Search filter
        if (self.searchText && item.text.indexOf(self.searchText) < 0) return false;

        // Custom filters
        for (var f = 0; f < self.filters.length; f++) {
            var filter = self.filters[f];
            var val = self.filterValues[filter.id];
            if (val && val !== 'all') {
                var rowVal = '';
                if (filter.attr) {
                    rowVal = item.row.getAttribute(filter.attr) || '';
                } else if (typeof filter.column === 'number') {
                    var cell = item.row.cells[filter.column];
                    rowVal = cell ? cell.textContent.toLowerCase().trim() : '';
                }
                if (rowVal !== val) return false;
            }
        }
        return true;
    });

    this.applySort();
    this.render();
};

CSM.Table.prototype.applySort = function() {
    if (this.sortColumn < 0) return;
    var col = this.sortColumn;
    var asc = this.sortAsc;
    this.filteredRows.sort(function(a, b) {
        var cellA = a.row.cells[col];
        var cellB = b.row.cells[col];
        if (!cellA || !cellB) return 0;
        var valA = cellA.textContent.trim().toLowerCase();
        var valB = cellB.textContent.trim().toLowerCase();
        // Try numeric sort
        var numA = parseFloat(valA), numB = parseFloat(valB);
        if (!isNaN(numA) && !isNaN(numB)) {
            return asc ? numA - numB : numB - numA;
        }
        return asc ? valA.localeCompare(valB) : valB.localeCompare(valA);
    });
};

CSM.Table.prototype.render = function() {
    var total = this.filteredRows.length;
    var showAll = !this.perPage;
    var perPage = showAll ? total : this.perPage;
    var totalPages = Math.max(1, Math.ceil(total / (perPage || 1)));
    if (this.currentPage > totalPages) this.currentPage = totalPages;

    var start = showAll ? 0 : (this.currentPage - 1) * perPage;
    var end = showAll ? total : Math.min(start + perPage, total);

    // Hide all rows first
    for (var i = 0; i < this.allRows.length; i++) {
        this.allRows[i].row.style.display = 'none';
        if (this.allRows[i].detail) this.allRows[i].detail.style.display = 'none';
    }

    // Show only current page rows
    for (var j = start; j < end; j++) {
        this.filteredRows[j].row.style.display = '';
    }

    // Render pagination controls
    this._renderControls(total, totalPages);

    // Notify caller (e.g. findings page resets bulk selection)
    if (this.onRender) this.onRender();
};

CSM.Table.prototype._renderControls = function(total, totalPages) {
    var self = this;
    var showAll = !this.perPage;
    var start = total === 0 ? 0 : (showAll ? 1 : (this.currentPage - 1) * this.perPage + 1);
    var end = showAll ? total : Math.min(this.currentPage * this.perPage, total);
    var totalAll = this.allRows ? this.allRows.length : total;
    var suffix = (total < totalAll) ? ' (' + totalAll + ' total)' : '';
    var html = '<span class="text-muted small">Showing ' + start + '\u2013' + end + ' of ' + total + suffix + '</span>';

    if (totalPages > 1) {
        html += '<div class="d-flex gap-1">';
        if (this.currentPage > 1) {
            html += '<button class="btn btn-sm btn-ghost-secondary" data-page="' + (this.currentPage - 1) + '">Previous</button>';
        }

        // Page numbers (show max 7)
        var startPage = Math.max(1, this.currentPage - 3);
        var endPage = Math.min(totalPages, startPage + 6);
        startPage = Math.max(1, endPage - 6);

        for (var p = startPage; p <= endPage; p++) {
            if (p === this.currentPage) {
                html += '<button class="btn btn-sm btn-primary" disabled>' + p + '</button>';
            } else {
                html += '<button class="btn btn-sm btn-ghost-secondary" data-page="' + p + '">' + p + '</button>';
            }
        }

        if (this.currentPage < totalPages) {
            html += '<button class="btn btn-sm btn-ghost-secondary" data-page="' + (this.currentPage + 1) + '">Next</button>';
        }
        html += '</div>';
    }

    this.controlsEl.innerHTML = html;

    // Bind page buttons
    var buttons = this.controlsEl.querySelectorAll('[data-page]');
    for (var b = 0; b < buttons.length; b++) {
        buttons[b].addEventListener('click', function() {
            self.currentPage = parseInt(this.getAttribute('data-page'));
            self.render();
            self._saveState();
        });
    }
};

// Expand/collapse detail rows (for history page)
CSM.Table.prototype.toggleDetail = function(row) {
    var item = null;
    for (var i = 0; i < this.filteredRows.length; i++) {
        if (this.filteredRows[i].row === row) { item = this.filteredRows[i]; break; }
    }
    if (item && item.detail) {
        item.detail.style.display = item.detail.style.display === 'none' ? '' : 'none';
    }
};

// Persistent table state — save to localStorage
CSM.Table.prototype._saveState = function() {
    if (!this.stateKey) return;
    try {
        var state = {
            page: this.currentPage,
            sortCol: this.sortColumn,
            sortAsc: this.sortAsc,
            search: this.searchText
        };
        localStorage.setItem(this.stateKey, JSON.stringify(state));
    } catch (e) { /* localStorage may be unavailable */ }
};

// Persistent table state — restore from localStorage
CSM.Table.prototype._restoreState = function(opts) {
    if (!this.stateKey) return;
    try {
        var raw = localStorage.getItem(this.stateKey);
        if (!raw) return;
        var state = JSON.parse(raw);
        if (typeof state.page === 'number' && state.page > 0) {
            this.currentPage = state.page;
        }
        if (typeof state.sortCol === 'number' && state.sortCol >= 0) {
            this.sortColumn = state.sortCol;
            this.sortAsc = state.sortAsc !== false;
            // Apply visual indicator to the header
            var headers = this.table.querySelectorAll('thead th');
            if (headers[state.sortCol]) {
                headers[state.sortCol].classList.add(this.sortAsc ? 'sort-asc' : 'sort-desc');
            }
        }
        if (state.search) {
            this.searchText = state.search;
            // Also set the search input value
            var searchEl = opts.searchId ? document.getElementById(opts.searchId) : null;
            if (searchEl) searchEl.value = state.search;
        }
    } catch (e) { /* ignore parse errors */ }
};
