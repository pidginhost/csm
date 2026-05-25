/**
 * CSM.Table - Reusable table component with search, filter, sort, pagination.
 *
 * Usage:
 *   new CSM.Table({
 *     tableId: 'my-table',          // ID of <table> element
 *     perPage: 25,                  // rows per page (default 25)
 *     search: true,                 // enable search (default true)
 *     searchId: 'my-search',        // ID of existing search <input> (optional)
 *     searchAttr: 'data-search',    // row attribute to search instead of all text (optional)
 *     filters: [                    // optional filters
 *       { id: 'sev-filter', column: 0, attr: 'data-sev' }
 *     ],
 *     sortable: true,               // enable column sorting (default true)
 *     detailRows: true,             // rows with class 'details-row' are expandable
 *     controlsId: 'my-controls',    // ID of div for pagination controls (auto-created)
 *     controls: false,              // disable auto-created pagination controls
 *     stateKey: 'my-table-state',   // localStorage key for persistent state (optional)
 *     persistPerPage: false,        // do not save/restore perPage in localStorage
 *     density: 'compact',           // 'comfortable' (default) or 'compact' (adds table-sm)
 *     emptyState: {                 // optional: rendered when filteredRows is empty
 *       icon: 'circle-check',
 *       title: 'No matches',
 *       reason: 'Try adjusting your filters.',
 *       actionHTML: '<button class="btn btn-sm btn-ghost-secondary" data-clear-filters>Clear filters</button>',
 *     },
 *     clearFiltersId: 'my-clear',   // optional id of a clear-filters button
 *     mobileRowCard: true,          // optional: stack rows as cards on narrow viewports
 *   });
 */
var CSM = CSM || {};

CSM._tableInstances = CSM._tableInstances || [];

CSM.printTables = CSM.printTables || (function() {
    var snapshots = [];

    function liveTables() {
        var out = [];
        for (var i = 0; i < CSM._tableInstances.length; i++) {
            var tbl = CSM._tableInstances[i];
            if (tbl && tbl.table && document.documentElement.contains(tbl.table)) {
                out.push(tbl);
            }
        }
        CSM._tableInstances = out;
        return out;
    }

    return {
        prepare: function() {
            this.restore();
            var tables = liveTables();
            for (var i = 0; i < tables.length; i++) {
                var tbl = tables[i];
                if (!tbl.perPage) continue;
                snapshots.push({ table: tbl, perPage: tbl.perPage, currentPage: tbl.currentPage });
                tbl.perPage = 0;
                tbl.currentPage = 1;
                tbl.render();
            }
        },
        restore: function() {
            for (var i = snapshots.length - 1; i >= 0; i--) {
                var snap = snapshots[i];
                if (!snap.table || !snap.table.table || !document.documentElement.contains(snap.table.table)) continue;
                snap.table.perPage = snap.perPage;
                snap.table.currentPage = snap.currentPage;
                snap.table.render();
            }
            snapshots = [];
            liveTables();
        }
    };
})();

function csmTableListen(tbl, el, eventName, fn) {
    if (!el) return;
    el.addEventListener(eventName, fn);
    tbl._listeners.push({ el: el, eventName: eventName, fn: fn });
}

CSM.Table = function(opts) {
    this.table = document.getElementById(opts.tableId);
    if (!this.table) return;

    this.tbody = this.table.querySelector('tbody');
    if (!this.tbody) return;

    this.perPage = typeof opts.perPage === 'number' ? opts.perPage : 25;
    this.currentPage = 1;
    this.searchText = '';
    this.filterValues = {};
    this.sortColumn = -1;
    this.sortAsc = true;
    this.hasDetailRows = opts.detailRows || false;
    this.filters = opts.filters || [];
    this.rowFilter = opts.rowFilter || null;
    this.stateKey = opts.stateKey || null;
    this.persistPerPage = opts.persistPerPage !== false;
    this.onRender = opts.onRender || null;
    this.opts = opts;
    this.emptyState = opts.emptyState || null;
    this._searchInput = null;
    this._searchDebounce = null;
    this._listeners = [];
    this._createdControls = false;

    if (opts.density === 'compact') {
        this.table.classList.add('table-sm');
    }
    if (opts.mobileRowCard) {
        this.table.classList.add('csm-table-rowcard');
    }
    if (opts.stickyHeader) {
        this.table.classList.add('csm-table-sticky');
    }
    this.countTargetEl = opts.countTargetId ? document.getElementById(opts.countTargetId) : null;
    this.onRowClick = typeof opts.onRowClick === 'function' ? opts.onRowClick : null;

    // Collect all data rows (skip detail rows)
    this.allRows = [];
    var rows = this.tbody.querySelectorAll('tr');
    for (var i = 0; i < rows.length; i++) {
        if (!rows[i].classList.contains('details-row')) {
            var detailRow = null;
            if (this.hasDetailRows && rows[i+1] && rows[i+1].classList.contains('details-row')) {
                detailRow = rows[i+1];
            }
            var rowText = rows[i].textContent;
            if (opts.searchAttr) {
                rowText = rows[i].getAttribute(opts.searchAttr) || '';
            }
            this.allRows.push({ row: rows[i], detail: detailRow, text: String(rowText || '').toLowerCase() });
        }
    }
    if (opts.mobileRowCard) {
        this._applyMobileRowLabels();
    }

    this.filteredRows = this.allRows.slice();
    CSM._tableInstances.push(this);

    // Build controls
    this._buildControls(opts);

    // Bind search
    if (opts.search !== false) {
        var searchEl = opts.searchId ? document.getElementById(opts.searchId) : null;
        if (searchEl) {
            this._searchInput = searchEl;
            var self = this;
            this._searchDebounce = CSM.debounce(function(val) {
                self.searchText = val;
                self.currentPage = 1;
                self.applyFilters();
                self._saveState();
            }, 300);
            csmTableListen(this, searchEl, 'input', function() {
                self._searchDebounce(this.value.toLowerCase());
            });
        }
    }

    // Bind explicit clear-filters button (optional)
    if (opts.clearFiltersId) {
        var clearEl = document.getElementById(opts.clearFiltersId);
        if (clearEl) {
            var clearSelf = this;
            csmTableListen(this, clearEl, 'click', function() { clearSelf.clearFilters(); });
        }
    }

    // Optional external page-size select (rendered into the page toolbar)
    if (opts.perPageSelectId) {
        var perPageEl = document.getElementById(opts.perPageSelectId);
        if (perPageEl) {
            var perPageSelf = this;
            this._syncPerPageSelect(opts);
            csmTableListen(this, perPageEl, 'change', function() {
                var n = parseInt(this.value, 10);
                perPageSelf.perPage = (isFinite(n) && n > 0) ? n : 0;
                perPageSelf.currentPage = 1;
                perPageSelf.render();
                perPageSelf._saveState();
            });
        }
    }

    // Optional row-click handler -> caller opens detail panel
    if (this.onRowClick) {
        var rowClickSelf = this;
        csmTableListen(this, this.tbody, 'click', function(ev) {
            // Ignore clicks that originated on interactive children (buttons,
            // checkboxes, links, form controls) so the row hook does not
            // hijack their default action.
            var t = ev.target;
            while (t && t !== rowClickSelf.tbody) {
                var tag = t.tagName;
                if (tag === 'BUTTON' || tag === 'A' || tag === 'INPUT' || tag === 'SELECT' || tag === 'LABEL' || tag === 'TEXTAREA') return;
                t = t.parentNode;
            }
            var row = ev.target.closest('tr');
            if (!row || !rowClickSelf.tbody.contains(row)) return;
            if (row.classList.contains('csm-empty-row') || row.classList.contains('details-row')) return;
            var item = null;
            for (var i = 0; i < rowClickSelf.filteredRows.length; i++) {
                if (rowClickSelf.filteredRows[i].row === row) { item = rowClickSelf.filteredRows[i]; break; }
            }
            rowClickSelf.onRowClick.call(rowClickSelf, row, item);
        });
    }

    // Bind filters
    for (var f = 0; f < this.filters.length; f++) {
        (function(filter, tbl) {
            var el = document.getElementById(filter.id);
            if (el) {
                csmTableListen(tbl, el, 'change', function() {
                    tbl.filterValues[filter.id] = this.value;
                    tbl.currentPage = 1;
                    tbl.applyFilters();
                    tbl._saveState();
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
                csmTableListen(tbl, header, 'click', function() {
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
    this._syncPerPageSelect(opts);

    // Initial render
    this.applyFilters();
};

CSM.Table.prototype._buildControls = function(opts) {
    if (opts.controls === false) {
        this.controlsEl = null;
        return;
    }
    var controlsId = opts.controlsId || opts.tableId + '-controls';
    var controls = document.getElementById(controlsId);
    if (!controls) {
        controls = document.createElement('div');
        controls.id = controlsId;
        controls.className = 'card-footer d-flex justify-content-between align-items-center';
        // Append to card level so controls don't end up inside table-responsive overflow
        var card = this.table.closest('.card');
        (card || this.table.parentNode).appendChild(controls);
        this._createdControls = true;
    }
    this.controlsEl = controls;
};

CSM.Table.prototype.destroy = function() {
    if (this._searchDebounce && this._searchDebounce.cancel) this._searchDebounce.cancel();
    for (var i = 0; i < (this._listeners || []).length; i++) {
        var l = this._listeners[i];
        l.el.removeEventListener(l.eventName, l.fn);
    }
    this._listeners = [];
    if (this.controlsEl) {
        if (this._createdControls && this.controlsEl.parentNode) {
            this.controlsEl.parentNode.removeChild(this.controlsEl);
        } else {
            this.controlsEl.innerHTML = '';
        }
    }
    for (var j = CSM._tableInstances.length - 1; j >= 0; j--) {
        if (CSM._tableInstances[j] === this) CSM._tableInstances.splice(j, 1);
    }
    this.controlsEl = null;
    this.countTargetEl = null;
    this.allRows = [];
    this.filteredRows = [];
    this.tbody = null;
    this.table = null;
    this.rowFilter = null;
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
        // Caller-supplied predicate for filters CSM.Table's built-in
        // exact-match logic can't express (date ranges, regex etc.).
        if (typeof self.rowFilter === 'function' && !self.rowFilter(item.row)) {
            return false;
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

        // Check for data-timestamp attribute (on cell or child element)
        var tsElA = cellA.getAttribute('data-timestamp') ? cellA : cellA.querySelector('[data-timestamp]');
        var tsElB = cellB.getAttribute('data-timestamp') ? cellB : cellB.querySelector('[data-timestamp]');
        if (tsElA && tsElB) {
            var tsA = tsElA.getAttribute('data-timestamp');
            var tsB = tsElB.getAttribute('data-timestamp');
            if (tsA && tsB) {
                return asc ? tsA.localeCompare(tsB) : tsB.localeCompare(tsA);
            }
        }

        var sortElA = cellA.getAttribute('data-sort') !== null ? cellA : cellA.querySelector('[data-sort]');
        var sortElB = cellB.getAttribute('data-sort') !== null ? cellB : cellB.querySelector('[data-sort]');
        var valA = (sortElA ? sortElA.getAttribute('data-sort') : cellA.textContent).trim().toLowerCase();
        var valB = (sortElB ? sortElB.getAttribute('data-sort') : cellB.textContent).trim().toLowerCase();
        // Try numeric sort - only if the entire value is a number
        var numA = parseFloat(valA), numB = parseFloat(valB);
        if (!isNaN(numA) && !isNaN(numB) && String(numA) === valA && String(numB) === valB) {
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
    this._orderRows();

    // Show only current page rows
    for (var j = start; j < end; j++) {
        this.filteredRows[j].row.style.display = '';
    }

    // Empty-state placeholder when filteredRows is empty
    if (total === 0 && this.emptyState) {
        this._renderEmptyState();
    } else {
        this._removeEmptyState();
    }

    // Render pagination controls
    this._renderControls(total, totalPages);

    // Notify caller (e.g. findings page resets bulk selection)
    if (this.onRender) this.onRender();
};

CSM.Table.prototype._orderRows = function() {
    if (!this.tbody || !this.allRows) return;
    this._removeEmptyState();
    var fragment = document.createDocumentFragment();
    var seen = [];
    var appendItem = function(item) {
        if (!item || seen.indexOf(item) >= 0) return;
        seen.push(item);
        fragment.appendChild(item.row);
        if (item.detail) fragment.appendChild(item.detail);
    };
    for (var i = 0; i < this.filteredRows.length; i++) {
        appendItem(this.filteredRows[i]);
    }
    for (var j = 0; j < this.allRows.length; j++) {
        appendItem(this.allRows[j]);
    }
    this.tbody.appendChild(fragment);
};

CSM.Table.prototype._renderControls = function(total, totalPages) {
    var self = this;
    var showAll = !this.perPage;
    var start = total === 0 ? 0 : (showAll ? 1 : (this.currentPage - 1) * this.perPage + 1);
    var end = showAll ? total : Math.min(this.currentPage * this.perPage, total);
    var totalAll = this.allRows ? this.allRows.length : total;
    var suffix = (total < totalAll) ? ' (' + totalAll + ' total)' : '';
    var countText = 'Showing ' + start + '\u2013' + end + ' of ' + total + suffix;
    if (this.countTargetEl) {
        this.countTargetEl.textContent = countText;
    }
    if (!this.controlsEl) return;
    var html = '<span class="text-muted small">' + countText + '</span>';

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

CSM.Table.prototype._applyMobileRowLabels = function() {
    var headers = this.table.querySelectorAll('thead th');
    if (!headers.length) return;
    for (var i = 0; i < this.allRows.length; i++) {
        var cells = this.allRows[i].row.cells;
        for (var c = 0; c < cells.length; c++) {
            if (cells[c].hasAttribute('data-label')) continue;
            var header = headers[c];
            if (!header) continue;
            var label = header.getAttribute('data-label') || header.textContent.replace(/\s+/g, ' ').trim();
            if (label) cells[c].setAttribute('data-label', label);
        }
    }
};

// Clear search + all filter values, reset to page 1.
CSM.Table.prototype.clearFilters = function() {
    this.searchText = '';
    this.filterValues = {};
    if (this._searchDebounce && this._searchDebounce.cancel) this._searchDebounce.cancel();
    if (this._searchInput) this._searchInput.value = '';
    for (var f = 0; f < this.filters.length; f++) {
        var el = document.getElementById(this.filters[f].id);
        if (el) {
            var value = (el.options && el.options[0]) ? el.options[0].value : '';
            el.value = value;
            if (value && value !== 'all') this.filterValues[this.filters[f].id] = value;
        }
    }
    this.currentPage = 1;
    this.applyFilters();
    this._saveState();
};

// Render empty-state placeholder inside the table when filteredRows is empty.
// Uses one full-width row so existing colgroup / responsive wrapper stays intact.
CSM.Table.prototype._renderEmptyState = function() {
    if (!this.emptyState) return;
    var headers = this.table.querySelectorAll('thead th');
    var colspan = headers.length || 1;
    var row = this.tbody.querySelector('tr.csm-empty-row');
    if (!row) {
        row = document.createElement('tr');
        row.className = 'csm-empty-row';
        var emptyCell = document.createElement('td');
        emptyCell.colSpan = colspan;
        row.appendChild(emptyCell);
        this.tbody.appendChild(row);
    }
    var cell = row.firstChild;
    cell.colSpan = colspan;
    // CSM.emptyStateBlock returns pre-escaped HTML (csm-ui.js).
    cell.innerHTML = CSM.emptyStateBlock(this.emptyState);

    var btn = cell.querySelector('[data-clear-filters]');
    if (btn) {
        var self = this;
        btn.addEventListener('click', function() { self.clearFilters(); });
    }
};

CSM.Table.prototype._removeEmptyState = function() {
    var row = this.tbody.querySelector('tr.csm-empty-row');
    if (row) row.remove();
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

// Persistent table state - save to localStorage
CSM.Table.prototype._saveState = function() {
    if (!this.stateKey) return;
    try {
        var filters = {};
        for (var f = 0; f < this.filters.length; f++) {
            var id = this.filters[f].id;
            var val = this.filterValues[id];
            if (val && val !== 'all') filters[id] = val;
        }
        var state = {
            page: this.currentPage,
            sortCol: this.sortColumn,
            sortAsc: this.sortAsc,
            search: this.searchText,
            filters: filters
        };
        if (this.persistPerPage) state.perPage = this.perPage;
        localStorage.setItem(this.stateKey, JSON.stringify(state));
    } catch (e) { /* localStorage may be unavailable */ }
};

// Persistent table state - restore from localStorage
CSM.Table.prototype._restoreState = function(opts) {
    if (!this.stateKey) return;
    try {
        var raw = localStorage.getItem(this.stateKey);
        if (!raw) return;
        var state = JSON.parse(raw);
        if (typeof state.page === 'number' && state.page > 0) {
            this.currentPage = state.page;
        }
        if (opts.persistPerPage !== false && typeof state.perPage === 'number' && state.perPage >= 0) {
            this.perPage = state.perPage;
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
        if (state.search && opts.search !== false && opts.searchId) {
            this.searchText = state.search;
            // Also set the search input value
            var searchEl = opts.searchId ? document.getElementById(opts.searchId) : null;
            if (searchEl) searchEl.value = state.search;
        }
        if (state.filters && typeof state.filters === 'object') {
            for (var f = 0; f < this.filters.length; f++) {
                var id = this.filters[f].id;
                if (!Object.prototype.hasOwnProperty.call(state.filters, id)) continue;
                var val = String(state.filters[id] || '');
                var el = document.getElementById(id);
                if (el) {
                    el.value = val;
                    val = el.value;
                }
                if (val && val !== 'all') this.filterValues[id] = val;
            }
        }
    } catch (e) { /* ignore parse errors */ }
};

CSM.Table.prototype._syncPerPageSelect = function(opts) {
    if (!opts.perPageSelectId) return;
    var perPageEl = document.getElementById(opts.perPageSelectId);
    if (perPageEl) perPageEl.value = String(this.perPage || 0);
};
