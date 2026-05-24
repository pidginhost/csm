// CSM.ui - Shared rendering primitives (no modal/confirm logic - that stays in toast.js)
var CSM = CSM || {};

// Severity badge HTML
var _sevTitles = {
    2: 'Critical: immediate action required',
    1: 'High: should be addressed promptly',
    0: 'Warning: low-risk issue to review'
};
CSM.severityBadge = function(severity) {
    var cls = 'warning', label = 'WARNING';
    if (severity === 2) { cls = 'critical'; label = 'CRITICAL'; }
    else if (severity === 1) { cls = 'high'; label = 'HIGH'; }
    var title = _sevTitles[severity] || _sevTitles[0];
    return '<span class="badge badge-' + cls + '" title="' + title + '">' + label + '</span>';
};

// Severity class name from numeric severity
CSM.severityClass = function(severity) {
    if (severity === 2) return 'critical';
    if (severity === 1) return 'high';
    return 'warning';
};

// Centralized severity map: numeric level → { label, cls }
CSM.sevMap = {
    2: { label: 'CRITICAL', cls: 'critical' },
    1: { label: 'HIGH', cls: 'high' },
    0: { label: 'WARNING', cls: 'warning' }
};

// Empty state placeholder HTML
CSM.emptyState = function(message, colspan) {
    if (colspan) {
        return '<tr><td colspan="' + colspan + '" class="text-center text-muted py-4">' + CSM.esc(message) + '</td></tr>';
    }
    return '<div class="text-muted text-center py-3">' + CSM.esc(message) + '</div>';
};

// Country flag emoji from 2-letter ISO code (e.g. "US" → 🇺🇸).
// Returns '' for anything other than two ASCII letters so a malformed
// payload from the API cannot throw RangeError out of String.fromCodePoint
// or smuggle surrogate code points into the regional-indicator range.
CSM.countryFlag = function(code) {
    if (typeof code !== 'string' || code.length !== 2) return '';
    var a = code.charCodeAt(0), b = code.charCodeAt(1);
    if (a >= 97 && a <= 122) a -= 32;
    else if (a < 65 || a > 90) return '';
    if (b >= 97 && b <= 122) b -= 32;
    else if (b < 65 || b > 90) return '';
    return String.fromCodePoint(127397 + a, 127397 + b);
};

// Make a non-table element keyboard-accessible (tabindex + Enter/Space activation)
CSM.makeClickable = function(el) {
    el.setAttribute('tabindex', '0');
    el.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            el.click();
        }
    });
};

// fmtDateTime removed - use CSM.fmtDate(ts) instead (defined in csrf.js)

// Standard empty state block (non-table). Tables still use CSM.emptyState.
//
//   CSM.emptyStateBlock({
//       icon: 'circle-check',          // ti-icon name without prefix
//       title: 'No active findings',
//       reason: 'Last scan completed 4 min ago.',
//       actionHTML: '<button id="run-scan" class="btn btn-primary">Run scan</button>',
//   })
CSM.emptyStateBlock = function(opts) {
    opts = opts || {};
    var html = '<div class="csm-empty">';
    if (opts.icon) {
        html += '<div class="csm-empty__icon"><i class="ti ti-' + CSM.esc(opts.icon) + '"></i></div>';
    }
    if (opts.title)  html += '<div class="csm-empty__title">' + CSM.esc(opts.title) + '</div>';
    if (opts.reason) html += '<div class="csm-empty__reason">' + CSM.esc(opts.reason) + '</div>';
    if (opts.actionHTML) html += '<div>' + opts.actionHTML + '</div>';
    html += '</div>';
    return html;
};

// Build a single grouped action row for the csm-summary-list pattern.
// Returns an HTMLElement; caller appends and may bind a click handler.
//
//   CSM.summaryItem({
//       severity: 2,                      // 0=warn, 1=high, 2=crit (optional)
//       title: 'jane@example.com',
//       meta: '54 auth failures from 3 IPs',
//       count: 54,                         // optional badge value
//       age: '12m',                        // optional relative age
//       statusHTML: '<span class="badge bg-danger-lt">Compromised</span>',
//       actionHTML: '<button class="btn btn-sm btn-primary">Review</button>',
//       href: '/incident?id=42',           // optional; renders <a> instead of <div>
//       onClick: function(ev) { ... },     // optional click handler (also Enter/Space)
//   })
CSM.summaryItem = function(opts) {
    opts = opts || {};
    var tag = opts.href ? 'a' : 'div';
    var el = document.createElement(tag);
    el.className = 'csm-summary-list__item';
    if (opts.severity === 2) el.classList.add('csm-summary-list__item--crit');
    else if (opts.severity === 1) el.classList.add('csm-summary-list__item--high');
    else if (opts.severity === 0) el.classList.add('csm-summary-list__item--warn');
    if (opts.href) {
        el.setAttribute('href', opts.href);
    }
    el.setAttribute('role', 'button');
    el.tabIndex = 0;

    var sevHTML = '';
    if (typeof opts.severity === 'number') {
        sevHTML = '<span class="csm-summary-list__sev">' + CSM.severityBadge(opts.severity) + '</span>';
    }
    var titleHTML = '<div class="csm-summary-list__title">' + (opts.titleHTML || CSM.esc(opts.title || '')) + '</div>';
    var metaHTML = opts.meta ? '<div class="csm-summary-list__meta">' + CSM.esc(opts.meta) + '</div>' : '';
    var mainHTML = '<div class="csm-summary-list__main">' + titleHTML + metaHTML + '</div>';
    var countHTML = (opts.count != null) ? '<span class="csm-summary-list__count" title="Hit count">' + CSM.esc(String(opts.count)) + '</span>' : '';
    var ageHTML = opts.age ? '<span class="csm-summary-list__age">' + CSM.esc(opts.age) + '</span>' : '';
    var statusHTML = opts.statusHTML ? '<span class="csm-summary-list__status">' + opts.statusHTML + '</span>' : '';
    var actionHTML = opts.actionHTML ? '<span class="csm-summary-list__action">' + opts.actionHTML + '</span>' : '';
    el.innerHTML = sevHTML + mainHTML + countHTML + ageHTML + statusHTML + actionHTML;

    if (typeof opts.onClick === 'function') {
        el.addEventListener('click', opts.onClick);
        el.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                opts.onClick.call(el, e);
            }
        });
    }
    return el;
};

// Middle-truncate a string. Keeps the head and tail and inserts a single
// ellipsis in the middle. Used for paths, URIs, message IDs.
//
//   CSM.truncateMiddle('/very/long/path/to/file.php', 24)
//   -> '/very/lo...o/file.php'
CSM.truncateMiddle = function(text, max) {
    text = text == null ? '' : String(text);
    max = max | 0;
    if (max <= 0 || text.length <= max) return text;
    var keep = max - 1;
    var head = Math.ceil(keep / 2);
    var tail = Math.floor(keep / 2);
    return text.slice(0, head) + '…' + text.slice(text.length - tail);
};

// Apply CSM.truncateMiddle to every element with [data-csm-truncate-middle].
// The attribute value is the max character budget. The original text is
// preserved on data-csm-full and surfaced via title so operators can hover
// for the full value.
CSM.applyTruncateMiddle = function(root) {
    var scope = root || document;
    var nodes = scope.querySelectorAll('[data-csm-truncate-middle]');
    for (var i = 0; i < nodes.length; i++) {
        var el = nodes[i];
        var max = parseInt(el.getAttribute('data-csm-truncate-middle'), 10);
        if (!isFinite(max) || max <= 0) continue;
        var full = el.getAttribute('data-csm-full');
        if (full == null) {
            full = el.textContent;
            el.setAttribute('data-csm-full', full);
        }
        var truncated = CSM.truncateMiddle(full, max);
        if (truncated !== full) {
            el.textContent = truncated;
            if (!el.hasAttribute('title')) el.setAttribute('title', full);
            el.classList.add('csm-truncate-middle');
        } else {
            el.textContent = full;
        }
    }
};

CSM.clampPercent = function(value) {
    var n = Number(value);
    if (!isFinite(n)) return 0;
    return Math.max(0, Math.min(100, Math.round(n)));
};

CSM.setProgressBar = function(bar, value) {
    if (!bar) return 0;
    var pct = CSM.clampPercent(value);
    if (!bar.hasAttribute('role')) bar.setAttribute('role', 'progressbar');
    if (!bar.hasAttribute('aria-valuemin')) bar.setAttribute('aria-valuemin', '0');
    if (!bar.hasAttribute('aria-valuemax')) bar.setAttribute('aria-valuemax', '100');
    bar.style.width = pct + '%';
    bar.setAttribute('aria-valuenow', String(pct));
    return pct;
};

CSM.applyProgressBars = function(root) {
    var scope = root || document;
    var bars = scope.querySelectorAll('[data-csm-progress]');
    for (var i = 0; i < bars.length; i++) {
        CSM.setProgressBar(bars[i], bars[i].getAttribute('data-csm-progress'));
    }
};

// Bulk-action wiring (WEB_ROADMAP P2.5). Centralizes select-all
// indeterminate state, per-button enable/disable, and count-aware
// labels so every page with a row-checkbox bulk bar uses the same
// behavior. Returns a small handle:
//
//   var bulk = CSM.bulk({
//       rowCheckboxSelector: '.q-cb',
//       selectAllEl: document.getElementById('q-select-all'),
//       selectAllSelector: '#q-select-all', // optional, for re-rendered tables
//       valueAttr: 'data-id', // attribute to read for selectedValues()
//       buttons: [
//           { el: btn1, labelTemplate: 'Restore {n} file(s)' },
//           { el: btn2, labelTemplate: 'Delete {n} file(s)' }
//       ],
//       onChange: function(count, values) { ... } // optional
//   });
//   bulk.selectedValues();  // returns ['id-a', 'id-b']
//   bulk.clear();           // unchecks every row + select-all + refreshes labels
//   bulk.refresh();         // re-reads checkboxes (call after re-render)
//
// labelTemplate placeholders: {n} = selected count. When n===0 the
// button gets the d-none class and disabled=true so a stale click
// during a re-render can't fire on the previous selection.
CSM.bulk = function(opts) {
    opts = opts || {};
    var rowSel = opts.rowCheckboxSelector;
    var selectAllEl = opts.selectAllEl || null;
    var selectAllSelector = opts.selectAllSelector || '';
    var selectAllID = selectAllEl && selectAllEl.id ? selectAllEl.id : '';
    var valueAttr = opts.valueAttr || 'data-id';
    var buttons = opts.buttons || [];
    var changeCb = (typeof opts.onChange === 'function') ? opts.onChange : function() {};

    function resolveSelectAll() {
        var el = null;
        if (selectAllSelector) {
            selectAllEl = document.querySelector(selectAllSelector);
            return selectAllEl;
        } else if (selectAllID) {
            el = document.getElementById(selectAllID);
        }
        if (el) {
            selectAllEl = el;
        }
        return selectAllEl;
    }

    function checked() {
        return all().filter(function(cb) { return cb.checked; });
    }
    function all() {
        return Array.prototype.slice.call(document.querySelectorAll(rowSel));
    }

    function paint() {
        var sel = checked();
        var total = all().length;
        var n = sel.length;
        var selectAll = resolveSelectAll();
        if (selectAll) {
            selectAll.checked = (n > 0 && n === total);
            selectAll.indeterminate = (n > 0 && n < total);
        }
        for (var i = 0; i < buttons.length; i++) {
            var b = buttons[i];
            if (!b || !b.el) continue;
            if (b.labelTemplate) {
                b.el.textContent = b.labelTemplate.replace(/\{n\}/g, n);
            }
            b.el.disabled = (n === 0);
            b.el.classList.toggle('d-none', n === 0);
        }
        var values = sel.map(function(cb) { return cb.getAttribute(valueAttr); });
        changeCb(n, values);
    }

    function bindRowListeners() {
        all().forEach(function(cb) {
            if (cb.dataset.csmBulkBound === '1') return;
            cb.dataset.csmBulkBound = '1';
            cb.addEventListener('change', paint);
        });
    }

    function bindSelectAllListener() {
        selectAllEl = resolveSelectAll();
        if (!selectAllEl) return;
        if (selectAllEl.dataset.csmBulkSelectAllBound === '1') return;
        selectAllEl.dataset.csmBulkSelectAllBound = '1';
        selectAllEl.addEventListener('change', function() {
            var v = this.checked;
            all().forEach(function(cb) { cb.checked = v; });
            paint();
        });
    }
    bindSelectAllListener();
    bindRowListeners();
    paint();

    return {
        selectedValues: function() {
            return checked().map(function(cb) { return cb.getAttribute(valueAttr); });
        },
        selectedCount: function() { return checked().length; },
        clear: function() {
            all().forEach(function(cb) { cb.checked = false; });
            var selectAll = resolveSelectAll();
            if (selectAll) { selectAll.checked = false; selectAll.indeterminate = false; }
            paint();
        },
        refresh: function() {
            bindSelectAllListener();
            bindRowListeners();
            paint();
        }
    };
};

// Detail panel helper. Thin wrapper around the Bootstrap offcanvas that
// ships with Tabler. Mounts a single shared offcanvas element on first use
// so callers do not need page-specific markup.
//
//   CSM.detailPanel.open({
//       title: 'Finding detail',
//       bodyHTML: pre_escaped_html,
//       footerHTML: pre_escaped_actions,
//   });
//   CSM.detailPanel.close();
CSM.detailPanel = (function() {
    var instance = null;
    var panelEl  = null;
    var dismissBound = false;
    var api = null;

    function isOpen() {
        return panelEl && panelEl.classList.contains('show');
    }

    function onKey(e) {
        if (!isOpen()) return;
        if (e.key === 'Escape' || e.key === 'Esc' || e.keyCode === 27) {
            e.preventDefault();
            api.close();
            return;
        }
        // WEB_ROADMAP P4.2: focus trap. Cycle Tab through focusable
        // descendants so keyboard users don't lose focus to the page
        // behind the panel while it's open.
        if (e.key === 'Tab' && panelEl) {
            var focusables = panelEl.querySelectorAll(
                'a[href], button:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
            );
            if (focusables.length === 0) {
                e.preventDefault();
                panelEl.focus();
                return;
            }
            var first = focusables[0];
            var last = focusables[focusables.length - 1];
            if (!panelEl.contains(document.activeElement)) {
                e.preventDefault();
                (e.shiftKey ? last : first).focus();
                return;
            }
            if (e.shiftKey && document.activeElement === first) {
                e.preventDefault();
                last.focus();
            } else if (!e.shiftKey && document.activeElement === last) {
                e.preventDefault();
                first.focus();
            }
        }
    }

    function onOutsideClick(e) {
        if (!isOpen()) return;
        if (panelEl.contains(e.target)) return;
        // Triggers that toggle the panel themselves rely on their own
        // click handler running first; closing here would reopen a beat
        // later and feel like a flash. Skip the click when the target is
        // a button/anchor inside a modal trigger group.
        if (e.target.closest && e.target.closest('[data-bs-toggle], .modal, .modal-dialog')) {
            return;
        }
        api.close();
    }

    function bindDismissShortcuts() {
        if (dismissBound) return;
        dismissBound = true;
        // Defer one tick so the click event that opened the panel finishes
        // propagating before the outside-click listener attaches; otherwise
        // the open-triggering click would itself match "outside" and
        // immediately close the panel.
        setTimeout(function() {
            if (!dismissBound) return;
            document.addEventListener('keydown', onKey);
            document.addEventListener('mousedown', onOutsideClick);
        }, 0);
    }

    function unbindDismissShortcuts() {
        if (!dismissBound) return;
        dismissBound = false;
        document.removeEventListener('keydown', onKey);
        document.removeEventListener('mousedown', onOutsideClick);
    }

    function ensureMount() {
        if (panelEl) return panelEl;
        panelEl = document.createElement('div');
        panelEl.className = 'offcanvas offcanvas-end csm-detail-panel';
        panelEl.tabIndex = -1;
        panelEl.setAttribute('role', 'dialog');
        panelEl.setAttribute('aria-modal', 'true');
        panelEl.setAttribute('aria-labelledby', 'csm-detail-panel-title');
        var header = document.createElement('div');
        header.className = 'csm-detail-panel__header';
        var title = document.createElement('h2');
        title.className = 'csm-detail-panel__title';
        title.id = 'csm-detail-panel-title';
        var close = document.createElement('button');
        close.type = 'button';
        close.className = 'btn-close';
        close.setAttribute('aria-label', 'Close');
        close.setAttribute('data-bs-dismiss', 'offcanvas');
        // Bootstrap's data-bs-dismiss delegated handler does not fire on every
        // build (Tabler bundles the JS without the offcanvas dismiss event
        // wiring on dynamically mounted nodes). Bind explicitly so the X
        // button always closes the panel.
        close.addEventListener('click', function() {
            api.close();
        });
        header.appendChild(title);
        header.appendChild(close);
        var body = document.createElement('div');
        body.className = 'csm-detail-panel__body offcanvas-body';
        var footer = document.createElement('div');
        footer.className = 'csm-detail-panel__footer';
        panelEl.appendChild(header);
        panelEl.appendChild(body);
        panelEl.appendChild(footer);
        document.body.appendChild(panelEl);
        // hidden.bs.offcanvas runs after the backdrop click handler so we
        // can lean on it to drop the global listeners even when the close
        // happens through Bootstrap's own backdrop or ESC path.
        panelEl.addEventListener('hidden.bs.offcanvas', unbindDismissShortcuts);
        return panelEl;
    }

    api = {
        open: function(opts) {
            var el = ensureMount();
            opts = opts || {};
            var titleEl = el.querySelector('.csm-detail-panel__title');
            var bodyEl  = el.querySelector('.csm-detail-panel__body');
            var footEl  = el.querySelector('.csm-detail-panel__footer');

            titleEl.textContent = opts.title || '';

            // Callers must pre-escape any HTML they pass; CSM.esc / CSM.attr.
            if (typeof opts.bodyHTML === 'string') {
                bodyEl.innerHTML = opts.bodyHTML;
            } else if (opts.bodyNode) {
                bodyEl.replaceChildren(opts.bodyNode);
            } else {
                bodyEl.replaceChildren();
            }

            if (typeof opts.footerHTML === 'string' && opts.footerHTML.length > 0) {
                footEl.innerHTML = opts.footerHTML;
                footEl.hidden = false;
            } else {
                footEl.replaceChildren();
                footEl.hidden = true;
            }

            if (window.bootstrap && window.bootstrap.Offcanvas) {
                instance = window.bootstrap.Offcanvas.getOrCreateInstance(el);
                instance.show();
            } else {
                el.classList.add('show');
            }
            bindDismissShortcuts();
        },
        close: function() {
            unbindDismissShortcuts();
            if (instance) {
                instance.hide();
            } else if (panelEl) {
                panelEl.classList.remove('show');
            }
        },
        element: function() { return panelEl; }
    };
    return api;
})();
