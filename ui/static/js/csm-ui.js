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

// Country flag emoji from 2-letter ISO code (e.g. "US" → 🇺🇸)
CSM.countryFlag = function(code) {
    if (!code || code.length !== 2) return '';
    return String.fromCodePoint.apply(null, [].map.call(code.toUpperCase(), function(c) { return 127397 + c.charCodeAt(0); }));
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
        return panelEl;
    }

    return {
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
        },
        close: function() {
            if (instance) {
                instance.hide();
            } else if (panelEl) {
                panelEl.classList.remove('show');
            }
        },
        element: function() { return panelEl; }
    };
})();
