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
