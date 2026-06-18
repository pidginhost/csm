// CSM ModSecurity Rule Configuration page

(function() {
'use strict';

var _rules = [];
var _originalEnabled = {}; // ruleID → original enabled state
var _pendingChanges = {};  // ruleID → new enabled state (only if changed)
var _rulesTable = null;    // CSM.Table instance

function setRowAttr(id, attr, value) {
    var row = document.getElementById('rule-row-' + id);
    if (row) row.setAttribute(attr, value);
    return row;
}

function refreshRulesTable() {
    if (_rulesTable && typeof _rulesTable.applyFilters === 'function') {
        _rulesTable.applyFilters();
    }
}

function loadRules() {
    CSM.get('/api/v1/modsec/rules')
        .then(function(data) {
            document.getElementById('modsec-rules-loading').classList.add('d-none');

            if (!data.configured) {
                document.getElementById('modsec-rules-unconfigured').classList.remove('d-none');
                document.getElementById('missing-fields').textContent = (data.missing || []).join(', ');
                return;
            }

            _rules = data.rules || [];
            document.getElementById('modsec-rules-content').classList.remove('d-none');
            renderStats(data);
            renderTable();
        })
        .catch(function(err) {
            document.getElementById('modsec-rules-loading').innerHTML =
                CSM.emptyStateBlock({
                    icon: 'alert-triangle',
                    title: 'Failed to load rules',
                    reason: err.message || 'unknown'
                });
        });
}

function renderStats(data) {
    document.getElementById('stat-total').textContent = data.total || 0;
    document.getElementById('stat-active').textContent = data.active || 0;
    var noEscalate = 0;
    for (var i = 0; i < _rules.length; i++) {
        if (!_rules[i].escalate) noEscalate++;
    }
    document.getElementById('stat-no-escalate').textContent = noEscalate;
}

function renderTable() {
    var tbody = document.getElementById('modsec-rules-tbody');
    var html = '';
    _pendingChanges = {};

    for (var i = 0; i < _rules.length; i++) {
        var r = _rules[i];
        _originalEnabled[r.id] = r.enabled;

        var actionBadge = r.action === 'deny'
            ? '<span class="badge bg-danger">' + r.action + '/' + r.status_code + '</span>'
            : '<span class="badge bg-warning">' + r.action + '</span>';

        var lastHit = r.last_hit ? CSM.timeAgo(r.last_hit) : '\u2014';
        var lastHitTS = r.last_hit ? CSM.attr(r.last_hit) : '';
        var statusAttr = r.enabled ? 'enabled' : 'disabled';
        var escalateAttr = r.escalate ? 'yes' : 'no';

        html += '<tr id="rule-row-' + r.id + '" data-id="' + r.id +
            '" data-status="' + statusAttr +
            '" data-action="' + CSM.attr(r.action || '') +
            '" data-escalate="' + escalateAttr + '">';
        html += '<td><label class="form-check form-switch mb-0"><input type="checkbox" class="form-check-input enable-toggle" data-id="' + r.id + '"' + (r.enabled ? ' checked' : '') + '></label></td>';
        html += '<td><code>' + r.id + '</code></td>';
        html += '<td>' + CSM.esc(r.description) + '</td>';
        html += '<td>' + actionBadge + '</td>';
        html += '<td>' + r.phase + '</td>';
        html += '<td>' + (r.hits_24h || 0) + '</td>';
        html += '<td><label class="form-check form-switch mb-0"><input type="checkbox" class="form-check-input escalate-toggle" data-id="' + r.id + '"' + (r.escalate ? ' checked' : '') + '></label></td>';
        html += '<td class="text-muted small" data-timestamp="' + lastHitTS + '">' + lastHit + '</td>';
        html += '</tr>';
    }

    tbody.innerHTML = html;

    _rulesTable = new CSM.Table({
        tableId: 'modsec-rules-table',
        perPage: 50,
        searchId: 'rules-search',
        sortable: true,
        countTargetId: 'rules-count',
        stateKey: 'csm-modsec-rules-table',
        filters: [
            { id: 'rules-status-filter', attr: 'data-status' },
            { id: 'rules-action-filter', attr: 'data-action' },
            { id: 'rules-escalate-filter', attr: 'data-escalate' }
        ],
        emptyState: {
            icon: 'list-search',
            title: 'No rules match',
            reason: 'Try clearing the search or filter selections.'
        }
    });

    // Bind enable/disable toggles (staged)
    document.querySelectorAll('.enable-toggle').forEach(function(toggle) {
        toggle.addEventListener('change', function() {
            var id = parseInt(this.getAttribute('data-id'), 10);
            var newEnabled = this.checked;
            var row = setRowAttr(id, 'data-status', newEnabled ? 'enabled' : 'disabled');

            if (newEnabled === _originalEnabled[id]) {
                delete _pendingChanges[id];
                if (row) row.style.backgroundColor = '';
            } else {
                _pendingChanges[id] = newEnabled;
                if (row) row.style.backgroundColor = 'rgba(255, 193, 7, 0.1)';
            }
            refreshRulesTable();
            updateApplyBar();
        });
    });

    // Bind escalation toggles (immediate save with confirmation)
    document.querySelectorAll('.escalate-toggle').forEach(function(toggle) {
        toggle.addEventListener('change', function() {
            var id = parseInt(this.getAttribute('data-id'), 10);
            var escalate = this.checked;
            var self = this;

            var action = escalate ? 'Enable' : 'Disable';
            CSM.confirm(action + ' escalation for rule ' + id + '?').then(function() {
                CSM.post('/api/v1/modsec/rules/escalation', {rule_id: id, escalate: escalate})
                    .then(function(data) {
                        // CSM.post rejects non-OK responses, so a server-side
                        // failure lands in .catch; normalise a 200 ok:false
                        // body the same way so one path handles every failure.
                        if (!data.ok) throw new Error(data.error || 'unknown');
                        CSM.toast('Escalation updated for rule ' + id, 'success');
                        // Update local state
                        for (var i = 0; i < _rules.length; i++) {
                            if (_rules[i].id === id) _rules[i].escalate = escalate;
                        }
                        setRowAttr(id, 'data-escalate', escalate ? 'yes' : 'no');
                        refreshRulesTable();
                        renderStats({total: _rules.length, active: countActive()});
                    })
                    .catch(function(e) {
                        CSM.toast('Failed to update escalation for rule ' + id + ': ' + (e && e.message ? e.message : 'unknown'), 'error');
                        self.checked = !escalate; // revert toggle
                    });
            }).catch(function() {
                self.checked = !escalate; // revert toggle on cancel
            });
        });
    });
}

function countActive() {
    var active = 0;
    for (var i = 0; i < _rules.length; i++) {
        var id = _rules[i].id;
        var enabled = currentRuleEnabled(_rules[i]);
        if (enabled) active++;
    }
    return active;
}

function currentRuleEnabled(rule) {
    if (!rule) return false;
    var id = String(rule.id);
    if (Object.prototype.hasOwnProperty.call(_pendingChanges, id)) {
        return _pendingChanges[id];
    }
    if (Object.prototype.hasOwnProperty.call(_originalEnabled, id)) {
        return _originalEnabled[id];
    }
    return !!rule.enabled;
}

function formatRuleAction(rule) {
    if (!rule) return '';
    if (rule.action === 'deny' && rule.status_code) {
        return rule.action + '/' + rule.status_code;
    }
    return rule.action || '';
}

function updateApplyBar() {
    var count = Object.keys(_pendingChanges).length;
    var bar = document.getElementById('apply-bar');
    if (count > 0) {
        bar.classList.remove('d-none');
        bar.style.display = 'flex';
        document.getElementById('pending-count').textContent = count;
    } else {
        bar.classList.add('d-none');
        bar.style.display = 'none';
    }
}

// Apply Changes
document.getElementById('btn-apply').addEventListener('click', function() {
    var btn = this;
    var changeCount = Object.keys(_pendingChanges).length;

    CSM.confirm('Apply ' + changeCount + ' rule change' + (changeCount !== 1 ? 's' : '') + '? ModSecurity will be reloaded.').then(function() {
    btn.disabled = true;
    btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span> Applying...';

    // Build disabled list: start with currently disabled, apply pending changes
    var disabled = [];
    for (var i = 0; i < _rules.length; i++) {
        var id = _rules[i].id;
        var enabled = (id in _pendingChanges) ? _pendingChanges[id] : _originalEnabled[id];
        if (!enabled) disabled.push(id);
    }

    CSM.post('/api/v1/modsec/rules/apply', {disabled: disabled})
        .then(function(data) {
            // CSM.post rejects non-OK responses, and the reload-failure
            // rollback returns 200 with ok:false; throw on either so the
            // single .catch below owns all failure handling.
            if (!data.ok) throw new Error(data.error || 'unknown');
            btn.disabled = false;
            btn.innerHTML = '<i class="ti ti-check"></i>&nbsp;Apply Changes';
            CSM.toast('Rules applied successfully', 'success');
            // Update original state
            for (var id in _pendingChanges) {
                _originalEnabled[parseInt(id, 10)] = _pendingChanges[id];
            }
            _pendingChanges = {};
            // Clear highlights
            document.querySelectorAll('[id^="rule-row-"]').forEach(function(row) {
                row.style.backgroundColor = '';
            });
            updateApplyBar();
            // Reload to refresh stats
            loadRules();
        })
        .catch(function(e) {
            btn.disabled = false;
            btn.innerHTML = '<i class="ti ti-check"></i>&nbsp;Apply Changes';
            CSM.toast('Apply failed: ' + (e && e.message ? e.message : 'unknown'), 'error');
            // A failed apply (rolled back, write failed, or rejected) left
            // the live ruleset at its previous state, so drop the optimistic
            // pending changes and reload to resync the table with the server.
            _pendingChanges = {};
            updateApplyBar();
            loadRules();
        });
    }).catch(function() { /* cancelled */ });
});

// Discard
document.getElementById('btn-discard').addEventListener('click', function() {
    for (var id in _pendingChanges) {
        var toggle = document.querySelector('.enable-toggle[data-id="' + id + '"]');
        var original = _originalEnabled[parseInt(id, 10)];
        if (toggle) toggle.checked = original;
        var row = document.getElementById('rule-row-' + id);
        if (row) {
            row.style.backgroundColor = '';
            row.setAttribute('data-status', original ? 'enabled' : 'disabled');
        }
    }
    _pendingChanges = {};
    refreshRulesTable();
    updateApplyBar();
});

// WEB_ROADMAP P2.4: shared export of the loaded rules.
var _modsecRulesExportCols = [
    {key: 'id',           label: 'Rule ID'},
    {key: 'description',  label: 'Description'},
    {key: 'enabled',      label: 'Enabled'},
    {key: 'action',       label: 'Action'},
    {key: 'phase',        label: 'Phase'},
    {key: 'hits_24h',     label: 'Hits (24h)'},
    {key: 'escalate',     label: 'Escalates'},
    {key: 'last_hit',     label: 'Last Hit'}
];
document.querySelectorAll('[data-export]').forEach(function(el) {
    el.addEventListener('click', function(e) {
        e.preventDefault();
        var rows = (_rules || []).map(function(r) {
            return {
                id:          r.id || '',
                description: r.description || '',
                enabled:     currentRuleEnabled(r) ? 'yes' : 'no',
                action:      formatRuleAction(r),
                phase:       r.phase || '',
                hits_24h:    r.hits_24h || 0,
                escalate:    r.escalate ? 'yes' : 'no',
                last_hit:    r.last_hit || ''
            };
        });
        CSM.exportTable(rows, _modsecRulesExportCols, this.getAttribute('data-export'), 'csm-modsec-rules');
    });
});

loadRules();

})();
