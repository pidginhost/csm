// CSM ModSecurity Rule Configuration page

(function() {
'use strict';

var _rules = [];
var _noEscalate = [];      // rule IDs excluded from escalation, sorted
var _escalationLoaded = false;
var _escalationLoading = false;
var _escalationBusy = false;
var _originalEnabled = {}; // ruleID → original enabled state
var _pendingChanges = {};  // ruleID → new enabled state (only if changed)
var _rulesTable = null;    // CSM.Table instance
var _rulesLoading = false;

function setRulesLoading(loading) {
    _rulesLoading = loading;
    document.querySelectorAll('.enable-toggle, #btn-apply, #btn-discard').forEach(function(el) {
        el.disabled = loading;
    });
}

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

function resetPendingToggleState() {
    for (var id in _pendingChanges) {
        if (!Object.prototype.hasOwnProperty.call(_pendingChanges, id)) continue;
        var ruleID = parseInt(id, 10);
        var original = !!_originalEnabled[ruleID];
        var toggle = document.querySelector('.enable-toggle[data-id="' + ruleID + '"]');
        if (toggle) toggle.checked = original;
        var row = document.getElementById('rule-row-' + ruleID);
        if (row) {
            row.style.backgroundColor = '';
            row.setAttribute('data-status', original ? 'enabled' : 'disabled');
        }
    }
    refreshRulesTable();
}

function loadRules(options) {
    setRulesLoading(true);
    CSM.get('/api/v1/modsec/rules', options)
        .then(function(data) {
            document.getElementById('modsec-rules-loading').classList.add('d-none');

            if (!data.configured) {
                _rules = [];
                if (_rulesTable) { _rulesTable.destroy(); _rulesTable = null; }
                document.getElementById('modsec-rules-content').classList.add('d-none');
                document.getElementById('modsec-rules-unconfigured').classList.remove('d-none');
                document.getElementById('missing-fields').textContent = (data.missing || []).join(', ');
                renderEscalation();
                return;
            }

            document.getElementById('modsec-rules-unconfigured').classList.add('d-none');
            _rules = data.items;
            if (_escalationLoaded) {
                _rules.forEach(function(rule) { rule.escalate = _noEscalate.indexOf(rule.id) < 0; });
            }
            document.getElementById('modsec-rules-content').classList.remove('d-none');
            renderStats(data);
            renderTable();
            renderEscalation();
        })
        .catch(function(err) {
            document.getElementById('modsec-rules-loading').innerHTML =
                CSM.emptyStateBlock({
                    icon: 'alert-triangle',
                    title: 'Failed to load rules',
                    reason: err.message || 'unknown'
                });
        }).then(function() { setRulesLoading(false); });
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
    _originalEnabled = {};
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
        html += '<td><label class="form-check form-switch mb-0"><input type="checkbox" class="form-check-input enable-toggle" data-id="' + r.id + '" aria-label="Enable rule ' + r.id + '"' + (r.enabled ? ' checked' : '') + '></label></td>';
        html += '<td><code>' + r.id + '</code></td>';
        html += '<td>' + CSM.esc(r.description) + '</td>';
        html += '<td>' + actionBadge + '</td>';
        html += '<td>' + r.phase + '</td>';
        html += '<td>' + (r.hits_24h || 0) + '</td>';
        html += '<td><label class="form-check form-switch mb-0"><input type="checkbox" class="form-check-input escalate-toggle" data-id="' + r.id + '" aria-label="Escalate rule ' + r.id + ' to a firewall block"' + (r.escalate ? ' checked' : '') + '></label></td>';
        html += '<td class="text-muted small" data-timestamp="' + lastHitTS + '" data-time-ago="' + lastHitTS + '">' + lastHit + '</td>';
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
            if (this.disabled) return;
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
            if (this.disabled) return;
            var id = parseInt(this.getAttribute('data-id'), 10);
            var escalate = this.checked;
            var self = this;

            var action = escalate ? 'Enable' : 'Disable';
            _escalationBusy = true;
            updateEscalationControls();
            CSM.confirm(action + ' escalation for rule ' + id + '?').then(function() {
                setEscalation(id, escalate).catch(function(e) {
                    escalationFailed(id, e);
                    self.checked = !escalate; // revert toggle
                });
            }).catch(function() {
                self.checked = !escalate; // revert toggle on cancel
                _escalationBusy = false;
                updateEscalationControls();
            });
        });
    });
    updateEscalationControls();
}

function updateEscalationControls() {
    var disabled = !_escalationLoaded || _escalationLoading || _escalationBusy;
    document.getElementById('escalation-add-btn').disabled = disabled;
    document.querySelectorAll('.escalate-toggle, [data-escalation-remove]').forEach(function(el) {
        el.disabled = disabled;
    });
}

// setEscalation turns firewall escalation on or off for one rule and brings
// the rule table and the exclusion list up to date.
function setEscalation(id, escalate) {
    _escalationBusy = true;
    updateEscalationControls();
    function finish() {
        _escalationBusy = false;
        updateEscalationControls();
    }
    return CSM.post('/api/v1/modsec/rules/escalation', {rule_id: id, escalate: escalate})
        .then(function(data) {
            // CSM.post rejects non-OK responses, so a server-side failure
            // lands in the caller's catch; treat a 200 ok:false body the same.
            if (!data || !data.ok) throw new Error((data && data.error) || 'unknown');
            applyEscalation(id, escalate);
            CSM.toast('Escalation updated for rule ' + id, 'success');
        }).then(finish, function(err) { finish(); throw err; });
}

function escalationFailed(id, e) {
    CSM.toast('Failed to update escalation for rule ' + id + ': ' + (e && e.message ? e.message : 'unknown'), 'error');
}

function applyEscalation(id, escalate) {
    _noEscalate = _noEscalate.filter(function(r) { return r !== id; });
    if (!escalate) {
        _noEscalate.push(id);
        _noEscalate.sort(function(a, b) { return a - b; });
    }
    for (var i = 0; i < _rules.length; i++) {
        if (_rules[i].id === id) _rules[i].escalate = escalate;
    }
    var toggle = document.querySelector('.escalate-toggle[data-id="' + id + '"]');
    if (toggle) toggle.checked = escalate;
    if (setRowAttr(id, 'data-escalate', escalate ? 'yes' : 'no')) {
        refreshRulesTable();
        renderStats({total: _rules.length, active: countActive()});
    }
    renderEscalation();
}

function loadEscalation(options) {
    _escalationLoading = true;
    _escalationLoaded = false;
    updateEscalationControls();
    CSM.get('/api/v1/modsec/rules/escalation', options)
        .then(function(data) {
            _noEscalate = data.items.slice().sort(function(a, b) { return a - b; });
            _escalationLoaded = true;
            _rules.forEach(function(rule) {
                rule.escalate = _noEscalate.indexOf(rule.id) < 0;
                var toggle = document.querySelector('.escalate-toggle[data-id="' + rule.id + '"]');
                if (toggle) toggle.checked = rule.escalate;
                setRowAttr(rule.id, 'data-escalate', rule.escalate ? 'yes' : 'no');
            });
            refreshRulesTable();
            renderStats({total: _rules.length, active: countActive()});
            renderEscalation();
        })
        .catch(function(err) {
            CSM.loadError(document.getElementById('escalation-list'), loadEscalation, { title: 'Failed to load the escalation list', error: err });
        }).then(function() {
            _escalationLoading = false;
            updateEscalationControls();
        });
}

function renderEscalation() {
    if (!_escalationLoaded) return;
    var container = document.getElementById('escalation-list');
    if (!container) return;
    if (_noEscalate.length === 0) {
        container.innerHTML = '<div class="text-muted small">No rules excluded: every CSM rule escalates to a firewall block.</div>';
        return;
    }
    var described = {};
    for (var i = 0; i < _rules.length; i++) described[_rules[i].id] = _rules[i].description || '';
    var html = '<table class="table table-sm table-vcenter mb-0"><thead><tr><th>Rule ID</th><th>Description</th><th class="w-1"><span class="visually-hidden">Actions</span></th></tr></thead><tbody>';
    for (var j = 0; j < _noEscalate.length; j++) {
        var id = _noEscalate[j];
        html += '<tr data-escalation-id="' + id + '"><td><code>' + id + '</code></td>' +
            '<td class="small">' + (Object.prototype.hasOwnProperty.call(described, id) ? CSM.esc(described[id]) : '<span class="text-muted">-</span>') + '</td>' +
            '<td><button type="button" class="btn btn-ghost-danger btn-sm" data-escalation-remove="' + id + '" aria-label="Stop excluding rule ' + id + '" title="Stop excluding rule ' + id + '"><i class="ti ti-trash"></i></button></td></tr>';
    }
    html += '</tbody></table>';
    container.innerHTML = html;
    container.querySelectorAll('[data-escalation-remove]').forEach(function(btn) {
        btn.addEventListener('click', function() {
            if (btn.disabled) return;
            var ruleID = parseInt(btn.getAttribute('data-escalation-remove'), 10);
            _escalationBusy = true;
            updateEscalationControls();
            CSM.confirm('Stop excluding rule ' + ruleID + '?\n\nMatching requests will again escalate to a firewall block.').then(function() {
                return setEscalation(ruleID, true).catch(function(e) { escalationFailed(ruleID, e); });
            }).catch(function() { /* cancelled */ }).then(function() {
                _escalationBusy = false;
                updateEscalationControls();
            });
        });
    });
    updateEscalationControls();
}

document.getElementById('escalation-form').addEventListener('submit', function(e) {
    e.preventDefault();
    var input = document.getElementById('escalation-rule-id');
    var button = document.getElementById('escalation-add-btn');
    var id = parseInt(input.value, 10);
    if (isNaN(id) || id < 900000 || id > 900999) {
        CSM.toast('Rule ID must be between 900000 and 900999', 'warning');
        return;
    }
    if (_noEscalate.indexOf(id) >= 0) {
        CSM.toast('Rule ' + id + ' is already excluded', 'warning');
        return;
    }
    if (button.disabled) return;
    button.disabled = true;
    setEscalation(id, false).then(function() {
        if (input.value === String(id)) input.value = '';
    }).catch(function(err) {
        escalationFailed(id, err);
    }).then(function() {
        button.disabled = false;
    });
});

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
    if (_rulesLoading || this.disabled) return;
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
            resetPendingToggleState();
            _pendingChanges = {};
            updateApplyBar();
            loadRules();
        });
    }).catch(function() { /* cancelled */ });
});

// Discard
document.getElementById('btn-discard').addEventListener('click', function() {
    resetPendingToggleState();
    _pendingChanges = {};
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

loadEscalation();
loadRules();

// Refresh reloads the rules, which drops staged toggles; ask first.
if (CSM.refresh) CSM.refresh.onRefresh(function() {
    if (_escalationBusy || _escalationLoading || document.getElementById('btn-apply').disabled) return;
    var staged = Object.keys(_pendingChanges).length;
    var ask = staged === 0 ? Promise.resolve() :
        CSM.confirm('Discard ' + staged + ' staged rule change' + (staged !== 1 ? 's' : '') + ' and reload?', { danger: true, okLabel: 'Discard' });
    ask.then(function() {
        resetPendingToggleState();
        _pendingChanges = {};
        updateApplyBar();
        loadEscalation({ refresh: true });
        loadRules({ refresh: true });
    }, function() { /* kept */ });
});

})();
