// CSM ModSecurity Rule Configuration page

(function() {
'use strict';

var _rules = [];
var _originalEnabled = {}; // ruleID → original enabled state
var _pendingChanges = {};  // ruleID → new enabled state (only if changed)

function loadRules() {
    fetch(CSM.apiUrl('/api/v1/modsec/rules'), {credentials: 'same-origin'})
        .then(function(r) { return r.json(); })
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
                '<div class="text-danger"><i class="ti ti-alert-triangle"></i> Failed to load rules: ' + CSM.esc(err.message || 'unknown') + '</div>';
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
    var tbody = document.getElementById('rules-tbody');
    var html = '';
    _pendingChanges = {};

    for (var i = 0; i < _rules.length; i++) {
        var r = _rules[i];
        _originalEnabled[r.id] = r.enabled;

        var actionBadge = r.action === 'deny'
            ? '<span class="badge bg-danger">' + r.action + '/' + r.status_code + '</span>'
            : '<span class="badge bg-warning">' + r.action + '</span>';

        var lastHit = r.last_hit ? CSM.timeAgo(r.last_hit) : '\u2014';

        html += '<tr id="rule-row-' + r.id + '" data-id="' + r.id + '">';
        html += '<td><label class="form-check form-switch mb-0"><input type="checkbox" class="form-check-input enable-toggle" data-id="' + r.id + '"' + (r.enabled ? ' checked' : '') + '></label></td>';
        html += '<td><code>' + r.id + '</code></td>';
        html += '<td>' + CSM.esc(r.description) + '</td>';
        html += '<td>' + actionBadge + '</td>';
        html += '<td>' + r.phase + '</td>';
        html += '<td>' + (r.hits_24h || 0) + '</td>';
        html += '<td><label class="form-check form-switch mb-0"><input type="checkbox" class="form-check-input escalate-toggle" data-id="' + r.id + '"' + (r.escalate ? ' checked' : '') + '></label></td>';
        html += '<td class="text-muted small">' + lastHit + '</td>';
        html += '</tr>';
    }

    tbody.innerHTML = html;

    // Bind enable/disable toggles (staged)
    document.querySelectorAll('.enable-toggle').forEach(function(toggle) {
        toggle.addEventListener('change', function() {
            var id = parseInt(this.getAttribute('data-id'), 10);
            var newEnabled = this.checked;
            var row = document.getElementById('rule-row-' + id);

            if (newEnabled === _originalEnabled[id]) {
                delete _pendingChanges[id];
                row.style.backgroundColor = '';
            } else {
                _pendingChanges[id] = newEnabled;
                row.style.backgroundColor = 'rgba(255, 193, 7, 0.1)';
            }
            updateApplyBar();
        });
    });

    // Bind escalation toggles (immediate save)
    document.querySelectorAll('.escalate-toggle').forEach(function(toggle) {
        toggle.addEventListener('change', function() {
            var id = parseInt(this.getAttribute('data-id'), 10);
            var escalate = this.checked;
            var self = this;

            CSM.post('/api/v1/modsec/rules/escalation', {rule_id: id, escalate: escalate})
                .then(function(data) {
                    if (data.ok) {
                        CSM.toast('Escalation updated for rule ' + id, 'success');
                        // Update local state
                        for (var i = 0; i < _rules.length; i++) {
                            if (_rules[i].id === id) _rules[i].escalate = escalate;
                        }
                        renderStats({total: _rules.length, active: countActive()});
                    }
                })
                .catch(function(e) {
                    CSM.toast('Error: ' + e, 'error');
                    self.checked = !escalate; // revert toggle
                });
        });
    });
}

function countActive() {
    var active = 0;
    for (var i = 0; i < _rules.length; i++) {
        var id = _rules[i].id;
        var enabled = (id in _pendingChanges) ? _pendingChanges[id] : _originalEnabled[id];
        if (enabled) active++;
    }
    return active;
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
            btn.disabled = false;
            btn.innerHTML = '<i class="ti ti-check"></i>&nbsp;Apply Changes';

            if (data.ok) {
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
            } else {
                var msg = 'Apply failed: ' + (data.error || 'unknown');
                if (data.rolled_back) msg += ' (changes rolled back)';
                CSM.toast(msg, 'error');
                if (data.rolled_back) {
                    // Revert toggles
                    for (var id in _pendingChanges) {
                        var toggle = document.querySelector('.enable-toggle[data-id="' + id + '"]');
                        if (toggle) toggle.checked = _originalEnabled[parseInt(id, 10)];
                        var row = document.getElementById('rule-row-' + id);
                        if (row) row.style.backgroundColor = '';
                    }
                    _pendingChanges = {};
                    updateApplyBar();
                }
            }
        })
        .catch(function(e) {
            btn.disabled = false;
            btn.innerHTML = '<i class="ti ti-check"></i>&nbsp;Apply Changes';
            CSM.toast('Error: ' + e, 'error');
        });
});

// Discard
document.getElementById('btn-discard').addEventListener('click', function() {
    for (var id in _pendingChanges) {
        var toggle = document.querySelector('.enable-toggle[data-id="' + id + '"]');
        if (toggle) toggle.checked = _originalEnabled[parseInt(id, 10)];
        var row = document.getElementById('rule-row-' + id);
        if (row) row.style.backgroundColor = '';
    }
    _pendingChanges = {};
    updateApplyBar();
});

loadRules();

})();
