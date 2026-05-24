// CSM ModSecurity Workbench (phase 8.5)
// Status strip + WAF pressure groups + tabs (Blocked IPs / Events / Rules).
(function() {
    'use strict';

    var _modsecBlocks = [];
    var _modsecPoller = null;
    var eventsLoaded = false;

    window.addEventListener('beforeunload', function() {
        if (_modsecPoller) { _modsecPoller.stop(); _modsecPoller = null; }
    });

    // ---------- Status strip ----------

    function chip(opts) {
        var span = document.createElement('span');
        span.className = 'csm-status-strip__chip' + (opts.cls ? ' ' + opts.cls : '');
        if (opts.title) span.title = opts.title;
        var icon = document.createElement('i');
        icon.className = 'ti ' + (opts.icon || 'ti-circle');
        span.appendChild(icon);
        var val = document.createElement('span');
        val.className = 'csm-status-strip__chip-value';
        val.textContent = opts.value;
        span.appendChild(val);
        var lbl = document.createElement('span');
        lbl.className = 'csm-status-strip__chip-label';
        lbl.textContent = opts.label;
        span.appendChild(lbl);
        return span;
    }

    var _strip = { stats: null, latest: '' };

    function refreshStatusStrip() {
        var el = document.getElementById('modsec-status-strip');
        if (!el) return;
        el.replaceChildren();
        if (_strip.stats) {
            var s = _strip.stats;
            el.appendChild(chip({ icon: 'ti-shield-x', value: String(s.total || 0), label: 'blocks 24h',
                title: 'Total ModSecurity blocks in the last 24h' }));
            el.appendChild(chip({ icon: 'ti-network', value: String(s.unique_ips || 0), label: 'unique IPs' }));
            if ((s.escalated || 0) > 0) {
                el.appendChild(chip({ icon: 'ti-firewall', value: String(s.escalated), label: 'escalated',
                    cls: 'csm-status-strip__chip--crit', title: 'Blocks escalated to firewall' }));
            }
            if (s.top_rule && s.top_rule !== '--') {
                el.appendChild(chip({ icon: 'ti-list-numbers', value: s.top_rule, label: 'top rule' }));
            }
        }
        if (_strip.latest) {
            el.appendChild(chip({ icon: 'ti-clock', value: _strip.latest, label: 'latest event' }));
        }
    }

    // ---------- Stats ----------

    function loadStats() {
        CSM.get('/api/v1/modsec/stats', { silent: true })
            .then(function(d) {
                _strip.stats = d;
                refreshStatusStrip();
            })
            .catch(function() { /* non-fatal */ });
    }

    // ---------- Active WAF pressure (csm-summary-list) + side summaries ----------

    function buildEmpty(icon, title, reason) {
        var wrap = document.createElement('div');
        wrap.className = 'csm-empty';
        var i = document.createElement('div');
        i.className = 'csm-empty__icon';
        var ie = document.createElement('i');
        ie.className = 'ti ti-' + icon;
        i.appendChild(ie);
        wrap.appendChild(i);
        if (title) {
            var t = document.createElement('div');
            t.className = 'csm-empty__title';
            t.textContent = title;
            wrap.appendChild(t);
        }
        if (reason) {
            var r = document.createElement('div');
            r.className = 'csm-empty__reason';
            r.textContent = reason;
            wrap.appendChild(r);
        }
        return wrap;
    }

    function statusFor(block) {
        return block.escalated ? 'escalated' : 'waf';
    }

    function statusLabel(block) {
        return block.escalated ? 'Firewall blocked' : 'WAF deny only';
    }

    function statusBadgeHTML(block) {
        var cls = block.escalated ? 'bg-red-lt' : 'bg-yellow-lt';
        return '<span class="badge ' + cls + '">' + CSM.esc(statusLabel(block)) + '</span>';
    }

    function ruleSeverity(block) {
        // Severity is approximated: escalated rows are critical; non-escalated
        // with high hits are high; rest are warning.
        if (block.escalated) return 2;
        if (block.hits >= 25) return 1;
        return 0;
    }

    function ageLabel(iso, fallback) {
        if (iso && CSM.timeAgo) return CSM.timeAgo(iso);
        return fallback || '';
    }

    function domainList(block) {
        if (block.domain_list && block.domain_list.length) return block.domain_list;
        if (!block.domains) return [];
        return String(block.domains).split(',').map(function(d) {
            return d.trim();
        }).filter(function(d) {
            return d && d !== '...';
        });
    }

    function domainListText(block) {
        var domains = domainList(block);
        return domains.join(', ');
    }

    function renderActiveWAFPressure(blocks) {
        var el = document.getElementById('modsec-pressure');
        if (!el) return;
        // Take top 10 by hits for the first viewport.
        var top = blocks.slice().sort(function(a, b) { return b.hits - a.hits; }).slice(0, 10);
        el.replaceChildren();
        if (top.length === 0) {
            el.appendChild(buildEmpty('shield-check', 'No active WAF pressure', 'No ModSecurity blocks observed in the last 24 hours.'));
            var c = document.getElementById('modsec-pressure-count');
            if (c) c.textContent = '';
            return;
        }
        var c2 = document.getElementById('modsec-pressure-count');
        if (c2) c2.textContent = blocks.length + ' groups tracked';
        for (var i = 0; i < top.length; i++) {
            var b = top[i];
            var titleHTML = '<code>' + CSM.esc(b.ip) + '</code>';
            if (b.rule_id) titleHTML += ' <span class="text-muted">rule ' + CSM.esc(b.rule_id) + '</span>';
            var domains = domainListText(b);
            var meta = (b.description || '') + (domains ? ' (' + domains + ')' : '');
            var item = CSM.summaryItem({
                severity: ruleSeverity(b),
                titleHTML: titleHTML,
                meta: meta,
                count: b.hits,
                age: ageLabel(b.last_seen_iso, b.last_seen),
                statusHTML: statusBadgeHTML(b),
                onClick: (function(block) { return function() { openBlockDetail(block); }; })(b),
            });
            el.appendChild(item);
        }
    }

    function renderSideSummaries(blocks) {
        var ruleEl = document.getElementById('modsec-top-rules');
        var domEl = document.getElementById('modsec-top-domains');
        var escPill = document.getElementById('modsec-escalated-pill');
        var denyPill = document.getElementById('modsec-deny-pill');
        if (!ruleEl || !domEl) return;

        var ruleHits = {};
        var ruleDesc = {};
        var domainHits = {};
        var escalated = 0, denyOnly = 0;
        for (var i = 0; i < blocks.length; i++) {
            var b = blocks[i];
            if (b.escalated) escalated++; else denyOnly++;
            if (b.rule_id) {
                ruleHits[b.rule_id] = (ruleHits[b.rule_id] || 0) + b.hits;
                if (b.description && !ruleDesc[b.rule_id]) ruleDesc[b.rule_id] = b.description;
            }
            var parts = domainList(b);
            for (var p = 0; p < parts.length; p++) {
                var d = parts[p];
                domainHits[d] = (domainHits[d] || 0) + b.hits;
            }
        }
        if (escPill) escPill.textContent = escalated + ' escalated';
        if (denyPill) denyPill.textContent = denyOnly + ' WAF only';

        ruleEl.replaceChildren();
        var ruleEntries = Object.keys(ruleHits).map(function(k) { return [k, ruleHits[k]]; });
        ruleEntries.sort(function(a, b) { return b[1] - a[1]; });
        ruleEntries = ruleEntries.slice(0, 5);
        if (ruleEntries.length === 0) {
            ruleEl.innerHTML = '<div class="text-muted small">No rules triggered.</div>';
        } else {
            var ruleHTML = '';
            for (var r = 0; r < ruleEntries.length; r++) {
                var rid = ruleEntries[r][0];
                var rcount = ruleEntries[r][1];
                ruleHTML += '<div class="d-flex justify-content-between mb-1 small">';
                ruleHTML += '<span><code>' + CSM.esc(rid) + '</code> <span class="text-muted">' + CSM.esc(ruleDesc[rid] || '') + '</span></span>';
                ruleHTML += '<span class="fw-bold">' + rcount + '</span>';
                ruleHTML += '</div>';
            }
            ruleEl.innerHTML = ruleHTML;
        }

        domEl.replaceChildren();
        var domEntries = Object.keys(domainHits).map(function(k) { return [k, domainHits[k]]; });
        domEntries.sort(function(a, b) { return b[1] - a[1]; });
        domEntries = domEntries.slice(0, 5);
        if (domEntries.length === 0) {
            domEl.innerHTML = '<div class="text-muted small">No affected domains.</div>';
        } else {
            var domHTML = '';
            for (var dx = 0; dx < domEntries.length; dx++) {
                domHTML += '<div class="d-flex justify-content-between mb-1 small">';
                domHTML += '<span class="font-monospace">' + CSM.esc(domEntries[dx][0]) + '</span>';
                domHTML += '<span class="fw-bold">' + domEntries[dx][1] + '</span>';
                domHTML += '</div>';
            }
            domEl.innerHTML = domHTML;
        }
    }

    function openBlockDetail(b) {
        var bodyHTML = '';
        bodyHTML += '<dl class="row mb-2">';
        bodyHTML += '<dt class="col-4 text-muted">Source IP</dt><dd class="col-8 font-monospace">' + CSM.esc(b.ip) + '</dd>';
        if (b.rule_id) bodyHTML += '<dt class="col-4 text-muted">Rule</dt><dd class="col-8 font-monospace">' + CSM.esc(b.rule_id) + '</dd>';
        if (b.description) bodyHTML += '<dt class="col-4 text-muted">Description</dt><dd class="col-8">' + CSM.esc(b.description) + '</dd>';
        bodyHTML += '<dt class="col-4 text-muted">Hits</dt><dd class="col-8">' + b.hits + '</dd>';
        bodyHTML += '<dt class="col-4 text-muted">Status</dt><dd class="col-8">' + statusBadgeHTML(b) + '</dd>';
        if (b.first_seen) bodyHTML += '<dt class="col-4 text-muted">First seen</dt><dd class="col-8">' + CSM.fmtDate(b.first_seen) + '</dd>';
        if (b.last_seen_iso) bodyHTML += '<dt class="col-4 text-muted">Last seen</dt><dd class="col-8">' + CSM.fmtDate(b.last_seen_iso) + '</dd>';
        if (b.domain_count != null) bodyHTML += '<dt class="col-4 text-muted">Domains</dt><dd class="col-8">' + b.domain_count + '</dd>';
        bodyHTML += '</dl>';

        var domains = domainListText(b);
        if (domains) {
            bodyHTML += '<div class="mb-2"><div class="subheader">Affected domains</div><div class="font-monospace small">' + CSM.esc(domains) + '</div></div>';
        }
        if (b.top_uris && b.top_uris.length > 0) {
            bodyHTML += '<div class="mb-2"><div class="subheader">Top URIs</div>';
            for (var u = 0; u < b.top_uris.length; u++) {
                bodyHTML += '<div class="font-monospace small csm-truncate-middle" data-csm-truncate-middle="60">' + CSM.esc(b.top_uris[u]) + '</div>';
            }
            bodyHTML += '</div>';
        }
        if (b.sample_events && b.sample_events.length > 0) {
            bodyHTML += '<div class="mb-2"><div class="subheader">Recent events</div>';
            for (var s = 0; s < b.sample_events.length; s++) {
                var ev = b.sample_events[s];
                bodyHTML += '<div class="mb-2 border-start border-2 ps-2 small">';
                bodyHTML += '<div><strong>' + CSM.esc(ev.severity) + '</strong> <code>' + CSM.esc(ev.rule_id || '') + '</code> ' + CSM.fmtDate(ev.time) + '</div>';
                if (ev.hostname) bodyHTML += '<div class="text-muted">' + CSM.esc(ev.hostname) + '</div>';
                if (ev.uri) bodyHTML += '<div class="font-monospace csm-truncate-middle" data-csm-truncate-middle="60">' + CSM.esc(ev.uri) + '</div>';
                bodyHTML += '</div>';
            }
            bodyHTML += '</div>';
        }

        var footerHTML = '';
        footerHTML += '<a class="btn btn-ghost-secondary btn-sm" href="/threat?ip=' + encodeURIComponent(b.ip) + '"><i class="ti ti-radar"></i>&nbsp;Threat Intel</a>';
        footerHTML += '<a class="btn btn-ghost-secondary btn-sm" href="/firewall?view=lookup&ip=' + encodeURIComponent(b.ip) + '"><i class="ti ti-firewall"></i>&nbsp;Firewall</a>';
        footerHTML += '<a class="btn btn-ghost-secondary btn-sm" href="/modsec/rules?rule=' + encodeURIComponent(b.rule_id || '') + '"><i class="ti ti-settings"></i>&nbsp;Rule</a>';

        CSM.detailPanel.open({
            title: 'Block: ' + b.ip,
            bodyHTML: bodyHTML,
            footerHTML: footerHTML,
        });
        if (CSM.applyTruncateMiddle) CSM.applyTruncateMiddle(CSM.detailPanel.element());
    }

    // ---------- Blocked IPs tab (full table) ----------

    function loadBlocked() {
        CSM.get('/api/v1/modsec/blocks')
            .then(function(blocks) {
                _modsecBlocks = blocks || [];
                renderActiveWAFPressure(_modsecBlocks);
                renderSideSummaries(_modsecBlocks);
                renderBlockedTable(_modsecBlocks);
            })
            .catch(function(e) {
                document.getElementById('modsec-content').innerHTML = '<div class="card-body text-center text-danger py-3">Failed to load blocks</div>';
                var p = document.getElementById('modsec-pressure');
                if (p) {
                    p.replaceChildren();
                    p.appendChild(buildEmpty('alert-circle', 'Could not load WAF pressure', 'Retry from the refresh button.'));
                }
            });
    }

    function renderBlockedTable(blocks) {
        var container = document.getElementById('modsec-content');
        if (!container) return;
        var statusFilter = (document.getElementById('modsec-status-filter') || {}).value || '';
        var filtered = statusFilter
            ? blocks.filter(function(b) { return statusFor(b) === statusFilter; })
            : blocks;

        if (!filtered || filtered.length === 0) {
            container.innerHTML = '<div class="card-body text-center text-muted py-3">No ModSecurity blocks match the current filter.</div>';
            var c = document.getElementById('modsec-blocked-count');
            if (c) c.textContent = '0';
            return;
        }
        var h = '<div class="table-responsive"><table class="table table-vcenter card-table table-sm csm-table-rowcard csm-table-sticky" id="modsec-table">';
        h += '<thead><tr>';
        h += '<th class="csm-w-narrow"><input type="checkbox" class="form-check-input" id="modsec-select-all" aria-label="Select all visible rules"></th>';
        h += '<th>IP</th><th>Location</th><th>Rule</th><th>Description</th><th>Domains</th><th>Hits</th><th>Last Seen</th><th>Status</th>';
        h += '</tr></thead><tbody>';
        for (var i = 0; i < filtered.length; i++) {
            var b = filtered[i];
            var domains = domainListText(b);
            h += '<tr data-csm-modsec-ip="' + CSM.attr(b.ip) + '" data-csm-modsec-rule="' + CSM.attr(b.rule_id || '') + '">';
            h += '<td><input type="checkbox" class="form-check-input modsec-block-cb" data-rule="' + CSM.attr(b.rule_id || '') + '" aria-label="Select rule"' + (b.rule_id ? '' : ' disabled') + '></td>';
            h += '<td data-label="IP"><code>' + CSM.esc(b.ip) + '</code></td>';
            h += '<td data-label="Location" class="geo-cell" data-ip="' + CSM.attr(b.ip) + '"><span class="text-muted">--</span></td>';
            h += '<td data-label="Rule"><code>' + CSM.esc(b.rule_id || '') + '</code></td>';
            h += '<td data-label="Description">' + CSM.esc(b.description || '') + '</td>';
            h += '<td data-label="Domains">' + CSM.esc(domains) + '</td>';
            h += '<td data-label="Hits"><strong>' + b.hits + '</strong></td>';
            h += '<td data-label="Last Seen">' + CSM.esc(b.last_seen || '') + '</td>';
            h += '<td data-label="Status">' + statusBadgeHTML(b) + '</td>';
            h += '</tr>';
        }
        h += '</tbody></table></div>';
        container.innerHTML = h;

        new CSM.Table({
            tableId: 'modsec-table',
            perPage: 25,
            searchId: 'modsec-search',
            sortable: true,
            mobileRowCard: true,
            stickyHeader: true,
            stateKey: 'csm-modsec-blocked',
            countTargetId: 'modsec-blocked-count',
            emptyState: {
                icon: 'shield-check',
                title: 'No blocked IPs match',
                reason: 'Try clearing the search or status filter.'
            },
            onRowClick: function(rowEl) {
                var ip = rowEl.getAttribute('data-csm-modsec-ip');
                var rule = rowEl.getAttribute('data-csm-modsec-rule') || '';
                var b = _modsecBlocks.find(function(x) { return x.ip === ip && (x.rule_id || '') === rule; });
                if (b) openBlockDetail(b);
            }
        });
        // WEB_ROADMAP P3.7: bulk-disable across selected rule IDs. The
        // blocks table is rule-by-rule across IPs, so dedupe the
        // selection by rule_id before sending the apply request.
        var modsecBulkBtn = document.getElementById('modsec-bulk-disable');
        if (modsecBulkBtn) {
            CSM.bulk({
                rowCheckboxSelector: '.modsec-block-cb',
                selectAllEl: document.getElementById('modsec-select-all'),
                valueAttr: 'data-rule',
                buttons: [{ el: modsecBulkBtn, labelTemplate: 'Disable {n} rule(s)' }]
            });
            if (!modsecBulkBtn.dataset.csmBound) {
                modsecBulkBtn.dataset.csmBound = '1';
                modsecBulkBtn.addEventListener('click', function() {
                    var checked = document.querySelectorAll('.modsec-block-cb:checked');
                    var ruleSet = {};
                    checked.forEach(function(cb) {
                        var r = cb.getAttribute('data-rule');
                        if (r) ruleSet[r] = true;
                    });
                    var rules = Object.keys(ruleSet);
                    if (rules.length === 0) return;
                    CSM.confirm('Disable ' + rules.length + ' ModSecurity rule(s)?\n\nThis writes the override and reloads ModSecurity.').then(function() {
                        CSM.post('/api/v1/modsec/rules/apply', { disabled: rules })
                            .then(function() {
                                CSM.toast('Disabled ' + rules.length + ' rule(s)', 'success');
                                loadBlocked();
                            })
                            .catch(function(err) { CSM.toast('Apply failed: ' + (err.message || ''), 'error'); });
                    }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
                });
            }
        }
        enrichGeoIP(container);
    }

    // ---------- Events tab ----------

    function loadEvents() {
        if (eventsLoaded) return;
        eventsLoaded = true;
        CSM.get('/api/v1/modsec/events?limit=100')
            .then(function(events) {
                _strip.latest = events && events.length > 0 ? events[0].time : '';
                refreshStatusStrip();
                renderEvents(events || []);
            })
            .catch(function() {
                var el = document.getElementById('modsec-events');
                if (el) el.innerHTML = '<div class="card-body text-center text-danger py-3">Failed to load events</div>';
                eventsLoaded = false;
            });
    }

    function renderEvents(events) {
        var el = document.getElementById('modsec-events');
        if (!el) return;
        if (events.length === 0) {
            el.innerHTML = '<div class="card-body text-center text-muted py-3">No recent events</div>';
            var c = document.getElementById('modsec-events-count');
            if (c) c.textContent = '0';
            return;
        }
        var h = '<div class="table-responsive"><table class="table table-vcenter card-table table-sm csm-table-sticky" id="events-table">';
        h += '<thead><tr>';
        h += '<th>Time</th><th>IP</th><th>Rule</th><th>Domain</th><th>URI</th><th>Severity</th>';
        h += '</tr></thead><tbody>';
        for (var i = 0; i < events.length; i++) {
            var e = events[i];
            var sevClass = e.severity === 'CRITICAL' ? 'bg-red' : e.severity === 'HIGH' ? 'bg-orange' : 'bg-yellow';
            h += '<tr>';
            h += '<td class="text-nowrap">' + CSM.esc(e.time) + '</td>';
            h += '<td><code>' + CSM.esc(e.ip) + '</code></td>';
            h += '<td><code>' + CSM.esc(e.rule_id) + '</code></td>';
            h += '<td>' + CSM.esc(e.hostname) + '</td>';
            h += '<td class="font-monospace small csm-truncate-middle" data-csm-truncate-middle="60">' + CSM.esc(e.uri) + '</td>';
            h += '<td><span class="badge ' + sevClass + '">' + CSM.esc(e.severity) + '</span></td>';
            h += '</tr>';
        }
        h += '</tbody></table></div>';
        el.innerHTML = h;
        new CSM.Table({
            tableId: 'events-table',
            perPage: 25,
            searchId: 'events-search',
            sortable: true,
            stickyHeader: true,
            countTargetId: 'modsec-events-count',
            mobileRowCard: true,
            emptyState: {
                icon: 'list-search',
                title: 'No events match',
                reason: 'Try clearing the search to see all recent events.'
            }
        });
        if (CSM.applyTruncateMiddle) CSM.applyTruncateMiddle(el);
    }

    // /api/v1/geoip/batch caps each request at 500 IPs, so chunk the call;
    // hosts with thousands of unique attackers otherwise see HTTP 400.
    var GEOIP_CHUNK = 250;

    function enrichGeoIP(container) {
        var cells = container.querySelectorAll('.geo-cell');
        if (cells.length === 0) return;
        // Map IP -> [cell, ...] so chunked responses paint every matching cell.
        var byIP = {};
        for (var i = 0; i < cells.length; i++) {
            var ip = cells[i].dataset.ip;
            if (!ip) continue;
            (byIP[ip] = byIP[ip] || []).push(cells[i]);
        }
        var uniqueIPs = Object.keys(byIP);
        if (uniqueIPs.length === 0) return;

        function paint(results) {
            for (var ip in results) {
                if (!Object.prototype.hasOwnProperty.call(results, ip)) continue;
                var matched = byIP[ip];
                if (!matched) continue;
                var g = results[ip];
                var html = CSM.countryFlag(g.country) + ' ' + CSM.esc(g.country);
                if (g.org) html += '<br><small class="text-muted">' + CSM.esc(g.org) + '</small>';
                for (var k = 0; k < matched.length; k++) matched[k].innerHTML = html;
            }
        }

        for (var s = 0; s < uniqueIPs.length; s += GEOIP_CHUNK) {
            var slice = uniqueIPs.slice(s, s + GEOIP_CHUNK);
            CSM.post('/api/v1/geoip/batch', { ips: slice })
                .then(function(data) { paint(data.results || {}); })
                .catch(function() { /* non-fatal */ });
        }
    }

    // ---------- Tab activation + filters ----------

    var tabButtons = document.querySelectorAll('[data-bs-toggle="tab"]');
    for (var t = 0; t < tabButtons.length; t++) {
        tabButtons[t].addEventListener('shown.bs.tab', function(ev) {
            var id = ev.target.id.replace('modsec-tab-', '');
            if (id === 'events') loadEvents();
        });
    }

    var statusFilter = document.getElementById('modsec-status-filter');
    if (statusFilter) {
        statusFilter.addEventListener('change', function() {
            renderBlockedTable(_modsecBlocks);
        });
    }

    var refreshBtn = document.getElementById('modsec-refresh');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            loadStats();
            loadBlocked();
            eventsLoaded = false;
            if (document.getElementById('modsec-pane-events').classList.contains('active')) loadEvents();
        });
    }

    // ---------- Initialize ----------

    loadStats();
    loadBlocked();

    _modsecPoller = CSM.poll('/api/v1/modsec/stats', 30000, function(err, d) {
        if (err) return;
        _strip.stats = d;
        refreshStatusStrip();
    });

    var subtitle = document.getElementById('modsec-subtitle');
    if (subtitle) subtitle.textContent = 'Active WAF pressure, top rules and domains, with raw events behind tabs.';
})();
