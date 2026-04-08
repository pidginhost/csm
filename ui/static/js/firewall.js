// CSM Firewall page

var _fwBlockedData = [];

function removeTableControls(id) {
    var el = document.getElementById(id);
    if (el) el.remove();
}

function formatReason(reason, fallback) {
    return CSM.esc(reason || fallback || '-');
}

function formatExpiresBadge(expiresIn) {
    if (!expiresIn || expiresIn === 'permanent') {
        return '<span class="badge bg-red-lt">Permanent</span>';
    }
    return '<span class="badge bg-azure-lt">' + CSM.esc(expiresIn) + '</span>';
}

function formatGeo(geo) {
    if (!geo || geo.error || !geo.country) return '-';
    var html = CSM.countryFlag(geo.country) + ' ' + CSM.esc(geo.country);
    if (geo.as_org) html += ' <span class="text-muted small">' + CSM.esc(geo.as_org) + '</span>';
    return html;
}

function humanizeAction(action) {
    return CSM.esc((action || '').replace(/_/g, ' '));
}

function renderStatusBadge(enabled, onLabel, offLabel) {
    return enabled ? '<span class="badge bg-green-lt">' + onLabel + '</span>' : '<span class="badge bg-secondary-lt">' + offLabel + '</span>';
}

function sourceLabel(source) {
    var labels = {
        web_ui: 'Web UI',
        cli: 'CLI',
        auto_response: 'Auto-response',
        challenge: 'Challenge',
        whitelist: 'Whitelist',
        dyndns: 'DynDNS',
        system: 'System',
        unknown: 'Unknown'
    };
    return labels[source] || 'Unknown';
}

function sourceBadge(source) {
    var cls = {
        web_ui: 'bg-blue-lt',
        cli: 'bg-indigo-lt',
        auto_response: 'bg-red-lt',
        challenge: 'bg-yellow-lt',
        whitelist: 'bg-green-lt',
        dyndns: 'bg-cyan-lt',
        system: 'bg-secondary-lt',
        unknown: 'bg-secondary-lt'
    };
    return '<span class="badge ' + (cls[source] || 'bg-secondary-lt') + '">' + CSM.esc(sourceLabel(source)) + '</span>';
}

function classifyLifetime(item) {
    return item && item.expires_at ? 'temporary' : 'permanent';
}

function extractLookupIP(target) {
    if (!target) return '';
    if (CSM.validateIP(target)) return target;
    if (target.indexOf('/') > 0) {
        var base = target.split('/')[0];
        if (CSM.validateIP(base)) return base;
    }
    if (target.indexOf('.') >= 0 && target.indexOf(':') > 0) {
        var ipv4 = target.split(':')[0];
        if (CSM.validateIP(ipv4)) return ipv4;
    }
    return '';
}

function setAuditSearch(value) {
    var el = document.getElementById('audit-search');
    if (!el) return;
    el.value = value || '';
    el.dispatchEvent(new Event('input', { bubbles: true }));
}

function currentAuditURL() {
    var url = '/api/v1/firewall/audit?limit=50';
    var params = [];
    var search = document.getElementById('audit-search');
    var action = document.getElementById('audit-action-filter');
    var source = document.getElementById('audit-source-filter');
    if (search && search.value.trim()) params.push('search=' + encodeURIComponent(search.value.trim()));
    if (action && action.value && action.value !== 'all') params.push('action=' + encodeURIComponent(action.value));
    if (source && source.value && source.value !== 'all') params.push('source=' + encodeURIComponent(source.value));
    if (!params.length) return url;
    return url + '&' + params.join('&');
}

function inspectIP(ip) {
    if (!ip) return;
    document.getElementById('lookup-ip').value = ip;
    loadLookup(ip);
}

function loadStatus() {
    fetch(CSM.apiUrl('/api/v1/firewall/status'), { credentials: 'same-origin' })
        .then(function(r) { return r.json(); })
        .then(function(d) {
            var allowedTotal = (d.allowed_count || 0) + (d.port_allow_count || 0);
            var countryCount = (d.country_block || []).length;
            var dynDNSCount = (d.dyndns_hosts || []).length;

            document.getElementById('fw-enabled').innerHTML = d.enabled ? '<span class="text-success">ACTIVE</span>' : '<span class="text-muted">DISABLED</span>';
            document.getElementById('fw-status-meta').textContent = 'IPv6 ' + (d.ipv6 ? 'on' : 'off') + ' • drop logging ' + (d.log_dropped ? 'on' : 'off');
            document.getElementById('fw-blocked').textContent = d.blocked_count || 0;
            document.getElementById('fw-blocked-meta').textContent = (d.blocked_temporary || 0) + ' temporary • ' + (d.blocked_permanent || 0) + ' permanent';
            document.getElementById('fw-subnets').textContent = d.blocked_net_count || 0;
            document.getElementById('fw-subnets-meta').textContent = (d.deny_ip_limit || 'unlimited') + ' deny limit';
            document.getElementById('fw-allowed').textContent = allowedTotal;
            document.getElementById('fw-allowed-meta').textContent = (d.allow_temporary || 0) + ' temporary • ' + (d.port_allow_count || 0) + ' port exceptions';
            document.getElementById('fw-geo-summary').textContent = countryCount + dynDNSCount;
            document.getElementById('fw-geo-meta').textContent = countryCount + ' countries • ' + dynDNSCount + ' DynDNS hosts';

            var highlights = [
                '<span class="badge bg-blue-lt">Infra IPs: ' + (d.infra_count || 0) + '</span>',
                '<span class="badge bg-azure-lt">Restricted TCP: ' + ((d.restricted_tcp || []).length || 0) + '</span>',
                '<span class="badge bg-yellow-lt">Port flood rules: ' + (d.port_flood_rules || 0) + '</span>',
                '<span class="badge bg-orange-lt">Conn limit: ' + (d.conn_limit || 'off') + '</span>'
            ];
            document.getElementById('fw-highlights').innerHTML = highlights.join('');

            var flags = [
                renderStatusBadge(d.syn_flood_protection, 'SYN flood protection', 'SYN flood off'),
                renderStatusBadge(d.udp_flood, 'UDP flood protection', 'UDP flood off'),
                renderStatusBadge(d.smtp_block, 'SMTP block', 'SMTP open'),
                renderStatusBadge(d.log_dropped, 'Drop logging', 'Drop logging off'),
                renderStatusBadge(d.ipv6, 'IPv6 enabled', 'IPv6 disabled')
            ];
            if (countryCount > 0) flags.push('<span class="badge bg-red-lt">Country blocks: ' + countryCount + '</span>');
            if (dynDNSCount > 0) flags.push('<span class="badge bg-blue-lt">DynDNS hosts: ' + dynDNSCount + '</span>');
            document.getElementById('fw-config-flags').innerHTML = flags.join('');

            function portList(ports) {
                return '<code class="small">' + ((ports || []).length ? CSM.esc((ports || []).join(', ')) : 'none') + '</code>';
            }

            var passiveFtp = d.passive_ftp && d.passive_ftp.length >= 2 && d.passive_ftp[0] > 0 && d.passive_ftp[1] > 0
                ? d.passive_ftp[0] + '-' + d.passive_ftp[1]
                : 'not configured';

            var infraList = d.infra_ips || [];
            var countryList = d.country_block || [];
            var dynHosts = d.dyndns_hosts || [];

            var t1 = '<tr><td class="text-muted">TCP In</td><td>' + portList(d.tcp_in) + '</td></tr>';
            t1 += '<tr><td class="text-muted">TCP Out</td><td>' + portList(d.tcp_out) + '</td></tr>';
            t1 += '<tr><td class="text-muted">UDP In</td><td>' + portList(d.udp_in) + '</td></tr>';
            t1 += '<tr><td class="text-muted">UDP Out</td><td>' + portList(d.udp_out) + '</td></tr>';
            t1 += '<tr><td class="text-muted">Restricted TCP</td><td>' + portList(d.restricted_tcp) + '</td></tr>';
            t1 += '<tr><td class="text-muted">Passive FTP</td><td><code>' + CSM.esc(passiveFtp) + '</code></td></tr>';
            t1 += '<tr><td class="text-muted">Infra IPs</td><td>' + (infraList.length ? '<code class="small">' + CSM.esc(infraList.join(', ')) + '</code>' : '<span class="text-danger">none configured</span>') + '</td></tr>';
            document.getElementById('fw-config-table').innerHTML = t1;

            var t2 = '<tr><td class="text-muted">Conn rate</td><td>' + (d.conn_rate_limit || 0) + '/min per IP</td></tr>';
            t2 += '<tr><td class="text-muted">Conn limit</td><td>' + (d.conn_limit || 'disabled') + '</td></tr>';
            t2 += '<tr><td class="text-muted">Deny limit</td><td>' + (d.deny_ip_limit || 'unlimited') + '</td></tr>';
            t2 += '<tr><td class="text-muted">Country block</td><td>' + (countryList.length ? '<code class="small">' + CSM.esc(countryList.join(', ')) + '</code>' : '<span class="text-muted">none</span>') + '</td></tr>';
            t2 += '<tr><td class="text-muted">DynDNS allow</td><td>' + (dynHosts.length ? '<code class="small">' + CSM.esc(dynHosts.join(', ')) + '</code>' : '<span class="text-muted">none</span>') + '</td></tr>';
            t2 += '<tr><td class="text-muted">Port flood rules</td><td>' + (d.port_flood_rules || 0) + '</td></tr>';
            document.getElementById('fw-config-table2').innerHTML = t2;
        })
        .catch(function() {
            CSM.loadError(document.getElementById('fw-status'), loadStatus);
        });
}

function loadSubnets() {
    fetch(CSM.apiUrl('/api/v1/firewall/subnets'), { credentials: 'same-origin' })
        .then(function(r) { return r.json(); })
        .then(function(subs) {
            var el = document.getElementById('subnet-content');
            removeTableControls('subnets-table-controls');
            if (!subs || subs.length === 0) {
                el.innerHTML = '<div class="card-body text-center text-muted py-3">No blocked subnets.</div>';
                return;
            }

            var h = '<div class="table-responsive"><table class="table table-vcenter card-table" id="subnets-table">';
            h += '<thead><tr><th>CIDR</th><th>Location</th><th>Reason</th><th>Blocked</th><th>Expires</th><th>Action</th></tr></thead><tbody>';
            for (var i = 0; i < subs.length; i++) {
                var baseIP = subs[i].cidr.replace(/\/.*/, '');
                h += '<tr>';
                h += '<td><code class="csm-copy" title="Click to copy">' + CSM.esc(subs[i].cidr) + '</code></td>';
                h += '<td class="small text-muted text-nowrap geo-cell" data-ip="' + CSM.esc(baseIP) + '"></td>';
                h += '<td class="small"><div>' + formatReason(subs[i].reason, 'Blocked via CSM') + '</div><div class="mt-1">' + sourceBadge(subs[i].source || 'unknown') + '</div></td>';
                h += '<td class="small text-muted" data-timestamp="' + CSM.esc(subs[i].blocked_at || '') + '">' + CSM.esc(subs[i].time_ago || '-') + '</td>';
                h += '<td>' + formatExpiresBadge(subs[i].expires_in) + '</td>';
                h += '<td><button class="btn btn-sm btn-outline-secondary remove-subnet-btn" data-cidr="' + CSM.esc(subs[i].cidr) + '">Remove</button></td>';
                h += '</tr>';
            }
            h += '</tbody></table></div>';
            el.innerHTML = h;

            new CSM.Table({ tableId: 'subnets-table', searchId: 'subnet-search', sortable: true, perPage: 10 });
            enrichGeoIP(el);
            el.querySelectorAll('.remove-subnet-btn').forEach(function(btn) {
                btn.addEventListener('click', function() { removeSubnet(this.getAttribute('data-cidr')); });
            });
        })
        .catch(function() {
            CSM.loadError(document.getElementById('subnet-content'), loadSubnets);
        });
}

function loadBlocked() {
    fetch(CSM.apiUrl('/api/v1/blocked-ips'), { credentials: 'same-origin' })
        .then(function(r) { return r.json(); })
        .then(function(ips) {
            var el = document.getElementById('blocked-content');
            removeTableControls('blocked-table-controls');
            if (!ips || ips.length === 0) {
                _fwBlockedData = [];
                el.innerHTML = '<div class="card-body text-center text-muted py-3">No blocked IPs.</div>';
                updateBulkUnblock();
                return;
            }

            _fwBlockedData = ips.map(function(b) {
                return {
                    ip: b.ip,
                    reason: b.reason || '',
                    source: b.source || 'unknown',
                    blocked_at: b.blocked_at || '',
                    expires: b.expires_in || '',
                    lifetime: classifyLifetime(b)
                };
            });

            var h = '<div class="table-responsive"><table class="table table-vcenter card-table table-sm" id="blocked-table"><thead><tr>';
            h += '<th><input type="checkbox" class="form-check-input" id="blocked-select-all"></th>';
            h += '<th>IP</th><th>Location</th><th>Reason</th><th>Blocked</th><th>Expires</th><th>Action</th></tr></thead><tbody>';

            for (var i = 0; i < ips.length; i++) {
                var blockedAt = ips[i].blocked_at ? CSM.fmtDate(ips[i].blocked_at) : '-';
                var source = ips[i].source || 'unknown';
                var lifetime = classifyLifetime(ips[i]);
                h += '<tr data-source="' + CSM.esc(source) + '" data-lifetime="' + lifetime + '">';
                h += '<td><input type="checkbox" class="form-check-input blocked-cb" data-ip="' + CSM.esc(ips[i].ip) + '"></td>';
                h += '<td><code class="csm-copy" title="Click to copy">' + CSM.esc(ips[i].ip) + '</code></td>';
                h += '<td class="small text-muted text-nowrap geo-cell" data-ip="' + CSM.esc(ips[i].ip) + '"></td>';
                h += '<td class="small"><div>' + formatReason(ips[i].reason, 'Blocked via CSM') + '</div><div class="mt-1">' + sourceBadge(source) + '</div></td>';
                h += '<td class="small text-muted" data-timestamp="' + CSM.esc(ips[i].blocked_at || '') + '">' + blockedAt + '</td>';
                h += '<td>' + formatExpiresBadge(ips[i].expires_in) + '</td>';
                h += '<td class="text-nowrap">';
                h += '<div class="dropdown d-inline-block me-1">';
                h += '<button class="btn btn-sm btn-outline-primary dropdown-toggle" data-bs-toggle="dropdown">Respond</button>';
                h += '<div class="dropdown-menu dropdown-menu-end">';
                h += '<a class="dropdown-item fw-inspect-btn" href="#" data-ip="' + CSM.esc(ips[i].ip) + '"><i class="ti ti-search me-2"></i>Inspect</a>';
                h += '<a class="dropdown-item fw-clear-btn" href="#" data-ip="' + CSM.esc(ips[i].ip) + '"><i class="ti ti-eraser me-2"></i>Clear only</a>';
                h += '<a class="dropdown-item fw-temp-whitelist-btn" href="#" data-ip="' + CSM.esc(ips[i].ip) + '"><i class="ti ti-clock-check me-2"></i>Clear and allow 24h</a>';
                h += '<a class="dropdown-item fw-cphulk-btn" href="#" data-ip="' + CSM.esc(ips[i].ip) + '"><i class="ti ti-door-exit me-2"></i>Flush cPHulk only</a>';
                h += '</div></div>';
                h += '<button class="btn btn-sm btn-outline-secondary fw-unblock-btn me-1" data-ip="' + CSM.esc(ips[i].ip) + '">Unblock</button>';
                h += '<button class="btn btn-sm btn-outline-success fw-whitelist-btn" data-ip="' + CSM.esc(ips[i].ip) + '">Whitelist</button>';
                h += '</td>';
                h += '</tr>';
            }
            h += '</tbody></table></div>';
            el.innerHTML = h;

            new CSM.Table({
                tableId: 'blocked-table',
                perPage: 25,
                searchId: 'blocked-search',
                sortable: true,
                filters: [
                    { id: 'blocked-lifetime-filter', attr: 'data-lifetime' },
                    { id: 'blocked-source-filter', attr: 'data-source' }
                ],
                onRender: updateBulkUnblock
            });
            if (document.getElementById('blocked-search').value) {
                document.getElementById('blocked-search').dispatchEvent(new Event('input', { bubbles: true }));
            }
            if (document.getElementById('blocked-lifetime-filter').value !== 'all') {
                document.getElementById('blocked-lifetime-filter').dispatchEvent(new Event('change', { bubbles: true }));
            }
            if (document.getElementById('blocked-source-filter').value !== 'all') {
                document.getElementById('blocked-source-filter').dispatchEvent(new Event('change', { bubbles: true }));
            }
            enrichGeoIP(el);

            el.querySelectorAll('.fw-unblock-btn').forEach(function(btn) {
                btn.addEventListener('click', function() { unblockIP(this.getAttribute('data-ip')); });
            });
            el.querySelectorAll('.fw-whitelist-btn').forEach(function(btn) {
                btn.addEventListener('click', function() { whitelistIP(this.getAttribute('data-ip'), 'permanent'); });
            });
            el.querySelectorAll('.fw-inspect-btn').forEach(function(btn) {
                btn.addEventListener('click', function(e) {
                    e.preventDefault();
                    inspectIP(this.getAttribute('data-ip'));
                });
            });
            el.querySelectorAll('.fw-clear-btn').forEach(function(btn) {
                btn.addEventListener('click', function(e) {
                    e.preventDefault();
                    clearThreatState(this.getAttribute('data-ip'));
                });
            });
            el.querySelectorAll('.fw-temp-whitelist-btn').forEach(function(btn) {
                btn.addEventListener('click', function(e) {
                    e.preventDefault();
                    whitelistIP(this.getAttribute('data-ip'), '24');
                });
            });
            el.querySelectorAll('.fw-cphulk-btn').forEach(function(btn) {
                btn.addEventListener('click', function(e) {
                    e.preventDefault();
                    flushCphulkOnly(this.getAttribute('data-ip'));
                });
            });

            var selectAll = document.getElementById('blocked-select-all');
            if (selectAll) {
                selectAll.addEventListener('change', function() {
                    var checked = this.checked;
                    el.querySelectorAll('.blocked-cb').forEach(function(cb) {
                        if (cb.closest('tr').style.display !== 'none') cb.checked = checked;
                    });
                    updateBulkUnblock();
                });
            }
            el.querySelectorAll('.blocked-cb').forEach(function(cb) {
                cb.addEventListener('change', updateBulkUnblock);
            });
            updateBulkUnblock();
        })
        .catch(function() {
            CSM.loadError(document.getElementById('blocked-content'), loadBlocked);
        });
}

function loadAllowed() {
    fetch(CSM.apiUrl('/api/v1/firewall/allowed'), { credentials: 'same-origin' })
        .then(function(r) { return r.json(); })
        .then(function(data) {
            var el = document.getElementById('allowed-content');
            var allowed = data.allowed || [];
            var portAllowed = data.port_allowed || [];
            removeTableControls('allowed-table-controls');

            if (allowed.length === 0 && portAllowed.length === 0) {
                el.innerHTML = '<div class="card-body text-center text-muted py-3">No active allow rules.</div>';
                return;
            }

            var h = '<div class="card-body border-bottom">';
            h += '<div class="d-flex flex-wrap gap-2">';
            h += '<span class="badge bg-green-lt">IP allow rules: ' + allowed.length + '</span>';
            h += '<span class="badge bg-blue-lt">Port exceptions: ' + portAllowed.length + '</span>';
            h += '</div></div>';

            if (allowed.length > 0) {
                h += '<div class="table-responsive"><table class="table table-vcenter card-table table-sm" id="allowed-table">';
                h += '<thead><tr><th>IP</th><th>Location</th><th>Reason</th><th>Expires</th><th>Action</th></tr></thead><tbody>';
                for (var i = 0; i < allowed.length; i++) {
                    var expiresText = allowed[i].expires_at ? CSM.fmtDate(allowed[i].expires_at) : 'Permanent';
                    h += '<tr>';
                    h += '<td><code class="csm-copy" title="Click to copy">' + CSM.esc(allowed[i].ip) + '</code></td>';
                    h += '<td class="small text-muted text-nowrap geo-cell" data-ip="' + CSM.esc(allowed[i].ip) + '"></td>';
                    h += '<td class="small"><div>' + formatReason(allowed[i].reason, 'Allowed via CSM') + '</div><div class="mt-1">' + sourceBadge(allowed[i].source || 'unknown') + '</div></td>';
                    h += '<td data-timestamp="' + CSM.esc(allowed[i].expires_at || '') + '">' + (allowed[i].expires_at ? '<div>' + expiresText + '</div><div class="text-muted small">' + CSM.esc(allowed[i].expires_in) + '</div>' : formatExpiresBadge('permanent')) + '</td>';
                    h += '<td><button class="btn btn-sm btn-outline-secondary remove-allow-btn" data-ip="' + CSM.esc(allowed[i].ip) + '">Remove</button></td>';
                    h += '</tr>';
                }
                h += '</tbody></table></div>';
            } else {
                h += '<div class="card-body text-muted small border-bottom">No active IP allow rules.</div>';
            }

            if (portAllowed.length > 0) {
                h += '<div class="card-body border-top">';
                h += '<div class="text-muted small mb-2">Port exceptions are shown for visibility. They are tracked separately from full-IP allow rules.</div>';
                h += '<div class="table-responsive"><table class="table table-vcenter table-sm mb-0">';
                h += '<thead><tr><th>IP</th><th>Port</th><th>Proto</th><th>Reason</th></tr></thead><tbody>';
                for (var j = 0; j < portAllowed.length; j++) {
                    h += '<tr>';
                    h += '<td><code class="csm-copy">' + CSM.esc(portAllowed[j].ip) + '</code></td>';
                    h += '<td><code>' + CSM.esc(String(portAllowed[j].port)) + '</code></td>';
                    h += '<td><span class="badge bg-blue-lt">' + CSM.esc(portAllowed[j].proto || 'tcp') + '</span></td>';
                    h += '<td class="small"><div>' + formatReason(portAllowed[j].reason, 'Port allow') + '</div><div class="mt-1">' + sourceBadge(portAllowed[j].source || 'unknown') + '</div></td>';
                    h += '</tr>';
                }
                h += '</tbody></table></div></div>';
            }

            el.innerHTML = h;
            if (allowed.length > 0) {
                new CSM.Table({ tableId: 'allowed-table', perPage: 15, searchId: 'allowed-search', sortable: true });
                el.querySelectorAll('.remove-allow-btn').forEach(function(btn) {
                    btn.addEventListener('click', function() { removeAllowRule(this.getAttribute('data-ip')); });
                });
                enrichGeoIP(el);
            }
        })
        .catch(function() {
            CSM.loadError(document.getElementById('allowed-content'), loadAllowed);
        });
}

function loadWhitelist() {
    fetch(CSM.apiUrl('/api/v1/threat/whitelist'), { credentials: 'same-origin' })
        .then(function(r) { return r.json(); })
        .then(function(ips) {
            var el = document.getElementById('whitelist-content');
            removeTableControls('whitelist-table-controls');
            if (!ips || ips.length === 0) {
                el.innerHTML = '<div class="card-body text-center text-muted py-3">No whitelisted IPs.</div>';
                return;
            }

            var h = '<div class="table-responsive"><table class="table table-vcenter card-table table-sm" id="whitelist-table">';
            h += '<thead><tr><th>IP</th><th>Status</th><th>Action</th></tr></thead><tbody>';
            for (var i = 0; i < ips.length; i++) {
                var wl = ips[i];
                var ip = typeof wl === 'string' ? wl : wl.ip;
                var status = '<span class="badge bg-green-lt">Permanent</span>';
                if (wl && wl.expires_at) {
                    status = '<div><span class="badge bg-yellow-lt">Temporary</span></div><div class="text-muted small mt-1">' + CSM.fmtDate(wl.expires_at) + '</div>';
                }
                h += '<tr>';
                h += '<td><code class="csm-copy">' + CSM.esc(ip) + '</code></td>';
                h += '<td>' + status + '</td>';
                h += '<td><button class="btn btn-sm btn-outline-secondary wl-remove-btn" data-ip="' + CSM.esc(ip) + '">Remove</button></td>';
                h += '</tr>';
            }
            h += '</tbody></table></div>';
            el.innerHTML = h;

            new CSM.Table({ tableId: 'whitelist-table', searchId: 'whitelist-search', sortable: true, perPage: 15 });
            el.querySelectorAll('.wl-remove-btn').forEach(function(btn) {
                btn.addEventListener('click', function() { removeWhitelist(this.getAttribute('data-ip')); });
            });
        })
        .catch(function() {
            CSM.loadError(document.getElementById('whitelist-content'), loadWhitelist);
        });
}

function loadAudit() {
    fetch(CSM.apiUrl(currentAuditURL()), { credentials: 'same-origin' })
        .then(function(r) { return r.json(); })
        .then(function(entries) {
            var el = document.getElementById('audit-content');
            removeTableControls('firewall-audit-table-controls');
            if (!entries || entries.length === 0) {
                el.innerHTML = '<div class="card-body text-center text-muted py-3">No recent firewall activity.</div>';
                return;
            }

            var h = '<div class="table-responsive"><table class="table table-vcenter card-table table-sm" id="firewall-audit-table">';
            h += '<thead><tr><th>When</th><th>Action</th><th>Target</th><th>Reason</th><th>Duration</th><th>Inspect</th></tr></thead><tbody>';
            for (var i = 0; i < entries.length; i++) {
                var source = entries[i].source || 'unknown';
                var inspectIPValue = extractLookupIP(entries[i].ip || '');
                h += '<tr data-action="' + CSM.esc(entries[i].action || '') + '" data-source="' + CSM.esc(source) + '">';
                h += '<td data-timestamp="' + CSM.esc(entries[i].timestamp || '') + '"><div>' + CSM.esc(entries[i].time_ago || '-') + '</div><div class="text-muted small">' + CSM.esc(entries[i].timestamp || '') + '</div></td>';
                h += '<td><div><span class="badge bg-secondary-lt">' + humanizeAction(entries[i].action) + '</span></div><div class="mt-1">' + sourceBadge(source) + '</div></td>';
                h += '<td><code>' + CSM.esc(entries[i].ip || '-') + '</code></td>';
                h += '<td class="small">' + formatReason(entries[i].reason, '-') + '</td>';
                h += '<td class="small text-muted">' + CSM.esc(entries[i].duration || '-') + '</td>';
                h += '<td>' + (inspectIPValue ? '<button class="btn btn-sm btn-outline-secondary audit-inspect-btn" data-ip="' + CSM.esc(inspectIPValue) + '">Inspect</button>' : '') + '</td>';
                h += '</tr>';
            }
            h += '</tbody></table></div>';
            el.innerHTML = h;
            new CSM.Table({
                tableId: 'firewall-audit-table',
                perPage: 12,
                searchId: 'audit-search',
                sortable: true,
                controlsId: 'firewall-audit-table-controls',
                filters: [
                    { id: 'audit-action-filter', attr: 'data-action' },
                    { id: 'audit-source-filter', attr: 'data-source' }
                ]
            });
            if (document.getElementById('audit-search').value) {
                document.getElementById('audit-search').dispatchEvent(new Event('input', { bubbles: true }));
            }
            if (document.getElementById('audit-action-filter').value !== 'all') {
                document.getElementById('audit-action-filter').dispatchEvent(new Event('change', { bubbles: true }));
            }
            if (document.getElementById('audit-source-filter').value !== 'all') {
                document.getElementById('audit-source-filter').dispatchEvent(new Event('change', { bubbles: true }));
            }
            el.querySelectorAll('.audit-inspect-btn').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    inspectIP(this.getAttribute('data-ip'));
                });
            });
        })
        .catch(function() {
            CSM.loadError(document.getElementById('audit-content'), loadAudit);
        });
}

function loadLookup(ip) {
    var resultEl = document.getElementById('lookup-result');
    resultEl.innerHTML = '<div class="text-muted"><span class="spinner-border spinner-border-sm me-2"></span>Checking firewall and GeoIP status</div>';
    setAuditSearch(ip);
    loadAudit();

    Promise.all([
        fetch(CSM.apiUrl('/api/v1/firewall/check?ip=' + encodeURIComponent(ip)), { credentials: 'same-origin' }).then(function(r) { return r.json(); }),
        fetch(CSM.apiUrl('/api/v1/geoip?ip=' + encodeURIComponent(ip)), { credentials: 'same-origin' }).then(function(r) { return r.json(); }).catch(function() { return {}; })
    ]).then(function(results) {
        var data = results[0] || {};
        var geo = results[1] || {};
        if (!data.success) {
            resultEl.innerHTML = '<div class="text-danger">' + CSM.esc(data.error_msg || 'Lookup failed') + '</div>';
            return;
        }

        var state = [];
        if (data.permanent) state.push('<span class="badge bg-red-lt">Blocked</span>');
        if (data.temporary) state.push('<span class="badge bg-orange-lt">Temporary block</span>');
        if (data.cphulk) state.push('<span class="badge bg-yellow-lt">cPHulk match</span>');
        if (state.length === 0) state.push('<span class="badge bg-green-lt">No active block</span>');

        var details = '<div class="fw-lookup-target mb-2"><code>' + CSM.esc(ip) + '</code></div>';
        details += '<div class="d-flex flex-wrap gap-2 mb-3">' + state.join('') + '</div>';
        details += '<div class="row g-3">';
        details += '<div class="col-md-6"><div class="border rounded p-3 h-100">';
        details += '<div class="subheader mb-2">Firewall</div>';
        details += '<div class="small"><strong>Permanent:</strong> ' + formatReason(data.permanent, 'No') + '</div>';
        details += '<div class="small mt-2"><strong>Temporary:</strong> ' + formatReason(data.temporary, 'No') + '</div>';
        details += '<div class="small mt-2"><strong>cPHulk:</strong> ' + (data.cphulk ? 'Yes' : 'No') + '</div>';
        details += '</div></div>';
        details += '<div class="col-md-6"><div class="border rounded p-3 h-100">';
        details += '<div class="subheader mb-2">GeoIP</div>';
        details += '<div class="small">' + formatGeo(geo) + '</div>';
        if (geo.city) details += '<div class="small text-muted mt-2">' + CSM.esc(geo.city) + '</div>';
        if (geo.asn) details += '<div class="small text-muted mt-2">AS' + CSM.esc(String(geo.asn)) + '</div>';
        details += '</div></div>';
        details += '</div>';
        details += '<div class="d-flex gap-2 flex-wrap mt-3">';
        if (data.permanent || data.temporary || data.cphulk) {
            details += '<button class="btn btn-outline-danger btn-sm" id="lookup-unban-btn" data-ip="' + CSM.esc(ip) + '">Unban everywhere</button>';
        }
        details += '<button class="btn btn-outline-secondary btn-sm" id="lookup-clear-btn" data-ip="' + CSM.esc(ip) + '">Clear only</button>';
        details += '<button class="btn btn-outline-success btn-sm" id="lookup-allow-btn" data-ip="' + CSM.esc(ip) + '">Clear and allow 24h</button>';
        details += '<button class="btn btn-outline-primary btn-sm" id="lookup-cphulk-btn" data-ip="' + CSM.esc(ip) + '">Flush cPHulk only</button>';
        details += '<button class="btn btn-success btn-sm" id="lookup-whitelist-btn" data-ip="' + CSM.esc(ip) + '">Permanent whitelist</button>';
        details += '</div>';
        resultEl.innerHTML = details;

        var unbanBtn = document.getElementById('lookup-unban-btn');
        if (unbanBtn) {
            unbanBtn.addEventListener('click', function() { unbanEverywhere(this.getAttribute('data-ip')); });
        }
        document.getElementById('lookup-clear-btn').addEventListener('click', function() {
            clearThreatState(this.getAttribute('data-ip'));
        });
        document.getElementById('lookup-allow-btn').addEventListener('click', function() {
            whitelistIP(this.getAttribute('data-ip'), '24');
        });
        document.getElementById('lookup-cphulk-btn').addEventListener('click', function() {
            flushCphulkOnly(this.getAttribute('data-ip'));
        });
        document.getElementById('lookup-whitelist-btn').addEventListener('click', function() {
            whitelistIP(this.getAttribute('data-ip'), 'permanent');
        });
    }).catch(function() {
        resultEl.innerHTML = '<div class="text-danger">Lookup failed. Try again.</div>';
    });
}

function removeSubnet(cidr) {
    CSM.confirm('Remove subnet block ' + cidr + '?').then(function() {
        CSM.post('/api/v1/firewall/remove-subnet', { cidr: cidr }).then(function() {
            loadSubnets();
            loadStatus();
            loadAudit();
        }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(err) {
        if (err) CSM.toast(err.message || 'Request failed', 'error');
    });
}

function unblockIP(ip) {
    CSM.confirm('Unblock ' + ip + '?').then(function() {
        CSM.post('/api/v1/unblock-ip', { ip: ip }).then(function() {
            refreshFirewallData();
        }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(err) {
        if (err) CSM.toast(err.message || 'Request failed', 'error');
    });
}

function unbanEverywhere(ip) {
    CSM.confirm('Unban ' + ip + ' from CSM and cPHulk?').then(function() {
        CSM.post('/api/v1/firewall/unban', { ip: ip }).then(function(data) {
            var msg = 'Removed lockouts for ' + ip;
            if (data.subnet_removed) msg += ' (also removed subnet ' + data.subnet_removed + ')';
            CSM.toast(msg, 'success');
            refreshFirewallData();
            loadLookup(ip);
        }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(err) {
        if (err) CSM.toast(err.message || 'Request failed', 'error');
    });
}

function bulkUnblock() {
    var checked = getVisibleChecked();
    if (checked.length === 0) return;
    var ips = [];
    checked.forEach(function(cb) { ips.push(cb.dataset.ip); });
    CSM.confirm('Unblock ' + ips.length + ' visible IPs?').then(function() {
        CSM.post('/api/v1/unblock-bulk', { ips: ips }).then(function(data) {
            CSM.toast('Unblocked ' + (data.succeeded || 0) + ' of ' + (data.total || 0) + ' IPs', 'success');
            refreshFirewallData();
        }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(err) {
        if (err) CSM.toast(err.message || 'Request failed', 'error');
    });
}

function removeAllowRule(ip) {
    CSM.confirm('Remove allow rule for ' + ip + '?').then(function() {
        CSM.post('/api/v1/firewall/remove-allow', { ip: ip }).then(function() {
            CSM.toast('Allow rule removed', 'success');
            loadAllowed();
            loadStatus();
            loadAudit();
        }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(err) {
        if (err) CSM.toast(err.message || 'Request failed', 'error');
    });
}

function clearThreatState(ip) {
    CSM.confirm('Clear firewall and threat state for ' + ip + ' without whitelisting it?').then(function() {
        CSM.post('/api/v1/threat/clear-ip', { ip: ip }).then(function() {
            CSM.toast('Threat state cleared', 'success');
            refreshFirewallData();
            loadLookup(ip);
        }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(err) {
        if (err) CSM.toast(err.message || 'Request failed', 'error');
    });
}

function flushCphulkOnly(ip) {
    CSM.confirm('Flush cPHulk login history for ' + ip + ' without changing firewall state?').then(function() {
        CSM.post('/api/v1/firewall/cphulk-clear', { ip: ip }).then(function() {
            CSM.toast('cPHulk history cleared', 'success');
            loadAudit();
            loadLookup(ip);
        }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(err) {
        if (err) CSM.toast(err.message || 'Request failed', 'error');
    });
}

function whitelistIP(ip, durationHours, onSuccess) {
    var permanent = !durationHours || durationHours === 'permanent';
    var confirmMsg = permanent
        ? 'Whitelist ' + ip + ' permanently?\n\nThis will unblock the IP, add a firewall allow rule, and prevent future auto-blocking.'
        : 'Temporarily whitelist ' + ip + ' for ' + durationHours + ' hours?';
    CSM.confirm(confirmMsg).then(function() {
        var endpoint = permanent ? '/api/v1/threat/whitelist-ip' : '/api/v1/threat/temp-whitelist-ip';
        var payload = permanent ? { ip: ip } : { ip: ip, hours: parseInt(durationHours, 10) };
        CSM.post(endpoint, payload).then(function() {
            CSM.toast(permanent ? 'IP whitelisted' : 'Temporary whitelist added', 'success');
            refreshFirewallData();
            if (onSuccess) onSuccess();
        }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(err) {
        if (err) CSM.toast(err.message || 'Request failed', 'error');
    });
}

function removeWhitelist(ip) {
    CSM.confirm('Remove ' + ip + ' from whitelist?').then(function() {
        CSM.post('/api/v1/threat/unwhitelist-ip', { ip: ip }).then(function() {
            CSM.toast('Removed from whitelist', 'success');
            loadWhitelist();
            loadStatus();
            loadAllowed();
        }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(err) {
        if (err) CSM.toast(err.message || 'Request failed', 'error');
    });
}

function flushBlocked() {
    CSM.confirm('Flush all blocked IPs?\n\nSubnet bans and allow rules will remain in place.').then(function() {
        CSM.post('/api/v1/firewall/flush', {}).then(function() {
            CSM.toast('Blocked IPs flushed', 'success');
            refreshFirewallData();
        }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(err) {
        if (err) CSM.toast(err.message || 'Request failed', 'error');
    });
}

function refreshFirewallData() {
    loadStatus();
    loadBlocked();
    loadAllowed();
    loadSubnets();
    loadWhitelist();
    loadAudit();
}

function getVisibleChecked() {
    var all = document.querySelectorAll('.blocked-cb:checked');
    var visible = [];
    all.forEach(function(cb) {
        if (cb.closest('tr').style.display !== 'none') visible.push(cb);
    });
    return visible;
}

function updateBulkUnblock() {
    var checked = getVisibleChecked();
    var btn = document.getElementById('bulk-unblock-btn');
    if (!btn) return;
    btn.classList.toggle('d-none', checked.length === 0);
    btn.textContent = 'Unblock ' + checked.length + ' IPs';
}

function enrichGeoIP(container) {
    var cells = container.querySelectorAll('.geo-cell');
    if (cells.length === 0) return;

    var ips = [];
    var cellMap = {};
    for (var i = 0; i < cells.length; i++) {
        var ip = cells[i].dataset.ip;
        if (!ip) continue;
        ips.push(ip);
        cellMap[ip] = cellMap[ip] || [];
        cellMap[ip].push(cells[i]);
    }
    if (ips.length === 0) return;

    CSM.post('/api/v1/geoip/batch', { ips: ips }).then(function(data) {
        var results = data.results || {};
        for (var ip in results) {
            var html = formatGeo(results[ip]);
            var targets = cellMap[ip] || [];
            for (var j = 0; j < targets.length; j++) {
                targets[j].innerHTML = html;
            }
        }
    }).catch(function() {
        enrichGeoIPFallback(cells);
    });
}

function enrichGeoIPFallback(cells) {
    var idx = 0;
    function next() {
        if (idx >= cells.length) return;
        var cell = cells[idx++];
        var ip = cell.dataset.ip;
        if (!ip) {
            next();
            return;
        }
        fetch(CSM.apiUrl('/api/v1/geoip?ip=' + encodeURIComponent(ip)), { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(geo) { cell.innerHTML = formatGeo(geo); })
            .catch(function() { cell.textContent = '-'; })
            .finally(function() { setTimeout(next, 50); });
    }
    for (var c = 0; c < 3 && c < cells.length; c++) next();
}

function updateTrustForm() {
    var modeEl = document.getElementById('trust-mode');
    var durationEl = document.getElementById('trust-duration');
    var durationGroupEl = document.getElementById('trust-duration-group');
    var reasonEl = document.getElementById('trust-reason');
    var reasonGroupEl = document.getElementById('trust-reason-group');
    var helpEl = document.getElementById('trust-help');
    var submitEl = document.getElementById('trust-submit-btn');
    if (!modeEl || !durationEl || !durationGroupEl || !reasonEl || !reasonGroupEl || !helpEl || !submitEl) return;

    var mode = modeEl.value || 'firewall';
    if (mode === 'trusted') {
        durationEl.innerHTML = [
            '<option value="permanent">Permanent trusted IP</option>',
            '<option value="24">Temporary trusted IP: 24 hours</option>',
            '<option value="168">Temporary trusted IP: 7 days</option>'
        ].join('');
        durationGroupEl.className = 'col-lg-8';
        reasonGroupEl.classList.add('d-none');
        reasonEl.value = '';
        submitEl.innerHTML = '<i class="ti ti-shield-check"></i>&nbsp;Trust IP';
        helpEl.textContent = 'Trusted IP clears current blocks, adds a firewall allow, and prevents future auto-blocking until it expires or is removed.';
        return;
    }

    durationEl.innerHTML = [
        '<option value="24h">24 hours</option>',
        '<option value="7d">7 days</option>',
        '<option value="30d">30 days</option>',
        '<option value="0">Permanent</option>'
    ].join('');
    durationGroupEl.className = 'col-lg-4';
    reasonGroupEl.classList.remove('d-none');
    reasonEl.placeholder = 'Reason for firewall allow rule';
    submitEl.innerHTML = '<i class="ti ti-shield-up"></i>&nbsp;Add allow rule';
    helpEl.textContent = 'Firewall allow rules bypass only the firewall. Threat systems may still flag or clear the IP separately.';
}

document.getElementById('block-form').addEventListener('submit', function(e) {
    e.preventDefault();
    var target = document.getElementById('block-target').value.trim();
    var reason = document.getElementById('block-reason').value.trim() || 'Blocked via CSM Web UI';
    var duration = document.getElementById('block-duration').value;
    if (!target) return;

    var isSubnet = target.indexOf('/') !== -1;
    if (!isSubnet && !CSM.validateIP(target)) {
        CSM.toast('Invalid IP address format', 'error');
        return;
    }

    var confirmLabel = isSubnet ? 'subnet ' + target : 'IP ' + target;
    var endpoint = isSubnet ? '/api/v1/firewall/deny-subnet' : '/api/v1/block-ip';
    var payload = isSubnet
        ? { cidr: target, reason: reason, duration: duration }
        : { ip: target, reason: reason, duration: duration };

    CSM.confirm('Block ' + confirmLabel + '?').then(function() {
        CSM.post(endpoint, payload).then(function() {
            document.getElementById('block-target').value = '';
            document.getElementById('block-reason').value = '';
            if (isSubnet) {
                loadSubnets();
                loadStatus();
                loadAudit();
                return;
            }
            refreshFirewallData();
        }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(err) {
        if (err) CSM.toast(err.message || 'Request failed', 'error');
    });
});

document.getElementById('trust-form').addEventListener('submit', function(e) {
    e.preventDefault();
    var ip = document.getElementById('trust-ip').value.trim();
    var mode = document.getElementById('trust-mode').value;
    var duration = document.getElementById('trust-duration').value;
    var reason = document.getElementById('trust-reason').value.trim() || 'Allowed via CSM Web UI';
    if (!ip) return;
    if (!CSM.validateIP(ip)) {
        CSM.toast('Invalid IP address format', 'error');
        return;
    }

    if (mode === 'trusted') {
        whitelistIP(ip, duration, function() {
            document.getElementById('trust-ip').value = '';
            updateTrustForm();
        });
        return;
    }

    CSM.confirm('Add firewall allow rule for ' + ip + '?').then(function() {
        CSM.post('/api/v1/firewall/allow-ip', { ip: ip, reason: reason, duration: duration }).then(function() {
            document.getElementById('trust-ip').value = '';
            document.getElementById('trust-reason').value = '';
            loadAllowed();
            loadBlocked();
            loadStatus();
            loadAudit();
        }).catch(function(e) { CSM.toast('Error: ' + e, 'error'); });
    }).catch(function(err) {
        if (err) CSM.toast(err.message || 'Request failed', 'error');
    });
});

document.getElementById('lookup-form').addEventListener('submit', function(e) {
    e.preventDefault();
    var ip = document.getElementById('lookup-ip').value.trim();
    if (!ip) return;
    if (!CSM.validateIP(ip)) {
        CSM.toast('Invalid IP address format', 'error');
        return;
    }
    loadLookup(ip);
});

var bulkUnblockBtn = document.getElementById('bulk-unblock-btn');
if (bulkUnblockBtn) bulkUnblockBtn.addEventListener('click', bulkUnblock);

var flushBtn = document.getElementById('flush-blocked-btn');
if (flushBtn) flushBtn.addEventListener('click', flushBlocked);

var refreshBtn = document.getElementById('firewall-refresh-btn');
if (refreshBtn) refreshBtn.addEventListener('click', refreshFirewallData);

var trustMode = document.getElementById('trust-mode');
if (trustMode) {
    trustMode.addEventListener('change', updateTrustForm);
    updateTrustForm();
}

var auditResetBtn = document.getElementById('audit-reset-btn');
if (auditResetBtn) {
    auditResetBtn.addEventListener('click', function() {
        document.getElementById('audit-search').value = '';
        document.getElementById('audit-action-filter').value = 'all';
        document.getElementById('audit-source-filter').value = 'all';
        document.getElementById('audit-search').dispatchEvent(new Event('input', { bubbles: true }));
        document.getElementById('audit-action-filter').dispatchEvent(new Event('change', { bubbles: true }));
        document.getElementById('audit-source-filter').dispatchEvent(new Event('change', { bubbles: true }));
    });
}

(function() {
    var cols = [
        { key: 'ip', label: 'IP' },
        { key: 'reason', label: 'Reason' },
        { key: 'source', label: 'Source' },
        { key: 'blocked_at', label: 'Blocked At' },
        { key: 'expires', label: 'Expires' }
    ];
    document.querySelectorAll('[data-export]').forEach(function(el) {
        el.addEventListener('click', function(e) {
            e.preventDefault();
            CSM.exportTable(_fwBlockedData, cols, this.getAttribute('data-export'), 'csm-firewall-blocked');
        });
    });
})();

refreshFirewallData();
