// Run with: node --test ui/collections_test.js
// Every list the API returns comes as {"items": [...]} with its count and
// paging keys next to it. Each page reads its rows from items.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, items, SHARED, settle } = require('./pagekit.js');

const AT = '2026-09-22T10:00:00Z';

// answerAll answers what the page asks for until it stops asking: the
// route under test gets its body, every other list route an empty list.
async function answerAll(page, route, body) {
    for (let round = 0; round < 8; round++) {
        const pending = page.pending();
        if (pending.length === 0) break;
        for (const req of pending) {
            if (req.settled) continue;
            page.respond(req.url, 200, route(req.url) ? body : items([]));
        }
        await settle();
    }
}

const CASES = [
    { name: 'audit log', page: 'audit', scripts: ['audit.js'], route: '/api/v1/audit',
      item: { timestamp: AT, action: 'block', target: '203.0.113.41', details: 'manual' }, host: 'audit-content', text: '203.0.113.41' },
    { name: 'DB object backups', page: 'cleanup-history', scripts: ['cleanup-history.js'], route: '/api/v1/db-object-backups',
      item: { key: 'k1', account: 'alice', schema: 'alice_wp', kind: 'TRIGGER', name: 'evil_trigger', dropped_at: AT, body_bytes: 10, restored: false },
      host: 'cleanup-db-content', text: 'evil_trigger' },
    { name: 'email action groups', page: 'email', scripts: ['email.js'], route: u => u.includes('/api/v1/email/groups?') && !u.includes('auth_failure'),
      item: { kind: 'spam_outbreak', severity: 'HIGH', title: 'outbreak@example.com', summary: 'two messages', count: 2, last_seen: AT },
      host: 'email-action-groups', text: 'outbreak@example.com' },
    { name: 'email findings', page: 'email', scripts: ['email.js'], route: '/api/v1/history?',
      item: { severity: 2, check: 'email_spam_outbreak', message: 'history row message', timestamp: AT },
      host: 'email-tbody', text: 'history row message' },
    { name: 'email quarantine', page: 'email', scripts: ['email.js'], tab: 'email-tab-quarantine', route: '/api/v1/email/quarantine',
      item: { message_id: '1abcDE-000001-AB', direction: 'inbound', from: 'sender@example.org', to: ['user@example.com'], subject: 'invoice',
              quarantined_at: AT, findings: [{ filename: 'a.exe', engine: 'clamav', signature: 'Eicar-Test', severity: 'high' }] },
      host: 'quarantine-table', text: 'sender@example.org' },
    { name: 'email forwarders', page: 'email', scripts: ['email.js'], tab: 'email-tab-forwarders', route: '/api/v1/email/forwarders',
      item: { source: 'info@example.com', domain: 'example.com', owner: 'alice', destinations: [{ address: 'fwd@example.net', domain: 'example.net', provider: 'other' }],
              providers: ['other'], keep_local: false, forward_only: true, has_external: true, has_free_provider: false },
      extra: { summary: { total: 1, external: 1, free_provider: 0 } }, host: 'email-fwd-tbody', text: 'info@example.com' },
    { name: 'held forwards', page: 'email', scripts: ['email.js'], tab: 'email-tab-forwarders', route: '/api/v1/email/held',
      item: { id: 'h1', forwarder: 'held@example.com', recipient: 'x@example.net', sender: 's@example.org', reasons: ['spam'], held_at: AT, size: 100 },
      host: 'email-held-tbody', text: 'held@example.com' },
    { name: 'outbound relay abuse', page: 'email', scripts: ['email.js'], tab: 'email-tab-outbound-abuse', route: '/api/v1/email/relay-abuse',
      item: { path: '/home/alice/public_html/relay.php', path_label: 'relay.php', severity: 'HIGH', trigger_count: 3, detected_at: AT },
      extra: { limit: 20, truncated: false }, host: 'outbound-abuse-body', text: 'relay.php' },
    { name: 'blocked subnets', page: 'firewall', scripts: ['firewall.js'], route: '/api/v1/firewall/subnets',
      item: { cidr: '198.51.100.0/24', reason: 'scanner', source: 'web_ui', blocked_at: AT, expires_in: '' }, host: 'subnet-content', text: '198.51.100.0/24' },
    { name: 'whitelist', page: 'firewall', scripts: ['firewall.js'], route: '/api/v1/threat/whitelist',
      item: { ip: '203.0.113.77', permanent: true }, host: 'whitelist-content', text: '203.0.113.77' },
    { name: 'ModSecurity blocks', page: 'modsec', scripts: ['modsec.js'], route: '/api/v1/modsec/blocks',
      item: { ip: '203.0.113.66', rule_id: '900112', description: 'enumeration', domains: 'site.example.com', domain_count: 1, hits: 3,
              last_seen: '10:00:00', first_seen: AT, last_seen_iso: AT, top_uris: [], sample_events: [], escalated: false },
      extra: { truncated: false }, host: 'modsec-content', text: '203.0.113.66' },
    { name: 'ModSecurity events', page: 'modsec', scripts: ['modsec.js'], tab: 'modsec-tab-events', route: '/api/v1/modsec/events',
      item: { time: '10:00:00', time_iso: AT, ip: '203.0.113.67', rule_id: '900112', hostname: 'site.example.com', uri: '/x', severity: 'HIGH' },
      extra: { limit: 100, truncated: false }, host: 'modsec-events', text: '203.0.113.67' },
    { name: 'suppression rules', page: 'rules', scripts: ['rules.js'], route: '/api/v1/suppressions',
      item: { id: 's1', check: 'webshell', path_pattern: '/home/*/tmp/*', reason: 'vendor cache', created_at: AT },
      host: 'suppressions-content', text: '/home/*/tmp/*' },
    { name: 'incident groups', page: 'incident', scripts: ['incident.js'], tab: 'grouped-tab', click: true, route: '/api/v1/incidents/groups?',
      item: { key: 'k', kind: 'web_attack', source_kind: 'ip', source: '203.0.113.88', incident_count: 2, open_count: 2, severity_max: 'HIGH', last_seen: AT, sample_ids: [] },
      extra: { offset: 0, limit: 50, scanned_incidents: 2, truncated: false }, host: 'grouped-content', text: '203.0.113.88' },
];

for (const c of CASES) {
    test('the ' + c.name + ' list renders from items', async () => {
        const page = loadPage(templateBody(c.page), SHARED.concat(c.scripts),
            { url: 'https://csm.example.test/' + c.page, globals: { Chart: function () { return { destroy() {}, update() {} }; } } });
        page.document.dispatchEvent(new page.window.Event('DOMContentLoaded'));
        const route = typeof c.route === 'string' ? (u => u.includes(c.route)) : c.route;
        const body = items([c.item], c.extra);
        await answerAll(page, route, body);
        if (c.tab) {
            const tab = page.document.getElementById(c.tab);
            if (c.click) tab.click();
            else tab.dispatchEvent(new page.window.Event('shown.bs.tab'));
            await answerAll(page, route, body);
        }
        const host = page.document.getElementById(c.host);
        assert.ok(host, 'no #' + c.host);
        assert.ok(host.textContent.includes(c.text), c.host + ' does not show ' + c.text + ': ' + host.textContent.slice(0, 300));
    });
}

test('the incident groups footer counts groups from total', async () => {
    const page = loadPage(templateBody('incident'), SHARED.concat(['incident.js']));
    await answerAll(page, () => false, null);
    page.document.getElementById('grouped-tab').click();
    await settle();
    const group = { key: 'k', kind: 'web_attack', source_kind: 'ip', source: '203.0.113.88', incident_count: 2, open_count: 2, severity_max: 'HIGH', last_seen: AT, sample_ids: [] };
    page.respond('/api/v1/incidents/groups?', 200, { items: [group], total: 7, offset: 0, limit: 50, scanned_incidents: 9, truncated: false });
    await settle();
    assert.match(page.document.getElementById('grouped-content').parentElement.textContent, /7 groups from 9 incidents/);
});

test('check names for a new suppression come from the active findings items', async () => {
    const page = loadPage(templateBody('rules'), SHARED.concat(['rules.js']));
    await answerAll(page, u => /\/api\/v1\/findings(\?|$)/.test(u),
        items([{ severity: 'HIGH', check: 'unique_check_name', message: 'm', time: AT, first_seen: AT, last_seen: AT, has_fix: false }]));
    const offered = Array.from(page.document.getElementById('check-types').children).map(o => o.value);
    assert.deepEqual(offered, ['unique_check_name']);
});

test('account names for a scan come from the accounts items', async () => {
    const page = loadPage(templateBody('findings'), SHARED.concat(['findings.js']));
    await answerAll(page, u => u.includes('/api/v1/accounts'), items(['alice']));
    const offered = Array.from(page.document.getElementById('account-list').children).map(o => o.value);
    assert.deepEqual(offered, ['alice']);
});

test('saved views list the items the server returns', async () => {
    const page = loadPage('<div data-csm-saved-views="findings"></div>', SHARED.concat(['views.js']));
    await settle();
    page.respond('/api/v1/prefs/views?page=findings', 200, items([{ name: 'mine', page: 'findings', params: 'severity=2', updated: AT }]));
    await settle();
    assert.match(page.document.querySelector('[data-csm-saved-views]').textContent, /Views \(1\)/);
});

test('dashboard charts plot the items of the trend and timeline', async () => {
    const plotted = [];
    function Chart(el, config) { plotted.push(config.data.labels.length); return { destroy() {}, update() {}, data: config.data, options: config.options || {} }; }
    Chart.defaults = new Proxy({}, { get(t, k) { if (typeof k === 'symbol') return t[k]; if (!(k in t)) t[k] = Chart.defaults; return t[k]; } });
    Chart.instances = {};
    const page = loadPage(templateBody('dashboard'), SHARED.concat(['dashboard.js']), { globals: { Chart } });
    const hour = { hour: '10:00', critical: 1, high: 0, warning: 0, total: 1 };
    const day = { date: '2026-09-22', critical: 1, high: 0, warning: 0, total: 1 };
    for (let round = 0; round < 6; round++) {
        for (const req of page.pending()) {
            if (req.settled) continue;
            if (req.url.includes('/api/v1/stats/timeline')) page.respond(req.url, 200, items([hour, hour]));
            else if (req.url.includes('/api/v1/stats/trend')) page.respond(req.url, 200, items([day, day, day]));
            else page.respond(req.url, 200, items([]));
        }
        await settle();
    }
    assert.ok(plotted.includes(2), 'the timeline chart did not plot its items: ' + JSON.stringify(plotted));
    assert.ok(plotted.includes(3), 'the trend chart did not plot its items: ' + JSON.stringify(plotted));
});
