// Run with: node --test ui/times_test.js
// The API sends every time as an RFC 3339 instant in UTC and every duration
// in seconds. The pages format both themselves, in the operator's zone.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, items, SHARED, RUNTIME, settle } = require('./pagekit.js');

const HOUR = 3600;
const DAY = 86400;

test('durations read as their two largest units', () => {
    const page = loadPage('', RUNTIME);
    const f = page.window.CSM.formatDuration;
    assert.equal(f(0), '0s');
    assert.equal(f(45), '45s');
    assert.equal(f(60), '1m');
    assert.equal(f(125), '2m 5s');
    assert.equal(f(HOUR), '1h');
    assert.equal(f(HOUR + 30 * 60), '1h 30m');
    assert.equal(f(DAY), '1d');
    assert.equal(f(DAY + HOUR + 61), '1d 1h');
    assert.equal(f(4 * DAY), '4d');
    assert.equal(f(1.6), '1s');
    for (const bad of [null, undefined, '', 'x', -5, NaN]) assert.equal(f(bad), '', String(bad));
});

// Sub-second digits vary in length ("05Z", "05.12Z", "05.5Z"); as text they
// sort 05.12, 05.5, 05. Times sort as instants.
test('tables sort time columns as instants', () => {
    const rows = ['2026-09-22T10:04:05.5Z', '2026-09-22T10:04:05Z', '2026-09-22T10:04:05.12Z']
        .map(ts => '<tr><td data-timestamp="' + ts + '">' + ts + '</td></tr>').join('');
    const page = loadPage('<table id="t"><thead><tr><th>When</th></tr></thead><tbody>' + rows + '</tbody></table>',
        RUNTIME.concat(['table.js']));
    page.run('window.__t = new CSM.Table({ tableId: "t", perPage: 25 }); __t.sortColumn = 0; __t.sortAsc = true; __t.applySort(); __t._orderRows();');
    const order = page.document.querySelectorAll('#t tbody tr').map(r => r.textContent);
    assert.deepEqual(order, ['2026-09-22T10:04:05Z', '2026-09-22T10:04:05.12Z', '2026-09-22T10:04:05.5Z']);
});

const chart = function () { return { destroy() {}, update() {}, data: { datasets: [] }, options: {} }; };
chart.defaults = new Proxy({}, { get(t, k) { if (typeof k === 'symbol') return t[k]; if (!(k in t)) t[k] = chart.defaults; return t[k]; } });
chart.instances = {};

// answerAll answers every request: bodies by URL fragment, lists empty.
async function answerAll(page, bodies) {
    for (let round = 0; round < 8; round++) {
        const pending = page.pending().filter(r => !r.settled);
        if (pending.length === 0) break;
        for (const req of pending) {
            const hit = Object.keys(bodies).find(k => req.url.includes(k));
            page.respond(req.url, 200, hit ? bodies[hit] : items([]));
        }
        await settle();
    }
}

function ago(seconds) {
    return new Date(Date.now() - seconds * 1000).toISOString();
}

test('the dashboard reads uptime, last critical and watcher times from instants and seconds', async () => {
    const page = loadPage(templateBody('dashboard'), SHARED.concat(['dashboard.js']), { globals: { Chart: chart } });
    await answerAll(page, {
        '/api/v1/status': { status: 'ok', uptime_seconds: 2 * DAY + 3 * HOUR, security_posture: 'healthy' },
        '/api/v1/health': { uptime_seconds: 2 * DAY + 3 * HOUR, rules_loaded: 1, log_watchers: 1 },
        '/api/v1/stats': { last_24h: { critical: 1, high: 0, warning: 0, total: 1 }, last_critical: ago(2 * HOUR) },
        '/api/v1/components': items([{ name: 'fanotify', label: 'File monitor', status: 'ok', attached: true,
            changed_at: ago(3 * HOUR), last_event_at: ago(5 * 60), last_event_check: 'webshell_realtime' }])
    });
    assert.match(page.document.getElementById('system-health-pill').getAttribute('title'), /Uptime: 2d 3h/);
    const lastCrit = page.document.getElementById('stat-last-critical');
    assert.equal(lastCrit.textContent, '2h ago');
    assert.ok(lastCrit.getAttribute('data-time-ago'), 'the last critical time does not tick');
    const matrix = page.document.getElementById('components-matrix').textContent;
    assert.match(matrix, /3h ago/);
    assert.match(matrix, /5m ago/);
});

test('the findings timeline labels each hour from its start instant', async () => {
    const labels = [];
    function Chart(el, config) { labels.push(config.data.labels); return { destroy() {}, update() {}, data: config.data, options: {} }; }
    Chart.defaults = chart.defaults;
    Chart.instances = {};
    const page = loadPage(templateBody('dashboard'), SHARED.concat(['dashboard.js']),
        { globals: { Chart }, storage: { 'csm-prefs': JSON.stringify({ timezone: 'Etc/UTC' }) } });
    const bucket = start => ({ start, critical: 0, high: 0, warning: 0, total: 0 });
    await answerAll(page, {
        '/api/v1/prefs/user': { timezone: 'Etc/UTC' },
        '/api/v1/stats/timeline': items([bucket('2026-09-22T09:00:00Z'), bucket('2026-09-22T10:00:00Z')])
    });
    assert.ok(labels.some(l => l.length === 2 && l[0] === '09:00' && l[1] === '10:00'), JSON.stringify(labels));
});

test('firewall expiry and audit lifetimes come from instants and seconds', async () => {
    const page = loadPage(templateBody('firewall'), SHARED.concat(['firewall.js']));
    const inTwoDays = new Date(Date.now() + 2 * DAY * 1000 + 60000).toISOString();
    await answerAll(page, {
        '/api/v1/blocked-ips': items([
            { ip: '203.0.113.5', reason: 'scanner', source: 'auto_block', blocked_at: ago(60), expires_at: inTwoDays },
            { ip: '203.0.113.6', reason: 'manual', source: 'web_ui', blocked_at: ago(60) }
        ]),
        '/api/v1/firewall/subnets': items([{ cidr: '198.51.100.0/24', reason: 'r', source: 'web_ui', blocked_at: ago(60), expires_at: inTwoDays }]),
        '/api/v1/firewall/audit': items([{ timestamp: ago(60), action: 'block', ip: '203.0.113.5', reason: 'r', source: 'web_ui', duration_seconds: DAY }], { limit: 50, truncated: false })
    });
    const blocked = page.document.getElementById('blocked-content').textContent;
    assert.match(blocked, /in 2d/);
    assert.match(blocked, /Permanent/);
    assert.match(page.document.getElementById('subnet-content').textContent, /in 2d/);
    assert.match(page.document.getElementById('subnets-table').querySelector('tbody tr').cells[3].textContent, /1m ago/);
    assert.match(page.document.getElementById('fw-audit-content').textContent, /1d/);
});

test('the mail queue age comes from seconds', async () => {
    const page = loadPage(templateBody('email'), SHARED.concat(['email.js']));
    page.document.dispatchEvent(new page.window.Event('DOMContentLoaded'));
    await answerAll(page, { '/api/v1/email/stats': { queue_size: 3, frozen_count: 1, oldest_age_seconds: 4 * DAY, smtp_allow_users: [], smtp_ports: [], port_flood: [], top_senders: [] } });
    assert.match(page.document.body.textContent, /4d/);
});

test('ModSecurity events and blocks show their instants', async () => {
    const page = loadPage(templateBody('modsec'), SHARED.concat(['modsec.js']));
    await answerAll(page, {
        '/api/v1/modsec/blocks': items([{ ip: '203.0.113.66', rule_id: '900112', description: 'd', domains: 'site.example.com', domain_count: 1, hits: 3,
            first_seen: ago(3 * HOUR), last_seen: ago(2 * HOUR), top_uris: [], sample_events: [], escalated: false }], { truncated: false })
    });
    assert.match(page.document.getElementById('modsec-content').textContent, /\d{4}-\d{2}-\d{2} \d{2}:\d{2}/);
    page.document.getElementById('modsec-tab-events').dispatchEvent(new page.window.Event('shown.bs.tab'));
    await answerAll(page, {
        '/api/v1/modsec/events': items([{ time: ago(5 * 60), ip: '203.0.113.67', rule_id: '900112', hostname: 'site.example.com', uri: '/x', severity: 'HIGH' }], { limit: 100, truncated: false })
    });
    assert.match(page.document.getElementById('modsec-events').textContent, /\d{4}-\d{2}-\d{2} \d{2}:\d{2}/);
    assert.match(page.document.body.textContent, /5m ago/);
});

test('a clean account scan reports how long it took', async () => {
    const page = loadPage(templateBody('findings'), SHARED.concat(['findings.js']));
    await answerAll(page, {});
    page.document.getElementById('scan-account').value = 'alice';
    page.document.getElementById('scan-form').dispatchEvent(new page.window.Event('submit'));
    await settle();
    page.respond('/api/v1/scan-account', 200, { ok: true, account: 'alice', count: 0, elapsed_seconds: 125.4 });
    await settle();
    assert.match(page.document.getElementById('scan-status').textContent, /alice is clean \(2m 5s\)/);
});

test('the verified bots range refresh interval comes from seconds', async () => {
    const page = loadPage(templateBody('verified-bots'), SHARED.concat(['verified-bots.js']));
    page.document.dispatchEvent(new page.window.Event('DOMContentLoaded'));
    await answerAll(page, { '/api/v1/verified-bots': items([], { etag: 'e', bot_ranges: { auto_update: true, update_interval_seconds: 12 * HOUR, prefixes: {} } }) });
    assert.equal(page.document.getElementById('vbots-ranges-interval').textContent, '12h');
});

// A finding stamped later within the same second is newer. As text,
// "10:04:05.5Z" sorts before "10:04:05Z", so it was taken for an old one.
test('a critical finding newer by a fraction of a second still notifies', async () => {
    const shown = [];
    function Notification(title, opts) { shown.push(opts.body); }
    Notification.permission = 'granted';
    const page = loadPage(templateBody('dashboard'), SHARED.concat(['dashboard.js']),
        { globals: { Chart: chart, Notification }, storage: { 'csm-notif': 'on' } });
    await answerAll(page, { '/api/v1/history': items([{ severity: 2, check: 'webshell', message: 'old', timestamp: '2026-09-22T10:04:05Z' }],
        { limit: 10, offset: 0, truncated: false }) });
    const raw = JSON.stringify({ severity: 2, check: 'webshell', message: 'new', timestamp: '2026-09-22T10:04:05.5Z' });
    page.window.dispatchEvent(new page.window.CustomEvent('csm:sse-message', { detail: { raw } }));
    await new Promise(r => setTimeout(r, 1700));
    assert.deepEqual(shown, ['webshell: new']);
});

test('live notifications keep every new finding in an unordered batch', async () => {
    const shown = [];
    function Notification(title, opts) { shown.push(opts.body); }
    Notification.permission = 'granted';
    const page = loadPage(templateBody('dashboard'), SHARED.concat(['dashboard.js']),
        { globals: { Chart: chart, Notification }, storage: { 'csm-notif': 'on' } });
    await answerAll(page, { '/api/v1/history': items([{ severity: 'CRITICAL', check: 'webshell', message: 'old', timestamp: '2026-09-22T10:04:05Z' }]) });
    const findings = [
        { message: 'newest', timestamp: '2026-09-22T10:04:07Z' },
        { message: 'earlier', timestamp: '2026-09-22T10:04:06Z' },
        { message: 'same instant', timestamp: '2026-09-22T10:04:07Z' }
    ].map(f => Object.assign({ severity: 'CRITICAL', check: 'webshell' }, f));
    for (const f of findings) page.window.dispatchEvent(new page.window.CustomEvent('csm:sse-message', { detail: { raw: JSON.stringify(f) } }));
    await new Promise(r => setTimeout(r, 1700));
    assert.deepEqual(shown.slice().sort(), ['webshell: earlier', 'webshell: newest', 'webshell: same instant']);
    page.window.CSM.refresh.manual();
    await answerAll(page, { '/api/v1/history': items(findings) });
    assert.equal(shown.length, 3, 'polling repeated a live notification');
});

test('the first finding after an empty history notifies', async () => {
    const shown = [];
    function Notification(title, opts) { shown.push(opts.body); }
    Notification.permission = 'granted';
    const page = loadPage(templateBody('dashboard'), SHARED.concat(['dashboard.js']),
        { globals: { Chart: chart, Notification }, storage: { 'csm-notif': 'on' } });
    await answerAll(page, {});
    const f = { severity: 'CRITICAL', check: 'webshell', message: 'first', timestamp: '2026-09-22T10:04:05Z' };
    page.window.dispatchEvent(new page.window.CustomEvent('csm:sse-message', { detail: { raw: JSON.stringify(f) } }));
    await new Promise(r => setTimeout(r, 1700));
    assert.deepEqual(shown, ['webshell: first']);
});
