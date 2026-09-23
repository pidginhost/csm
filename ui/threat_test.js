// Run with: node --test ui/threat_test.js
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

function autoObject() {
    return new Proxy({}, { get(t, k) { if (typeof k === 'symbol') return t[k]; if (!(k in t)) t[k] = autoObject(); return t[k]; } });
}
const chart = function () { return { destroy() {}, update() {}, data: { datasets: [] }, options: {} }; };
chart.defaults = autoObject();

// attacker is one Top Attackers row. Rows in country RO stay visible when
// the country filter is set to RO; rows in US are hidden by it.
function attacker(ip, country) {
    return { ip, country: country || 'RO', verdict: 'malicious', unified_score: 90, event_count: 3, last_seen: '2026-09-22T10:00:00Z' };
}

// threatPage loads Threat Intel with the given Top Attackers rows, all on one
// page of the table, and records confirms, toasts and undo offers.
async function threatPage(rows, opts = {}) {
    const page = loadPage(templateBody('threat'), SHARED.concat(['threat.js']), {
        url: opts.url || 'https://csm.example.test/threat',
        storage: { 'csm-threat-attackers': JSON.stringify({ perPage: 0 }) },
        globals: { Chart: chart }
    });
    const log = { confirms: [], toasts: [], undo: [] };
    page.window.CSM.confirm = (message) => {
        log.confirms.push(message);
        return opts.cancel ? Promise.reject(new Error('cancelled')) : Promise.resolve();
    };
    page.window.CSM.toast = (message, kind) => { log.toasts.push({ message, kind }); };
    page.window.CSM.undo = { offer(entry) { log.undo.push(entry); } };
    page.respond('/api/v1/threat/stats', 200, {});
    page.respond('/api/v1/threat/top-attackers', 200, rows || []);
    await settle();
    return { page, log };
}

function selectAll(page) {
    const all = page.document.getElementById('select-all-attackers');
    all.checked = true;
    all.dispatchEvent(new page.window.Event('change'));
}

// showOnly narrows the table to one country with the country filter.
async function showOnly(page, country) {
    const filter = page.document.getElementById('attackers-country');
    filter.value = country;
    filter.dispatchEvent(new page.window.Event('change'));
    await settle();
}

const posts = (page, url) => page.requests.filter(r => r.method === 'POST' && r.url.includes(url));

async function lookup(intel) {
    const { page } = await threatPage([], { url: 'https://csm.example.test/threat?ip=203.0.113.9' });
    page.respond('/api/v1/threat/ip?ip=203.0.113.9', 200, Object.assign({
        ip: '203.0.113.9', verdict: 'suspicious', unified_score: 40, local_score: 40, abuse_score: -1
    }, intel));
    page.respond('/api/v1/threat/events?ip=203.0.113.9', 200, []);
    await settle();
    return { html: page.document.getElementById('tr-lookup-result').innerHTML, CSM: page.window.CSM };
}

test('lookup explains a permanent threat entry on an unblocked IP', async () => {
    const permanent = (await lookup({ in_threat_db: true, threat_db_permanent: true })).html;
    assert.match(permanent, /Not blocked/);
    assert.match(permanent, /permanent threat entry/);

    const expiring = await lookup({ in_threat_db: true, threat_db_expires_at: '2026-09-18T10:00:00Z' });
    const timed = expiring.html;
    assert.match(timed, /Not blocked/);
    assert.doesNotMatch(timed, /permanent threat entry/);
    assert.ok(timed.includes('threat entry until ' + expiring.CSM.fmtDate('2026-09-18T10:00:00Z')), 'the expiry is missing');

    const clean = (await lookup({ in_threat_db: false })).html;
    assert.match(clean, /Not blocked/);
    assert.doesNotMatch(clean, /threat entry/);
});

test('permanent block asks for confirmation and calls the permanent endpoint', async () => {
    const { page, log } = await threatPage([attacker('192.0.2.10')]);
    page.document.querySelector('.quick-block-perm-btn[data-ip="192.0.2.10"]').click();
    await settle();
    assert.match(log.confirms[0], /permanently/i);
    const req = posts(page, '/api/v1/threat/block-ip-permanent');
    assert.equal(req.length, 1);
    assert.equal(req[0].body.ip, '192.0.2.10');
});

test('24h block still calls the 24h endpoint', async () => {
    const { page } = await threatPage([attacker('192.0.2.11')]);
    page.document.querySelector('.quick-block-btn[data-ip="192.0.2.11"]').click();
    await settle();
    assert.equal(posts(page, '/api/v1/threat/block-ip').length, 1);
    assert.equal(posts(page, '/api/v1/threat/block-ip-permanent').length, 0);
});

test('cancelled permanent block sends nothing', async () => {
    const { page } = await threatPage([attacker('192.0.2.12')], { cancel: true });
    page.document.querySelector('.quick-block-perm-btn[data-ip="192.0.2.12"]').click();
    await settle();
    assert.equal(page.requests.filter(r => r.method === 'POST').length, 0);
});

test('bulk permanent block posts the permanent action', async () => {
    const { page } = await threatPage([attacker('192.0.2.1')]);
    selectAll(page);
    page.document.getElementById('bulk-block-perm-btn').click();
    await settle();
    const req = posts(page, '/api/v1/threat/bulk-action');
    assert.equal(req.length, 1, 'bulk permanent block button is not wired');
    assert.equal(req[0].body.action, 'block_permanent');
});

test('bulk timed block shows refused permanent blocks', async () => {
    const { page, log } = await threatPage([attacker('192.0.2.20')]);
    selectAll(page);
    page.document.getElementById('bulk-block-btn').click();
    await settle();
    page.respond('/api/v1/threat/bulk-action', 200, { count: 0, warnings: ['192.0.2.20: permanently blocked; unblock first'] });
    await settle();
    assert.ok(log.toasts.some(t => t.kind === 'warning' && /permanently blocked/.test(t.message)));
    assert.ok(!log.toasts.some(t => t.kind === 'success'), 'all-refused action must not show success');
});

const BUTTONS = { block: 'bulk-block-btn', block_permanent: 'bulk-block-perm-btn', whitelist: 'bulk-whitelist-btn' };

for (const action of ['block', 'block_permanent', 'whitelist']) {
    for (const count of [0, 100, 101]) {
        test('bulk ' + action + ' handles selection size ' + count, async () => {
            const rows = Array.from({ length: Math.max(count, 1) }, (_, i) => attacker('192.0.2.' + (i + 1)));
            const { page, log } = await threatPage(rows);
            if (count > 0) selectAll(page);
            page.document.getElementById(BUTTONS[action]).click();
            await settle();
            const req = posts(page, '/api/v1/threat/bulk-action');
            if (count === 100) {
                assert.equal(req.length, 1);
                assert.equal(req[0].body.ips.length, count);
                assert.equal(req[0].body.action, action);
                page.respond('/api/v1/threat/bulk-action', 200, { count, undo_token: 'test-undo' });
                await settle();
                assert.equal(log.undo.length, 1);
            } else {
                assert.equal(req.length, 0);
                assert.equal(log.confirms.length, 0);
                assert.equal(log.undo.length, 0);
                if (count > 100) assert.ok(log.toasts.some(t => /bulk limit is 100/.test(t.message)));
            }
        });
    }
}

test('bulk block acts only on selected rows the operator can see', async () => {
    const { page } = await threatPage([
        attacker('192.0.2.1'), attacker('192.0.2.2'),
        attacker('198.51.100.1', 'US'), attacker('198.51.100.2', 'US'), attacker('198.51.100.3', 'US')
    ]);
    selectAll(page);
    await showOnly(page, 'RO');
    page.document.getElementById('bulk-block-perm-btn').click();
    await settle();
    const req = posts(page, '/api/v1/threat/bulk-action');
    assert.equal(req.length, 1);
    assert.deepEqual(Array.from(req[0].body.ips), ['192.0.2.1', '192.0.2.2']);
});

test('bulk whitelist acts only on selected rows the operator can see', async () => {
    const { page } = await threatPage([
        attacker('192.0.2.1'),
        attacker('198.51.100.1', 'US'), attacker('198.51.100.2', 'US'), attacker('198.51.100.3', 'US'), attacker('198.51.100.4', 'US')
    ]);
    selectAll(page);
    await showOnly(page, 'RO');
    page.document.getElementById('bulk-whitelist-btn').click();
    await settle();
    const req = posts(page, '/api/v1/threat/bulk-action');
    assert.equal(req.length, 1);
    assert.deepEqual(Array.from(req[0].body.ips), ['192.0.2.1']);
});

test('select-all never checks rows hidden by paging or filters', async () => {
    const { page } = await threatPage([
        attacker('192.0.2.1'), attacker('192.0.2.2'),
        attacker('198.51.100.1', 'US'), attacker('198.51.100.2', 'US'), attacker('198.51.100.3', 'US')
    ]);
    await showOnly(page, 'RO');
    selectAll(page);
    const boxes = Array.from(page.document.querySelectorAll('.bulk-ip-cb'));
    assert.deepEqual(boxes.filter(cb => cb.checked).map(cb => cb.getAttribute('data-ip')).sort(), ['192.0.2.1', '192.0.2.2']);
});
