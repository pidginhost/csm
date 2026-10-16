// Run with: node --test ui/threat_test.js
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, items, SHARED, settle } = require('./pagekit.js');

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
    page.respond('/api/v1/threat/top-attackers', 200, items(rows || []));
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

test('temporary whitelist confirmation formats duration seconds', async () => {
    const { page, log } = await threatPage([], { url: 'https://csm.example.test/threat?ip=203.0.113.9' });
    page.respond('/api/v1/threat/ip?ip=203.0.113.9', 200, { ip: '203.0.113.9', verdict: 'suspicious', unified_score: 40 });
    page.respond('/api/v1/threat/events?ip=203.0.113.9', 200, items([]));
    await settle();
    page.window.CSM.prompt = () => Promise.resolve('2');
    page.document.querySelector('.temp-wl-btn').click();
    await settle();
    page.respond('/api/v1/threat/temp-whitelist-ip', 200, { ok: true, duration_seconds: 7200, actions: [] });
    await settle();
    assert.ok(log.toasts.some(t => /temp-whitelisted for 2h\./.test(t.message)), JSON.stringify(log.toasts));
});

async function lookup(intel) {
    const { page } = await threatPage([], { url: 'https://csm.example.test/threat?ip=203.0.113.9' });
    page.respond('/api/v1/threat/ip?ip=203.0.113.9', 200, Object.assign({
        ip: '203.0.113.9', verdict: 'suspicious', unified_score: 40, local_score: 40, abuse_score: -1
    }, intel));
    page.respond('/api/v1/threat/events?ip=203.0.113.9', 200, items([]));
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
    // Nothing changed: the server answers 422 with each address's reason.
    const reason = '192.0.2.20: permanently blocked; unblock first';
    page.respond('/api/v1/threat/bulk-action', 422, { error: 'No address was changed: ' + reason, count: 0, warnings: [reason] });
    await settle();
    assert.ok(log.toasts.some(t => t.kind === 'error' && /permanently blocked/.test(t.message)), JSON.stringify(log.toasts));
    assert.ok(!log.toasts.some(t => t.kind === 'success'), 'all-refused action must not show success');
});

const BUTTONS = { block: 'bulk-block-btn', block_permanent: 'bulk-block-perm-btn', whitelist: 'bulk-whitelist-btn' };

test('bulk whitelist displays partial failures', async () => {
    const { page, log } = await threatPage([attacker('192.0.2.20'), attacker('192.0.2.21')]);
    selectAll(page);
    page.document.getElementById('bulk-whitelist-btn').click();
    await settle();
    const reason = '192.0.2.21: allow in firewall: unavailable';
    page.respond('/api/v1/threat/bulk-action', 200, { ok: true, count: 1, warnings: [reason] });
    await settle();
    assert.ok(log.toasts.some(t => t.kind === 'success' && /1 IP/.test(t.message)), JSON.stringify(log.toasts));
    assert.ok(log.toasts.some(t => t.kind === 'warning' && t.message === reason), JSON.stringify(log.toasts));
});

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

test('Spam column shows verdict counts, score and listing threshold', async () => {
    const row = attacker('198.51.100.80');
    row.mail = { spam: 3, ham: 1 };
    row.spam_score = 60;
    const { page } = await threatPage([row, attacker('198.51.100.81')]);
    const cells = page.document.querySelectorAll('#attackers-tbody tr');
    const spamCell = cells[0].querySelector('td.spam-cell');
    assert.match(spamCell.textContent, /3 spam/);
    assert.match(spamCell.textContent, /1 ham/);
    assert.match(spamCell.textContent, /score 60/);
    assert.ok(spamCell.querySelector('.badge'), 'a qualifying score shows a badge');
    assert.equal(cells[1].querySelector('td.spam-cell').textContent.trim(), '—');
});

test('Spam evidence only asks the server for spam senders', async () => {
    const { page } = await threatPage([attacker('198.51.100.82')]);
    const select = page.document.getElementById('attackers-spam');
    select.value = 'spam';
    select.dispatchEvent(new page.window.Event('change'));
    await settle();
    assert.ok(page.requests.some((r) => r.url.includes('/api/v1/threat/top-attackers') && r.url.includes('spam_only=1')));
});

test('Spam evidence filter survives a reload', async () => {
    const { page } = await threatPage([], { url: 'https://csm.example.test/threat?spam=spam' });
    assert.equal(page.document.getElementById('attackers-spam').value, 'spam');
    assert.ok(page.requests.some((r) => r.url.includes('/api/v1/threat/top-attackers') && r.url.includes('spam_only=1')));
});

test('an empty spam list does not claim there is no attack history', async () => {
    const { page } = await threatPage([], { url: 'https://csm.example.test/threat?spam=spam' });
    assert.equal(page.document.getElementById('attackers-tbody').textContent, 'No spam evidence recorded yet');
    const all = await threatPage([]);
    assert.equal(all.page.document.getElementById('attackers-tbody').textContent, 'No attack data recorded yet');
});

test('a fast spam response preserves the filter and its bookmarked value', async (t) => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const { page } = await threatPage([attacker('192.0.2.1')]);
    const select = page.document.getElementById('attackers-spam');
    for (const value of ['spam', '']) {
        select.value = value;
        select.dispatchEvent(new page.window.Event('change'));
        page.respond('/api/v1/threat/top-attackers', 200, items([attacker('198.51.100.82')]));
        await settle();
        assert.equal(select.value, value, 'rendering must not restore the previous URL value');
        assert.equal(page.pending('/api/v1/threat/top-attackers').length, 0, 'rendering must not start another load');
        t.mock.timers.tick(200);
        assert.equal(page.window.CSM.urlState.get('spam'), value);
    }
});

test('spam changes before the first response are retained', async () => {
    const page = loadPage(templateBody('threat'), SHARED.concat(['threat.js']), { globals: { Chart: chart } });
    const select = page.document.getElementById('attackers-spam');
    select.value = 'spam';
    select.dispatchEvent(new page.window.Event('change'));
    page.respond('spam_only=1', 200, items([]));
    await settle();
    assert.equal(select.value, 'spam');
    page.respond('/api/v1/threat/top-attackers', 200, items([attacker('192.0.2.1')]));
    await settle();
    assert.equal(page.document.querySelectorAll('#attackers-tbody .ip-row').length, 0, 'late all-attacker rows must stay discarded');
    assert.equal(page.pending('/api/v1/threat/top-attackers').length, 0);
});

test('restoring the spam filter from history requests the matching rows once', async () => {
    const { page } = await threatPage([attacker('192.0.2.1')]);
    for (const spam of ['spam', '']) {
        page.window.CSM.urlState.replace({ spam });
        page.window.dispatchEvent(new page.window.Event('popstate'));
        const pending = page.pending('/api/v1/threat/top-attackers');
        assert.equal(pending.length, 1);
        assert.equal(pending[0].url.includes('spam_only=1'), spam === 'spam');
        page.respond('/api/v1/threat/top-attackers', 200, items([attacker('198.51.100.82')]));
        await settle();
        assert.equal(page.document.getElementById('attackers-spam').value, spam);
        assert.equal(page.pending('/api/v1/threat/top-attackers').length, 0);
    }
});

test('changing the spam filter retires rows and exports until a successful load', async () => {
    const { page } = await threatPage([attacker('192.0.2.1')]);
    const exported = [];
    page.window.CSM.exportTable = rows => exported.push(Array.from(rows));
    const select = page.document.getElementById('attackers-spam');
    select.value = 'spam';
    select.dispatchEvent(new page.window.Event('change'));
    assert.equal(page.document.querySelectorAll('#attackers-tbody .ip-row').length, 0, 'old rows must not remain actionable under the new filter');
    page.document.querySelector('[data-export="json"]').click();
    assert.deepEqual(exported[0], []);
    selectAll(page);
    page.document.getElementById('bulk-block-perm-btn').click();
    await settle();
    assert.equal(posts(page, '/api/v1/threat/bulk-action').length, 0);

    page.respond('spam_only=1', 503, { error: 'temporarily unavailable' });
    await settle();
    page.document.querySelector('.csm-retry-btn').click();
    assert.equal(page.document.querySelectorAll('#attackers-tbody .ip-row').length, 0, 'retry must not reveal old rows');
    page.respond('spam_only=1', 200, items([attacker('198.51.100.82')]));
    await settle();
    page.document.querySelector('[data-export="json"]').click();
    assert.deepEqual(exported[1].map(row => row.ip), ['198.51.100.82']);
});

test('refreshing the same filter keeps rows in place until their replacement arrives', async () => {
    const { page } = await threatPage([attacker('192.0.2.1')]);
    const row = page.document.querySelector('#attackers-tbody .ip-row');
    page.window.CSM.refresh.manual();
    assert.equal(page.pending('/api/v1/threat/top-attackers').length, 1);
    assert.equal(page.document.querySelector('#attackers-tbody .ip-row'), row, 'refresh must not collapse the table and lose its scroll position');
    page.respond('/api/v1/threat/top-attackers', 200, items([attacker('198.51.100.82')]));
    await settle();
    assert.equal(page.document.querySelector('#attackers-tbody .ip-row').getAttribute('data-ip'), '198.51.100.82');
});

test('the Spam column sorts numerically by spam score', async () => {
    const low = Object.assign(attacker('198.51.100.83'), { mail: { spam: 2, ham: 0 }, spam_score: 50 });
    const high = Object.assign(attacker('198.51.100.84'), { mail: { spam: 10, ham: 0 }, spam_score: 83 });
    const { page } = await threatPage([high, low, attacker('198.51.100.85')]);
    const header = Array.from(page.document.querySelectorAll('#attackers-table th')).find(th => th.textContent === 'Spam');
    const ips = () => Array.from(page.document.querySelectorAll('#attackers-tbody .ip-row'), row => row.getAttribute('data-ip'));
    header.click();
    assert.deepEqual(ips(), ['198.51.100.85', '198.51.100.83', '198.51.100.84']);
    header.click();
    assert.deepEqual(ips(), ['198.51.100.84', '198.51.100.83', '198.51.100.85']);
});

test('a spam score alone does not claim an active IP map listing', async () => {
    const rows = [49, 50].map((score, i) => Object.assign(attacker('198.51.100.' + (86 + i)), {
        mail: { spam: 2, ham: 0 }, spam_score: score
    }));
    const { page } = await threatPage(rows);
    const cells = page.document.querySelectorAll('td.spam-cell');
    assert.equal(cells[0].querySelector('.badge'), null);
    const badge = cells[1].querySelector('.badge');
    assert.equal(badge.textContent, 'Listing threshold');
    assert.match(badge.getAttribute('title'), /feed.*exclusions/);
});

test('IP detail lists mail login attacks and spam verdicts', async () => {
    const { page } = await threatPage([], { url: 'https://csm.example.test/threat?ip=203.0.113.90' });
    page.respond('/api/v1/threat/ip?ip=203.0.113.90', 200, {
        ip: '203.0.113.90', verdict: 'suspicious', unified_score: 40, spam_score: 50,
        attack_record: { event_count: 1, attack_counts: {}, accounts: {},
            mail: { auth_attacks: 4, last_auth_attack: '2026-10-16T10:00:00Z', spam: 2, ham: 0 } }
    });
    page.respond('/api/v1/threat/events?ip=203.0.113.90', 200, items([]));
    await settle();
    const text = page.document.body.textContent;
    assert.match(text, /Mail login attacks/);
    assert.match(text, /Spam verdicts/);
    assert.match(text, /2 spam, 0 ham, score 50/);
});
