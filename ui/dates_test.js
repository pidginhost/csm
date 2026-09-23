// Run with: node --test ui/dates_test.js
// Absolute dates follow the operator's time zone preference on every page.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, items, SHARED, settle } = require('./pagekit.js');

// A zone no test machine runs in, so a date formatted in the browser zone
// cannot pass by accident.
const ZONE = { 'csm-prefs': JSON.stringify({ timezone: 'Pacific/Chatham' }) };
const AT = '2026-09-23T00:00:00Z';
const IN_ZONE = '2026-09-23 12:45';

function firewallPage() {
    return loadPage(templateBody('firewall'), SHARED.concat(['firewall.js']), { storage: ZONE });
}

test('firewall audit dates follow the time zone preference', async () => {
    const page = firewallPage();
    page.respond('/api/v1/firewall/audit', 200, items([
        { timestamp: AT, action: 'block', ip: '203.0.113.9', reason: 'scanner', source: 'auto_block', time_ago: '1h ago' }
    ]));
    await settle();
    const cell = page.document.querySelector('#firewall-audit-table tbody td');
    assert.ok(cell, 'audit table not rendered');
    assert.ok(cell.textContent.includes(IN_ZONE), 'got ' + cell.textContent);
    assert.equal(cell.getAttribute('data-timestamp'), AT, 'sort key must stay the raw instant');
    assert.ok(cell.querySelector('[data-time-ago="' + AT + '"]'), 'relative time must tick on the page');
});

test('recent challenges show when they happened in the time zone preference', async () => {
    const page = firewallPage();
    page.respond('/api/v1/challenge/stats', 200, { recent: [{ at: AT, ip: '203.0.113.9', check: 'waf' }] });
    await settle();
    const cell = page.document.querySelector('#fw-chal-recent td');
    assert.ok(cell.textContent.includes(IN_ZONE), 'got ' + cell.textContent);
});

test('hardening last run follows the time zone preference', async () => {
    const page = loadPage(templateBody('hardening'), SHARED.concat(['hardening.js']), { storage: ZONE });
    page.respond('/api/v1/hardening', 200, {
        timestamp: AT, server_type: 'bare', score: 1, total: 1,
        results: [{ category: 'ssh', name: 'root login', status: 'pass', message: 'ok' }]
    });
    await settle();
    const text = page.document.getElementById('audit-timestamp').textContent;
    assert.ok(text.includes(IN_ZONE), 'got ' + text);
});

test('server-rendered dates are rewritten in the time zone preference', async () => {
    const page = loadPage('<table><tr><td><time data-csm-date datetime="' + AT + '">2026-09-23 03:00:00</time></td></tr></table>',
        SHARED, { storage: ZONE });
    await settle();
    const el = page.document.querySelector('time');
    assert.ok(el.textContent.startsWith(IN_ZONE), 'got ' + el.textContent);
});
