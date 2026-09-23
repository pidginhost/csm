// Run with: node --test ui/findingblock_test.js
// A finding that reports an attacker address can be blocked from its detail
// panel, as an incident can. Findings without one offer no Block.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

function finding(check, message, blockIP) {
    return {
        key: check + ':' + message, severity: 'HIGH', sev_class: 'high', check, message, block_ip: blockIP,
        first_seen: '2026-09-22T10:00:00Z', last_seen: '2026-09-22T10:00:00Z'
    };
}

async function openDetail(f) {
    const page = loadPage(templateBody('findings'), SHARED.concat(['findings.js']));
    page.respond('/api/v1/findings/enriched', 200, { findings: [f], check_types: [], accounts: [], total: 1 });
    await settle();
    page.document.querySelector('.finding-row').querySelectorAll('td')[2].click();
    await settle();
    page.respond('/api/v1/finding-detail', 200, { actions: [] });
    await settle();
    return page;
}

test('a finding with an attacker address offers Block', async () => {
    const page = await openDetail(finding('wp_login_bruteforce', 'WordPress brute force from 203.0.113.5', '203.0.113.5'));
    let asked;
    page.window.CSM.confirm = message => { asked = message; return Promise.resolve(); };
    const toasts = [];
    page.window.CSM.toast = (message, kind) => toasts.push({ message, kind });
    const btn = page.window.CSM.detailPanel.element().querySelector('[data-csm-finding-block]');
    assert.ok(btn, 'no Block button');
    assert.ok(btn.textContent.includes('203.0.113.5'));
    btn.click();
    await settle();
    assert.match(asked, /203\.0\.113\.5/);
    assert.match(asked, /permanently/);
    const req = page.respond('/api/v1/block-ip', 200, { ok: true, ip: '203.0.113.9' });
    assert.equal(req.body.ip, '203.0.113.5');
    assert.equal(req.body.duration, '0');
    assert.match(req.body.reason, /wp_login_bruteforce/);
    await settle();
    assert.ok(toasts.some(t => t.kind === 'success'), JSON.stringify(toasts));
});

test('a cancelled block sends nothing', async () => {
    const page = await openDetail(finding('wp_login_bruteforce', 'WordPress brute force from 203.0.113.5', '203.0.113.5'));
    page.window.CSM.confirm = () => Promise.reject(null);
    page.window.CSM.detailPanel.element().querySelector('[data-csm-finding-block]').click();
    await settle();
    assert.equal(page.pending('/api/v1/block-ip').length, 0);
});

test('a finding without an attacker address has no Block', async () => {
    const page = await openDetail(finding('webshell', 'shell uploaded from 203.0.113.6', ''));
    assert.equal(page.window.CSM.detailPanel.element().querySelector('[data-csm-finding-block]'), null);
});
