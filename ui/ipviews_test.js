// Run with: node --test ui/ipviews_test.js
// Firewall is where an operator acts on an address and keeps the allow list;
// Threat Intel explains an address. Each page links to the other's view of
// the same IP instead of repeating it.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

const chartStub = { Chart: function () { return { destroy() {}, update() {} }; } };

function threatPage(url) {
    return loadPage(templateBody('threat'), SHARED.concat(['threat.js']),
        { url: url || 'https://csm.example.test/threat', globals: chartStub });
}

test('Threat Intel does not keep its own copy of the allow list', async () => {
    const page = threatPage();
    await settle();
    assert.equal(page.document.getElementById('wl-tbody'), null, 'whitelist table still on Threat Intel');
    assert.equal(page.document.getElementById('add-wl-form'), null, 'whitelist form still on Threat Intel');
    assert.equal(page.pending('/api/v1/threat/whitelist').length, 0, 'Threat Intel still loads the whitelist');
    assert.ok(page.document.querySelector('a[href="/firewall?view=allow"]'), 'no link to the allow list on Firewall');
});

test('a whitelist action on Threat Intel still reaches the server', async () => {
    const page = threatPage();
    await settle();
    page.window.CSM.confirm = () => Promise.resolve();
    page.respond('/api/v1/threat/top-attackers', 200, [{ ip: '203.0.113.9', event_count: 1, verdict: 'suspicious' }]);
    await settle();
    page.document.querySelector('.quick-wl-btn[data-ip="203.0.113.9"]').click();
    await settle();
    const req = page.respond('/api/v1/threat/whitelist-ip', 200, { actions: [] });
    assert.equal(req.body.ip, '203.0.113.9');
    await settle();
    assert.equal(page.pending('/api/v1/threat/whitelist').length, 0);
});

test('a Threat Intel lookup links to the Firewall view of the address', async () => {
    const page = threatPage('https://csm.example.test/threat?ip=203.0.113.9');
    await settle();
    page.respond('/api/v1/threat/ip?ip=203.0.113.9', 200,
        { ip: '203.0.113.9', verdict: 'clean', unified_score: 0, local_score: 0, abuse_score: -1 });
    page.respond('/api/v1/threat/events?ip=203.0.113.9', 200, []);
    await settle();
    const result = page.document.getElementById('tr-lookup-result');
    assert.ok(result.querySelector('a[href="/firewall?ip=203.0.113.9"]'), 'no Firewall link in the lookup result');
});

test('a Firewall lookup links to the Threat Intel view of the address', async () => {
    const page = loadPage(templateBody('firewall'), SHARED.concat(['firewall.js']),
        { url: 'https://csm.example.test/firewall?ip=203.0.113.9' });
    await settle();
    page.respond('/api/v1/firewall/check?ip=203.0.113.9', 200, { success: true });
    page.respond('/api/v1/geoip?ip=203.0.113.9', 200, {});
    await settle();
    const result = page.document.getElementById('lookup-result');
    assert.ok(result.querySelector('a[href="/threat?ip=203.0.113.9"]'), 'no Threat Intel link in the lookup result');
});

test('suppression help points at the allow list on Firewall', () => {
    const rules = templateBody('rules');
    assert.ok(!/on the Threat page/.test(rules), 'Rules page still sends operators to Threat Intel to allowlist');
    assert.ok(rules.includes('href="/firewall?view=allow"'), 'Rules page does not link the allow list');
    const docs = fs.readFileSync(path.join(__dirname, '..', 'docs', 'src', 'signatures.md'), 'utf8');
    assert.ok(!/from the Threat page/.test(docs), 'signatures.md still sends operators to Threat Intel to allowlist');
});
