// Run with: node --test ui/deeplink_test.js
// Other pages link here with ?ip=; the page must act on it.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

test('Firewall opens the lookup for the address in ?ip=', async () => {
    const page = loadPage(templateBody('firewall'), SHARED.concat(['firewall.js']),
        { url: 'https://csm.example.test/firewall?ip=203.0.113.9' });
    await settle();
    assert.equal(page.document.getElementById('lookup-ip').value, '203.0.113.9');
    assert.ok(page.pending('/api/v1/firewall/check?ip=203.0.113.9').length === 1, 'no lookup request for the linked address');
});

test('Threat Intel runs the lookup for the address in ?ip=', async () => {
    const page = loadPage(templateBody('threat'), SHARED.concat(['threat.js']),
        { url: 'https://csm.example.test/threat?ip=203.0.113.9', globals: { Chart: function () { return { destroy() {}, update() {} }; } } });
    await settle();
    assert.equal(page.document.getElementById('tr-lookup-ip').value, '203.0.113.9');
    assert.ok(page.pending('203.0.113.9').length >= 1, 'no lookup request for the linked address');
});

test('a malformed ?ip= is ignored', async () => {
    const page = loadPage(templateBody('firewall'), SHARED.concat(['firewall.js']),
        { url: 'https://csm.example.test/firewall?ip=%3Cscript%3E' });
    await settle();
    assert.equal(page.document.getElementById('lookup-ip').value, '');
    assert.equal(page.pending('/api/v1/firewall/check').length, 0);
});

test('ModSecurity links to pages that read the address', () => {
    const src = fs.readFileSync(path.join(__dirname, 'static/js/modsec.js'), 'utf8');
    assert.ok(!src.includes('view=lookup'), 'Firewall has no lookup view; link with ?ip= alone');
    assert.ok(src.includes('href="/firewall?ip=\' + encodeURIComponent(b.ip)'), 'Firewall link missing');
    assert.ok(src.includes('href="/threat?ip=\' + encodeURIComponent(b.ip)'), 'Threat Intel link missing');
});
