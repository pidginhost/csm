// Run with: node --test ui/actions_test.js
// An action that did not happen answers with an error status and a reason;
// the page shows that reason and never reports the action as done.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

function recordToasts(page) {
    const toasts = [];
    page.window.CSM.toast = (message, kind) => { toasts.push({ message, kind }); };
    page.window.CSM.confirm = () => Promise.resolve();
    return toasts;
}

test('a failed unban shows the server reason and no success', async () => {
    const page = loadPage(templateBody('firewall'), SHARED.concat(['firewall.js']),
        { url: 'https://csm.example.test/firewall?ip=203.0.113.9' });
    const toasts = recordToasts(page);
    await settle();
    page.respond('/api/v1/firewall/check?ip=203.0.113.9', 200,
        { success: true, ip: '203.0.113.9', permanent: 'scanner', temporary: null, cphulk: false });
    page.respond('/api/v1/geoip?ip=203.0.113.9', 200, {});
    await settle();
    page.document.querySelector('.lookup-unban-btn').click();
    await settle();
    page.respond('/api/v1/firewall/unban', 400, { error: 'invalid IP address: 203.0.113.9x' });
    await settle();
    assert.ok(toasts.some(t => t.kind === 'error' && /invalid IP address/.test(t.message)), JSON.stringify(toasts));
    assert.ok(!toasts.some(t => t.kind === 'success'), 'a failed unban was reported as done');
});

test('a fix that did not apply shows why and allows a retry', async () => {
    const page = loadPage(templateBody('findings'), SHARED.concat(['findings.js']));
    const toasts = recordToasts(page);
    page.respond('/api/v1/findings/enriched', 200, { findings: [{
        key: 'webshell:x', severity: 'HIGH', check: 'webshell', message: 'x', has_fix: true,
        first_seen: '2026-09-22T10:00:00Z', last_seen: '2026-09-22T10:00:00Z'
    }], total: 1 });
    await settle();
    const btn = page.document.querySelector('.fix-btn');
    btn.click();
    await settle();
    page.respond('/api/v1/fix', 422, { error: 'file changed since the scan' });
    await settle();
    assert.ok(toasts.some(t => t.kind === 'error' && /Fix failed: file changed since the scan/.test(t.message)), JSON.stringify(toasts));
    assert.equal(page.document.querySelector('.fix-btn').disabled, false, 'the fix button stayed locked');
});

test('a test alert the channel refused is reported as failed', async () => {
    const page = loadPage(templateBody('rules'), SHARED.concat(['rules.js']));
    const toasts = recordToasts(page);
    await settle();
    page.document.getElementById('btn-test-alert').click();
    await settle();
    page.respond('/api/v1/test-alert', 502, { error: 'Alert delivery failed: smtp down' });
    await settle();
    assert.ok(toasts.some(t => t.kind === 'error' && /smtp down/.test(t.message)), JSON.stringify(toasts));
    assert.ok(!toasts.some(t => t.kind === 'success'));
});

test('an import reports what it imported and what it skipped', async () => {
    const bundle = JSON.stringify({ suppressions: [], whitelist: [{ ip: '203.0.113.10', permanent: true }] });
    function FakeReader() {}
    FakeReader.prototype.readAsText = function () { this.onload({ target: { result: bundle } }); };
    const page = loadPage(templateBody('rules'), SHARED.concat(['rules.js']), { globals: { FileReader: FakeReader } });
    const toasts = recordToasts(page);
    await settle();
    const input = page.document.getElementById('import-file');
    Object.defineProperty(input, 'files', { value: [{ name: 'state.json' }] });
    input.dispatchEvent(new page.window.Event('change'));
    await settle();
    page.respond('/api/v1/import', 200, { ok: true, imported: 1, skipped: 2 });
    await settle();
    assert.ok(toasts.some(t => /1 imported, 2 skipped/.test(t.message)), JSON.stringify(toasts));
});
