const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

async function unbanPage() {
    const page = loadPage(templateBody('firewall'), SHARED.concat(['firewall.js']),
        { url: 'https://192.0.2.1/firewall?ip=203.0.113.5' });
    await settle();
    page.respond('/api/v1/firewall/check?ip=', 200,
        { ip: '203.0.113.5', permanent: 'Subnet block', cphulk: false });
    page.respond('/api/v1/geoip?ip=', 200, {});
    await settle();
    const toasts = [];
    page.window.CSM.toast = (message, kind) => toasts.push({ message, kind });
    page.window.CSM.confirm = () => Promise.resolve();
    page.document.querySelector('.lookup-unban-btn').click();
    await settle();
    assert.equal(page.pending('/api/v1/firewall/unban').length, 1);
    return { page, toasts };
}

test('unban warns when an operator subnet remains after automatic subnet removal', async () => {
    const { page, toasts } = await unbanPage();
    page.respond('/api/v1/firewall/unban', 200,
        { ok: true, subnet_removed: '203.0.113.0/24', subnet_kept: '203.0.113.0/25' });
    await settle();
    assert.equal(toasts.length, 1);
    assert.equal(toasts[0].kind, 'warning');
    assert.match(toasts[0].message, /still dropped.*203\.0\.113\.0\/25/);
    assert.match(toasts[0].message, /removed subnet 203\.0\.113\.0\/24/);
    assert.equal(page.pending('/api/v1/firewall/check?ip=').length, 1);
});

test('unban succeeds when no subnet remains', async () => {
    const { page, toasts } = await unbanPage();
    page.respond('/api/v1/firewall/unban', 200, { ok: true, subnet_removed: '203.0.113.0/24' });
    await settle();
    assert.equal(toasts.length, 1);
    assert.equal(toasts[0].kind, 'success');
    assert.doesNotMatch(toasts[0].message, /still dropped/);
});

test('subnet removal errors never show a successful unban', async () => {
    const { page, toasts } = await unbanPage();
    page.respond('/api/v1/firewall/unban', 500, { error: 'Subnet changed during unban; retry the request' });
    await settle();
    assert.equal(toasts.length, 1);
    assert.equal(toasts[0].kind, 'error');
    assert.match(toasts[0].message, /Subnet changed during unban/);
});
