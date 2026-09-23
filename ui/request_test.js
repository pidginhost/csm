// Run with: node --test ui/request_test.js
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, settle, RUNTIME } = require('./pagekit.js');

function requestPage() {
    const page = loadPage('', RUNTIME);
    const toasts = [];
    page.window.CSM.toast = (message, kind) => toasts.push({ message, kind });
    page.toasts = toasts;
    return page;
}

function banner(page) {
    return !page.document.getElementById('csm-connection-lost').classList.contains('d-none');
}

test('an expired session sends the browser to the login page once', async () => {
    const page = requestPage();
    const a = page.window.CSM.get('/api/v1/stats').catch(e => e);
    const b = page.window.CSM.get('/api/v1/findings').catch(e => e);
    page.respond('/api/v1/stats', 401, { error: 'Unauthorized' });
    page.respond('/api/v1/findings', 401, { error: 'Unauthorized' });
    const [ea, eb] = await Promise.all([a, b]);
    assert.ok(ea instanceof Error && eb instanceof Error);
    assert.deepEqual(page.window.location.assigned, ['/login']);
    assert.equal(page.toasts.length, 0, 'no error toast while the page leaves for the login form');
});

test('three network failures in a row show the connection banner', async () => {
    const page = requestPage();
    for (let i = 0; i < 3; i++) {
        const p = page.window.CSM.get('/api/v1/stats', { silent: true }).catch(() => {});
        page.fail('/api/v1/stats');
        await p;
        await settle();
    }
    assert.equal(banner(page), true);
    assert.equal(page.toasts.length, 0, 'silent requests never toast');
    const ok = page.window.CSM.get('/api/v1/stats', { silent: true });
    page.respond('/api/v1/stats', 200, {});
    await ok;
    assert.equal(banner(page), false, 'a response clears the banner');
});

test('server errors count toward the banner but client errors do not', async () => {
    const page = requestPage();
    for (let i = 0; i < 3; i++) {
        const p = page.window.CSM.get('/api/v1/x', { silent: true }).catch(() => {});
        page.respond('/api/v1/x', 404, { error: 'not found' });
        await p;
    }
    assert.equal(banner(page), false, 'a 404 means the daemon answered');
    for (let i = 0; i < 3; i++) {
        const p = page.window.CSM.get('/api/v1/x', { silent: true }).catch(() => {});
        page.respond('/api/v1/x', 503, { error: 'unavailable' });
        await p;
    }
    assert.equal(banner(page), true);
});

test('writes count toward the banner too', async () => {
    const page = requestPage();
    for (let i = 0; i < 3; i++) {
        const p = page.window.CSM.post('/api/v1/dismiss', { key: 'k' }).catch(() => {});
        page.fail('/api/v1/dismiss');
        await p;
    }
    assert.equal(banner(page), true);
});

test('a daemon restart does not flood the page with the same error toast', async () => {
    const page = requestPage();
    const calls = [];
    for (let i = 0; i < 6; i++) {
        calls.push(page.window.CSM.get('/api/v1/stats').catch(() => {}));
        page.fail('/api/v1/stats');
        await settle();
    }
    await Promise.all(calls);
    assert.ok(page.toasts.length <= 1, 'got ' + page.toasts.length + ' toasts: ' + JSON.stringify(page.toasts));
});

test('a real error from a reachable daemon still shows its message', async () => {
    const page = requestPage();
    const p = page.window.CSM.get('/api/v1/x').catch(() => {});
    page.respond('/api/v1/x', 400, { error: 'IP is required' });
    await p;
    assert.deepEqual(page.toasts.map(t => t.message), ['Request failed: IP is required']);
});
