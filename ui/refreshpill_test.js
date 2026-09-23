// Run with: node --test ui/refreshpill_test.js
// "Updated N ago" reports when the page's data was last loaded, so it moves
// on the page's own loads, refresh ticks and manual refresh, not on every
// request: an action or a detail lookup does not make the page any fresher.
// The pause control shows only on pages that refresh on a timer.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, SHARED, settle } = require('./pagekit.js');

const TOPBAR = '<span id="csm-refresh-pill" class="d-none"><span id="csm-refresh-age">Never updated</span></span>' +
    '<button id="csm-refresh-now" class="d-none"></button>' +
    '<button id="csm-refresh-toggle" class="d-none"><i class="ti ti-player-pause"></i></button>';

function page() {
    // theme-init.js runs from <head> before the shared scripts, as in layout.html.
    return loadPage(TOPBAR, ['theme-init.js'].concat(SHARED, ['layout.js']));
}

// The browser fires load once the page and its first loads have started.
function finishLoading(p) {
    p.window.dispatchEvent(new p.window.Event('load'));
}

test('the first data load counts as an update', async () => {
    const p = page();
    p.window.CSM.get('/api/v1/stats');
    p.respond('/api/v1/stats', 200, {});
    await settle();
    assert.ok(p.window.CSM.refresh.lastFetchAt > 0);
});

test('an action or a lookup after load is not an update', async () => {
    const p = page();
    finishLoading(p);
    p.window.CSM.post('/api/v1/dismiss', { keys: ['x'] });
    p.respond('/api/v1/dismiss', 200, {});
    p.window.CSM.get('/api/v1/finding-detail?check=x&message=y');
    p.respond('/api/v1/finding-detail', 200, {});
    await settle();
    assert.equal(p.window.CSM.refresh.lastFetchAt, 0);
});

test('a manual refresh and a refresh tick are updates', async () => {
    const p = page();
    finishLoading(p);
    p.window.CSM.refresh.onRefresh(() => { p.window.CSM.get('/api/v1/stats'); });
    p.window.CSM.refresh.manual();
    p.respond('/api/v1/stats', 200, {});
    await settle();
    const first = p.window.CSM.refresh.lastFetchAt;
    assert.ok(first > 0, 'manual refresh did not count');
    let tick;
    p.window.CSM.refresh.interval(() => { tick = p.window.CSM.get('/api/v1/history'); }, 5);
    await new Promise(r => setTimeout(r, 30));
    p.respond('/api/v1/history', 200, {});
    await settle();
    assert.ok(tick, 'the tick did not run');
    assert.ok(p.window.CSM.refresh.lastFetchAt >= first);
});

test('a poller response is an update', async () => {
    const p = page();
    finishLoading(p);
    const poller = p.window.CSM.poll('/api/v1/status', 5, () => {});
    await new Promise(r => setTimeout(r, 30));
    p.respond('/api/v1/status', 200, {});
    poller.stop();
    await settle();
    assert.ok(p.window.CSM.refresh.lastFetchAt > 0);
});

test('the pause control shows only while something refreshes on a timer', () => {
    const p = page();
    const toggle = p.document.getElementById('csm-refresh-toggle');
    assert.ok(toggle.classList.contains('d-none'), 'pause shown on a page with no timer');
    assert.ok(!p.document.getElementById('csm-refresh-now').classList.contains('d-none'), 'Refresh button hidden');
    const handle = p.window.CSM.refresh.interval(() => {}, 60000);
    assert.ok(!toggle.classList.contains('d-none'), 'pause hidden on a page with a timer');
    handle.stop();
    assert.ok(toggle.classList.contains('d-none'), 'pause still shown after the timer stopped');
});

test('a poller also shows the pause control', () => {
    const p = page();
    const stop = p.window.CSM.poll('/api/v1/status', 60000, () => {});
    assert.ok(!p.document.getElementById('csm-refresh-toggle').classList.contains('d-none'));
    if (stop && stop.stop) stop.stop();
});
