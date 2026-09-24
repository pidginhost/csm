// Run with: node --test ui/runtime_test.js
// Behaviour of the shared runtime that page tests lean on: URL-bound
// filters, the event stream client, and poller backoff. Static source pins
// said these pieces existed; these tests say they work.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, SHARED, settle } = require('./pagekit.js');

const wait = ms => new Promise(r => setTimeout(r, ms));

test('urlState.bind restores inputs from the URL and writes changes back', async () => {
    const page = loadPage('<input id="q"><select id="sev"><option value="all">All</option><option value="2">Critical</option></select>',
        SHARED, { url: 'https://csm.example.test/findings?q=shell&keep=1' });
    const q = page.document.getElementById('q');
    const sev = page.document.getElementById('sev');
    let restored = 0;
    q.addEventListener('input', () => { restored++; });
    const unbind = page.window.CSM.urlState.bind({ inputs: { q, sev }, defaults: { sev: 'all' }, debounceMs: 0 });
    assert.equal(q.value, 'shell');
    assert.equal(sev.value, 'all');
    assert.equal(restored, 1, 'restoring the value did not tell dependent listeners');
    sev.value = '2';
    sev.dispatchEvent(new page.window.Event('change'));
    q.value = '';
    q.dispatchEvent(new page.window.Event('input'));
    await wait(10);
    const params = new URLSearchParams(page.window.location.search);
    assert.equal(params.get('sev'), '2');
    assert.equal(params.get('q'), null, 'a cleared filter stayed in the URL');
    assert.equal(params.get('keep'), '1', 'an unrelated parameter was dropped');
    sev.value = 'all';
    sev.dispatchEvent(new page.window.Event('change'));
    await wait(10);
    assert.equal(new URLSearchParams(page.window.location.search).get('sev'), null, 'the default was written to the URL');
    unbind();
    q.value = 'after';
    q.dispatchEvent(new page.window.Event('input'));
    await wait(10);
    assert.equal(new URLSearchParams(page.window.location.search).get('q'), null, 'an unbound input still wrote the URL');
});

function streamGlobals() {
    const streams = [];
    function EventSource(url) { this.url = url; this.readyState = 0; streams.push(this); }
    EventSource.CLOSED = 2;
    EventSource.prototype.close = function() { this.readyState = 2; };
    return { streams, globals: { EventSource } };
}

test('the event stream reconnects after it closes and reports each state', async () => {
    const { streams, globals } = streamGlobals();
    const page = loadPage('', SHARED, { globals });
    const states = [];
    page.window.addEventListener('csm:sse-state', ev => states.push(ev.detail.state));
    page.window.CSM.sse.start();
    assert.equal(streams.length, 1);
    streams[0].onopen();
    streams[0].readyState = 2;
    streams[0].onerror();
    assert.equal(page.window.CSM.sse.state, 'reconnecting');
    await wait(1600);
    assert.equal(streams.length, 2, 'no reconnect after the stream closed');
    streams[1].onopen();
    assert.deepEqual(Array.from(states), ['connecting', 'connected', 'reconnecting', 'connected']);
});

test('a replaced stream cannot change the state', () => {
    const { streams, globals } = streamGlobals();
    const page = loadPage('', SHARED, { globals });
    page.window.CSM.sse.start();
    const old = streams[0];
    page.window.CSM.sse.start();
    streams[1].onopen();
    old.readyState = 2;
    old.onerror();
    assert.equal(page.window.CSM.sse.state, 'connected');
});

test('the event stream closes while the tab is hidden and reopens after', () => {
    const { streams, globals } = streamGlobals();
    const page = loadPage('', SHARED, { globals });
    page.window.CSM.sse.start();
    streams[0].onopen();
    page.document.hidden = true;
    page.document.dispatchEvent(new page.window.Event('visibilitychange'));
    assert.equal(streams[0].readyState, 2);
    assert.equal(page.window.CSM.sse.state, 'disconnected');
    page.document.hidden = false;
    page.document.dispatchEvent(new page.window.Event('visibilitychange'));
    assert.equal(streams.length, 2);
});

test('a throwing poll callback does not stop the poller', async () => {
    const page = loadPage('', SHARED);
    let calls = 0;
    const poller = page.window.CSM.poll('/api/v1/status', 5, () => { calls++; throw new Error('render failed'); });
    await wait(20);
    page.respond('/api/v1/status', 200, { ok: true });
    await wait(30);
    assert.equal(calls, 1);
    assert.equal(page.pending('/api/v1/status').length, 1, 'the poller stopped after its callback threw');
    poller.stop();
});

test('a poller doubles its interval after a failure and resets after a success', async () => {
    const page = loadPage('', SHARED);
    const poller = page.window.CSM.poll('/api/v1/status', 10, () => {});
    async function nextAfter(ms) {
        const start = Date.now();
        while (page.pending('/api/v1/status').length === 0) {
            if (Date.now() - start > 500) throw new Error('no poll');
            await wait(2);
        }
        return Date.now() - start;
    }
    await nextAfter();
    page.fail('/api/v1/status');
    const slow = await nextAfter();
    page.respond('/api/v1/status', 200, {});
    const fast = await nextAfter();
    assert.ok(slow >= 18, 'no backoff after a failure: ' + slow + 'ms');
    assert.ok(fast < slow, 'the interval did not reset after a success: ' + fast + 'ms vs ' + slow + 'ms');
    poller.stop();
});
