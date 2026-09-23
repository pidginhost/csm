// Run with: node --test ui/live_test.js
// Findings arrive over the event stream as they are dispatched. Pages react
// to them within a couple of seconds, and their timers become a slow safety
// net while the stream is connected.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

const wait = ms => new Promise(r => setTimeout(r, ms));

// A fake EventSource the test opens and feeds by hand.
function streamGlobals() {
    const streams = [];
    function EventSource(url) { this.url = url; this.readyState = 0; streams.push(this); }
    EventSource.CLOSED = 2;
    EventSource.prototype.close = function() { this.readyState = 2; };
    return { streams, globals: { EventSource } };
}

function connect(page, streams) {
    page.window.CSM.sse.start();
    const s = streams[streams.length - 1];
    s.readyState = 1;
    s.onopen();
    return s;
}

function send(stream, finding) {
    stream.onmessage({ data: typeof finding === 'string' ? finding : JSON.stringify(finding) });
}

test('a burst of findings reaches the page once, as a batch', async () => {
    const { streams, globals } = streamGlobals();
    const page = loadPage('', SHARED, { globals });
    const s = connect(page, streams);
    const batches = [];
    page.window.CSM.live.onFinding(items => batches.push(items), { wait: 20 });
    send(s, { check: 'webshell', message: 'a' });
    send(s, 'not json');
    send(s, { check: 'webshell', message: 'b' });
    await wait(40);
    assert.equal(batches.length, 1);
    assert.deepEqual(Array.from(batches[0], f => f.message), ['a', 'b']);
});

test('live updates wait while auto-refresh is paused', async () => {
    const { streams, globals } = streamGlobals();
    const page = loadPage('', SHARED, { globals });
    const s = connect(page, streams);
    let calls = 0;
    page.window.CSM.live.onFinding(() => { calls++; }, { wait: 10 });
    page.window.CSM.refresh.setEnabled(false, { transient: true });
    send(s, { check: 'webshell', message: 'a' });
    await wait(30);
    assert.equal(calls, 0);
});

test('a load started by a live update counts as a data load', async () => {
    const { streams, globals } = streamGlobals();
    const page = loadPage('', SHARED, { globals });
    page.window.dispatchEvent(new page.window.Event('load'));
    const s = connect(page, streams);
    page.window.CSM.live.onFinding(() => { page.window.CSM.get('/api/v1/stats'); }, { wait: 5 });
    send(s, { check: 'webshell', message: 'a' });
    await wait(20);
    page.respond('/api/v1/stats', 200, {});
    await settle();
    assert.ok(page.window.CSM.refresh.lastFetchAt > 0);
});

test('timers slow down while the stream is connected and speed up when it drops', async () => {
    const { streams, globals } = streamGlobals();
    const page = loadPage('', SHARED, { globals });
    let runs = 0;
    const handle = page.window.CSM.refresh.interval(() => { runs++; }, 15, { whileLive: 10000 });
    await wait(60);
    const fast = runs;
    assert.ok(fast >= 2, 'fast interval did not run: ' + fast);
    const s = connect(page, streams);
    runs = 0;
    await wait(60);
    assert.equal(runs, 0, 'the interval kept its fast pace while live');
    s.readyState = 2;
    s.onerror();
    await wait(60);
    assert.ok(runs >= 2, 'the interval did not speed up after the stream dropped: ' + runs);
    handle.stop();
});

test('pollers slow down while the stream is connected', async () => {
    const { streams, globals } = streamGlobals();
    const page = loadPage('', SHARED, { globals });
    connect(page, streams);
    const poller = page.window.CSM.poll('/api/v1/status', 15, () => {}, { whileLive: 10000 });
    await wait(60);
    assert.equal(page.pending('/api/v1/status').length, 0, 'the poller kept its fast pace while live');
    poller.stop();
});

function finding(check, message) {
    return {
        key: check + ':' + message, severity: 'HIGH', sev_class: 'high', check, message,
        first_seen: '2026-09-22T10:00:00Z', last_seen: '2026-09-22T10:00:00Z'
    };
}

test('Findings offers the new list as soon as a finding arrives', async () => {
    const { streams, globals } = streamGlobals();
    const page = loadPage(templateBody('findings'), SHARED.concat(['findings.js']), { globals });
    page.respond('/api/v1/findings/enriched', 200, { items: [finding('webshell', 'a')], total: 1, version: 'v1' });
    await settle();
    const s = connect(page, streams);
    send(s, { check: 'webshell', message: 'b' });
    await wait(1700);
    page.respond('/api/v1/findings/enriched?fields=version', 200, { version: 'v2', total: 2 });
    await settle();
    assert.equal(page.document.getElementById('refresh-banner').classList.contains('d-none'), false);
});

test('Incidents reloads on a new finding but not under a selection', async () => {
    const { streams, globals } = streamGlobals();
    const page = loadPage(templateBody('incident'), SHARED.concat(['incident.js']), { globals });
    await settle();
    page.respond('/api/v1/incidents?', 200, { items: [
        { id: 'inc_a', status: 'open', severity: 'HIGH', kind: 'web_attack', updated_at: '2026-09-22T10:00:00Z', findings: [] }
    ], total: 1, offset: 0 });
    await settle();
    const s = connect(page, streams);
    send(s, { check: 'webshell', message: 'x' });
    await wait(1700);
    assert.equal(page.pending('/api/v1/incidents?').length, 1, 'no reload after a new finding');
    page.respond('/api/v1/incidents?', 200, { items: [
        { id: 'inc_a', status: 'open', severity: 'HIGH', kind: 'web_attack', updated_at: '2026-09-22T10:00:00Z', findings: [] }
    ], total: 1, offset: 0 });
    await settle();
    const cb = page.document.querySelector('.incident-cb');
    cb.checked = true;
    cb.dispatchEvent(new page.window.Event('change'));
    send(s, { check: 'webshell', message: 'y' });
    await wait(1700);
    assert.equal(page.pending('/api/v1/incidents?').length, 0, 'reloaded under the operator\'s selection');
});
