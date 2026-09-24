// Run with: node --test ui/refresh_test.js
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, items, SHARED, settle, RUNTIME } = require('./pagekit.js');

const wait = ms => new Promise(r => setTimeout(r, ms));
const chartStub = function () { return { destroy() {}, update() {}, data: { datasets: [] }, options: {} }; };
// Chart.defaults is a deep settings tree the dashboard writes into.
function autoObject() {
    return new Proxy({}, { get(t, k) { if (typeof k === 'symbol') return t[k]; if (!(k in t)) t[k] = autoObject(); return t[k]; } });
}
chartStub.defaults = autoObject();
chartStub.instances = {};

function setHidden(page, hidden) {
    page.document.hidden = hidden;
    page.document.visibilityState = hidden ? 'hidden' : 'visible';
    page.document.dispatchEvent(new page.window.Event('visibilitychange'));
}

// Counts the refresh timers a page script holds, created minus stopped.
function trackTimers(page) {
    const refresh = page.window.CSM.refresh;
    const real = refresh.interval;
    const live = { count: 0 };
    refresh.interval = function(fn, ms) {
        const handle = real.call(refresh, fn, ms);
        live.count++;
        const stop = handle.stop;
        let stopped = false;
        handle.stop = function() { if (!stopped) { stopped = true; live.count--; } return stop.apply(this, arguments); };
        return handle;
    };
    return live;
}

test('a refresh timer returning from a hidden tab runs once if it is overdue', async () => {
    const page = loadPage('', RUNTIME);
    let runs = 0;
    page.window.CSM.refresh.interval(() => { runs++; }, 40);
    setHidden(page, true);
    await wait(80);
    assert.equal(runs, 0, 'ran while hidden');
    setHidden(page, false);
    assert.equal(runs, 1, 'an overdue refresh should run as soon as the tab is visible');
    setHidden(page, true);
    setHidden(page, false);
    assert.equal(runs, 1, 'a refresh that just ran must not run again on a quick tab switch');
});

test('returning to a tab does not refresh while auto-refresh is paused', async () => {
    const page = loadPage('', RUNTIME);
    let runs = 0;
    page.window.CSM.refresh.interval(() => { runs++; }, 40);
    page.window.CSM.refresh.setEnabled(false, { transient: true });
    setHidden(page, true);
    await wait(80);
    setHidden(page, false);
    assert.equal(runs, 0);
});

test('a short tab switch keeps the original refresh deadline', () => {
    let now = 1000;
    const timers = new Map();
    let nextID = 0;
    class ClockDate extends Date { static now() { return now; } }
    const page = loadPage('', RUNTIME, { globals: {
        Date: ClockDate,
        setTimeout(fn, delay) { const id = ++nextID; timers.set(id, { fn, delay }); return id; },
        clearTimeout(id) { timers.delete(id); }
    } });
    const handle = page.window.CSM.refresh.interval(() => {}, 10000);
    now += 9000;
    setHidden(page, true);
    now += 500;
    setHidden(page, false);
    assert.deepEqual([...timers.values()].map(t => t.delay), [500]);
    handle.stop();
});

for (const [name, template, scripts, want, globals] of [
    ['Email', 'email', ['email.js'], 3, {}],
    ['Performance', 'performance', ['performance.js'], 1, {}],
    ['Dashboard', 'dashboard', ['dashboard.js'], null, { Chart: chartStub, Notification: undefined }]
]) {
    test(name + ' does not stack refresh timers when opened in a background tab', async () => {
        const page = loadPage(templateBody(template), SHARED, { globals });
        page.document.hidden = true;
        page.document.visibilityState = 'hidden';
        const live = trackTimers(page);
        scripts.forEach(s => page.load(s));
        await settle();
        const before = live.count;
        if (want !== null) assert.equal(before, want);
        for (let round = 0; round < 2; round++) {
            setHidden(page, false);
            await settle();
            assert.equal(live.count, before, name + ' holds ' + live.count + ' timers after becoming visible, started with ' + before);
            setHidden(page, true);
        }
    });
}

test('the dashboard does not reload on tab return while auto-refresh is paused', async () => {
    const page = loadPage(templateBody('dashboard'), SHARED.concat(['dashboard.js']), { globals: { Chart: chartStub } });
    await settle();
    page.window.CSM.refresh.setEnabled(false, { transient: true });
    setHidden(page, true);
    const before = page.requests.length;
    setHidden(page, false);
    await settle();
    const extra = page.requests.slice(before).map(r => r.url);
    assert.deepEqual(extra, [], 'requests sent while paused: ' + extra.join(', '));
});

test('the idle watcher list stays open across a dashboard refresh', async () => {
    const page = loadPage(templateBody('dashboard'), SHARED.concat(['dashboard.js']), { globals: { Chart: chartStub } });
    const rows = [
        { name: 'fanotify', label: 'File monitor', status: 'ok' },
        { name: 'modsec', label: 'ModSecurity', status: 'idle' }
    ];
    page.respond('/api/v1/components', 200, items(rows));
    await settle();
    const details = page.document.querySelector('details.csm-idle-watchers');
    assert.ok(details, 'no idle watcher list');
    details.open = true;
    page.document.getElementById('components-refresh').click();
    page.respond('/api/v1/components', 200, items(rows));
    await settle();
    assert.equal(page.document.querySelector('details.csm-idle-watchers').open, true, 'the list collapsed under the operator');
});
