// Run with: node --test ui/findings_poll_test.js
// The Findings page polls to learn whether the list changed. It asks for the
// list's version, not the whole list, and shows the refresh banner when the
// version moves.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

test('the findings poll compares versions instead of fetching the list', async () => {
    const timers = new Map();
    let nextID = 0;
    const page = loadPage(templateBody('findings'), SHARED.concat(['findings.js']), { globals: {
        setTimeout(fn, delay) { const id = ++nextID; timers.set(id, { fn, delay }); return id; },
        clearTimeout(id) { timers.delete(id); }
    } });
    async function tick() {
        // Exercise the scheduled poll; manual refresh also reloads the list.
        const pending = [...timers.entries()].filter(([, t]) => t.delay >= 15000 && t.delay < 20000);
        assert.equal(pending.length, 1, 'expected one scheduled version poll');
        const [id, timer] = pending[0];
        timers.delete(id);
        timer.fn();
        await settle();
    }
    page.respond('/api/v1/findings/enriched', 200, {
        findings: [{ key: 'k1', check: 'webshell', severity: 'CRITICAL', message: 'm' }],
        check_types: ['webshell'], accounts: [], total: 1, version: 'v1'
    });
    await settle();
    const banner = page.document.getElementById('refresh-banner');

    await tick();
    let polls = page.pending('/api/v1/findings/enriched');
    assert.equal(polls.length, 1, 'no poll sent');
    assert.ok(polls[0].url.includes('fields=version'), polls[0].url);
    page.respond('/api/v1/findings/enriched', 200, { version: 'v1', total: 1 });
    await settle();
    assert.ok(banner.classList.contains('d-none'), 'banner shown for an unchanged list');

    await tick();
    page.respond('/api/v1/findings/enriched', 200, { version: 'v2', total: 2 });
    await settle();
    assert.ok(!banner.classList.contains('d-none'), 'banner hidden after the list changed');
});
