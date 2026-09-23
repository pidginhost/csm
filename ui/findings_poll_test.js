// Run with: node --test ui/findings_poll_test.js
// The Findings page polls to learn whether the list changed. It asks for the
// list's version, not the whole list, and shows the refresh banner when the
// version moves.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

const tick = () => new Promise(resolve => setTimeout(resolve, 5)).then(settle);

test('the findings poll compares versions instead of fetching the list', async () => {
    const page = loadPage(templateBody('findings'), SHARED.concat(['findings.js']));
    page.respond('/api/v1/findings/enriched', 200, {
        findings: [{ key: 'k1', check: 'webshell', severity: 'CRITICAL', message: 'm' }],
        check_types: ['webshell'], accounts: [], total: 1, version: 'v1'
    });
    await settle();
    const banner = page.document.getElementById('refresh-banner');

    page.window.dispatchEvent(new page.window.CustomEvent('csm:refresh-now'));
    await tick();
    let polls = page.pending('/api/v1/findings/enriched');
    assert.equal(polls.length, 1, 'no poll sent');
    assert.ok(polls[0].url.includes('fields=version'), polls[0].url);
    page.respond('/api/v1/findings/enriched', 200, { version: 'v1', total: 1 });
    await settle();
    assert.ok(banner.classList.contains('d-none'), 'banner shown for an unchanged list');

    page.window.dispatchEvent(new page.window.CustomEvent('csm:refresh-now'));
    await tick();
    page.respond('/api/v1/findings/enriched', 200, { version: 'v2', total: 2 });
    await settle();
    assert.ok(!banner.classList.contains('d-none'), 'banner hidden after the list changed');
});
