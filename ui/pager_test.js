// Run with: node --test ui/pager_test.js
// Server-paged lists (History, Incidents, grouped incidents) share one pager:
// a summary, first/previous/next/last buttons and a page indicator.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

function pagerPage() {
    return loadPage('<div id="f" class="card-footer d-none"></div>', SHARED);
}

test('the pager summarises the page and moves by page', () => {
    const page = pagerPage();
    const footer = page.document.getElementById('f');
    const moves = [];
    page.window.CSM.pager(footer, { total: 120, offset: 50, limit: 50, count: 50, onOffset: o => moves.push(o) });
    assert.equal(footer.classList.contains('d-none'), false);
    assert.match(footer.textContent, /Showing 51-100 of 120/);
    assert.equal(footer.querySelector('[data-pager="indicator"]').textContent, '2 / 3');
    const btn = name => footer.querySelector('[data-pager="' + name + '"]');
    for (const name of ['first', 'prev', 'next', 'last']) {
        assert.ok(btn(name).getAttribute('aria-label'), name + ' has no name');
        btn(name).click();
    }
    assert.deepEqual(moves, [0, 0, 100, 100]);
});

test('the ends of the list disable the buttons that would leave it', () => {
    const page = pagerPage();
    const footer = page.document.getElementById('f');
    page.window.CSM.pager(footer, { total: 30, offset: 0, limit: 50, count: 30, onOffset() {} });
    for (const name of ['first', 'prev', 'next', 'last']) {
        assert.equal(footer.querySelector('[data-pager="' + name + '"]').disabled, true, name);
    }
    page.window.CSM.pager(footer, { total: 0, offset: 0, limit: 50, count: 0, onOffset() {} });
    assert.equal(footer.classList.contains('d-none'), true, 'an empty list shows a pager');
});

test('History pages through the shared pager', async () => {
    const page = loadPage(templateBody('findings'), SHARED.concat(['findings.js', 'history.js']),
        { url: 'https://csm.example.test/findings?tab=history' });
    page.document.querySelector('[href="#tab-history"]').dispatchEvent(new page.window.Event('shown.bs.tab'));
    await settle();
    page.respond('/api/v1/history', 200, { items: [{ severity: 1, check: 'x', message: 'm', timestamp: '2026-09-22T10:00:00Z' }], total: 120 });
    await settle();
    const footer = page.document.getElementById('history-pager');
    footer.querySelector('[data-pager="next"]').click();
    await settle();
    assert.ok(page.pending('/api/v1/history').some(r => /offset=50/.test(r.url)), 'next page not requested');
});

test('Incidents pages through the shared pager', async () => {
    const page = loadPage(templateBody('incident'), SHARED.concat(['incident.js']));
    await settle();
    page.respond('/api/v1/incidents?', 200, { items: [
        { id: 'inc_a', status: 'open', severity: 'HIGH', kind: 'web_attack', updated_at: '2026-09-22T10:00:00Z', findings: [] }
    ], total: 120, offset: 0 });
    await settle();
    const footer = page.document.getElementById('incidents-pagination');
    assert.match(footer.textContent, /of 120/);
    footer.querySelector('[data-pager="last"]').click();
    await settle();
    assert.ok(page.pending('/api/v1/incidents?').some(r => /offset=100/.test(r.url)), 'last page not requested');
});
