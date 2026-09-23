// Run with: node --test ui/incidentbulk_test.js
// Correlated incidents can change status in bulk: select rows, then mark
// them contained, resolved or dismissed.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

function incident(id) {
    return { id, status: 'open', severity: 'HIGH', kind: 'web_attack', account: 'alice', updated_at: '2026-09-22T10:00:00Z', findings: [] };
}

async function incidentsPage(ids) {
    const page = loadPage(templateBody('incident'), SHARED.concat(['incident.js']));
    await settle();
    page.respond('/api/v1/incidents?', 200, { items: ids.map(incident), total: ids.length, offset: 0 });
    await settle();
    page.window.CSM.confirm = message => { page.confirmed = message; return Promise.resolve(); };
    page.toasts = [];
    page.window.CSM.toast = (message, kind) => page.toasts.push({ message, kind });
    return page;
}

function select(page, id) {
    const cb = page.document.querySelector('.incident-cb[data-incident-id="' + id + '"]');
    assert.ok(cb, 'no checkbox for ' + id);
    cb.checked = true;
    cb.dispatchEvent(new page.window.Event('change'));
    return cb;
}

test('selected incidents are marked resolved one request each', async () => {
    const page = await incidentsPage(['inc_a', 'inc_b', 'inc_c']);
    select(page, 'inc_a');
    select(page, 'inc_c');
    const bar = page.document.getElementById('incidents-bulk-bar');
    assert.equal(bar.hidden, false, 'bulk bar hidden with a selection');
    assert.equal(page.document.getElementById('incidents-selected-count').textContent, '2');
    page.document.querySelector('#incidents-bulk-bar [data-bulk-status="resolved"]').click();
    await settle();
    assert.match(page.confirmed, /2 incident/);
    for (const id of ['inc_a', 'inc_c']) {
        const req = page.respond('/api/v1/incidents/' + id + '/status', 200, { status: 'resolved' });
        assert.equal(req.body.status, 'resolved');
        await settle();
    }
    assert.equal(page.pending('/status').length, 0);
    assert.ok(page.pending('/api/v1/incidents?').length >= 1, 'list not reloaded');
    assert.ok(page.toasts.some(t => t.kind === 'success' && /2 /.test(t.message)), JSON.stringify(page.toasts));
});

test('ticking a checkbox does not open the incident', async () => {
    const page = await incidentsPage(['inc_a']);
    const cb = select(page, 'inc_a');
    cb.click();
    await settle();
    assert.equal(page.pending('/api/v1/incidents/inc_a').length, 0);
});

test('a failed status change stops the rest', async () => {
    const page = await incidentsPage(['inc_a', 'inc_b']);
    select(page, 'inc_a');
    select(page, 'inc_b');
    page.document.querySelector('#incidents-bulk-bar [data-bulk-status="dismissed"]').click();
    await settle();
    page.respond('/api/v1/incidents/inc_a/status', 400, { error: 'invalid status transition' });
    await settle();
    assert.equal(page.pending('/status').length, 0, 'kept sending after a failure');
    assert.ok(page.toasts.some(t => t.kind === 'error' && /0 of 2/.test(t.message)), JSON.stringify(page.toasts));
});

test('an empty reload hides the bulk bar', async () => {
    const page = await incidentsPage(['inc_a']);
    select(page, 'inc_a');
    const filter = page.document.getElementById('incident-status-filter');
    filter.value = 'dismissed';
    filter.dispatchEvent(new page.window.Event('change'));
    await settle();
    page.respond('/api/v1/incidents?', 200, { items: [], total: 0, offset: 0 });
    await settle();
    assert.equal(page.document.getElementById('incidents-bulk-bar').hidden, true);
});

test('select-all reaches the incidents on this page', async () => {
    const page = await incidentsPage(['inc_a', 'inc_b']);
    const all = page.document.getElementById('incidents-select-all');
    all.checked = true;
    all.dispatchEvent(new page.window.Event('change'));
    assert.equal(page.document.getElementById('incidents-selected-count').textContent, '2');
});
