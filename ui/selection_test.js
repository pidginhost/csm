// Run with: node --test ui/selection_test.js
// Findings and Firewall select rows through the shared bulk helper: only
// visible rows count, select-all shows a partial state, and the bulk
// controls follow the selection.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, items, SHARED, settle } = require('./pagekit.js');

function finding(check, message, hasFix) {
    return {
        key: check + ':' + message, severity: 'HIGH', sev_class: 'high', check, message, has_fix: hasFix,
        first_seen: '2026-09-22T10:00:00Z', last_seen: '2026-09-22T10:00:00Z'
    };
}

function tick(page, el) {
    el.checked = !el.checked;
    el.dispatchEvent(new page.window.Event('change'));
}

test('Findings select-all shows a partial selection and follows the fix button', async () => {
    const page = loadPage(templateBody('findings'), SHARED.concat(['findings.js']));
    page.respond('/api/v1/findings/enriched', 200, { items: [
        finding('webshell', 'a', true), finding('perf_load', 'b', false)
    ], total: 2 });
    await settle();
    const boxes = page.document.querySelectorAll('.row-checkbox');
    const all = page.document.getElementById('select-all');
    tick(page, boxes[1]);
    assert.equal(all.indeterminate, true, 'one of two selected is not a partial selection');
    assert.equal(page.document.getElementById('bulk-fix-btn').classList.contains('d-none'), true, 'fix offered for an unfixable selection');
    tick(page, boxes[0]);
    assert.equal(all.checked, true);
    assert.equal(all.indeterminate, false);
    assert.equal(page.document.getElementById('bulk-fix-btn').classList.contains('d-none'), false);
    assert.equal(page.document.getElementById('selected-count').textContent, '2');
    tick(page, all);
    assert.equal(page.document.getElementById('findings-bulk-bar').hidden, true);
});

test('Findings select-all skips rows of a collapsed group', async () => {
    const page = loadPage(templateBody('findings'), SHARED.concat(['findings.js']));
    page.respond('/api/v1/findings/enriched', 200, { items: [
        finding('webshell', 'a', true), finding('perf_load', 'b', false)
    ], total: 2 });
    await settle();
    const sel = page.document.getElementById('group-by');
    sel.value = 'check';
    sel.dispatchEvent(new page.window.Event('change'));
    await settle();
    page.document.querySelector('.csm-group-header[data-csm-group-key="webshell"] .csm-group-toggle').click();
    const all = page.document.getElementById('select-all');
    all.checked = true;
    all.dispatchEvent(new page.window.Event('change'));
    assert.equal(page.document.getElementById('selected-count').textContent, '1');
});

test('Firewall select-all skips blocked IPs a filter hides', async () => {
    const page = loadPage(templateBody('firewall'), SHARED.concat(['firewall.js']),
        { url: 'https://csm.example.test/firewall?view=blocks' });
    await settle();
    page.respond('/api/v1/blocked-ips', 200, items([
        { ip: '192.0.2.1', reason: 'r', source: 'web_ui', expires_at: '2026-09-30T00:00:00Z' },
        { ip: '192.0.2.2', reason: 'r', source: 'web_ui' }
    ]));
    await settle();
    const lifetime = page.document.getElementById('blocked-lifetime-filter');
    lifetime.value = 'temporary';
    lifetime.dispatchEvent(new page.window.Event('change'));
    await settle();
    const all = page.document.getElementById('select-all-blocked');
    all.checked = true;
    all.dispatchEvent(new page.window.Event('change'));
    assert.equal(page.document.getElementById('blocked-bulk-unblock-btn').textContent, 'Unblock selected (1)');
});

test('Findings exports the rows it shows', async () => {
    const page = loadPage(templateBody('findings'), SHARED.concat(['findings.js']));
    page.respond('/api/v1/findings/enriched', 200, { items: [
        finding('webshell', 'a', true), finding('perf_load', 'b', false)
    ], total: 2 });
    await settle();
    let exported;
    page.window.CSM.exportTable = rows => { exported = rows; };
    page.document.getElementById('export-csv').click();
    assert.ok(exported, 'export did not run');
    assert.deepEqual(Array.from(exported, r => r.check), ['webshell', 'perf_load']);
});

test('Firewall selection drives the bulk unblock button', async () => {
    const page = loadPage(templateBody('firewall'), SHARED.concat(['firewall.js']),
        { url: 'https://csm.example.test/firewall?view=blocks' });
    await settle();
    page.respond('/api/v1/blocked-ips', 200, items([
        { ip: '192.0.2.1', reason: 'r', source: 'web_ui' },
        { ip: '192.0.2.2', reason: 'r', source: 'web_ui' }
    ]));
    await settle();
    const btn = page.document.getElementById('blocked-bulk-unblock-btn');
    assert.equal(btn.classList.contains('d-none'), true);
    tick(page, page.document.querySelectorAll('.fw-blocked-cb')[0]);
    assert.equal(btn.classList.contains('d-none'), false);
    assert.equal(btn.textContent, 'Unblock selected (1)');
    const all = page.document.getElementById('select-all-blocked');
    assert.equal(all.indeterminate, true);
    all.checked = true;
    all.dispatchEvent(new page.window.Event('change'));
    assert.equal(btn.textContent, 'Unblock selected (2)');
});
