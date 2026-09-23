// Run with: node --test ui/keyboard_test.js
// Everything that opens or sorts with a click also works from the keyboard:
// finding and incident rows, finding group headers, sortable table headers,
// and the j/k selection on Findings.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

function key(page, target, k) {
    const ev = new page.window.Event('keydown', { bubbles: true, cancelable: true });
    ev.key = k;
    target.dispatchEvent(ev);
    return ev;
}

function finding(check, message, account) {
    return {
        key: check + ':' + message, severity: 'HIGH', sev_class: 'high', check, message, account,
        first_seen: '2026-09-22T10:00:00Z', last_seen: '2026-09-22T10:00:00Z'
    };
}

async function findingsPage(extra) {
    const page = loadPage(templateBody('findings'), SHARED.concat(['findings.js'], extra || []));
    page.respond('/api/v1/findings/enriched', 200, {
        findings: [finding('webshell', 'shell a', 'alice'), finding('perf_load', 'load high', '')],
        check_types: ['webshell', 'perf_load'], total: 2
    });
    await settle();
    return page;
}

test('a finding row opens with Enter', async () => {
    const page = await findingsPage();
    const row = page.document.querySelector('.finding-row');
    assert.equal(row.getAttribute('tabindex'), '0', 'finding row is not focusable');
    const ev = key(page, row, 'Enter');
    await settle();
    assert.equal(ev.defaultPrevented, true);
    assert.equal(page.pending('/api/v1/finding-detail').length, 1);
});

test('Enter on a button inside the row does not also open the row', async () => {
    const page = await findingsPage();
    const btn = page.document.querySelector('.finding-row .dismiss-btn');
    key(page, btn, 'Enter');
    await settle();
    assert.equal(page.pending('/api/v1/finding-detail').length, 0);
});

test('j moves focus to a finding and o opens it', async () => {
    const page = await findingsPage(['shortcuts.js']);
    key(page, page.document.body, 'j');
    const row = page.document.activeElement;
    assert.ok(row && row.classList.contains('finding-row'), 'j did not focus a finding row');
    key(page, page.document.body, 'o');
    await settle();
    assert.equal(page.pending('/api/v1/finding-detail').length, 1, 'o did not open the selected finding');
});

test('a finding group header toggles from a button', async () => {
    const page = await findingsPage();
    const sel = page.document.getElementById('group-by');
    sel.value = 'check';
    sel.dispatchEvent(new page.window.Event('change'));
    await settle();
    const header = page.document.querySelector('.csm-group-header[data-csm-group-key="webshell"]');
    const btn = header.querySelector('button.csm-group-toggle');
    assert.ok(btn, 'group header has no toggle button');
    assert.equal(btn.getAttribute('aria-expanded'), 'true');
    btn.click();
    assert.equal(btn.getAttribute('aria-expanded'), 'false');
    assert.equal(header.classList.contains('collapsed'), true);
});

test('a sortable header sorts from the keyboard and reports its order', () => {
    const page = loadPage('<table id="t"><thead><tr><th>Name</th><th>Actions</th></tr></thead>' +
        '<tbody><tr><td>b</td><td></td></tr><tr><td>a</td><td></td></tr></tbody></table>', SHARED);
    new page.window.CSM.Table({ tableId: 't', perPage: 0, sortable: true, controls: false, search: false });
    const th = page.document.querySelectorAll('#t th')[0];
    assert.equal(th.getAttribute('tabindex'), '0');
    assert.equal(th.getAttribute('aria-sort'), 'none');
    key(page, th, 'Enter');
    assert.equal(th.getAttribute('aria-sort'), 'ascending');
    assert.equal(page.document.querySelector('#t tbody tr td').textContent, 'a');
    key(page, th, ' ');
    assert.equal(th.getAttribute('aria-sort'), 'descending');
    const actions = page.document.querySelectorAll('#t th')[1];
    assert.equal(actions.getAttribute('tabindex'), null, 'the Actions column is not sortable');
});

test('an incident row opens with Enter', async () => {
    const page = loadPage(templateBody('incident'), SHARED.concat(['incident.js']));
    await settle();
    page.respond('/api/v1/incidents?', 200, { items: [
        { id: 'inc_a', status: 'open', severity: 'HIGH', kind: 'web_attack', updated_at: '2026-09-22T10:00:00Z', findings: [] }
    ], total: 1, offset: 0 });
    await settle();
    const row = page.document.querySelector('tr[data-incident-id="inc_a"]');
    assert.equal(row.getAttribute('tabindex'), '0');
    key(page, row, 'Enter');
    await settle();
    assert.equal(page.pending('/api/v1/incidents/inc_a').length, 1);
});
