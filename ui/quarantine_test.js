// Run with: node --test ui/quarantine_test.js
// The Quarantine page is the one list of file backups: quarantined files and
// pre-clean backups, with their type and live state. Cleanup History used to
// list the same files a second time; it now keeps the DB object backups and
// points here.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

function file(id, extra) {
    return Object.assign({
        id, original_path: '/home/alice/public_html/' + id + '.php', size: 10,
        quarantined_at: '2026-09-22T10:00:00Z', reason: 'YARA rule match: x', kind: 'quarantine', live_state: 'original_missing'
    }, extra || {});
}

async function quarantinePage(files) {
    const page = loadPage(templateBody('quarantine'), SHARED.concat(['quarantine.js']));
    page.window.CSM.confirm = () => Promise.resolve();
    page.respond('/api/v1/quarantine', 200, files);
    await settle();
    return page;
}

function tick(page, el) {
    el.checked = !el.checked;
    el.dispatchEvent(new page.window.Event('change'));
}

function row(page, id) {
    return page.document.querySelector('.q-cb[data-id="' + id + '"]').closest('tr');
}

test('Quarantine shows each file backup with its type and live state', async () => {
    const page = await quarantinePage([
        file('a', { kind: 'pre_clean', live_state: 'live_differs' }),
        file('b')
    ]);
    assert.match(row(page, 'a').textContent, /Pre-clean backup/);
    assert.match(row(page, 'a').textContent, /Live differs/);
    assert.match(row(page, 'b').textContent, /Quarantine/);
    assert.match(row(page, 'b').textContent, /Original missing/);
});

test('Quarantine filters by type', async () => {
    const page = await quarantinePage([file('a', { kind: 'pre_clean' }), file('b')]);
    const filter = page.document.getElementById('quarantine-kind-filter');
    assert.ok(filter, 'no type filter');
    filter.value = 'pre_clean';
    filter.dispatchEvent(new page.window.Event('change'));
    await settle();
    assert.equal(row(page, 'a').offsetParent !== null, true);
    assert.equal(row(page, 'b').offsetParent, null, 'a quarantined file shows under pre-clean backups');
});

test('Quarantine keeps a row restore from racing a batched delete', async () => {
    const page = await quarantinePage([file('a'), file('b')]);
    tick(page, page.document.getElementById('q-select-all'));
    page.document.getElementById('bulk-delete-btn').click();
    await settle();
    assert.equal(page.pending('/api/v1/quarantine/bulk-delete').length, 1);
    const restore = row(page, 'a').querySelector('.restore-btn');
    assert.equal(restore.disabled, true, 'row restore open during the delete');
    restore.click();
    await settle();
    assert.equal(page.pending('/api/v1/quarantine-restore').length, 0, 'a restore raced the delete');
    page.respond('/api/v1/quarantine/bulk-delete', 200, { count: 2 });
    await settle();
    assert.equal(page.document.querySelector('.restore-btn').disabled, true, 'unlocked before the list reloaded');
    page.respond('/api/v1/quarantine', 200, [file('c')]);
    await settle();
    assert.equal(page.document.querySelector('.restore-btn').disabled, false);
});

test('Quarantine select-all and bulk delete never reach rows a filter hides', async () => {
    const page = await quarantinePage([file('a'), file('b'), file('c', { original_path: '/home/bob/c.php' })]);
    const search = page.document.getElementById('quarantine-search');
    search.value = 'alice';
    search.dispatchEvent(new page.window.Event('input'));
    await new Promise(r => setTimeout(r, 400));
    await settle();
    const selectAll = page.document.getElementById('q-select-all');
    selectAll.checked = true;
    selectAll.dispatchEvent(new page.window.Event('change'));
    // A row a later filter hid while it was checked is not acted on either.
    page.document.querySelector('.q-cb[data-id="c"]').checked = true;
    page.document.getElementById('bulk-delete-btn').click();
    await settle();
    const req = page.pending('/api/v1/quarantine/bulk-delete');
    assert.equal(req.length, 1);
    assert.deepEqual(Array.from(req[0].body.ids), ['a', 'b']);
});

test('Quarantine selection controls follow paging', async () => {
    const files = Array.from({ length: 30 }, (_, i) => file('f' + String(i).padStart(2, '0')));
    const page = await quarantinePage(files);
    const selectAll = page.document.getElementById('q-select-all');
    selectAll.checked = true;
    selectAll.dispatchEvent(new page.window.Event('change'));
    const del = page.document.getElementById('bulk-delete-btn');
    assert.equal(del.disabled, false);
    assert.equal(del.textContent, 'Delete 25 file(s)');
    const next = page.document.querySelector('#quarantine-table-controls [data-page="2"], #quarantine-table-controls .page-link[aria-label="Next"]');
    assert.ok(next, 'no pager');
    next.click();
    await settle();
    assert.equal(selectAll.checked, false, 'select-all stays checked for rows the page no longer shows');
    assert.equal(del.disabled, true, 'bulk delete offered for rows the page no longer shows');
});

test('Quarantine bulk buttons show progress and keep their icons', async () => {
    const page = await quarantinePage([file('a')]);
    tick(page, page.document.querySelector('.q-cb'));
    const del = page.document.getElementById('bulk-delete-btn');
    const before = del.innerHTML;
    del.click();
    await settle();
    assert.match(del.textContent, /Deleting/);
    assert.ok(del.querySelector('i.ti'), 'the busy label dropped the icon');
    page.respond('/api/v1/quarantine/bulk-delete', 200, { count: 1 });
    await settle();
    page.respond('/api/v1/quarantine', 200, [file('b')]);
    await settle();
    assert.doesNotMatch(del.textContent, /Deleting/);
    assert.ok(del.querySelector('i.ti'));
    assert.notEqual(before, '');
});

test('Quarantine Refresh waits for a restore or delete to finish', async () => {
    const page = await quarantinePage([file('a')]);
    tick(page, page.document.querySelector('.q-cb'));
    page.document.getElementById('bulk-delete-btn').click();
    await settle();
    page.window.CSM.refresh.manual();
    await settle();
    assert.equal(page.pending('/api/v1/quarantine').filter(r => !r.url.includes('bulk')).length, 0,
        'Refresh reloaded the list under a running delete');
});

test('Quarantine preview states the size of a whole file', async () => {
    const page = await quarantinePage([file('a')]);
    let info;
    page.window.CSM.filePreview = (path, i) => { info = i; };
    row(page, 'a').querySelector('.view-btn').click();
    page.respond('/api/v1/quarantine-preview', 200, { preview: 'x', total_size: 2048, truncated: false });
    await settle();
    assert.equal(info, page.window.CSM.formatSize(2048));
});

test('Cleanup History lists DB object backups and sends file backups to Quarantine', async () => {
    const page = loadPage(templateBody('cleanup-history'), SHARED.concat(['cleanup-history.js']));
    await settle();
    assert.equal(page.pending('/api/v1/quarantine').length, 0, 'Cleanup History still loads the file list');
    assert.ok(page.pending('/api/v1/db-object-backups').length > 0);
    assert.ok(page.document.querySelector('a[href="/quarantine"]'), 'no way to the file backups');
});
