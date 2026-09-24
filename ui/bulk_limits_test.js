// Run with: node --test ui/bulk_limits_test.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const { loadPage, templateBody, items, SHARED, settle } = require('./pagekit.js');

function script(name) {
    return fs.readFileSync(path.join(__dirname, 'static/js', name), 'utf8');
}

function batchHelper(CSM) {
    const source = script('csm-core.js');
    vm.runInNewContext(source.slice(source.indexOf('CSM.QUARANTINE_BULK_MAX'),
        source.indexOf('// Wrapper for DELETE')), { CSM });
}

const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
    let resolve, reject;
    const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
    return { promise, resolve, reject };
}

test('batches are sequential, preserve order and report completed batches', async () => {
    const requests = [], replies = [], pending = [];
    const CSM = { post(url, body) {
        requests.push({ url, body });
        const d = deferred();
        pending.push(d);
        return d.promise;
    } };
    batchHelper(CSM);
    const ids = Array.from({ length: 250 }, (_, i) => String(i));
    const done = CSM.postBatches('/delete', ids, CSM.QUARANTINE_BULK_MAX,
        batch => ({ ids: batch }), data => replies.push(data.count));
    for (let i = 0; i < 3; i++) {
        await tick();
        assert.equal(requests.length, i + 1);
        assert.deepEqual(replies, [100, 100].slice(0, i));
        pending[i].resolve({ count: requests[i].body.ids.length });
    }
    await done;
    assert.deepEqual(requests.map(r => r.body.ids.length), [100, 100, 50]);
    assert.deepEqual(requests.flatMap(r => r.body.ids), ids);
    assert.deepEqual(replies, [100, 100, 50]);
});

test('a failed batch stops later requests and preserves the completed count', async () => {
    let calls = 0, deleted = 0;
    const CSM = { post() {
        calls++;
        return calls === 2 ? Promise.reject(new Error('offline')) : Promise.resolve({ count: 100 });
    } };
    batchHelper(CSM);
    await assert.rejects(CSM.postBatches('/delete', Array(250).fill('id'), 100,
        ids => ({ ids }), data => { deleted += data.count; }), /offline/);
    assert.equal(calls, 2);
    assert.equal(deleted, 100);
});

// quarantinePage loads the Quarantine page with count files, all on one
// page of the table, and every row selected.
async function quarantinePage(count = 1) {
    const files = Array.from({ length: count }, (_, i) => ({
        id: 'id-' + i, original_path: '/home/alice/f' + i + '.php', size: 1, quarantined_at: '2026-09-22T10:00:00Z', reason: 'r'
    }));
    const page = loadPage(templateBody('quarantine'), SHARED.concat(['quarantine.js']),
        { storage: { 'csm-quarantine-table': JSON.stringify({ perPage: 0 }) } });
    const toasts = [];
    page.window.CSM.confirm = () => Promise.resolve();
    page.window.CSM.toast = (message, kind) => { toasts.push({ message, kind }); };
    page.respond('/api/v1/quarantine', 200, items(files));
    await settle();
    selectAll(page);
    return { page, files, toasts };
}

function selectAll(page) {
    const all = page.document.getElementById('q-select-all');
    all.checked = true;
    all.dispatchEvent(new page.window.Event('change'));
}

const deletes = page => page.requests.filter(r => r.url.includes('/api/v1/quarantine/bulk-delete'));
const reloads = page => page.pending().filter(r => r.url.endsWith('/api/v1/quarantine'));

test('quarantine reports the confirmed count when the second batch fails', async () => {
    const { page, files, toasts } = await quarantinePage(250);
    page.document.getElementById('bulk-delete-btn').click();
    await settle();
    assert.equal(deletes(page).length, 1);
    assert.equal(deletes(page)[0].body.ids.length, 100);
    page.respond('/api/v1/quarantine/bulk-delete', 200, { count: 100 });
    await settle();
    assert.equal(deletes(page).length, 2);
    page.fail('/api/v1/quarantine/bulk-delete', new Error('offline'));
    await settle();
    assert.equal(deletes(page).length, 2, 'third batch must not run');
    assert.deepEqual(toasts, [{ message: 'Deleted 100 file(s), then failed: offline', kind: 'error' }]);
    assert.equal(reloads(page).length, 1);
    page.respond('/api/v1/quarantine', 200, items(files.slice(100)));
    await settle();
    selectAll(page);
    assert.equal(page.document.getElementById('bulk-delete-btn').disabled, false);
});

test('quarantine reports files the server could not delete', async () => {
    const { page, files, toasts } = await quarantinePage(3);
    page.document.getElementById('bulk-delete-btn').click();
    await settle();
    page.respond('/api/v1/quarantine/bulk-delete', 200, { count: 2, failed: ['id-1'] });
    await settle();
    page.respond('/api/v1/quarantine', 200, items(files.slice(1, 2)));
    await settle();
    assert.deepEqual(toasts, [{ message: 'Deleted 2 file(s); 1 could not be deleted and stay listed', kind: 'warning' }]);
});

for (const failure of [false, true]) {
    test('quarantine excludes overlapping mutations through refresh, failure=' + failure, async () => {
        const { page, files } = await quarantinePage(1);
        const byId = id => page.document.getElementById(id);
        const rowRestore = () => page.document.querySelector('.restore-btn');
        byId('bulk-delete-btn').click();
        await settle();
        assert.equal(deletes(page).length, 1);
        assert.equal(byId('bulk-delete-btn').disabled, true);
        assert.equal(byId('bulk-restore-btn').disabled, true);
        assert.equal(rowRestore().disabled, true);
        // A selection repaint must keep the lock.
        page.document.querySelector('.q-cb').dispatchEvent(new page.window.Event('change'));
        assert.equal(byId('bulk-delete-btn').disabled, true);
        byId('bulk-delete-btn').click();
        byId('bulk-restore-btn').click();
        rowRestore().click();
        await settle();
        assert.equal(deletes(page).length, 1);
        assert.equal(page.pending('/api/v1/quarantine-restore').length, 0);
        if (failure) page.fail('/api/v1/quarantine/bulk-delete', new Error('offline'));
        else page.respond('/api/v1/quarantine/bulk-delete', 200, { count: 1 });
        await settle();
        assert.equal(byId('bulk-delete-btn').disabled, true, 'refresh still pending');
        page.respond('/api/v1/quarantine', 200, items(files));
        await settle();
        assert.equal(rowRestore().disabled, false);
        selectAll(page);
        assert.equal(byId('bulk-delete-btn').disabled, false);
        byId('bulk-delete-btn').click();
        await settle();
        assert.equal(deletes(page).length, 2, 'lock released after refresh');
        page.respond('/api/v1/quarantine/bulk-delete', 200, { count: 0 });
        await settle();
    });
}

function findingsBulk(CSM, row) {
    const context = vm.createContext({ CSM, Blob,
        getSelectedRows() { return [{ getAttribute(name) { return row[name] || ''; } }]; },
        refreshFindings() {}
    });
    const source = script('findings.js');
    vm.runInContext(source.slice(source.indexOf('// --- Bulk actions ---'),
        source.indexOf('// --- Scan account ---')), context);
    return context;
}

// Findings had a bulk "quarantine" path with no button that sent every
// selected finding to the fix endpoint under a quarantine label. It is gone:
// nothing reaches the fix endpoint except the Fix action.
test('Findings has no bulk quarantine path to the fix endpoint', async () => {
    const requests = [], confirmations = [];
    const CSM = {
        confirm(message) { confirmations.push(message); return Promise.resolve(); },
        post(url, body) { requests.push({ url, body }); return Promise.resolve({}); },
        toast() {}
    };
    batchHelper(CSM);
    const context = findingsBulk(CSM, { 'data-check': 'webshell', 'data-message': 'File found', 'data-hasFix': 'false' });
    context.bulkAction('quarantine');
    await tick();
    assert.equal(requests.length, 0);
    assert.equal(confirmations.length, 0);
});

for (const action of ['fix']) {
    for (const oversized of [false, true]) {
        test('Findings ' + action + ' checks the UTF-8 request size, oversized=' + oversized, async () => {
            const requests = [], confirmations = [], toasts = [];
            const CSM = {
                confirm(message) { confirmations.push(message); return Promise.resolve(); },
                post(url, body) { requests.push({ url, body }); return Promise.resolve({}); },
                toast(message) { toasts.push(message); }
            };
            batchHelper(CSM);
            const row = {
                'data-check': 'webshell', 'data-message': 'File found',
                // Fewer than 64K UTF-16 code units, but over 64K UTF-8 bytes.
                'data-details': oversized ? '\u20ac'.repeat(23000) : 'small',
                'data-hasFix': 'true'
            };
            const context = vm.createContext({ CSM, Blob,
                getSelectedRows() { return [{ getAttribute(name) { return row[name] || ''; } }]; },
                refreshFindings() {}
            });
            const source = script('findings.js');
            vm.runInContext(source.slice(source.indexOf('// --- Bulk actions ---'),
                source.indexOf('// --- Scan account ---')), context);
            context.bulkAction(action);
            await tick();
            assert.equal(requests.length, oversized ? 0 : 1);
            assert.equal(confirmations.length, oversized ? 0 : 1);
            if (oversized) assert.ok(toasts.some(message => /[Ss]elect fewer/.test(message)));
        });
    }
}

test('Findings accepts the exact byte limit and refuses the next byte', () => {
    const CSM = { toast() {} };
    batchHelper(CSM);
    const context = vm.createContext({ CSM, Blob });
    const source = script('findings.js');
    vm.runInContext(source.slice(source.indexOf('// --- Bulk actions ---'),
        source.indexOf('// --- Scan account ---')), context);
    const overhead = new Blob([JSON.stringify([{ details: '' }])]).size;
    for (const bytes of [CSM.FIX_BULK_BODY_MAX - 1, CSM.FIX_BULK_BODY_MAX, CSM.FIX_BULK_BODY_MAX + 1]) {
        const result = context.bulkFixPayload([{ details: 'x'.repeat(bytes - overhead) }]);
        assert.equal(result !== null, bytes <= CSM.FIX_BULK_BODY_MAX);
        if (result) assert.equal(new Blob([JSON.stringify(result)]).size, bytes);
    }
});

// The Cleanup History file-backup cases (row restore racing a batched delete,
// select-all past filters, selection controls across paging) moved to
// quarantine_test.js with the list itself.
