// Run with: node --test ui/bulk_limits_test.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

function script(name) {
    return fs.readFileSync(path.join(__dirname, 'static/js', name), 'utf8');
}

function batchHelper(CSM) {
    const source = script('csrf.js');
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

function quarantinePage(count = 1) {
    const elements = new Map();
    function element(id) {
        if (!elements.has(id)) elements.set(id, {
            id, disabled: false, dataset: {}, listeners: {},
            classList: { add() {}, toggle() {} },
            addEventListener(type, fn) { this.listeners[type] = fn; },
            getAttribute() { return 'id'; }
        });
        return elements.get(id);
    }
    const checkboxes = Array.from({ length: count }, (_, i) => ({
        checked: true, offsetParent: {}, dataset: {},
        getAttribute() { return 'id-' + i; }, addEventListener() {}
    }));
    const requests = [], toasts = [];
    const context = vm.createContext({
        document: {
            getElementById: element,
            querySelector(selector) { return selector === '.q-cb' ? checkboxes[0] : element(selector); },
            querySelectorAll(selector) { return selector === '.q-cb' ? checkboxes : [element('row-restore')]; }
        },
        CSM: {
            get() { return new Promise(() => {}); },
            confirm() { return Promise.resolve(); },
            post(url, body) {
                const d = deferred();
                requests.push({ url, body, ...d });
                return d.promise;
            },
            toast(message, kind) { toasts.push({ message, kind }); }
        }
    });
    batchHelper(context.CSM);
    const source = script('csm-ui.js');
    vm.runInContext(source.slice(source.indexOf('CSM.bulk = function'),
        source.indexOf('// Shared focus trap.')), context);
    vm.runInContext(script('quarantine.js'), context);
    context.updateBulkRestore();
    const reload = deferred();
    context.loadQuarantine = () => reload.promise;
    return { context, element, requests, toasts, reload };
}

test('quarantine reports the confirmed count when the second batch fails', async () => {
    const { element, requests, toasts, reload } = quarantinePage(250);
    element('bulk-delete-btn').listeners.click();
    await tick();
    assert.equal(requests.length, 1);
    assert.equal(requests[0].body.ids.length, 100);
    requests[0].resolve({ count: 100 });
    await tick();
    assert.equal(requests.length, 2);
    requests[1].reject(new Error('offline'));
    await tick();
    assert.equal(requests.length, 2, 'third batch must not run');
    assert.deepEqual(toasts, [{ message: 'Deleted 100 file(s), then failed: offline', kind: 'error' }]);
    reload.resolve();
    await tick();
    assert.equal(element('bulk-delete-btn').disabled, false);
});

test('quarantine reports files the server could not delete', async () => {
    const { element, requests, toasts, reload } = quarantinePage(3);
    element('bulk-delete-btn').listeners.click();
    await tick();
    requests[0].resolve({ count: 2, failed: ['id-1'] });
    await tick();
    reload.resolve();
    await tick();
    assert.deepEqual(toasts, [{ message: 'Deleted 2 file(s); 1 could not be deleted and stay listed', kind: 'warning' }]);
});

for (const failure of [false, true]) {
    test('quarantine excludes overlapping mutations through refresh, failure=' + failure, async () => {
        const { context, element, requests, reload } = quarantinePage();
        const click = id => element(id).listeners.click();
        click('bulk-delete-btn');
        await tick();
        assert.equal(requests.length, 1);
        assert.equal(element('bulk-delete-btn').disabled, true);
        assert.equal(element('bulk-restore-btn').disabled, true);
        assert.equal(element('row-restore').disabled, true);
        context._quarBulk.refresh(); // A selection/filter repaint must retain the lock.
        assert.equal(element('bulk-delete-btn').disabled, true);
        click('bulk-delete-btn');
        click('bulk-restore-btn');
        context.restoreFile('other');
        await tick();
        assert.equal(requests.length, 1);
        if (failure) requests[0].reject(new Error('offline'));
        else requests[0].resolve({ count: 1 });
        await tick();
        assert.equal(element('bulk-delete-btn').disabled, true, 'refresh still pending');
        reload.resolve();
        await tick();
        assert.equal(element('bulk-delete-btn').disabled, false);
        assert.equal(element('row-restore').disabled, false);
        click('bulk-delete-btn');
        await tick();
        assert.equal(requests.length, 2, 'lock released after refresh');
        requests[1].resolve({ count: 0 });
        await tick();
    });
}

for (const action of ['fix', 'quarantine']) {
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

test('Cleanup prevents a row restore from racing a batched delete', async () => {
    const elements = new Map();
    function element(id) {
        if (!elements.has(id)) elements.set(id, {
            disabled: false, innerHTML: '', listeners: {}, dataset: {},
            classList: { toggle() {} },
            getAttribute() { return 'id'; },
            addEventListener(type, fn) { this.listeners[type] = fn; }
        });
        return elements.get(id);
    }
    const requests = [], reload = deferred();
    const checkbox = {
        checked: true, offsetParent: {}, dataset: {},
        getAttribute() { return 'id'; }, addEventListener() {}
    };
    function query(selector) {
        if (selector === '.cleanup-file-restore') return [element('row')];
        if (selector === '.cleanup-file-cb' || selector === '.cleanup-file-cb:checked') return [checkbox];
        return [];
    }
    const context = vm.createContext({
        document: {
            getElementById: element,
            querySelector(selector) { return selector.charAt(0) === '#' ? element(selector.slice(1)) : null; },
            querySelectorAll: query
        },
        CSM: {
            confirm() { return Promise.resolve(); }, toast() {},
            get() { return reload.promise; },
            post(url) {
                const d = deferred();
                requests.push({ url, ...d });
                return d.promise;
            }
        }
    });
    batchHelper(context.CSM);
    const ui = script('csm-ui.js');
    vm.runInContext(ui.slice(ui.indexOf('CSM.bulk = function'), ui.indexOf('// Shared focus trap.')), context);
    // Expose the row handlers without bootstrapping unrelated backup tables.
    vm.runInContext(script('cleanup-history.js').replace('    loadFileBackups();\n    loadDBBackups();',
        '    globalThis.restoreFileBackup = restoreFileBackup;\n    globalThis.bindFileBackupActions = bindFileBackupActions;'), context);
    context.bindFileBackupActions({ querySelectorAll: query });
    element('cleanup-files-delete-btn').listeners.click();
    await tick();
    assert.equal(requests.length, 1);
    assert.equal(element('row').disabled, true);
    context.restoreFileBackup('id');
    await tick();
    assert.equal(requests.length, 1);
    requests[0].resolve({ count: 1 });
    await tick();
    assert.equal(element('row').disabled, true);
    reload.resolve([]);
    await tick();
    assert.equal(element('row').disabled, false);
});

test('Cleanup select-all and bulk delete never reach rows hidden by paging or filters', async () => {
    const elements = new Map();
    function element(id) {
        if (!elements.has(id)) elements.set(id, {
            id, checked: false, indeterminate: false, disabled: false, innerHTML: '', textContent: '',
            dataset: {}, listeners: {},
            classList: { toggle() {}, add() {}, remove() {} },
            getAttribute() { return ''; },
            addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
        });
        return elements.get(id);
    }
    function box(id, visible) {
        return {
            checked: false, offsetParent: visible ? {} : null, dataset: {}, listeners: {},
            getAttribute(name) { return name === 'data-id' ? id : ''; },
            addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
        };
    }
    const boxes = [box('a', true), box('b', true), box('c', false), box('d', false)];
    function query(selector) {
        if (selector === '.cleanup-file-cb') return boxes;
        if (selector === '.cleanup-file-cb:checked') return boxes.filter(cb => cb.checked);
        return [];
    }
    const requests = [];
    const context = vm.createContext({
        document: {
            getElementById: element,
            querySelector(selector) { return selector.charAt(0) === '#' ? element(selector.slice(1)) : null; },
            querySelectorAll: query
        },
        CSM: {
            confirm() { return Promise.resolve(); }, toast() {},
            get() { return new Promise(() => {}); },
            post(url, body) { requests.push(body); return Promise.resolve({ count: body.ids.length }); }
        }
    });
    batchHelper(context.CSM);
    const ui = script('csm-ui.js');
    vm.runInContext(ui.slice(ui.indexOf('CSM.bulk = function'), ui.indexOf('// Shared focus trap.')), context);
    vm.runInContext(script('cleanup-history.js').replace('    loadFileBackups();\n    loadDBBackups();',
        '    globalThis.bindFileBackupActions = bindFileBackupActions;'), context);
    context.bindFileBackupActions({ querySelectorAll: query });

    const selectAll = element('cleanup-files-select-all');
    selectAll.checked = true;
    (selectAll.listeners.change || []).forEach(fn => fn.call(selectAll));
    assert.deepEqual(boxes.map(cb => cb.checked), [true, true, false, false]);

    // A row an earlier filter hid while it was checked is not acted on either.
    boxes[2].checked = true;
    (element('cleanup-files-delete-btn').listeners.click || []).forEach(fn => fn());
    await tick();
    assert.equal(requests.length, 1);
    assert.deepEqual(Array.from(requests[0].ids), ['a', 'b']);
});
