// Run with: node --test ui/dismiss_test.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const tick = () => new Promise(resolve => setImmediate(resolve));

function section(source, from, to) {
    const start = source.indexOf(from);
    const end = source.indexOf(to);
    assert.ok(start >= 0 && end > start, 'missing section ' + from);
    return source.slice(start, end);
}

function findingsPage(selected = []) {
    const requests = [], confirms = [], offers = [], toasts = [];
    let refreshed = 0;
    const context = vm.createContext({
        Blob,
        CSM: {
            confirm(message) { confirms.push(message); return Promise.resolve(); },
            post(url, body) {
                requests.push({ url, body });
                const count = body.keys ? body.keys.length : 1;
                return Promise.resolve({ ok: true, count, undo_token: 'undo-1' });
            },
            toast(message, kind) { toasts.push({ message, kind }); },
            undo: { offer(entry) { offers.push(entry); } }
        },
        getSelectedRows() {
            return selected.map(key => ({ getAttribute(name) { return name === 'data-key' ? key : ''; } }));
        },
        refreshFindings() { refreshed++; }
    });
    const shared = fs.readFileSync(path.join(__dirname, 'static/js/csm-core.js'), 'utf8');
    vm.runInContext(section(shared, 'CSM.QUARANTINE_BULK_MAX', '// Wrapper for DELETE'), context);
    const src = fs.readFileSync(path.join(__dirname, 'static/js/findings.js'), 'utf8');
    vm.runInContext(section(src, '// --- Single actions ---', '// --- Suppress dialog ---'), context);
    vm.runInContext(section(src, '// --- Bulk actions ---', '// --- Scan account ---'), context);
    return { context, requests, confirms, offers, toasts, refreshed: () => refreshed };
}

test('dismiss says what it really does before acting', async () => {
    const { context, confirms } = findingsPage();
    context.dismissOne('webshell:x');
    await tick();
    assert.equal(confirms.length, 1);
    assert.doesNotMatch(confirms[0], /can be restored/i);
    assert.match(confirms[0], /Suppress/);
    assert.match(confirms[0], /undo/i);
});

test('dismiss offers the undo the server recorded', async () => {
    const { context, requests, offers } = findingsPage();
    context.dismissOne('webshell:x');
    await tick();
    assert.equal(requests.length, 1);
    assert.equal(requests[0].body.key, 'webshell:x');
    assert.equal(offers.length, 1);
    assert.equal(offers[0].token, 'undo-1');
});

test('bulk dismiss is one request with one undo', async () => {
    const { context, requests, offers, refreshed } = findingsPage(['a:1', 'b:2', 'c:3']);
    context.bulkAction('dismiss');
    await tick();
    await tick();
    assert.equal(requests.length, 1);
    assert.deepEqual(Array.from(requests[0].body.keys), ['a:1', 'b:2', 'c:3']);
    assert.equal(offers.length, 1);
    assert.equal(refreshed(), 1);
});

test('bulk dismiss over the server limit sends nothing', async () => {
    const keys = Array.from({ length: 501 }, (_, i) => 'k:' + i);
    const { context, requests, confirms, toasts } = findingsPage(keys);
    context.bulkAction('dismiss');
    await tick();
    assert.equal(requests.length, 0);
    assert.equal(confirms.length, 0);
    assert.ok(toasts.some(t => /500/.test(t.message)));
});
