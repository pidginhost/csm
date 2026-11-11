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

// selected rows are keys, or {key, sha} for a row that showed a content hash.
// opts.reject makes the post fail with that error; opts.response replaces its answer.
function findingsPage(selected = [], opts = {}) {
    const requests = [], confirms = [], offers = [], toasts = [];
    let refreshed = 0;
    const context = vm.createContext({
        Blob,
        CSM: {
            confirm(message) { confirms.push(message); return Promise.resolve(); },
            post(url, body) {
                requests.push({ url, body });
                if (opts.reject) return Promise.reject(Object.assign(new Error(opts.reject.message), opts.reject));
                if (opts.response) return Promise.resolve(opts.response);
                const count = body.keys ? body.keys.length : 1;
                return Promise.resolve({ ok: true, count, undo_token: 'undo-1' });
            },
            errorText(err) { return err && err.message ? err.message : 'request failed'; },
            toast(message, kind) { toasts.push({ message, kind }); },
            undo: { offer(entry) { offers.push(entry); } }
        },
        getSelectedRows() {
            return selected.map(row => {
                const { key, sha } = typeof row === 'string' ? { key: row, sha: '' } : row;
                return { getAttribute(name) { return name === 'data-key' ? key : name === 'data-content-sha256' ? sha : ''; } };
            });
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

const changedMessage = 'The file changed since the page loaded. Review the finding again.';

test('dismiss sends the content the row showed', async () => {
    const { context, requests } = findingsPage();
    context.dismissOne('webshell:x', 'a'.repeat(64));
    await tick();
    assert.deepEqual({ ...requests[0].body.contents }, { 'webshell:x': 'a'.repeat(64) });
});

test('bulk dismiss sends the content of every row', async () => {
    const { context, requests } = findingsPage([{ key: 'a:1', sha: 'a'.repeat(64) }, { key: 'b:2', sha: '' }]);
    context.bulkAction('dismiss');
    await tick();
    assert.deepEqual({ ...requests[0].body.contents }, { 'a:1': 'a'.repeat(64), 'b:2': '' });
});

test('a refused dismiss warns and reloads the list', async () => {
    const { context, toasts, offers, refreshed } = findingsPage([], { reject: { status: 409, message: changedMessage } });
    context.dismissOne('webshell:x', 'a'.repeat(64));
    await tick();
    await tick();
    assert.ok(toasts.some(t => t.message === changedMessage && t.kind === 'warning'), JSON.stringify(toasts));
    assert.equal(offers.length, 0);
    assert.equal(refreshed(), 1);
});

test('bulk dismiss says how many rows changed and were not dismissed', async () => {
    const response = { ok: true, count: 1, refused: ['b:2'], undo_token: 'undo-1' };
    const { context, toasts, offers, refreshed } = findingsPage([{ key: 'a:1', sha: 'a' }, { key: 'b:2', sha: 'b' }], { response });
    context.bulkAction('dismiss');
    await tick();
    await tick();
    assert.ok(toasts.some(t => /\b1\b.*not dismissed/.test(t.message) && t.kind === 'warning'), JSON.stringify(toasts));
    assert.equal(offers.length, 1);
    assert.equal(refreshed(), 1);
});
