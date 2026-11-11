// Run with: node --test ui/dismiss_test.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

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

function shownFinding(sha) {
    return {
        key: 'webshell:/home/a/public_html/x.php', check: 'webshell',
        message: 'Webshell found', severity: 'CRITICAL', content_sha256: sha
    };
}

async function renderedFindings(findings) {
    const page = loadPage(templateBody('findings'), SHARED.concat(['findings.js', 'shortcuts.js']));
    page.respond('/api/v1/findings/enriched', 200, { items: findings, total: findings.length });
    await settle();
    return page;
}

function pressKey(page, target, key) {
    const event = new page.window.Event('keydown', { bubbles: true, cancelable: true });
    event.key = key;
    target.dispatchEvent(event);
}

async function dismissFrom(page, action) {
    const row = page.document.querySelector('.finding-row');
    if (action === 'row') {
        row.querySelector('.dismiss-btn').click();
    } else if (action === 'detail') {
        row.click();
        await settle();
        page.respond('/api/v1/finding-detail', 200, {});
        await settle();
        page.document.querySelector('[data-csm-finding-dismiss]').click();
    } else if (action === 'shortcut') {
        row.focus();
        pressKey(page, row, 'd');
    } else if (action === 'bulk') {
        const checkbox = row.querySelector('.row-checkbox');
        checkbox.checked = true;
        checkbox.dispatchEvent(new page.window.Event('change', { bubbles: true }));
        page.document.getElementById('bulk-dismiss-btn').click();
    } else {
        assert.fail('unknown dismissal action ' + action);
    }
    await settle();
}

for (const action of ['row', 'detail', 'shortcut', 'bulk']) {
    for (const sha of ['a'.repeat(64), undefined]) {
        test(action + ' dismissal sends the displayed hash ' + (sha ? 'when present' : 'when absent'), async () => {
            const finding = shownFinding(sha);
            const page = await renderedFindings([finding]);
            let confirm;
            page.window.CSM.confirm = () => new Promise(resolve => { confirm = resolve; });
            await dismissFrom(page, action);
            assert.equal(page.pending('/api/v1/dismiss').length, 0);
            assert.equal(typeof confirm, 'function');
            // The confirmation must retain what the operator saw, even if
            // the page reloads newer evidence while it is open.
            page.document.getElementById('refresh-page-btn').click();
            await settle();
            page.respond('/api/v1/findings/enriched', 200, {
                items: [shownFinding('b'.repeat(64))], total: 1
            });
            await settle();
            confirm();
            await settle();
            const requests = page.pending('/api/v1/dismiss');
            assert.equal(requests.length, 1);
            assert.deepEqual(requests[0].body.contents, { [finding.key]: sha || '' });
            if (action === 'bulk') assert.deepEqual(requests[0].body.keys, [finding.key]);
            else assert.equal(requests[0].body.key, finding.key);
            page.respond('/api/v1/dismiss', 200, { count: 1 });
            await settle();
        });
    }
}

test('rendered content hashes cannot inject row attributes or markup', async () => {
    const sha = '\" data-injected=\"yes\"><img src=x> &\'';
    const page = await renderedFindings([shownFinding(sha)]);
    const row = page.document.querySelector('.finding-row');
    assert.equal(row.getAttribute('data-content-sha256'), sha);
    assert.equal(row.getAttribute('data-injected'), null);
    assert.equal(row.querySelector('img'), null);
});

for (const action of ['row', 'detail', 'shortcut', 'bulk']) {
    test(action + ' dismissal warns and reloads after a content conflict', async () => {
        const page = await renderedFindings([shownFinding('a'.repeat(64))]);
        const toasts = [], offers = [];
        page.window.CSM.confirm = () => Promise.resolve();
        page.window.CSM.toast = (message, kind) => toasts.push({ message, kind });
        page.window.CSM.undo = { offer(entry) { offers.push(entry); } };
        await dismissFrom(page, action);
        page.respond('/api/v1/dismiss', 409, { error: changedMessage });
        await settle();
        assert.deepEqual(toasts, [{ message: changedMessage, kind: 'warning' }]);
        assert.equal(offers.length, 0);
        assert.equal(page.pending('/api/v1/findings/enriched').length, 1);
        page.respond('/api/v1/findings/enriched', 200, {
            items: [shownFinding('b'.repeat(64))], total: 1
        });
        await settle();
        assert.equal(page.document.querySelector('.finding-row').getAttribute('data-content-sha256'), 'b'.repeat(64));
    });
}

test('a bulk dismissal with every row refused offers no undo', async () => {
    const response = { ok: true, count: 0, refused: ['a:1', 'b:2'] };
    const { context, toasts, offers, refreshed } = findingsPage(['a:1', 'b:2'], { response });
    context.bulkAction('dismiss');
    await tick();
    assert.equal(toasts.length, 1);
    assert.match(toasts[0].message, /^2 finding\(s\).*not dismissed/);
    assert.equal(toasts[0].kind, 'warning');
    assert.equal(offers.length, 0);
    assert.equal(refreshed(), 1);
});

test('other bulk dismissal errors stay errors without refreshing', async () => {
    const { context, toasts, offers, refreshed } = findingsPage(['a:1'], {
        reject: { status: 500, message: 'Unable to dismiss' }
    });
    context.bulkAction('dismiss');
    await tick();
    assert.deepEqual(toasts, [{ message: 'Dismiss failed: Unable to dismiss', kind: 'error' }]);
    assert.equal(offers.length, 0);
    assert.equal(refreshed(), 0);
});
