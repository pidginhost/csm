// Run with: node --test ui/bulksuppress_test.js
// Findings can suppress a selection: one rule per selected file. Findings
// without a file are skipped, since their only rule would hide the whole
// check, which stays a deliberate single-finding choice.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

function finding(check, message, filePath) {
    return {
        key: check + ':' + message, severity: 'HIGH', sev_class: 'high', check, message, file_path: filePath,
        first_seen: '2026-09-22T10:00:00Z', last_seen: '2026-09-22T10:00:00Z'
    };
}

async function findingsPage(findings) {
    const page = loadPage(templateBody('findings'), SHARED.concat(['findings.js']));
    page.respond('/api/v1/findings/enriched', 200, {
        findings, check_types: [], accounts: [], total: findings.length
    });
    await settle();
    page.window.CSM.confirm = message => { page.confirmed = message; return Promise.resolve(); };
    page.toasts = [];
    page.window.CSM.toast = (message, kind) => page.toasts.push({ message, kind });
    return page;
}

function selectAll(page) {
    page.document.querySelectorAll('.row-checkbox').forEach(cb => {
        cb.checked = true;
        cb.dispatchEvent(new page.window.Event('change'));
    });
}

function clickSuppress(page) {
    const btn = page.document.getElementById('bulk-suppress-btn');
    assert.ok(btn, 'no bulk suppress button');
    btn.click();
}

test('bulk suppress creates one rule per selected file', async () => {
    const page = await findingsPage([
        finding('webshell', 'shell a', '/home/a/public_html/[x].php'),
        finding('webshell', 'shell b', '/home/b/public_html/b.php'),
        finding('perf_load', 'load high', '')
    ]);
    selectAll(page);
    clickSuppress(page);
    await settle();
    assert.match(page.confirmed, /2 /);
    assert.match(page.confirmed, /1 .*without a file/);
    const bodies = [];
    for (let i = 0; i < 2; i++) {
        const req = page.respond('/api/v1/suppressions', 200, { ok: true, id: 'r' + i });
        assert.equal(req.method, 'POST');
        bodies.push(req.body);
        await settle();
    }
    assert.equal(page.pending('/api/v1/suppressions').length, 0);
    const patterns = bodies.map(b => b.path_pattern).sort();
    assert.deepEqual(patterns, ['/home/a/public_html/\\[x\\].php', '/home/b/public_html/b.php']);
    bodies.forEach(b => {
        assert.equal(b.check, 'webshell');
        assert.equal(b.all_paths, undefined, 'bulk suppress must never create a check-wide rule');
    });
    assert.ok(page.pending('/api/v1/findings/enriched').length >= 1, 'findings not refreshed');
    assert.ok(page.toasts.some(t => t.kind === 'success' && /2 /.test(t.message)), JSON.stringify(page.toasts));
});

test('bulk suppress sends nothing when no selected finding names a file', async () => {
    const page = await findingsPage([finding('perf_load', 'load high', '')]);
    selectAll(page);
    clickSuppress(page);
    await settle();
    assert.equal(page.pending('/api/v1/suppressions').length, 0);
    assert.equal(page.confirmed, undefined);
    assert.ok(page.toasts.some(t => t.kind === 'warning'), JSON.stringify(page.toasts));
});

test('bulk suppress stops at the first failure and says how many were saved', async () => {
    const page = await findingsPage([
        finding('webshell', 'shell a', '/home/a/a.php'),
        finding('webshell', 'shell b', '/home/b/b.php'),
        finding('webshell', 'shell c', '/home/c/c.php')
    ]);
    selectAll(page);
    clickSuppress(page);
    await settle();
    page.respond('/api/v1/suppressions', 200, { ok: true, id: 'r0' });
    await settle();
    page.respond('/api/v1/suppressions', 400, { error: 'invalid path_pattern' });
    await settle();
    assert.equal(page.pending('/api/v1/suppressions').length, 0, 'kept sending after a failure');
    assert.ok(page.toasts.some(t => t.kind === 'error' && /1 of 3/.test(t.message)), JSON.stringify(page.toasts));
});

test('bulk suppress refuses a selection over the limit before sending', async () => {
    const many = [];
    for (let i = 0; i < 101; i++) many.push(finding('webshell', 'shell ' + i, '/home/a/f' + i + '.php'));
    const page = await findingsPage(many);
    const perPage = page.document.getElementById('per-page');
    perPage.value = '0';
    perPage.dispatchEvent(new page.window.Event('change'));
    await settle();
    selectAll(page);
    clickSuppress(page);
    await settle();
    assert.equal(page.document.getElementById('selected-count').textContent, '101', 'not every row was selected');
    assert.equal(page.pending('/api/v1/suppressions').length, 0);
    assert.equal(page.confirmed, undefined);
    assert.ok(page.toasts.some(t => t.kind === 'error' && /limit is 100/.test(t.message)), JSON.stringify(page.toasts));
});

test('the same file selected twice gets one rule', async () => {
    const page = await findingsPage([
        finding('webshell', 'shell a', '/home/a/a.php'),
        finding('webshell', 'shell a again', '/home/a/a.php')
    ]);
    selectAll(page);
    clickSuppress(page);
    await settle();
    page.respond('/api/v1/suppressions', 200, { ok: true, id: 'r0' });
    await settle();
    assert.equal(page.pending('/api/v1/suppressions').length, 0);
});

test('bulk suppression opens one confirmation and unlocks after cancellation', async () => {
    const page = await findingsPage([finding('webshell', 'shell', '/home/a/x.php')]);
    selectAll(page);
    let reject, asks = 0;
    page.window.CSM.confirm = () => { asks++; return new Promise((_, no) => { reject = no; }); };
    clickSuppress(page);
    clickSuppress(page);
    assert.equal(asks, 1);
    reject(null);
    await settle();
    clickSuppress(page);
    assert.equal(asks, 2);
    assert.equal(page.pending('/api/v1/suppressions').length, 0);
    reject(null);
    await settle();
});
