// Run with: node --test ui/hardening_test.js
// Server Hardening: a section applies only the fixes the operator left
// checked, after a confirmation that lists each change, then shows what
// happened next to the rechecked audit.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

function report(results) {
    return { timestamp: '2026-11-18T10:00:00Z', server_type: 'cpanel', score: 0, total: results.length, results };
}

const FAILING = [
    { category: 'ssh', name: 'ssh_use_dns', title: 'UseDNS', status: 'warn', message: 'UseDNS yes', fix: 'Set UseDNS no', auto_fix: 'Sets UseDNS no.' },
    { category: 'ssh', name: 'ssh_x11_forwarding', title: 'X11', status: 'warn', message: 'X11 on', fix: 'Set X11Forwarding no', auto_fix: 'Sets X11Forwarding no.' },
    { category: 'ssh', name: 'ssh_port', title: 'SSH Port', status: 'warn', message: 'port 22', fix: 'Change the port' },
    { category: 'os', name: 'os_sysctl_aslr', title: 'ASLR', status: 'fail', message: '0', fix: 'sysctl', auto_fix: 'Sets ASLR.' }
];

async function hardeningPage(results) {
    const page = loadPage(templateBody('hardening'), SHARED.concat(['hardening.js']));
    page.respond('/api/v1/hardening', 200, report(results));
    await settle();
    page.asked = [];
    page.window.CSM.confirm = (message, opts) => { page.asked.push({ message, opts: opts || {} }); return Promise.resolve(); };
    page.toasts = [];
    page.window.CSM.toast = (message, type) => page.toasts.push([message, type]);
    return page;
}

function boxes(page, cat) {
    return Array.from(page.document.querySelectorAll('input[data-fix-cat="' + cat + '"]'));
}

test('only failing checks with an automatic fix get a checked box, and manual ones none', async () => {
    const page = await hardeningPage(FAILING);
    assert.deepEqual(boxes(page, 'ssh').map(b => [b.getAttribute('data-fix-name'), b.checked]), [['ssh_use_dns', true], ['ssh_x11_forwarding', true]]);
    assert.equal(page.document.querySelectorAll('[data-apply-cat]').length, 2, 'one apply button per fixable section');
});

test('apply sends only the checked fixes of its section after listing them', async () => {
    const page = await hardeningPage(FAILING);
    boxes(page, 'ssh')[1].checked = false;
    page.document.querySelector('[data-apply-cat="ssh"]').click();
    await settle();
    assert.equal(page.asked.length, 1);
    assert.match(page.asked[0].message, /Sets UseDNS no\./);
    assert.doesNotMatch(page.asked[0].message, /X11Forwarding/);
    const post = page.pending('/api/v1/hardening/apply')[0];
    assert.ok(post, 'no apply request');
    assert.deepEqual(typeof post.body === 'string' ? JSON.parse(post.body) : post.body, { category: 'ssh', names: ['ssh_use_dns'] });
    const after = FAILING.map(r => r.name === 'ssh_use_dns' ? Object.assign({}, r, { status: 'pass', auto_fix: undefined }) : r);
    page.respond('/api/v1/hardening/apply', 200, Object.assign({ ok: true, applied: [{ name: 'ssh_use_dns', title: 'UseDNS', status: 'applied', message: 'Written and sshd reloaded.' }] }, report(after)));
    await settle();
    const outcome = page.document.querySelector('[role="status"]');
    assert.ok(outcome, 'no outcome shown');
    assert.match(outcome.textContent, /Last apply \(audit re-run afterwards\)/);
    assert.match(outcome.textContent, /applied UseDNS: Written and sshd reloaded\./);
    assert.deepEqual(boxes(page, 'ssh').map(b => b.getAttribute('data-fix-name')), ['ssh_x11_forwarding'], 'the recheck did not re-render the section');
    assert.deepEqual(page.toasts.at(-1), ['SSH: 1 applied. Audit re-run.', 'success']);
});

test('nothing checked asks nothing and sends nothing', async () => {
    const page = await hardeningPage(FAILING);
    boxes(page, 'ssh').forEach(b => { b.checked = false; });
    page.document.querySelector('[data-apply-cat="ssh"]').click();
    await settle();
    assert.equal(page.asked.length, 0);
    assert.equal(page.pending('/api/v1/hardening/apply').length, 0);
});

test('a failed apply reloads the rechecked report', async () => {
    const page = await hardeningPage(FAILING);
    page.document.querySelector('[data-apply-cat="os"]').click();
    await settle();
    page.respond('/api/v1/hardening/apply', 500, { error: 'Applying fixes failed: hardening worker: signal: killed. The audit was re-run.' });
    await settle();
    assert.equal(page.toasts.at(-1)[1], 'error');
    assert.ok(page.pending('/api/v1/hardening')[0], 'the page did not reload the rechecked report');
    const fixed = FAILING.map(r => r.name === 'os_sysctl_aslr' ? Object.assign({}, r, { status: 'pass', auto_fix: undefined }) : r);
    page.respond('/api/v1/hardening', 200, report(fixed));
    await settle();
    assert.equal(boxes(page, 'os').length, 0);
    assert.equal(page.document.querySelector('[data-apply-cat="ssh"]').disabled, false, 'apply stayed disabled');
});

test('server text in apply outcomes stays text', async () => {
    const page = await hardeningPage(FAILING);
    page.document.querySelector('[data-apply-cat="ssh"]').click();
    await settle();
    page.respond('/api/v1/hardening/apply', 200, Object.assign({ ok: true, applied: [{ name: 'x', title: '<img src=x onerror=alert(1)>', status: 'failed', message: '<b>bad</b>' }] }, report(FAILING)));
    await settle();
    const outcome = page.document.querySelector('[role="status"]');
    assert.equal(outcome.querySelectorAll('img, b').length, 0);
    assert.match(outcome.textContent, /<img src=x/);
});

test('apply waits for the server deadline and preserves selections when the worker cannot start', async () => {
    const page = await hardeningPage(FAILING);
    const post = page.window.CSM.post;
    let opts;
    page.window.CSM.post = (url, body, options) => { opts = options; return post(url, body, options); };
    boxes(page, 'ssh')[1].checked = false;
    page.document.querySelector('[data-apply-cat="ssh"]').click();
    await settle();
    page.respond('/api/v1/hardening/apply', 503, { error: 'Worker unavailable' });
    await settle();
    assert.equal(page.pending('/api/v1/hardening').length, 0);
    assert.equal(boxes(page, 'ssh')[1].checked, false);
    assert.ok(opts && (opts.timeoutMs === 0 || opts.timeoutMs >= 600000));
});

test('a worker error shows the fresh audit even when it could not be saved', async () => {
    const page = await hardeningPage(FAILING);
    page.document.querySelector('[data-apply-cat="os"]').click();
    await settle();
    const after = FAILING.map(r => r.category === 'os' ? Object.assign({}, r, { status: 'pass' }) : r);
    page.respond('/api/v1/hardening/apply', 500, { error: 'Could not save the recheck', report: report(after) });
    await settle();
    assert.equal(boxes(page, 'os').length, 0);
    assert.equal(page.pending('/api/v1/hardening').length, 0);
    assert.deepEqual(page.toasts.at(-1), ['Could not save the recheck', 'error']);
});

// A fix that can disrupt a working host starts unticked and says what it can
// break; the others stay ticked.
test('fixes with a caution start unticked and show it', async () => {
    const page = await hardeningPage([
        { category: 'ssh', name: 'ssh_max_auth_tries', title: 'MaxAuthTries', status: 'warn', message: '6', fix: 'Set 4', auto_fix: 'Sets MaxAuthTries 4.', auto_fix_caution: 'Refuses clients that offer many keys.' },
        { category: 'ssh', name: 'ssh_use_dns', title: 'UseDNS', status: 'warn', message: 'UseDNS yes', fix: 'Set UseDNS no', auto_fix: 'Sets UseDNS no.' }
    ]);
    const boxes = Array.from(page.document.querySelectorAll('input[data-fix-name]'));
    const byName = Object.fromEntries(boxes.map(b => [b.getAttribute('data-fix-name'), b]));
    assert.equal(byName.ssh_max_auth_tries.checked, false);
    assert.equal(byName.ssh_use_dns.checked, true);
    assert.match(byName.ssh_max_auth_tries.closest('label').textContent, /Refuses clients that offer many keys\./);
});

for (const selected of [false, true]) {
    test('a cautioned fix is sent only after opt-in: ' + selected, async () => {
        const page = await hardeningPage([
            { category: 'ssh', name: 'ssh_max_auth_tries', title: 'MaxAuthTries', status: 'warn', auto_fix: 'Sets MaxAuthTries 4.', auto_fix_caution: 'Can refuse clients.' },
            FAILING[0]
        ]);
        const cautioned = boxes(page, 'ssh')[0];
        if (selected) cautioned.checked = true;
        page.document.querySelector('[data-apply-cat="ssh"]').click();
        await settle();
        const requests = page.pending('/api/v1/hardening/apply');
        assert.equal(requests.length, 1);
        const body = typeof requests[0].body === 'string' ? JSON.parse(requests[0].body) : requests[0].body;
        assert.deepEqual(body, { category: 'ssh', names: selected ? ['ssh_max_auth_tries', 'ssh_use_dns'] : ['ssh_use_dns'] });
    });
}

test('a section containing only cautioned fixes sends nothing by default', async () => {
    const page = await hardeningPage([
        { category: 'os', name: 'os_sysctl_rp_filter', title: 'Reverse path filtering', status: 'warn', auto_fix: 'Enables strict filtering.', auto_fix_caution: 'Can drop replies.' }
    ]);
    page.document.querySelector('[data-apply-cat="os"]').click();
    await settle();
    assert.equal(page.asked.length, 0);
    assert.equal(page.pending('/api/v1/hardening/apply').length, 0);
});

// A fix CSM applied and kept a record of offers Undo in its result row. Undo
// asks first, sends only the fix name, and shows what the root worker did,
// including a refusal and its reason, above the section's checks.
const APPLIED = [
    { category: 'ssh', name: 'ssh_use_dns', title: 'UseDNS', status: 'pass', message: 'UseDNS no', undo_available: true },
    { category: 'ssh', name: 'ssh_x11_forwarding', title: 'X11', status: 'warn', message: 'X11 on', fix: 'Set X11Forwarding no', auto_fix: 'Sets X11Forwarding no.' },
    { category: 'cpanel', name: 'cp_max_emails_hour', title: 'Max Emails Per Hour', status: 'pass', message: '200', undo_available: true },
    { category: 'os', name: 'os_sysctl_aslr', title: 'ASLR', status: 'pass', message: '2' }
];

function undoButtons(page) {
    return Array.from(page.document.querySelectorAll('[data-undo-name]'));
}

test('only a fix with an undo record gets an Undo button, in its result row', async () => {
    const page = await hardeningPage(APPLIED);
    const buttons = undoButtons(page);
    assert.deepEqual(buttons.map(b => b.getAttribute('data-undo-name')), ['ssh_use_dns', 'cp_max_emails_hour']);
    assert.match(buttons[0].closest('tr').textContent, /UseDNS no/);
    assert.equal(buttons[0].getAttribute('aria-label'), 'Undo UseDNS');
});

test('undo sends the fix name after asking, holds every action while it runs, then shows the outcome and the recheck', async () => {
    const page = await hardeningPage(APPLIED);
    undoButtons(page)[0].click();
    await settle();
    assert.equal(page.asked.length, 1);
    assert.match(page.asked[0].message, /UseDNS/);
    // Undo turns a protection off, so the dialog marks it as dangerous.
    assert.deepEqual({ ...page.asked[0].opts }, { okLabel: 'Undo', danger: true });
    const post = page.pending('/api/v1/hardening/undo')[0];
    assert.ok(post, 'no undo request');
    assert.deepEqual(typeof post.body === 'string' ? JSON.parse(post.body) : post.body, { name: 'ssh_use_dns' });
    assert.deepEqual(undoButtons(page).map(b => b.disabled), [true, true]);
    assert.equal(page.document.querySelector('[data-apply-cat="ssh"]').disabled, true);
    assert.equal(page.document.getElementById('btn-run-audit').disabled, true);
    const after = APPLIED.map(r => r.name === 'ssh_use_dns' ? { category: 'ssh', name: 'ssh_use_dns', title: 'UseDNS', status: 'warn', message: 'UseDNS yes', auto_fix: 'Sets UseDNS no.' } : r);
    page.respond('/api/v1/hardening/undo', 200, Object.assign({ ok: true, result: { name: 'ssh_use_dns', title: 'ssh_use_dns', status: 'undone', message: 'UseDNS taken out of the CSM block; sshd reloaded.' } }, report(after)));
    await settle();
    const outcome = page.document.querySelector('[role="status"]');
    assert.ok(outcome, 'no outcome shown');
    assert.ok(outcome.classList.contains('alert-success'));
    assert.match(outcome.textContent, /Last undo/);
    assert.match(outcome.textContent, /undone UseDNS: UseDNS taken out of the CSM block; sshd reloaded\./);
    assert.deepEqual(undoButtons(page).map(b => [b.getAttribute('data-undo-name'), b.disabled]), [['cp_max_emails_hour', false]]);
    assert.equal(page.document.querySelector('[data-apply-cat="ssh"]').disabled, false);
    assert.equal(page.document.getElementById('btn-run-audit').disabled, false);
    assert.deepEqual(page.toasts.at(-1), ['UseDNS: undone.', 'success']);
});

test('a refused undo shows its reason as the outcome and keeps Undo', async () => {
    const page = await hardeningPage(APPLIED);
    undoButtons(page)[1].click();
    await settle();
    const why = 'maxemailsperhour had no value before the apply, and whmapi1 cannot remove one. Set it back to its default in WHM Tweak Settings.';
    page.respond('/api/v1/hardening/undo', 200, Object.assign({ ok: true, result: { name: 'cp_max_emails_hour', title: 'cp_max_emails_hour', status: 'refused', message: why } }, report(APPLIED)));
    await settle();
    const outcome = page.document.querySelector('[role="status"]');
    assert.ok(outcome, 'no outcome shown');
    assert.ok(outcome.classList.contains('alert-warning'));
    assert.ok(outcome.textContent.includes('refused Max Emails Per Hour: ' + why), outcome.textContent);
    assert.doesNotMatch(outcome.textContent, /re-run/);
    assert.deepEqual(undoButtons(page).map(b => b.disabled), [false, false]);
    assert.deepEqual(page.toasts.at(-1), ['Max Emails Per Hour: refused.', 'warning']);
});

test('an undo that cannot start leaves the page as it was', async () => {
    const page = await hardeningPage(APPLIED);
    undoButtons(page)[0].click();
    await settle();
    page.respond('/api/v1/hardening/undo', 503, { error: 'Undoing a fix needs systemd-run, so nothing was changed: systemd-run not found' });
    await settle();
    assert.deepEqual(page.toasts.at(-1), ['Undoing a fix needs systemd-run, so nothing was changed: systemd-run not found', 'error']);
    assert.deepEqual(undoButtons(page).map(b => [b.textContent, b.disabled]), [['Undo', false], ['Undo', false]]);
    assert.equal(page.pending('/api/v1/hardening').length, 0);
    assert.equal(page.document.querySelector('[role="status"]'), null);
});

test('a worker error during undo shows the rechecked report', async () => {
    const page = await hardeningPage(APPLIED);
    undoButtons(page)[0].click();
    await settle();
    const after = APPLIED.map(r => r.name === 'ssh_use_dns' ? Object.assign({}, r, { undo_available: false }) : r);
    page.respond('/api/v1/hardening/undo', 500, { error: 'Hardening undo: hardening worker: signal: killed. The audit was re-run.', report: report(after) });
    await settle();
    assert.deepEqual(undoButtons(page).map(b => b.getAttribute('data-undo-name')), ['cp_max_emails_hour']);
    assert.equal(page.pending('/api/v1/hardening').length, 0);
    assert.deepEqual(page.toasts.at(-1), ['Hardening undo: hardening worker: signal: killed. The audit was re-run.', 'error']);
});
