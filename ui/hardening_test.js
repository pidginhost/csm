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
