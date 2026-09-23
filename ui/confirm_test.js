// Run with: node --test ui/confirm_test.js
// A confirm for an action that deletes data, blocks traffic, turns
// protection off or ends sessions names the action on a red button and
// starts on Cancel, so a stray Enter does not carry it out.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

function confirmModal() {
    const layout = fs.readFileSync(path.join(__dirname, 'templates', 'layout.html'), 'utf8');
    const start = layout.indexOf('<div class="modal fade" id="csm-confirm-modal"');
    const end = layout.indexOf('<div class="modal fade" id="csm-prefs-modal"');
    assert.ok(start > 0 && end > start, 'confirm modal not found in layout.html');
    return layout.slice(start, end);
}

function page(body) {
    return loadPage(confirmModal() + (body || ''), SHARED);
}

test('a danger confirm names the action on a red button and focuses Cancel', async () => {
    const p = page();
    const ok = p.document.getElementById('csm-confirm-ok');
    const cancel = p.document.getElementById('csm-confirm-cancel');
    const done = p.window.CSM.confirm('Delete 3 files?', { danger: true, okLabel: 'Delete' });
    assert.equal(ok.textContent, 'Delete');
    assert.ok(ok.classList.contains('btn-danger'));
    assert.ok(!ok.classList.contains('btn-primary'));
    assert.equal(p.document.activeElement, cancel, 'focus did not start on Cancel');
    ok.click();
    await done;
});

test('an ordinary confirm keeps the primary OK button after a danger one', async () => {
    const p = page();
    const ok = p.document.getElementById('csm-confirm-ok');
    const first = p.window.CSM.confirm('Delete it?', { danger: true, okLabel: 'Delete' });
    ok.click();
    await first;
    const second = p.window.CSM.confirm('Restore this file?');
    assert.equal(ok.textContent, 'OK');
    assert.ok(ok.classList.contains('btn-primary'));
    assert.ok(!ok.classList.contains('btn-danger'));
    assert.equal(p.document.activeElement, ok);
    ok.click();
    await second;
});

test('danger confirmation keeps Cancel focused after the modal transition', async () => {
    const p = page();
    const modal = p.document.getElementById('csm-confirm-modal');
    const done = p.window.CSM.confirm('Delete?', { danger: true, okLabel: 'Delete' });
    // Bootstrap activates its focus trap before emitting shown.bs.modal.
    modal.focus();
    modal.dispatchEvent(new p.window.Event('shown.bs.modal'));
    assert.equal(p.document.activeElement, p.document.getElementById('csm-confirm-cancel'));
    p.document.getElementById('csm-confirm-ok').click();
    await done;
});

test('a prompt resets the button after a danger confirmation', async () => {
    const p = page();
    const ok = p.document.getElementById('csm-confirm-ok');
    const done = p.window.CSM.confirm('Delete?', { danger: true, okLabel: 'Delete' });
    ok.click();
    await done;
    const prompt = p.window.CSM.prompt('Reason?', 'maintenance');
    assert.equal(ok.textContent, 'OK');
    assert.ok(ok.classList.contains('btn-primary'));
    assert.ok(!ok.classList.contains('btn-danger'));
    ok.click();
    assert.equal(await prompt, 'maintenance');
});

test('Log out all sessions asks first and submits only when confirmed', async () => {
    const p = page(templateBody('sessions'));
    const form = p.document.querySelector('form input[name="id"][value="all"]').closest('form');
    let submitted = 0;
    form.submit = () => { submitted++; };
    const asked = [];
    p.window.CSM.confirm = (message, opts) => { asked.push({ message, opts }); return Promise.reject(null); };
    const ev = new p.window.Event('submit', { bubbles: true, cancelable: true });
    form.dispatchEvent(ev);
    await settle();
    assert.equal(ev.defaultPrevented, true, 'the form submitted without asking');
    assert.equal(asked.length, 1);
    assert.match(asked[0].message, /every browser session/i);
    assert.equal(asked[0].opts.danger, true);
    assert.equal(submitted, 0);
    p.window.CSM.confirm = () => Promise.resolve();
    form.dispatchEvent(new p.window.Event('submit', { bubbles: true, cancelable: true }));
    await settle();
    assert.equal(submitted, 1);
});

test('a form without a confirmation attribute submits normally', () => {
    const p = page('<form id="ordinary"><button type="submit">Submit</button></form>');
    p.window.CSM.confirm = () => { throw new Error('unexpected confirmation'); };
    const ev = new p.window.Event('submit', { bubbles: true, cancelable: true });
    p.document.getElementById('ordinary').dispatchEvent(ev);
    assert.equal(ev.defaultPrevented, false);
});
