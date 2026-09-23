// Run with: node --test ui/focus_test.js
// Focus goes back where it came from when a panel or dialog closes, a dialog
// opened from the detail panel owns the keyboard while it is open, and the
// prompt dialog handles Escape and Tab like the confirm dialog.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const { loadPage, SHARED, settle } = require('./pagekit.js');

function confirmModal() {
    const layout = fs.readFileSync(path.join(__dirname, 'templates', 'layout.html'), 'utf8');
    return layout.slice(layout.indexOf('<div class="modal fade" id="csm-confirm-modal"'),
        layout.indexOf('<div class="modal fade" id="csm-prefs-modal"'));
}

function page() {
    return loadPage(confirmModal() + '<button id="opener">Open</button>', SHARED);
}

function key(p, k, opts) {
    const ev = new p.window.Event('keydown', { bubbles: true, cancelable: true });
    ev.key = k;
    Object.assign(ev, opts || {});
    (p.document.activeElement || p.document.body).dispatchEvent(ev);
    return ev;
}

const tick = () => new Promise(r => setTimeout(r, 5));

test('closing the detail panel returns focus to what opened it', async () => {
    const p = page();
    const opener = p.document.getElementById('opener');
    opener.focus();
    p.window.CSM.detailPanel.open({ title: 'x', bodyHTML: '<button id="inside">in</button>' });
    p.document.getElementById('inside').focus();
    // A second open replaces the content; the opener stays the same.
    p.window.CSM.detailPanel.open({ title: 'y', bodyHTML: '<button id="inside2">in</button>' });
    await tick();
    p.window.CSM.detailPanel.close();
    assert.equal(p.document.activeElement, opener);
});

test('a confirm opened from the detail panel owns Tab and Escape', async () => {
    const p = page();
    p.window.CSM.detailPanel.open({ title: 'x', bodyHTML: '<button id="inside">in</button>' });
    await tick();
    const done = p.window.CSM.confirm('Block 203.0.113.9 permanently?', { danger: true, okLabel: 'Block' });
    const cancel = p.document.getElementById('csm-confirm-cancel');
    assert.equal(p.document.activeElement, cancel);
    key(p, 'Tab');
    assert.ok(p.document.getElementById('csm-confirm-modal').contains(p.document.activeElement),
        'the panel pulled focus out of the dialog');
    key(p, 'Escape');
    await done.then(() => assert.fail('Escape confirmed'), () => {});
    assert.ok(p.window.CSM.detailPanel.element().classList.contains('show'), 'Escape in the dialog also closed the panel');
});

test('a confirm returns focus to what opened it', async () => {
    const p = page();
    const opener = p.document.getElementById('opener');
    opener.focus();
    const done = p.window.CSM.confirm('Restore this file?');
    p.document.getElementById('csm-confirm-ok').click();
    await done;
    assert.equal(p.document.activeElement, opener);
});

test('the prompt names its input, keeps Tab inside and cancels on Escape', async () => {
    const p = page();
    const opener = p.document.getElementById('opener');
    opener.focus();
    const done = p.window.CSM.prompt('Temp whitelist 203.0.113.9 for how many hours?', '24');
    const input = p.document.querySelector('#csm-confirm-body input');
    assert.equal(input.getAttribute('aria-label'), 'Temp whitelist 203.0.113.9 for how many hours?');
    p.document.getElementById('csm-confirm-ok').focus();
    key(p, 'Tab');
    assert.ok(p.document.getElementById('csm-confirm-modal').contains(p.document.activeElement), 'Tab left the prompt');
    key(p, 'Escape');
    let cancelled = false;
    await done.then(() => {}, () => { cancelled = true; });
    assert.equal(cancelled, true, 'Escape did not cancel the prompt');
    assert.equal(p.document.activeElement, opener);
});
