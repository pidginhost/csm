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
    return loadPage(confirmModal() + '<main id="csm-main" tabindex="-1"><button id="opener">Open</button></main>', SHARED);
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

// Unlike the pagekit's immediate transitions, this fixture keeps showing and
// hiding separate. Bootstrap ignores modal hide() while a show is in flight.
function transitions(p, kind) {
    let el, shown = false, showing = false, hiding = false;
    const event = name => el.dispatchEvent(new p.window.Event(name + '.bs.' + kind.toLowerCase()));
    const instance = {
        show() {
            if (shown || showing || hiding) return;
            showing = true;
            event('show');
            el.classList.add(kind === 'Modal' ? 'show' : 'showing');
        },
        hide() {
            if (!shown || showing || hiding) return;
            hiding = true;
            event('hide');
            el.classList.remove('show');
            if (el.contains(p.document.activeElement)) p.document.body.focus();
        }
    };
    p.window.bootstrap[kind] = { getOrCreateInstance(node) { el = node; return instance; } };
    return {
        shown() {
            assert.ok(showing, 'no show transition pending');
            showing = false; shown = true;
            el.classList.remove('showing'); el.classList.add('show');
            el.focus(); event('shown');
        },
        hidden() {
            assert.ok(hiding, 'no hide transition pending');
            hiding = false; shown = false;
            el.classList.remove('show'); event('hidden');
        }
    };
}

test('replacing a showing panel preserves the original opener', () => {
    const p = page();
    const t = transitions(p, 'Offcanvas');
    const opener = p.document.getElementById('opener');
    opener.focus();
    p.window.CSM.detailPanel.open({ bodyHTML: '<button id="inside">Act</button>' });
    p.document.getElementById('inside').focus();
    p.window.CSM.detailPanel.open({ bodyHTML: '<button>Replacement</button>' });
    t.shown();
    p.window.CSM.detailPanel.close();
    t.hidden();
    assert.equal(p.document.activeElement, opener);
});

test('reopening a closing panel retains focus until the final hide', () => {
    const p = page();
    const t = transitions(p, 'Offcanvas');
    const opener = p.document.getElementById('opener');
    opener.focus();
    p.window.CSM.detailPanel.open({ title: 'First' });
    t.shown();
    p.window.CSM.detailPanel.close();
    assert.notEqual(p.document.activeElement, opener, 'focus returned before hidden');
    p.window.CSM.detailPanel.open({ title: 'Second' });
    t.hidden(); t.shown();
    p.window.CSM.detailPanel.close();
    t.hidden();
    assert.equal(p.document.activeElement, opener);
});

test('removing a panel opener returns focus to main content', () => {
    const p = page();
    const opener = p.document.getElementById('opener');
    opener.focus();
    p.window.CSM.detailPanel.open({ title: 'Finding' });
    const panel = p.window.CSM.detailPanel.element();
    panel.focus(); opener.remove();
    p.window.CSM.detailPanel.close();
    assert.equal(p.document.activeElement, p.document.getElementById('csm-main'));
});

for (const kind of ['confirm', 'prompt']) {
    test(kind + ' waits for show and hide before returning focus', async () => {
        const p = page();
        const t = transitions(p, 'Modal');
        const opener = p.document.getElementById('opener');
        opener.focus();
        const done = p.window.CSM[kind]('Continue?');
        const cancelled = done.then(() => assert.fail('cancel confirmed'), () => {});
        key(p, 'Escape'); // Escape before the show animation finishes.
        assert.notEqual(p.document.activeElement, opener, 'focus returned during showing');
        t.shown();
        t.hidden();
        await cancelled;
        assert.equal(p.document.activeElement, opener);
    });

    test(kind + ' restores safe focus after its opener is removed', async () => {
        const p = page();
        const opener = p.document.getElementById('opener');
        opener.focus();
        const done = p.window.CSM[kind]('Continue?');
        opener.remove();
        p.document.getElementById('csm-confirm-ok').click();
        await done;
        assert.equal(p.document.activeElement, p.document.getElementById('csm-main'));
    });
}

test('a prompt keeps its input focused after Bootstrap finishes showing', async () => {
    const p = page();
    const t = transitions(p, 'Modal');
    const done = p.window.CSM.prompt('Reason?', 'maintenance');
    await new Promise(r => setTimeout(r, 120));
    t.shown();
    const input = p.document.querySelector('#csm-confirm-body input');
    assert.equal(p.document.activeElement, input);
    assert.equal(input.selectionStart, 0);
    assert.equal(input.selectionEnd, input.value.length);
    p.document.getElementById('csm-confirm-ok').click(); t.hidden();
    await done;
});

test('replacing a dialog during hide preserves its opener and focus', async () => {
    const p = page();
    const t = transitions(p, 'Modal');
    const opener = p.document.getElementById('opener');
    opener.focus();
    const first = p.window.CSM.confirm('First?');
    t.shown();
    p.document.getElementById('csm-confirm-ok').click();
    const second = p.window.CSM.prompt('Second?', 'value');
    t.hidden(); t.shown();
    assert.equal(p.document.activeElement, p.document.querySelector('#csm-confirm-body input'));
    p.document.getElementById('csm-confirm-ok').click(); t.hidden();
    await first;
    assert.equal(await second, 'value');
    assert.equal(p.document.activeElement, opener);
});

test('closing a showing panel waits for the transition before restoring focus', () => {
    const p = page();
    const t = transitions(p, 'Offcanvas');
    const opener = p.document.getElementById('opener');
    opener.focus();
    p.window.CSM.detailPanel.open({ title: 'First' });
    p.window.CSM.detailPanel.close();
    t.shown(); t.hidden();
    assert.equal(p.document.activeElement, opener);
});

test('replacing focused panel content keeps focus inside the panel', () => {
    const p = page();
    p.window.CSM.detailPanel.open({ bodyHTML: '<button id="inside">Act</button>' });
    p.document.getElementById('inside').focus();
    p.window.CSM.detailPanel.open({ bodyHTML: '<button>Replacement</button>' });
    assert.equal(p.document.activeElement, p.window.CSM.detailPanel.element());
});

test('Escape during modal hiding does not close its parent panel', async () => {
    const p = page();
    p.window.CSM.detailPanel.open({ bodyHTML: '<button id="inside">Act</button>' });
    await tick();
    p.document.getElementById('inside').focus();
    const t = transitions(p, 'Modal');
    const done = p.window.CSM.confirm('Continue?');
    t.shown();
    p.document.getElementById('csm-confirm-ok').click();
    key(p, 'Escape');
    assert.ok(p.window.CSM.detailPanel.element().classList.contains('show'));
    t.hidden(); await done;
    assert.equal(p.document.activeElement, p.document.getElementById('inside'));
});
