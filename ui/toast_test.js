// Run with: node --test ui/toast_test.js
// An error toast stays until the operator closes it: a failure that fades
// after five seconds is easy to miss. The same message is not stacked.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, SHARED } = require('./pagekit.js');

function page() {
    const p = loadPage('<div id="csm-toasts"></div>', SHARED);
    p.timers = [];
    p.window.setTimeout = (fn, ms) => { p.timers.push(ms); return 0; };
    return p;
}

function toasts(p) {
    return p.document.querySelectorAll('#csm-toasts .alert');
}

test('an error toast is not dismissed on a timer', () => {
    const p = page();
    p.window.CSM.toast('Delete failed: disk full', 'error');
    assert.equal(toasts(p).length, 1);
    assert.ok(!p.timers.includes(5000), 'error toast scheduled to disappear');
});

test('other toasts still fade on their own', () => {
    const p = page();
    p.window.CSM.toast('Saved', 'success');
    assert.ok(p.timers.includes(5000));
});

test('an error already on screen is not stacked again', () => {
    const p = page();
    p.window.CSM.toast('Lookup failed', 'error');
    p.window.CSM.toast('Lookup failed', 'error');
    assert.equal(toasts(p).length, 1);
    p.window.CSM.toast('Another failure', 'error');
    assert.equal(toasts(p).length, 2);
});

test('closing an error toast removes it', () => {
    const p = page();
    p.window.CSM.toast('Lookup failed', 'error');
    toasts(p)[0].querySelector('.btn-close').click();
    assert.equal(toasts(p)[0].style.opacity, '0');
});

test('errorText gives the message without an Error: prefix', () => {
    const p = page();
    const CSM = p.window.CSM;
    assert.equal(CSM.errorText(new Error('HTTP 403: forbidden')), 'HTTP 403: forbidden');
    assert.equal(CSM.errorText('plain text'), 'plain text');
    assert.equal(CSM.errorText(null), 'request failed');
    assert.equal(CSM.errorText(new TypeError('Failed to fetch')), 'Failed to fetch');
});
