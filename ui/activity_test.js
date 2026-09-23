// Run with: node --test ui/activity_test.js
// API calls that follow the operator's input carry X-CSM-Active, which is
// what extends an idle browser session; timer polls do not.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage } = require('./pagekit.js');

function header(req, name) {
    const h = req.headers || {};
    return h[name] !== undefined ? h[name] : (typeof h.get === 'function' ? h.get(name) : undefined);
}

test('requests carry the activity marker only after operator input', () => {
    const page = loadPage('', ['csrf.js']);
    page.window.CSM.get('/api/v1/idle');
    assert.equal(header(page.pending('/api/v1/idle')[0], 'X-CSM-Active'), undefined, 'poll marked active without input');

    page.document.dispatchEvent(new page.window.Event('keydown'));
    page.window.CSM.get('/api/v1/after-input');
    assert.equal(header(page.pending('/api/v1/after-input')[0], 'X-CSM-Active'), '1');

    page.window.CSM.post('/api/v1/action', {});
    const post = page.pending('/api/v1/action')[0];
    assert.equal(header(post, 'X-CSM-Active'), '1');
    assert.ok(header(post, 'X-CSRF-Token') !== undefined, 'existing headers kept');
});
