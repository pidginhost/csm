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

for (const kind of ['object', 'Headers', 'pairs']) {
    test('activity preserves ' + kind + ' headers and expires on reused options', () => {
        const page = loadPage('', ['csrf.js']);
        page.run('Date.now = function() { return 1000; }');
        const entries = [['Content-Type', 'application/json'], ['X-Request-ID', 'activity-test']];
        const headers = kind === 'Headers' ? new Headers(entries) : kind === 'pairs' ? entries : Object.fromEntries(entries);
        const options = { method: 'POST', headers };
        page.document.dispatchEvent(new page.window.Event('pointerdown'));
        page.window.CSM.request('/api/v1/active', options);
        const active = new Headers(page.pending('/api/v1/active')[0].headers);
        assert.equal(active.get('Content-Type'), 'application/json');
        assert.equal(active.get('X-Request-ID'), 'activity-test');
        assert.equal(active.get('X-CSM-Active'), '1');
        assert.equal(new Headers(options.headers).get('X-CSM-Active'), null, 'caller headers mutated');

        page.run('Date.now = function() { return 61000; }');
        page.window.CSM.request('/api/v1/idle', options);
        assert.equal(new Headers(page.pending('/api/v1/idle')[0].headers).get('X-CSM-Active'), null);
    });
}

test('activity marker is recomputed at dispatch and scroll counts as input', () => {
    const page = loadPage('', ['csrf.js']);
    page.run('Date.now = function() { return 1000; }');
    const options = { headers: { 'x-csm-active': '1' } };
    page.window.CSM.request('/api/v1/before-input', options);
    assert.equal(new Headers(page.pending('/api/v1/before-input')[0].headers).get('X-CSM-Active'), null);
    page.document.dispatchEvent(new page.window.Event('wheel'));
    page.window.CSM.request('/api/v1/scroll', options);
    assert.equal(new Headers(page.pending('/api/v1/scroll')[0].headers).get('X-CSM-Active'), '1');
    page.window.CSM.delete('/api/v1/delete', {});
    const deletion = new Headers(page.pending('/api/v1/delete')[0].headers);
    assert.equal(deletion.get('X-CSM-Active'), '1');
    assert.ok(deletion.has('X-CSRF-Token'), 'DELETE lost CSRF header');
    page.run('Date.now = function() { return 61000; }');
    page.window.CSM.request('/api/v1/expired', options);
    assert.equal(new Headers(page.pending('/api/v1/expired')[0].headers).get('X-CSM-Active'), null);
});

test('GET accepts Headers options before and after input', () => {
    const page = loadPage('', ['csrf.js']);
    const options = { headers: new Headers({ 'X-Request-ID': 'activity-test' }) };
    for (const active of [false, true]) {
        if (active) page.document.dispatchEvent(new page.window.Event('keydown'));
        const url = '/api/v1/get-' + active;
        page.window.CSM.get(url, options);
        const headers = new Headers(page.pending(url)[0].headers);
        assert.equal(headers.get('X-Request-ID'), 'activity-test');
        assert.equal(headers.get('Accept'), 'application/json');
        assert.equal(headers.get('X-CSM-Active'), active ? '1' : null);
    }
});


test('GET preserves an explicit Accept header without adding a second value', () => {
    const page = loadPage('', ['csrf.js']);
    page.window.CSM.get('/api/v1/custom-accept', { headers: new Headers({ accept: 'text/csv' }) });
    const headers = new Headers(page.pending('/api/v1/custom-accept')[0].headers);
    assert.equal(headers.get('Accept'), 'text/csv');
});

test('request header pairs retain repeated values across activity marking', () => {
    const page = loadPage('', ['csrf.js']);
    const options = { headers: [['X-Filter', 'one'], ['x-filter', 'two'], ['X-Filter', 'three']] };
    page.document.dispatchEvent(new page.window.Event('keydown'));
    page.window.CSM.request('/api/v1/repeated-headers', options);
    const headers = new Headers(page.pending('/api/v1/repeated-headers')[0].headers);
    assert.equal(headers.get('X-Filter'), 'one, two, three');
});


test('layout scrolling without operator input does not mark requests active', () => {
    const page = loadPage('', ['csrf.js']);
    page.document.dispatchEvent(new page.window.Event('scroll'));
    page.window.CSM.get('/api/v1/layout-scroll');
    assert.equal(new Headers(page.pending('/api/v1/layout-scroll')[0].headers).get('X-CSM-Active'), null);
});
