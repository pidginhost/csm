// Run with: node --test ui/helpers_test.js
// Pages put the output of these helpers straight into markup, so each one
// must return escaped or empty text whatever it is given.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, SHARED } = require('./pagekit.js');

test('escaping keeps zero and false', () => {
    const CSM = loadPage('', SHARED).window.CSM;
    assert.equal(CSM.esc(0), '0');
    assert.equal(CSM.esc(false), 'false');
    assert.equal(CSM.esc(null), '');
    assert.equal(CSM.esc(undefined), '');
    assert.equal(CSM.attr(0), '0');
    assert.equal(CSM.esc('<a href="x">'), '&lt;a href=&quot;x&quot;&gt;');
});

test('an unreadable time shows nothing rather than the raw value', () => {
    const CSM = loadPage('', SHARED).window.CSM;
    assert.equal(CSM.timeAgo('<img src=x onerror=alert(1)>'), '');
    assert.equal(CSM.timeAgo('not a time'), '');
    assert.equal(CSM.timeAgo(''), '');
    assert.equal(CSM.timeAgo(new Date(Date.now() - 120000).toISOString()), '2m ago');
});

test('a value that is not a number formats as blank', () => {
    const CSM = loadPage('', SHARED).window.CSM;
    assert.equal(CSM.formatNumber('<b>1</b>'), '');
    assert.equal(CSM.formatNumber(NaN), '');
    assert.equal(CSM.formatNumber(Infinity), '');
    assert.equal(CSM.formatNumber(null), '');
    assert.equal(CSM.formatNumber(0), '0');
    assert.equal(CSM.formatNumber('12'), (12).toLocaleString());
});
