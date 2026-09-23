// Run with: node --test ui/truncation_test.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const { loadPage, RUNTIME } = require('./pagekit.js');

test('a truncated result says so under the list', () => {
    const page = loadPage('<div id="list"><p>rows</p></div>', RUNTIME.concat(['csm-ui.js']));
    const list = page.document.getElementById('list');
    page.window.CSM.truncationNote(list, true, 'email findings');
    const note = list.querySelector('.csm-truncation-note');
    assert.ok(note, 'no note for a truncated result');
    assert.match(note.textContent, /email findings/);
    assert.match(note.textContent, /narrow the date range/i);
    // Groups can be ordered by severity, so omitted groups can be newer.
    assert.doesNotMatch(note.textContent, /newest|older/i);
});

test('a complete result has no note', () => {
    const page = loadPage('<div id="list"><p>rows</p></div>', RUNTIME.concat(['csm-ui.js']));
    const list = page.document.getElementById('list');
    page.window.CSM.truncationNote(list, false, 'email findings');
    assert.equal(list.querySelector('.csm-truncation-note'), null);
});

test('every email list fed by the capped endpoints reports truncation', () => {
    const src = fs.readFileSync(path.join(__dirname, 'static/js/email.js'), 'utf8');
    const calls = src.match(/CSM\.truncationNote\(/g) || [];
    assert.equal(calls.length, 3, 'action groups, auth groups and outbound abuse must each report truncation');
});
