// Run with: node --test ui/builders_test.js
// Status-strip chips and empty states are built by shared helpers. Values
// go in as text, so a hostile value from the server renders as text.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, SHARED } = require('./pagekit.js');

test('a status chip carries its icon, value, label and title as text', () => {
    const page = loadPage('', SHARED);
    const chip = page.window.CSM.statusChip({ icon: 'ti-mail', value: '<b>12</b>', label: 'queued', title: 'Mail queue', cls: 'csm-status-strip__chip--warn' });
    assert.equal(chip.className, 'csm-status-strip__chip csm-status-strip__chip--warn');
    assert.equal(chip.title, 'Mail queue');
    assert.equal(chip.querySelector('i').className, 'ti ti-mail');
    assert.equal(chip.querySelector('.csm-status-strip__chip-value').textContent, '<b>12</b>');
    assert.equal(chip.querySelector('b'), null, 'the value was parsed as markup');
    assert.equal(chip.querySelector('.csm-status-strip__chip-label').textContent, 'queued');
});

test('an empty state has an icon and only the parts it was given', () => {
    const page = loadPage('', SHARED);
    const full = page.window.CSM.emptyStateNode('inbox', 'Nothing queued', 'The <queue> is empty');
    assert.equal(full.className, 'csm-empty');
    assert.equal(full.querySelector('.csm-empty__icon i').className, 'ti ti-inbox');
    assert.equal(full.querySelector('.csm-empty__title').textContent, 'Nothing queued');
    assert.equal(full.querySelector('.csm-empty__reason').textContent, 'The <queue> is empty');
    const bare = page.window.CSM.emptyStateNode('inbox', '', '');
    assert.equal(bare.querySelector('.csm-empty__title'), null);
    assert.equal(bare.querySelector('.csm-empty__reason'), null);
});
