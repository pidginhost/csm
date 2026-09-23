// Run with: node --test ui/fakedom_test.js
// The page tests trust this harness, so it is tested on its own.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { createWindow, Event } = require('./fakedom.js');

test('innerHTML round-trips the markup pages generate', () => {
    const { document } = createWindow('<table id="t"><thead><tr><th>A</th></tr></thead><tbody>' +
        '<tr data-key="k&amp;1" class="finding-row feed-item"><td><input type="checkbox" class="form-check-input row-checkbox" checked></td>' +
        '<td><code>web&lt;shell&gt;</code></td></tr></tbody></table>');
    const row = document.querySelector('tbody tr');
    assert.equal(row.getAttribute('data-key'), 'k&1');
    assert.equal(row.dataset.key, 'k&1');
    assert.equal(document.querySelector('code').textContent, 'web<shell>');
    assert.equal(document.querySelector('.row-checkbox').checked, true);
    assert.match(document.getElementById('t').outerHTML, /web&lt;shell&gt;/);
});

test('selectors cover the forms the pages use', () => {
    const { document } = createWindow('<div id="a" class="x y"><p class="x"><span data-ts="1">s</span></p></div>' +
        '<input type="checkbox" class="cb" checked><input type="checkbox" class="cb">');
    assert.equal(document.querySelectorAll('.x').length, 2);
    assert.equal(document.querySelectorAll('#a > .x').length, 1);
    assert.equal(document.querySelectorAll('#a span').length, 1);
    assert.equal(document.querySelectorAll('div > span').length, 0);
    assert.equal(document.querySelectorAll('[data-ts]').length, 1);
    assert.equal(document.querySelectorAll('[data-ts="1"]').length, 1);
    assert.equal(document.querySelectorAll('.cb:checked').length, 1);
    assert.equal(document.querySelectorAll('.cb:not(:checked)').length, 1);
    assert.equal(document.querySelectorAll('.cb, #a').length, 3);
    const p = document.querySelector('p');
    assert.equal(p.querySelectorAll('div span').length, 0, 'scoped queries do not match through ancestors');
    assert.equal(document.querySelector('span').closest('.y').id, 'a');
});

test('events bubble and stop', () => {
    const { document } = createWindow('<div id="outer"><button id="b">x</button></div>');
    const seen = [];
    document.getElementById('outer').addEventListener('click', () => seen.push('outer'));
    document.getElementById('b').addEventListener('click', e => { seen.push('button'); });
    document.getElementById('b').click();
    assert.deepEqual(seen, ['button', 'outer']);
    document.getElementById('b').addEventListener('click', e => e.stopPropagation());
    seen.length = 0;
    document.getElementById('b').dispatchEvent(new Event('click', { bubbles: true }));
    assert.deepEqual(seen, ['button']);
});

test('offsetParent follows display none, hidden and d-none up the tree', () => {
    const { document } = createWindow('<table><tbody><tr id="r"><td><input id="c" type="checkbox"></td></tr></tbody></table>');
    const cb = document.getElementById('c');
    assert.notEqual(cb.offsetParent, null);
    document.getElementById('r').style.display = 'none';
    assert.equal(cb.offsetParent, null);
    document.getElementById('r').style.display = '';
    document.getElementById('r').classList.add('d-none');
    assert.equal(cb.offsetParent, null);
    const detached = document.createElement('input');
    assert.equal(detached.offsetParent, null);
});

test('form properties behave like a browser', () => {
    const { document } = createWindow('<select id="s"><option value="a">A</option><option value="b" selected>B</option></select>' +
        '<input id="t" value="x"><input id="cb" type="checkbox">');
    const s = document.getElementById('s');
    assert.equal(s.value, 'b');
    s.value = 'a';
    assert.equal(s.value, 'a');
    assert.equal(s.selectedIndex, 0);
    const t = document.getElementById('t');
    assert.equal(t.value, 'x');
    t.value = 'y';
    assert.equal(t.getAttribute('value'), 'x', 'value property does not rewrite the attribute');
    const cb = document.getElementById('cb');
    let changes = 0;
    cb.addEventListener('change', () => changes++);
    cb.click();
    assert.equal(cb.checked, true);
    assert.equal(changes, 1);
    t.disabled = true;
    assert.equal(t.hasAttribute('disabled'), true);
});

test('select.remove(index) removes an option and remove() removes the select', () => {
    const { document } = createWindow('<select id="s"><option>A</option><option>B</option></select>');
    const select = document.getElementById('s');
    select.remove(1);
    assert.equal(select.options.length, 1);
    assert.equal(select.options[0].textContent, 'A');
    assert.equal(document.getElementById('s'), select);
    select.remove(4);
    assert.equal(select.options.length, 1);
    select.remove();
    assert.equal(document.getElementById('s'), null);
});

test('a failing assertion on nodes stays small', () => {
    const { document } = createWindow('<div id="a" class="x y"><span>one</span></div><p>two</p>');
    const util = require('node:util');
    assert.equal(util.inspect(document.getElementById('a')), '<div#a.x.y>');
    let message = '';
    try {
        assert.equal(document.getElementById('a'), document.querySelector('p'));
    } catch (e) {
        message = e.message;
    }
    assert.ok(message.length > 0 && message.length < 20000, 'assertion message is ' + message.length + ' bytes');
});

test('textContent replaces children and data attributes map to dataset', () => {
    const { document } = createWindow('<div id="d"><b>x</b><i>y</i></div>');
    const d = document.getElementById('d');
    d.dataset.csmBulkBound = '1';
    assert.equal(d.getAttribute('data-csm-bulk-bound'), '1');
    d.textContent = 'plain';
    assert.equal(d.children.length, 0);
    assert.equal(d.innerHTML, 'plain');
});
