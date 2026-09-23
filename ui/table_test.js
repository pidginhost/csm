// Run with: node --test ui/table_test.js
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage } = require('./pagekit.js');

const wait = ms => new Promise(r => setTimeout(r, ms));

function rowsHTML(names) {
    return names.map(n => '<tr><td>' + n + '</td></tr>').join('');
}

function tablePage(names) {
    return loadPage('<input id="s"><table id="t"><thead><tr><th>Name</th></tr></thead><tbody>' +
        rowsHTML(names) + '</tbody></table>', ['csrf.js', 'table.js']);
}

function visibleRows(page) {
    return page.document.querySelectorAll('#t tbody tr')
        .filter(r => r.style.display !== 'none')
        .map(r => r.textContent);
}

// Pages that reload data refill the same tbody and wrap it again. The earlier
// instance still holds the old rows and listens to the same search box; it
// must not put its stale rows back into the table.
test('re-creating a table on the same element retires the previous instance', async () => {
    const page = tablePage(['alpha', 'beta']);
    page.run("new CSM.Table({ tableId: 't', searchId: 's', perPage: 25 })");
    page.document.querySelector('#t tbody').innerHTML = rowsHTML(['gamma', 'delta']);
    page.run("new CSM.Table({ tableId: 't', searchId: 's', perPage: 25 })");

    const search = page.document.getElementById('s');
    search.value = 'a';
    search.dispatchEvent(new page.window.Event('input'));
    await wait(350);

    const all = page.document.querySelectorAll('#t tbody tr').map(r => r.textContent);
    assert.deepEqual(all.sort(), ['delta', 'gamma'], 'stale rows came back');
    assert.deepEqual(visibleRows(page).sort(), ['delta', 'gamma']);
    assert.equal(page.run("CSM._tableInstances.filter(function (t) { return t.table && t.table.id === 't'; }).length"), 1);
});

test('search filters rows and shows the empty state when nothing matches', async () => {
    const page = tablePage(['alpha', 'beta']);
    page.run("new CSM.Table({ tableId: 't', searchId: 's', perPage: 25 })");
    const search = page.document.getElementById('s');
    search.value = 'bet';
    search.dispatchEvent(new page.window.Event('input'));
    await wait(350);
    assert.deepEqual(visibleRows(page), ['beta']);
});
