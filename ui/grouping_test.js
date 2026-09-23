// Run with: node --test ui/grouping_test.js
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

const wait = ms => new Promise(r => setTimeout(r, ms));

function finding(check, message, account) {
    return {
        key: check + ':' + message, severity: 'HIGH', sev_class: 'high', check, message,
        account, first_seen: '2026-09-22T10:00:00Z', last_seen: '2026-09-22T10:00:00Z'
    };
}

async function findingsPage() {
    const page = loadPage(templateBody('findings'), SHARED.concat(['findings.js']));
    page.respond('/api/v1/findings/enriched', 200, {
        items: [
            finding('webshell', 'shell in /home/alice/a.php', 'alice'),
            finding('webshell', 'shell in /home/bob/b.php', 'bob'),
            finding('perf_load', 'load high', ''),
            finding('world_writable_php', 'writable /home/alice/c.php', 'alice')
        ],
        check_types: ['webshell', 'perf_load', 'world_writable_php'],
        accounts: ['alice', 'bob'],
        total: 4
    });
    await settle();
    return page;
}

// Every group header must sit directly above its own visible rows.
function layout(page) {
    const out = [];
    let current = null;
    page.document.querySelectorAll('#findings-tbody tr').forEach(tr => {
        if (tr.classList.contains('csm-group-header')) {
            current = tr.getAttribute('data-csm-group-key');
            out.push(['header', current]);
        } else if (tr.style.display !== 'none') {
            out.push(['row', tr.getAttribute('data-check'), current]);
        }
    });
    return out;
}

function assertGrouped(page) {
    const rows = layout(page);
    for (let i = 0; i < rows.length; i++) {
        if (rows[i][0] === 'header') {
            assert.ok(i + 1 < rows.length && rows[i + 1][0] === 'row', 'empty or stacked group header at ' + i + ': ' + JSON.stringify(rows));
        } else {
            assert.equal(rows[i][1], rows[i][2], 'row under the wrong header: ' + JSON.stringify(rows));
        }
    }
}

function setGroupBy(page, mode) {
    const sel = page.document.getElementById('group-by');
    sel.value = mode;
    sel.dispatchEvent(new page.window.Event('change'));
}

async function dismissAndRefresh(page, data) {
    page.window.CSM.confirm = () => Promise.resolve();
    page.document.querySelector('.dismiss-btn').click();
    await settle();
    page.respond('/api/v1/dismiss', 200, {});
    await settle();
    page.respond('/api/v1/findings/enriched', 200, data);
    await settle();
}

test('grouping survives a search that the table applies after its debounce', async () => {
    const page = await findingsPage();
    setGroupBy(page, 'check');
    assertGrouped(page);
    const search = page.document.getElementById('findings-search');
    search.value = 'alice';
    search.dispatchEvent(new page.window.Event('input'));
    await wait(400);
    assertGrouped(page);
    const headers = layout(page).filter(r => r[0] === 'header').map(r => r[1]).sort();
    assert.deepEqual(headers, ['webshell', 'world_writable_php']);
});

test('a collapsed group stays collapsed when the table renders again', async () => {
    const page = await findingsPage();
    setGroupBy(page, 'check');
    const header = page.document.querySelector('.csm-group-header[data-csm-group-key="webshell"]');
    header.click();
    const search = page.document.getElementById('findings-search');
    search.value = 'shell';
    search.dispatchEvent(new page.window.Event('input'));
    await wait(400);
    const again = page.document.querySelector('.csm-group-header[data-csm-group-key="webshell"]');
    assert.ok(again, 'webshell group missing after the search');
    assert.equal(again.getAttribute('aria-expanded'), 'false');
    const shown = layout(page).filter(r => r[0] === 'row' && r[1] === 'webshell');
    assert.equal(shown.length, 0, 'rows of a collapsed group are visible again');
});

test('turning grouping off removes the headers', async () => {
    const page = await findingsPage();
    setGroupBy(page, 'account');
    assert.ok(page.document.querySelectorAll('.csm-group-header').length > 0);
    setGroupBy(page, 'none');
    assert.equal(page.document.querySelectorAll('.csm-group-header').length, 0);
});

test('an empty refresh retires the previous findings table', async () => {
    const page = await findingsPage();
    await dismissAndRefresh(page, { items: [], check_types: [], accounts: [], total: 0 });
    const search = page.document.getElementById('findings-search');
    search.value = 'shell';
    search.dispatchEvent(new page.window.Event('input'));
    await wait(400);
    assert.equal(page.document.querySelectorAll('#findings-tbody .finding-row').length, 0);
    assert.equal(page.window.CSM._tableInstances.filter(t => t.opts.tableId === 'findings-table').length, 0);
});

test('grouped refresh keeps all rows and restores the chosen page size', async () => {
    const page = await findingsPage();
    setGroupBy(page, 'check');
    const findings = Array.from({ length: 30 }, (_, i) => finding('webshell', 'shell ' + i, 'alice'));
    await dismissAndRefresh(page, { items: findings, check_types: ['webshell'], accounts: ['alice'], total: 30 });
    assert.equal(layout(page).filter(r => r[0] === 'row').length, 30);
    assertGrouped(page);
    setGroupBy(page, 'none');
    assert.equal(layout(page).filter(r => r[0] === 'row').length, 25);
});
