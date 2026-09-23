// Run with: node --test ui/export_test.js
// Exported text is attacker-chosen (paths, user agents, mailboxes). A cell
// that starts a formula must reach the spreadsheet as text.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

function capturingURL(blobs) {
    return class extends URL {
        static createObjectURL(blob) { blobs.push(blob); return 'blob:csm-test'; }
        static revokeObjectURL() {}
    };
}

// The History CSV link exports what the tab shows: its date range in the
// operator zone, severity and search.
test('history CSV export carries the history filters', async () => {
    const page = loadPage(templateBody('findings'), SHARED.concat(['history.js']), {
        storage: { 'csm-prefs': JSON.stringify({ timezone: 'Pacific/Chatham' }) },
        url: 'https://csm.example.test/findings?tab=history&from=2026-09-23&to=2026-09-23&severity=2&hsearch=shell',
        globals: { bootstrap: undefined }
    });
    await settle();
    const link = page.document.getElementById('history-csv');
    assert.ok(link, 'CSV link missing');
    const url = new URL(link.getAttribute('href'), 'https://csm.example.test/');
    assert.equal(url.pathname, '/api/v1/history/csv');
    assert.equal(url.searchParams.get('from'), '2026-09-22T11:15:00.000Z');
    assert.equal(url.searchParams.get('to'), '2026-09-23T11:15:00.000Z');
    assert.equal(url.searchParams.get('severity'), '2');
    assert.equal(url.searchParams.get('search'), 'shell');
});

test('incident CSV export neutralises formula cells', async () => {
    const blobs = [];
    const page = loadPage(templateBody('incident'), SHARED.concat(['incident.js']), {
        url: 'https://csm.example.test/incident?ip=203.0.113.9',
        globals: { URL: capturingURL(blobs) }
    });
    page.respond('/api/v1/incident?', 200, { events: [{
        timestamp: '2026-09-23T00:00:00Z', severity: 2, type: 'finding',
        summary: '=HYPERLINK("http://203.0.113.9/x","open")', details: '@SUM(1+1)'
    }] });
    await settle();
    page.document.getElementById('incident-export').dispatchEvent(new page.window.Event('click'));
    assert.equal(blobs.length, 1, 'no CSV produced');
    const csv = await blobs[0].text();
    const row = csv.split('\n')[1];
    assert.ok(row.includes('"\'=HYPERLINK(""http://203.0.113.9/x"",""open"")"'), row);
    assert.ok(row.includes('"\'@SUM(1+1)"'), row);
});
