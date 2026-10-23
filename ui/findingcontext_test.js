// Run with: node --test ui/findingcontext_test.js
// A finding's context, such as ModSecurity being off for its account, is
// shown wherever the operator reads the finding: the detail panel of an
// active finding and the expanded details of a history row.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

const CONTEXT = 'ModSecurity is disabled for account alice (all domains) (set in /etc/apache2/conf.d/userdata/ssl/2_4/alice/modsec.conf): requests there are not filtered and leave no modsec audit record.';

function finding(context) {
    return {
        key: 'webshell:Known webshell found', severity: 'CRITICAL', check: 'webshell',
        message: 'Known webshell found: /home/alice/public_html/x.php',
        details: 'Size: 10', context: context, file_path: '/home/alice/public_html/x.php',
        first_seen: '2026-09-22T10:00:00Z', last_seen: '2026-09-22T10:00:00Z'
    };
}

async function openDetail(f) {
    const page = loadPage(templateBody('findings'), SHARED.concat(['findings.js']));
    page.respond('/api/v1/findings/enriched', 200, { items: [f], check_types: [], accounts: [], total: 1 });
    await settle();
    page.document.querySelector('.finding-row').querySelectorAll('td')[2].click();
    await settle();
    page.respond('/api/v1/finding-detail', 200, { actions: [] });
    await settle();
    return page.window.CSM.detailPanel.element().textContent;
}

test('the finding detail panel shows the context', async () => {
    const text = await openDetail(finding(CONTEXT));
    assert.ok(text.includes(CONTEXT), text);
});

test('a finding without context shows no context block', async () => {
    const text = await openDetail(finding(undefined));
    assert.ok(!text.includes('Context:'), text);
});

test('a history row expands to its details and context', async () => {
    const page = loadPage(templateBody('findings'), SHARED.concat(['history.js']), {
        url: 'https://csm.example.test/findings?tab=history',
        globals: { bootstrap: undefined }
    });
    await settle();
    page.respond('/api/v1/history', 200, { items: [
        { severity: 2, check: 'webshell', message: 'Known webshell found', details: 'Size: 10', context: CONTEXT, timestamp: '2026-09-22T10:00:00Z' },
        { severity: 2, check: 'webshell', message: 'Context only', context: CONTEXT, timestamp: '2026-09-22T09:00:00Z' }
    ], total: 2 });
    await settle();
    const rows = page.document.querySelectorAll('.details-row');
    assert.equal(rows.length, 2, 'a row with context has no details row');
    assert.ok(rows[0].textContent.includes('Size: 10') && rows[0].textContent.includes(CONTEXT), rows[0].textContent);
    assert.ok(rows[1].textContent.includes(CONTEXT), rows[1].textContent);
});
