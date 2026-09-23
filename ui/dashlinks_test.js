// Run with: node --test ui/dashlinks_test.js
// Dashboard entries lead to the thing they show: a queued finding opens its
// own detail, and a 24h count opens the History tab for those 24 hours. The
// finding detail has its own URL, so it can be shared and reloaded.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

function finding(check, message) {
    return {
        key: check + ':' + message, severity: 'HIGH', sev_class: 'high', check, message,
        first_seen: '2026-09-22T10:00:00Z', last_seen: '2026-09-22T10:00:00Z'
    };
}

function findingsPage(url) {
    return loadPage(templateBody('findings'), SHARED.concat(['findings.js', 'history.js']),
        { url: 'https://csm.example.test' + url });
}

test('?key= opens that finding', async () => {
    const f = finding('webshell', 'shell in /home/a/x.php');
    const page = findingsPage('/findings?key=' + encodeURIComponent(f.key));
    page.respond('/api/v1/findings/enriched', 200, { findings: [finding('perf_load', 'load'), f], total: 2 });
    await settle();
    const detail = page.pending('/api/v1/finding-detail');
    assert.equal(detail.length, 1, 'the linked finding was not opened');
    assert.ok(detail[0].url.includes('check=webshell'));
});

test('?key= for a finding that is gone says so', async () => {
    const page = findingsPage('/findings?key=' + encodeURIComponent('webshell:old'));
    const toasts = [];
    page.window.CSM.toast = (message, kind) => toasts.push({ message, kind });
    page.respond('/api/v1/findings/enriched', 200, { findings: [finding('perf_load', 'load')], total: 1 });
    await settle();
    assert.equal(page.pending('/api/v1/finding-detail').length, 0);
    assert.ok(toasts.some(t => /no longer active/.test(t.message)), JSON.stringify(toasts));
});

test('opening a finding puts it in the URL and closing takes it out', async () => {
    const f = finding('webshell', 'shell in /home/a/x.php');
    const page = findingsPage('/findings?check=webshell');
    page.respond('/api/v1/findings/enriched', 200, { findings: [f], check_types: ['webshell'], total: 1 });
    await settle();
    page.document.querySelector('.finding-row').querySelectorAll('td')[2].click();
    await settle();
    const params = new URLSearchParams(page.window.location.search);
    assert.equal(params.get('key'), f.key);
    assert.equal(params.get('check'), 'webshell', 'other parameters were dropped');
    page.window.CSM.detailPanel.close();
    assert.equal(new URLSearchParams(page.window.location.search).get('key'), null);
});

test('History shows the last 24 hours for window=24h', async () => {
    const page = findingsPage('/findings?tab=history&severity=2&window=24h');
    // Bootstrap fires shown.bs.tab after showing the History tab; the stub does not.
    page.document.querySelector('[href="#tab-history"]').dispatchEvent(new page.window.Event('shown.bs.tab'));
    await settle();
    const req = page.pending('/api/v1/history').find(r => /severity=2/.test(r.url));
    assert.ok(req, 'no history request with the severity: ' + page.requests.map(r => r.url).join(', '));
    const from = new URLSearchParams(req.url.split('?')[1]).get('from');
    assert.ok(from, 'no start time sent');
    const age = Date.now() - Date.parse(from);
    assert.ok(Math.abs(age - 24 * 3600 * 1000) < 60 * 1000, 'start time is not 24 hours ago: ' + from);
    assert.equal(page.document.getElementById('history-window').classList.contains('d-none'), false);
    page.document.getElementById('date-clear-btn').click();
    await settle();
    const after = page.pending('/api/v1/history');
    const last = after[after.length - 1];
    assert.equal(new URLSearchParams(last.url.split('?')[1]).get('from'), null, 'clearing kept the window');
    assert.equal(new URLSearchParams(page.window.location.search).get('window'), null);
});

function historyLimit(req) {
    return new URLSearchParams(req.url.split('?')[1]).get('limit');
}

// History showed a fixed 50 rows per page.
test('History page size is chosen and kept in the URL', async () => {
    const page = findingsPage('/findings?tab=history');
    page.document.querySelector('[href="#tab-history"]').dispatchEvent(new page.window.Event('shown.bs.tab'));
    await settle();
    assert.equal(historyLimit(page.respond('/api/v1/history', 200, { findings: [], total: 0 })), '50');
    await settle();
    const size = page.document.getElementById('history-per-page');
    assert.ok(size, 'no page size control');
    size.value = '200';
    size.dispatchEvent(new page.window.Event('change'));
    await settle();
    assert.equal(historyLimit(page.respond('/api/v1/history', 200, { findings: [], total: 0 })), '200');
    await settle();
    assert.equal(new URLSearchParams(page.window.location.search).get('hperpage'), '200');

    const again = findingsPage('/findings?tab=history&hperpage=100');
    again.document.querySelector('[href="#tab-history"]').dispatchEvent(new again.window.Event('shown.bs.tab'));
    await settle();
    assert.equal(historyLimit(again.pending('/api/v1/history')[0]), '100');
    assert.equal(again.document.getElementById('history-per-page').value, '100');
});

test('dashboard links open the matching finding and the 24h history', () => {
    const tmpl = templateBody('dashboard');
    for (const sev of ['2', '1', '0']) {
        assert.ok(tmpl.includes('href="/findings?tab=history&severity=' + sev + '&window=24h"'), 'severity ' + sev + ' card');
    }
    const src = fs.readFileSync(path.join(__dirname, 'static/js/dashboard.js'), 'utf8');
    assert.ok(src.includes("href: '/findings?key=' + encodeURIComponent(fi.key || '')"), 'queued findings do not link to themselves');
});
