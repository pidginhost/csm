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
        key: check + ':' + message, severity: 'HIGH', check, message,
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
    page.respond('/api/v1/findings/enriched', 200, { items: [finding('perf_load', 'load'), f], total: 2 });
    await settle();
    const detail = page.pending('/api/v1/finding-detail');
    assert.equal(detail.length, 1, 'the linked finding was not opened');
    assert.ok(detail[0].url.includes('check=webshell'));
});

test('a linked finding past page one opens once across refreshes', async () => {
    const findings = Array.from({ length: 30 }, (_, i) => finding('webshell', 'file ' + i));
    const page = findingsPage('/findings?key=' + encodeURIComponent(findings[29].key));
    page.respond('/api/v1/findings/enriched', 200, { items: findings, total: 30 });
    await settle();
    const req = page.respond('/api/v1/finding-detail', 200, {});
    assert.equal(new URLSearchParams(req.url.split('?')[1]).get('message'), 'file 29');
    await settle();
    page.window.CSM.detailPanel.close();
    page.window.CSM.refresh.manual();
    page.respond('/api/v1/findings/enriched', 200, { items: findings, total: 30 });
    await settle();
    assert.equal(page.requests.filter(r => r.url.includes('/finding-detail')).length, 1);
});

test('a linked finding missing from an empty list is removed once', async () => {
    const page = findingsPage('/findings?key=missing&hperpage=100');
    const toasts = [];
    page.window.CSM.toast = message => { toasts.push(message); };
    page.respond('/api/v1/findings/enriched', 200, { items: [], total: 0 });
    await settle();
    assert.equal(new URLSearchParams(page.window.location.search).get('key'), null);
    assert.equal(new URLSearchParams(page.window.location.search).get('hperpage'), '100');
    page.window.CSM.refresh.manual();
    page.respond('/api/v1/findings/enriched', 200, { items: [], total: 0 });
    await settle();
    assert.equal(toasts.length, 1);
});

test('the new-findings banner refreshes data without reloading the document', async () => {
    const page = findingsPage('/findings');
    page.respond('/api/v1/findings/enriched', 200, { items: [], total: 0 });
    await settle();
    let reloads = 0;
    let updates = 0;
    page.window.dispatchEvent(new page.window.Event('load'));
    page.window.addEventListener('csm:refresh-bump', () => { updates++; });
    page.window.location.reload = () => { reloads++; };
    page.document.getElementById('refresh-page-btn').click();
    assert.equal(reloads, 0);
    assert.equal(page.pending('/api/v1/findings/enriched').length, 1);
    page.respond('/api/v1/findings/enriched', 200, { items: [], total: 0 });
    await settle();
    assert.equal(updates, 1);
});

test('?key= for a finding that is gone says so', async () => {
    const page = findingsPage('/findings?key=' + encodeURIComponent('webshell:old'));
    const toasts = [];
    page.window.CSM.toast = (message, kind) => toasts.push({ message, kind });
    page.respond('/api/v1/findings/enriched', 200, { items: [finding('perf_load', 'load')], total: 1 });
    await settle();
    assert.equal(page.pending('/api/v1/finding-detail').length, 0);
    assert.ok(toasts.some(t => /no longer active/.test(t.message)), JSON.stringify(toasts));
});

test('a closed linked finding stays closed when its details arrive', async () => {
    const f = finding('webshell', 'old');
    const page = findingsPage('/findings?key=' + encodeURIComponent(f.key) + '&hperpage=100');
    page.respond('/api/v1/findings/enriched', 200, { items: [f], total: 1 });
    await settle();
    page.window.CSM.detailPanel.close();
    page.respond('/api/v1/finding-detail', 200, {});
    await settle();
    assert.ok(!page.window.CSM.detailPanel.element().classList.contains('show'));
    const params = new URLSearchParams(page.window.location.search);
    assert.equal(params.get('key'), null);
    assert.equal(params.get('hperpage'), '100');
});

test('an older detail response cannot replace the latest linked finding', async () => {
    const a = finding('webshell', 'old');
    const b = finding('http_scanner', 'new');
    const page = findingsPage('/findings?key=' + encodeURIComponent(a.key));
    page.respond('/api/v1/findings/enriched', 200, { items: [a, b], total: 2 });
    await settle();
    page.document.querySelector('[data-check="http_scanner"] td').click();
    page.respond('finding-detail?check=http_scanner', 200, {});
    await settle();
    page.respond('finding-detail?check=webshell', 200, {});
    await settle();
    assert.equal(page.window.CSM.detailPanel.element().querySelector('h2').textContent, 'http_scanner');
    assert.equal(new URLSearchParams(page.window.location.search).get('key'), b.key);
});

test('opening a finding puts it in the URL and closing takes it out', async () => {
    const f = finding('webshell', 'shell in /home/a/x.php');
    const page = findingsPage('/findings?check=webshell');
    page.respond('/api/v1/findings/enriched', 200, { items: [f], check_types: ['webshell'], total: 1 });
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

for (const value of ['0', '-1', '1', '100x']) {
    test('History refuses unsupported page size ' + value, async () => {
        const page = findingsPage('/findings?tab=history&hperpage=' + value);
        page.document.querySelector('[href="#tab-history"]').dispatchEvent(new page.window.Event('shown.bs.tab'));
        await settle();
        assert.equal(historyLimit(page.pending('/api/v1/history')[0]), '50');
        assert.equal(new URLSearchParams(page.window.location.search).get('hperpage'), null);
    });
}

test('detail-panel close fires only the latest callback once', () => {
    const p = loadPage('', SHARED);
    let first = 0, second = 0;
    p.window.CSM.detailPanel.open({ onClose() { first++; } });
    p.window.CSM.detailPanel.open({ onClose() { second++; } });
    const panel = p.window.CSM.detailPanel.element();
    panel.dispatchEvent(new p.window.Event('hidden.bs.offcanvas'));
    p.window.CSM.detailPanel.close();
    panel.dispatchEvent(new p.window.Event('hidden.bs.offcanvas'));
    assert.equal(first, 0);
    assert.equal(second, 1);
});

// History showed a fixed 50 rows per page.
test('History page size is chosen and kept in the URL', async () => {
    const page = findingsPage('/findings?tab=history');
    page.document.querySelector('[href="#tab-history"]').dispatchEvent(new page.window.Event('shown.bs.tab'));
    await settle();
    assert.equal(historyLimit(page.respond('/api/v1/history', 200, { items: [], total: 0 })), '50');
    await settle();
    const size = page.document.getElementById('history-per-page');
    assert.ok(size, 'no page size control');
    size.value = '200';
    size.dispatchEvent(new page.window.Event('change'));
    await settle();
    assert.equal(historyLimit(page.respond('/api/v1/history', 200, { items: [], total: 0 })), '200');
    await settle();
    assert.equal(new URLSearchParams(page.window.location.search).get('hperpage'), '200');

    const again = findingsPage('/findings?tab=history&hperpage=100');
    again.document.querySelector('[href="#tab-history"]').dispatchEvent(new again.window.Event('shown.bs.tab'));
    await settle();
    assert.equal(historyLimit(again.pending('/api/v1/history')[0]), '100');
    assert.equal(again.document.getElementById('history-per-page').value, '100');
});

test('Refresh reloads the visible History tab with its rolling window', async () => {
    const page = findingsPage('/findings?tab=history&window=24h&hperpage=100');
    page.document.getElementById('tab-active').classList.remove('active');
    page.document.getElementById('tab-history').classList.add('active');
    page.document.querySelector('[href="#tab-history"]').dispatchEvent(new page.window.Event('shown.bs.tab'));
    page.respond('/api/v1/history', 200, { items: [], total: 0 });
    await settle();
    page.window.CSM.refresh.manual();
    await settle();
    const req = page.pending('/api/v1/history')[0];
    assert.ok(req, 'the visible history was not refreshed');
    assert.equal(historyLimit(req), '100');
    assert.ok(new URLSearchParams(req.url.split('?')[1]).has('from'));
});

test('changing History page size ignores the previous page response', async () => {
    const page = findingsPage('/findings?tab=history');
    page.document.querySelector('[href="#tab-history"]').dispatchEvent(new page.window.Event('shown.bs.tab'));
    const size = page.document.getElementById('history-per-page');
    size.value = '100';
    size.dispatchEvent(new page.window.Event('change'));
    const requests = page.pending('/api/v1/history');
    assert.equal(requests.length, 2);
    for (const [idx, req] of requests.map((r, i) => [i, r]).reverse()) {
        req.settled = true;
        req.resolve({ status: 200, ok: true, json: () => Promise.resolve({
            items: [{ check: 'webshell', message: idx ? 'current page' : 'stale page', severity: 1 }], total: 1
        }) });
        await settle();
    }
    assert.match(page.document.getElementById('history-content').textContent, /current page/);
    assert.doesNotMatch(page.document.getElementById('history-content').textContent, /stale page/);
});

test('a finding lookup before window load does not update page freshness', async () => {
    const f = finding('webshell', 'linked');
    const page = findingsPage('/findings?key=' + encodeURIComponent(f.key));
    page.respond('/api/v1/findings/enriched', 200, { items: [f], total: 1 });
    await settle();
    let updates = 0;
    page.window.addEventListener('csm:refresh-bump', () => { updates++; });
    page.respond('/api/v1/finding-detail', 200, {});
    await settle();
    assert.equal(updates, 0);
});

test('a previous offcanvas hide cannot close newly opened content', () => {
    const p = loadPage('', SHARED);
    let finishHide;
    p.window.bootstrap.Offcanvas = {
        getOrCreateInstance(el) {
            return {
                show() { el.classList.add('show'); },
                hide() {
                    el.dispatchEvent(new p.window.Event('hide.bs.offcanvas'));
                    finishHide = () => {
                        el.classList.remove('show');
                        el.dispatchEvent(new p.window.Event('hidden.bs.offcanvas'));
                    };
                }
            };
        }
    };
    let first = 0, second = 0;
    p.window.CSM.detailPanel.open({ title: 'first', onClose() { first++; } });
    p.window.CSM.detailPanel.close();
    p.window.CSM.detailPanel.open({ title: 'second', bodyHTML: '<button id="new-detail-action">Act</button>', onClose() { second++; } });
    // Callers bind actions immediately after open, including during a hide.
    const action = p.document.getElementById('new-detail-action');
    assert.ok(action, 'replacement content is not mounted for action binding');
    let actions = 0;
    action.addEventListener('click', () => { actions++; });
    finishHide();
    assert.equal(first, 1);
    assert.equal(second, 0);
    assert.ok(p.window.CSM.detailPanel.element().classList.contains('show'));
    p.document.getElementById('new-detail-action').click();
    assert.equal(actions, 1);
    p.window.CSM.detailPanel.close();
    finishHide();
    assert.equal(second, 1);
});

test('dashboard links open the matching finding and the 24h history', () => {
    const tmpl = templateBody('dashboard');
    for (const sev of ['2', '1', '0']) {
        assert.ok(tmpl.includes('href="/findings?tab=history&severity=' + sev + '&window=24h"'), 'severity ' + sev + ' card');
    }
    const src = fs.readFileSync(path.join(__dirname, 'static/js/dashboard.js'), 'utf8');
    assert.ok(src.includes("href: '/findings?key=' + encodeURIComponent(fi.key || '')"), 'queued findings do not link to themselves');
});
