// Run with: node --test ui/severity_test.js
// One severity table serves every page: a numeric level or a label in any
// case maps to the same label, badge class and sort rank everywhere. The API
// sends a severity as its label; pages derive the rest from it.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, items, SHARED, settle } = require('./pagekit.js');

test('levels and labels map to the same severity', () => {
    const CSM = loadPage('', SHARED).window.CSM;
    for (const [input, want] of [
        [2, ['CRITICAL', 'critical', 2, 3]],
        ['critical', ['CRITICAL', 'critical', 2, 3]],
        [1, ['HIGH', 'high', 1, 2]],
        [' High ', ['HIGH', 'high', 1, 2]],
        [0, ['WARNING', 'warning', 0, 1]],
        ['WARNING', ['WARNING', 'warning', 0, 1]]
    ]) {
        const s = CSM.severity(input);
        assert.deepEqual([s.label, s.cls, s.level, s.rank], want, 'severity(' + JSON.stringify(input) + ')');
    }
});

test('anything else is an unknown severity, never a guess', () => {
    const CSM = loadPage('', SHARED).window.CSM;
    for (const input of [3, -1, 1.5, '', 'info', null, undefined, '2']) {
        const s = CSM.severity(input);
        assert.deepEqual([s.label, s.cls, s.level, s.rank], ['UNKNOWN', 'secondary', -1, 0], 'severity(' + JSON.stringify(input) + ')');
    }
});

test('the badge and class helpers use the same table', () => {
    const CSM = loadPage('', SHARED).window.CSM;
    assert.match(CSM.severityBadge(2), /badge-critical/);
    assert.match(CSM.severityBadge(2), />CRITICAL</);
    assert.match(CSM.severityBadge('high'), /badge-high/);
    assert.match(CSM.severityBadge(7), /badge-secondary/);
    assert.equal(CSM.severityClass(1), 'high');
    assert.equal(CSM.severityClass('warning'), 'warning');
    assert.equal(CSM.severityClass('nope'), 'secondary');
});

test('a grouped row marks and badges a severity label', () => {
    const page = loadPage('', SHARED);
    const el = page.window.CSM.summaryItem({ severity: 'CRITICAL', title: 'jane@example.com' });
    assert.ok(el.classList.contains('csm-summary-list__item--crit'), el.className);
    assert.match(el.innerHTML, /badge-critical/);
    const high = page.window.CSM.summaryItem({ severity: 'high', title: 'x' });
    assert.ok(high.classList.contains('csm-summary-list__item--high'), high.className);
});

test('the findings table colours a severity from its label', async () => {
    const page = loadPage(templateBody('findings'), SHARED.concat(['findings.js']));
    page.respond('/api/v1/findings/enriched', 200, items([{
        key: 'webshell:x', severity: 'CRITICAL', check: 'webshell', message: 'shell', has_fix: false,
        first_seen: '2026-09-22T10:00:00Z', last_seen: '2026-09-22T10:00:00Z'
    }], { check_types: ['webshell'], accounts: [] }));
    await settle();
    const badge = page.document.querySelector('#findings-table tbody .badge');
    assert.ok(badge, 'no severity badge');
    assert.ok(badge.classList.contains('badge-critical'), badge.className);
});

test('a CRITICAL label raises a desktop notification', async () => {
    const shown = [];
    function Notification(title, opts) { shown.push(opts.body); }
    Notification.permission = 'granted';
    const chart = function () { return { destroy() {}, update() {}, data: { datasets: [] }, options: {} }; };
    chart.defaults = new Proxy({}, { get(t, k) { if (typeof k === 'symbol') return t[k]; if (!(k in t)) t[k] = chart.defaults; return t[k]; } });
    const page = loadPage(templateBody('dashboard'), SHARED.concat(['dashboard.js']),
        { globals: { Chart: chart, Notification }, storage: { 'csm-notif': 'on' } });
    for (let round = 0; round < 6; round++) {
        for (const req of page.pending()) {
            if (req.settled) continue;
            page.respond(req.url, 200, req.url.includes('/api/v1/history')
                ? items([{ severity: 'CRITICAL', check: 'webshell', message: 'old', timestamp: '2026-09-22T10:00:00Z' }])
                : items([]));
        }
        await settle();
    }
    const raw = JSON.stringify({ severity: 'CRITICAL', check: 'webshell', message: 'new', timestamp: '2026-09-22T11:00:00Z' });
    page.window.dispatchEvent(new page.window.CustomEvent('csm:sse-message', { detail: { raw } }));
    await new Promise(r => setTimeout(r, 1700));
    assert.deepEqual(shown, ['webshell: new']);
});

test('performance findings colour a severity from its label', async () => {
    const page = loadPage(templateBody('performance'), SHARED.concat(['performance.js']));
    page.document.dispatchEvent(new page.window.Event('DOMContentLoaded'));
    for (let round = 0; round < 6; round++) {
        for (const req of page.pending()) {
            if (req.settled) continue;
            page.respond(req.url, 200, req.url.includes('/api/v1/performance')
                ? { metrics: { cpu_cores: 1, load_avg: [0, 0, 0] }, findings: [{ severity: 'CRITICAL', check: 'perf_load', message: 'load', key: 'k',
                    first_seen: '2026-09-22T10:00:00Z', last_seen: '2026-09-22T10:00:00Z' }] }
                : items([]));
        }
        await settle();
    }
    assert.match(page.document.getElementById('perf-findings').innerHTML, /danger/);
});

test('account severity filters match API labels on both tabs', async () => {
    const page = loadPage(templateBody('account'), SHARED.concat(['account.js']),
        { url: 'https://csm.example.test/account?name=alice' });
    const rows = ['WARNING', 'HIGH', 'CRITICAL'].map(severity => ({ severity, check: 'webshell', message: severity, timestamp: '2026-09-22T10:00:00Z' }));
    page.respond('/api/v1/account', 200, { findings: rows, history: rows, quarantined: [] });
    await settle();
    for (const tab of ['findings', 'history']) {
        page.document.querySelector('#account-tabs [data-tab="' + tab + '"]').click();
        await settle();
        const filter = page.document.getElementById('account-' + tab + '-sev');
        for (const [value, label] of [['0', 'WARNING'], ['1', 'HIGH'], ['2', 'CRITICAL']]) {
            filter.value = value;
            filter.dispatchEvent(new page.window.Event('change'));
            const visible = page.document.querySelectorAll('#account-' + tab + '-table tbody tr').filter(row => row.style.display !== 'none');
            assert.equal(visible.length, 1, tab + ' did not match ' + label);
            assert.match(visible[0].textContent, new RegExp(label));
        }
    }
});
