// Run with: node --test ui/loaderror_test.js
// A failed load shows one error state on every page: what failed, why, and
// a Retry button. It covers the content instead of replacing it, so a
// loader that fills elements inside the covered area still finds them on
// Retry or on the next successful refresh.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, items, SHARED, settle, jsonResponse } = require('./pagekit.js');

function autoObject() {
    return new Proxy({}, { get(t, k) { if (typeof k === 'symbol') return t[k]; if (!(k in t)) t[k] = autoObject(); return t[k]; } });
}
const chart = function () { return { destroy() {}, update() {}, data: { datasets: [] }, options: {} }; };
chart.defaults = autoObject();
chart.instances = {};

function visible(el) {
    for (let n = el; n && n.nodeType === 1; n = n.parentNode) {
        if (n.hidden || n.classList.contains('d-none')) return false;
    }
    return true;
}

test('a load error covers the content and Retry brings it back', () => {
    const page = loadPage('<div id="box"><span id="value">-</span>Loading</div>', SHARED);
    const box = page.document.getElementById('box');
    let retries = 0;
    page.window.CSM.loadError(box, () => { retries++; }, { title: 'Failed to load stats', error: new Error('HTTP 502') });
    const value = page.document.getElementById('value');
    assert.ok(value, 'the covered content was removed');
    assert.equal(visible(value), false, 'the covered content still shows');
    const loose = Array.from(box.childNodes).filter(n => n.nodeType === 3 && /\S/.test(n.nodeValue));
    assert.equal(loose.length, 0, 'loose text still shows');
    assert.equal(visible(Array.from(box.children).find(c => c.textContent === 'Loading')), false, 'loose text still shows');
    const error = box.querySelector('.csm-load-error');
    assert.ok(error, 'no error state');
    assert.match(error.textContent, /Failed to load stats/);
    assert.match(error.textContent, /HTTP 502/);
    error.querySelector('button').click();
    assert.equal(retries, 1);
    assert.equal(box.querySelector('.csm-load-error'), null, 'the error stayed after Retry');
    assert.equal(visible(value), true, 'Retry did not bring the content back');
    assert.match(box.textContent, /Loading/);
});

test('the failure reason is shown as text', () => {
    const page = loadPage('<div id="box"></div>', SHARED);
    const box = page.document.getElementById('box');
    page.window.CSM.loadError(box, null, { error: new Error('<img src=x>') });
    assert.equal(box.querySelector('img'), null, 'the reason was parsed as markup');
    assert.match(box.textContent, /<img src=x>/);
    assert.match(box.textContent, /Failed to load data/);
    assert.equal(box.querySelector('button'), null, 'Retry offered with nothing to retry');
});

test('a second failure replaces the first and keeps what was already hidden', () => {
    const page = loadPage('<div id="box"><p id="shown">a</p><p id="kept" hidden>b</p></div>', SHARED);
    const box = page.document.getElementById('box');
    page.window.CSM.loadError(box, () => {});
    page.window.CSM.loadError(box, () => {});
    assert.equal(box.querySelectorAll('.csm-load-error').length, 1);
    page.window.CSM.clearLoadError(box);
    assert.equal(box.querySelector('.csm-load-error'), null);
    assert.equal(page.document.getElementById('shown').hidden, false);
    assert.equal(page.document.getElementById('kept').hidden, true, 'clearing showed content the page had hidden');
});

test('a load error inside a card body adds no second card padding', () => {
    const page = loadPage('<div id="panel" class="card-body"><p>x</p></div><div id="bare"></div>', SHARED);
    page.window.CSM.loadError(page.document.getElementById('panel'), null);
    page.window.CSM.loadError(page.document.getElementById('bare'), null);
    assert.equal(page.document.querySelector('#panel .csm-load-error').classList.contains('card-body'), false);
    assert.equal(page.document.querySelector('#bare .csm-load-error').classList.contains('card-body'), true);
});

test('a load error in a table body is one row across the table', () => {
    const page = loadPage('<table><thead><tr><th>A</th><th>B</th><th>C</th></tr></thead>' +
        '<tbody id="rows"><tr><td>1</td><td>2</td><td>3</td></tr></tbody></table>', SHARED);
    const tbody = page.document.getElementById('rows');
    page.window.CSM.loadError(tbody, () => {}, { title: 'Failed to load rows' });
    const rows = Array.from(tbody.children);
    assert.equal(rows.length, 2);
    assert.equal(rows[0].hidden, true, 'the old row still shows');
    assert.ok(rows[1].classList.contains('csm-load-error'));
    assert.equal(rows[1].tagName, 'TR');
    assert.equal(rows[1].querySelector('td').getAttribute('colspan'), '3');
});

// driveFailing answers every pending request, failing the ones `fails`
// matches, until the page stops asking.
async function driveFailing(page, fails, bodies) {
    for (let round = 0; round < 8; round++) {
        const pending = page.requests.filter(r => !r.settled);
        if (pending.length === 0) break;
        for (const req of pending) {
            req.settled = true;
            if (fails(req.url)) {
                req.reject(new Error('HTTP 502'));
                continue;
            }
            const hit = Object.keys(bodies || {}).find(k => req.url.includes(k));
            req.resolve(jsonResponse(200, hit ? bodies[hit] : items([])));
        }
        await settle();
    }
}

function answer(page, match, body) {
    const req = page.requests.find(r => !r.settled && match(r.url));
    assert.ok(req, 'no pending request');
    req.settled = true;
    req.resolve(jsonResponse(200, body));
}

test('Rules: Retry after a failed status load fills the stats', async () => {
    const page = loadPage(templateBody('rules'), SHARED.concat(['rules.js']));
    const status = u => u.includes('/api/v1/rules/status');
    await driveFailing(page, status, { '/api/v1/rules/list': items([]) });
    const error = page.document.querySelector('.csm-load-error');
    assert.ok(error, 'no error state');
    error.querySelector('button').click();
    await settle();
    answer(page, status, { yaml_rules: 12, yara_available: true, yara_rules: 3, yaml_version: 'v7', auto_update: true });
    await settle();
    assert.equal(page.document.getElementById('stat-yaml').textContent, '12');
    assert.equal(page.document.getElementById('stat-version').textContent, 'v7');
    assert.equal(page.document.querySelector('.csm-load-error'), null);
});

test('Rules: Retry after a failed file list fills the table', async () => {
    const page = loadPage(templateBody('rules'), SHARED.concat(['rules.js']));
    const list = u => u.includes('/api/v1/rules/list');
    await driveFailing(page, list, {});
    const tbody = page.document.getElementById('rules-tbody');
    assert.ok(tbody, 'the failed load removed the table');
    tbody.querySelector('.csm-load-error button').click();
    await settle();
    answer(page, list, items([{ name: 'malware.yml', type: 'yaml', size: 10 }]));
    await settle();
    assert.match(page.document.getElementById('rules-tbody').textContent, /malware\.yml/);
});

test('Firewall: the status cards recover after a failed refresh', async () => {
    const page = loadPage(templateBody('firewall'), SHARED.concat(['firewall.js']));
    const status = u => u.includes('/api/v1/firewall/status');
    await driveFailing(page, status, {});
    assert.ok(page.document.querySelector('#fw-status .csm-load-error'), 'no error state');
    page.window.CSM.refresh.manual();
    await settle();
    answer(page, status, { enabled: true });
    await settle();
    assert.match(page.document.getElementById('fw-enabled').textContent, /ACTIVE/);
    assert.equal(visible(page.document.getElementById('fw-enabled')), true);
    assert.equal(page.document.querySelector('#fw-status .csm-load-error'), null, 'the error stayed after a good refresh');
});

test('Threat Intel retries the part that failed, not the whole page', async () => {
    const page = loadPage(templateBody('threat'), SHARED.concat(['threat.js']), { globals: { Chart: chart } });
    let reloads = 0;
    page.window.location.reload = () => { reloads++; };
    const failing = u => u.includes('/api/v1/threat/stats') || u.includes('/api/v1/threat/top-attackers');
    await driveFailing(page, failing, {});
    for (const [host, endpoint] of [['chart-types', '/api/v1/threat/stats'], ['attackers-tbody', '/api/v1/threat/top-attackers']]) {
        const error = page.document.getElementById(host).querySelector('.csm-load-error');
        assert.ok(error, host + ': no error state');
        const before = page.requests.filter(r => r.url.includes(endpoint)).length;
        error.querySelector('button').click();
        await settle();
        assert.equal(page.requests.filter(r => r.url.includes(endpoint)).length, before + 1, host + ': Retry did not load again');
    }
    assert.equal(reloads, 0, 'Retry reloaded the whole page');
});

// Each page shows the shared error state where its data failed to load, and
// its Retry loads that data again.
const CASES = [
    { name: 'account', path: '/account?name=alice', scripts: ['account.js'], fails: '/api/v1/account?name=alice', host: 'account-tab-content', title: /account/i },
    { name: 'findings', scripts: ['findings.js'], fails: '/api/v1/findings/enriched', host: 'tab-active', title: /findings/i },
    { name: 'dashboard', scripts: ['dashboard.js'], fails: u => /\/api\/v1\/stats$/.test(u), host: 'accounts-at-risk', title: /Failed to load/ },
    { name: 'dashboard', scripts: ['dashboard.js'], fails: '/api/v1/stats/timeline', host: 'timeline-chart', parent: true, title: /timeline/i },
    { name: 'dashboard', scripts: ['dashboard.js'], fails: '/api/v1/threat/stats', host: 'attack-types-chart', parent: true, title: /attack/i },
    { name: 'dashboard', scripts: ['dashboard.js'], fails: '/api/v1/stats/trend', host: 'trend-chart', parent: true, title: /trend/i },
    { name: 'email', scripts: ['email.js'], fails: '/api/v1/email/stats', host: 'protection-queue' },
    { name: 'email', scripts: ['email.js'], fails: u => u.includes('/api/v1/email/groups?') && !u.includes('auth_failure'), host: 'email-action-groups', title: /action groups/i },
    { name: 'email', scripts: ['email.js'], tab: 'email-tab-auth', fails: 'kind=auth_failure', host: 'email-auth-groups', title: /clusters/i },
    { name: 'email', scripts: ['email.js'], fails: '/api/v1/history?', host: 'email-tbody', title: /findings/i },
    { name: 'email', scripts: ['email.js'], tab: 'email-tab-quarantine', fails: '/api/v1/email/quarantine', host: 'quarantine-table', title: /quarantine/i },
    { name: 'email', scripts: ['email.js'], tab: 'email-tab-forwarders', fails: '/api/v1/email/forwarders', host: 'email-fwd-tbody', title: /forwarders/i },
    { name: 'email', scripts: ['email.js'], tab: 'email-tab-forwarders', fails: '/api/v1/email/held', host: 'email-held-tbody', title: /held/i },
    { name: 'email', scripts: ['email.js'], tab: 'email-tab-deliverability', fails: '/api/v1/email/deferrals', host: 'email-deliv-providers-body', title: /deferral/i },
    { name: 'email', scripts: ['email.js'], tab: 'email-tab-outbound-abuse', fails: '/api/v1/email/relay-abuse', host: 'outbound-abuse-body', title: /outbound/i },
    { name: 'email', scripts: ['email.js'], tab: 'email-tab-queue', fails: '/api/v1/email/queue-composition', host: 'queue-composition', title: /queue composition/i },
    { name: 'firewall', scripts: ['firewall.js'], fails: '/api/v1/challenge/stats', host: 'fw-chal-body', title: /challenge/i },
    { name: 'incident', scripts: ['incident.js'], tab: 'grouped-tab', click: true, fails: '/api/v1/incidents/groups?', host: 'grouped-content', title: /groups/i },
    { name: 'hardening', scripts: ['hardening.js'], fails: '/api/v1/hardening', host: 'categories-container', title: /hardening report/i },
    { name: 'modsec', scripts: ['modsec.js'], fails: '/api/v1/modsec/blocks', host: 'modsec-content', title: /blocks/i },
    { name: 'modsec', scripts: ['modsec.js'], fails: '/api/v1/modsec/blocks', host: 'modsec-pressure', title: /WAF pressure/i },
    { name: 'modsec', scripts: ['modsec.js'], tab: 'modsec-tab-events', fails: '/api/v1/modsec/events', host: 'modsec-events', title: /events/i },
    { name: 'performance', scripts: ['performance.js'], fails: '/api/v1/performance', host: 'perf-findings', title: /performance/i },
    { name: 'settings', scripts: ['settings.js'], fails: '/api/v1/settings/alerts', host: 'settings-panel', title: /section/i,
        bodies: { '/api/v1/settings': { sections: [{ id: 'alerts', title: 'Alerts', group: 'Core' }], groups: ['Core'] } } },
    { name: 'verified-bots', scripts: ['verified-bots.js'], fails: '/api/v1/verified-bots', host: 'vbots-loading', title: /verified bots/i }
];

for (const c of CASES) {
    const label = c.name + ' ' + (typeof c.fails === 'string' ? c.fails : c.host);
    test('a failed load shows the shared error with Retry: ' + label, async () => {
        const page = loadPage(templateBody(c.name), SHARED.concat(c.scripts),
            { url: 'https://csm.example.test' + (c.path || '/' + c.name), globals: { Chart: chart } });
        page.window.location.reload = () => {};
        page.document.dispatchEvent(new page.window.Event('DOMContentLoaded'));
        const fails = typeof c.fails === 'string' ? (u => u.includes(c.fails)) : c.fails;
        await driveFailing(page, fails, c.bodies);
        if (c.tab) {
            const tab = page.document.getElementById(c.tab);
            if (c.click) tab.click();
            else tab.dispatchEvent(new page.window.Event('shown.bs.tab'));
            await driveFailing(page, fails, c.bodies);
        }
        let host = page.document.getElementById(c.host);
        assert.ok(host, 'no #' + c.host);
        if (c.parent) host = host.parentElement;
        const error = host.querySelector('.csm-load-error');
        assert.ok(error, 'no shared error state in #' + c.host + ': ' + host.innerHTML.slice(0, 200));
        assert.equal(visible(error), true, 'the error state is hidden');
        if (c.title) assert.match(error.textContent, c.title);
        assert.match(error.textContent, /HTTP 502/, 'the reason is missing');
        const before = page.requests.filter(r => fails(r.url)).length;
        error.querySelector('.csm-retry-btn').click();
        await settle();
        assert.ok(page.requests.filter(r => fails(r.url)).length > before, 'Retry did not load again');
    });
}

test('Hardening hides the no-results message when the report failed to load', async () => {
    const page = loadPage(templateBody('hardening'), SHARED.concat(['hardening.js']));
    await driveFailing(page, u => u.includes('/api/v1/hardening'), {});
    assert.equal(visible(page.document.getElementById('empty-state')), false, 'a failed load reads as no audit run');
});

test('Settings retries a failed metadata load by reloading the page', async () => {
    const page = loadPage(templateBody('settings'), SHARED.concat(['settings.js']));
    let reloads = 0;
    page.window.location.reload = () => { reloads++; };
    page.document.dispatchEvent(new page.window.Event('DOMContentLoaded'));
    await driveFailing(page, u => /\/api\/v1\/settings$/.test(u), {});
    const error = page.document.querySelector('#settings-panel .csm-load-error');
    assert.ok(error, 'no shared error state');
    assert.match(error.textContent, /settings/i);
    error.querySelector('.csm-retry-btn').click();
    assert.equal(reloads, 1);
});

test('a dashboard chart that failed and then loads empty drops the error', async () => {
    const page = loadPage(templateBody('dashboard'), SHARED.concat(['dashboard.js']), { globals: { Chart: chart } });
    const timeline = u => u.includes('/api/v1/stats/timeline');
    await driveFailing(page, timeline, {});
    const parent = page.document.getElementById('timeline-chart').parentElement;
    assert.ok(parent.querySelector('.csm-load-error'));
    page.window.CSM.refresh.manual();
    await settle();
    answer(page, timeline, items([]));
    await settle();
    assert.equal(parent.querySelector('.csm-load-error'), null);
});
