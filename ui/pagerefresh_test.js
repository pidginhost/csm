// Run with: node --test ui/pagerefresh_test.js
// The header Refresh button reloads the page's data in place on every page
// that loads its data with scripts. It used to reload the whole page on
// those that registered nothing, losing scroll, filters and open panels.
// A page with unsaved edits asks before Refresh discards them.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

const chart = function () { return { destroy() {}, update() {}, data: { datasets: [] }, options: {} }; };
chart.defaults = { color: '', borderColor: '' };
chart.instances = {};

// answerAll answers every pending request with a body the pages accept.
async function answerAll(page, bodies) {
    for (let round = 0; round < 6; round++) {
        const pending = page.pending();
        if (pending.length === 0) break;
        for (const req of pending) {
            if (req.settled) continue;
            const hit = Object.keys(bodies || {}).find(k => req.url.includes(k));
            page.respond(req.url, 200, hit ? bodies[hit] : {});
        }
        await settle();
    }
}

async function refreshes(t, name, scripts, endpoint, opts = {}) {
    const page = loadPage(templateBody(name), SHARED.concat(scripts),
        { url: 'https://csm.example.test' + (opts.path || '/' + name), globals: { Chart: chart } });
    let reloads = 0;
    page.window.location.reload = () => { reloads++; };
    // The browser fires DOMContentLoaded after the scripts; fakedom does not.
    page.document.dispatchEvent(new page.window.Event('DOMContentLoaded'));
    await answerAll(page, opts.bodies);
    page.window.dispatchEvent(new page.window.Event('load'));
    const before = page.requests.filter(r => r.url.includes(endpoint)).length;
    assert.ok(before >= 1, name + ' did not load ' + endpoint + ' at start');
    let updates = 0;
    page.window.addEventListener('csm:refresh-bump', () => { updates++; });
    page.window.CSM.refresh.manual();
    await settle();
    assert.equal(reloads, 0, name + ': Refresh reloaded the whole page');
    const after = page.requests.filter(r => r.url.includes(endpoint)).length;
    assert.ok(after > before, name + ': Refresh did not load ' + endpoint + ' again');
    await answerAll(page, opts.bodies);
    assert.ok(updates > 0, name + ': refreshed data did not update the timestamp');
    return page;
}

const PAGES = [
    ['account', ['account.js'], '/api/v1/account?name=alice', { path: '/account?name=alice' }],
    ['cleanup-history', ['cleanup-history.js'], '/api/v1/db-object-backups'],
    ['hardening', ['hardening.js'], '/api/v1/hardening'],
    ['incident', ['incident.js'], '/api/v1/incidents?'],
    ['modsec-rules', ['modsec-rules.js'], '/api/v1/modsec/rules'],
    ['rules', ['rules.js'], '/api/v1/suppressions'],
    ['threat', ['threat.js'], '/api/v1/threat/stats', { bodies: { '/api/v1/threat/top-attackers': [] } }],
    ['verified-bots', ['verified-bots.js'], '/api/v1/verified-bots'],
    ['settings', ['settings.js'], '/api/v1/settings/alerts', {
        bodies: {
            '/api/v1/settings/alerts': { etag: 'e1', section: { id: 'alerts', title: 'Alerts', fields: [] }, values: {} },
            '/api/v1/settings': { sections: [{ id: 'alerts', title: 'Alerts', group: 'Core' }], groups: ['Core'] }
        }
    }]
];

for (const [name, scripts, endpoint, opts] of PAGES) {
    test('Refresh reloads the ' + name + ' data in place', async (t) => {
        await refreshes(t, name, scripts, endpoint, opts);
    });
}

test('Refresh asks before discarding staged ModSecurity rule changes', async () => {
    const page = loadPage(templateBody('modsec-rules'), SHARED.concat(['modsec-rules.js']));
    await answerAll(page, {
        '/api/v1/modsec/rules/escalation': { rules: [] },
        '/api/v1/modsec/rules': { configured: true, total: 1, active: 1, rules: [
            { id: 900200, description: 'x', action: 'deny', status_code: 403, phase: 2, enabled: true, escalate: true }] }
    });
    const toggle = page.document.querySelector('.enable-toggle[data-id="900200"]');
    toggle.checked = false;
    toggle.dispatchEvent(new page.window.Event('change'));
    const asked = [];
    page.window.CSM.confirm = (message, opts) => { asked.push({ message, opts }); return Promise.reject(null); };
    const before = page.requests.length;
    page.window.CSM.refresh.manual();
    await settle();
    assert.equal(asked.length, 1, 'no question before discarding');
    assert.equal(asked[0].opts && asked[0].opts.danger, true);
    assert.equal(page.requests.length, before, 'reloaded after the operator said no');
    assert.equal(page.document.getElementById('apply-bar').classList.contains('d-none'), false, 'staged change lost');
});

test('Refresh asks before discarding unsaved verified bot edits', async () => {
    const page = loadPage(templateBody('verified-bots'), SHARED.concat(['verified-bots.js']));
    await answerAll(page, { '/api/v1/verified-bots': { etag: 'e', bots: [{ name: 'examplebot', ua_substrings: ['examplebot'] }] } });
    page.document.querySelector('.vb-name').value = 'renamed';
    const asked = [];
    page.window.CSM.confirm = (message, opts) => { asked.push({ message, opts }); return Promise.reject(null); };
    const before = page.requests.length;
    page.window.CSM.refresh.manual();
    await settle();
    assert.equal(asked.length, 1, 'no question before discarding');
    assert.equal(page.requests.length, before);
    assert.equal(page.document.querySelector('.vb-name').value, 'renamed');
    // Unchanged again: no question.
    page.document.querySelector('.vb-name').value = 'examplebot';
    page.window.CSM.refresh.manual();
    await settle();
    assert.equal(asked.length, 1);
    assert.ok(page.requests.length > before);
});

test('a server-rendered page still reloads on Refresh', () => {
    const page = loadPage(templateBody('sessions'), SHARED);
    let reloads = 0;
    page.window.location.reload = () => { reloads++; };
    page.window.CSM.refresh.manual();
    assert.equal(reloads, 1);
});

test('edits made while verified bots are refreshing survive the response', async () => {
    const page = loadPage(templateBody('verified-bots'), SHARED.concat(['verified-bots.js']));
    const body = { etag: 'e', bots: [{ name: 'examplebot', ua_substrings: ['examplebot'] }] };
    await answerAll(page, { '/api/v1/verified-bots': body });
    page.window.CSM.refresh.manual();
    await settle();
    page.document.querySelector('.vb-name').value = 'new edit';
    page.respond('/api/v1/verified-bots', 200, body);
    await settle();
    assert.equal(page.document.querySelector('.vb-name').value, 'new edit');
});

test('Refresh waits for a verified-bot save already in flight', async () => {
    const page = loadPage(templateBody('verified-bots'), SHARED.concat(['verified-bots.js']));
    await answerAll(page, { '/api/v1/verified-bots': { etag: 'e', bots: [] } });
    page.document.getElementById('vbots-save').click();
    await settle();
    page.window.CSM.refresh.manual();
    await settle();
    assert.equal(page.pending().filter(r => r.method === 'GET' && r.url.includes('/verified-bots')).length, 0);
    page.respond('/api/v1/verified-bots/apply', 200, { new_etag: 'e2', count: 0 });
    await settle();
    page.window.CSM.refresh.manual();
    await settle();
    assert.equal(page.pending('/api/v1/verified-bots').length, 1);
});

const settingsSection = {
    etag: 'e1', section: { id: 'alerts', title: 'Alerts', fields: [
        { yaml_path: 'alerts.enabled', label: 'Enabled', type: 'bool' }
    ] }, values: { alerts: { enabled: false } }
};

async function settingsPage() {
    const p = loadPage(templateBody('settings'), SHARED.concat(['settings.js']));
    p.document.dispatchEvent(new p.window.Event('DOMContentLoaded'));
    p.respond('/api/v1/settings', 200, { sections: [{ id: 'alerts', title: 'Alerts', group: 'Core' }], groups: ['Core'] });
    await settle();
    return p;
}

test('settings Refresh waits for the first section instead of requesting null', async () => {
    const p = await settingsPage();
    const before = p.requests.length;
    p.window.CSM.refresh.manual();
    await settle();
    assert.equal(p.requests.length, before);
});

test('settings initial section counts as data even after window load', async () => {
    const p = loadPage(templateBody('settings'), SHARED.concat(['settings.js']));
    p.document.dispatchEvent(new p.window.Event('DOMContentLoaded'));
    p.window.dispatchEvent(new p.window.Event('load'));
    p.respond('/api/v1/settings', 200, { sections: [{ id: 'alerts', title: 'Alerts', group: 'Core' }], groups: ['Core'] });
    await settle();
    let updates = 0;
    p.window.addEventListener('csm:refresh-bump', () => { updates++; });
    p.respond('/api/v1/settings/alerts', 200, settingsSection);
    await settle();
    assert.equal(updates, 1);
});

test('settings Refresh cannot replace the form while it is saving', async () => {
    const p = await settingsPage();
    p.respond('/api/v1/settings/alerts', 200, settingsSection);
    await settle();
    const field = p.document.querySelector('#settings-panel input');
    field.checked = true;
    field.dispatchEvent(new p.window.Event('change', { bubbles: true }));
    p.document.getElementById('settings-save').click();
    await settle();
    assert.equal(p.pending('/api/v1/settings/alerts').filter(r => r.method === 'POST').length, 1);
    p.window.CSM.confirm = () => Promise.resolve();
    p.window.CSM.refresh.manual();
    await settle();
    assert.equal(p.pending('/api/v1/settings/alerts').filter(r => r.method === 'GET').length, 0);
    assert.equal(p.document.querySelector('#settings-panel input'), field);
});

test('account refresh follows the current tab when requests finish out of order', async () => {
    const p = loadPage(templateBody('account'), SHARED.concat(['account.js']), { url: 'https://csm.example.test/account?name=alice' });
    p.respond('/api/v1/account', 200, { findings: [], quarantined: [], history: [] });
    await settle();
    p.window.CSM.refresh.manual();
    p.document.querySelector('#account-tabs [data-tab="history"]').click();
    const pending = p.pending('/api/v1/account');
    assert.ok(pending.length >= 1);
    // Answer the current tab request first, then the earlier refresh.
    for (const req of pending.slice().reverse()) {
        req.settled = true;
        req.resolve({ status: 200, ok: true, json: () => Promise.resolve({ findings: [], history: [] }) });
        await settle();
    }
    assert.match(p.document.getElementById('account-tab-content').textContent, /History/i);
    assert.doesNotMatch(p.document.getElementById('account-tab-content').textContent, /Active Findings/i);
});

test('account refresh preserves the custom History date filter', async () => {
    const p = loadPage(templateBody('account'), SHARED.concat(['account.js']), { url: 'https://csm.example.test/account?name=alice' });
    const data = { findings: [], history: [{ check: 'webshell', message: 'old', severity: 1, timestamp: '2026-09-20T12:00:00Z' }] };
    p.respond('/api/v1/account', 200, data);
    await settle();
    p.document.querySelector('#account-tabs [data-tab="history"]').click();
    const from = p.document.getElementById('account-history-from');
    from.value = '2026-09-23';
    from.dispatchEvent(new p.window.Event('change'));
    p.window.CSM.refresh.manual();
    p.respond('/api/v1/account', 200, data);
    await settle();
    assert.equal(p.document.getElementById('account-history-from').value, '2026-09-23');
    assert.equal(p.document.querySelector('#account-history-table tr[data-index="0"]').style.display, 'none');
});

test('a pending settings refresh cannot replace a newly selected section', async () => {
    const p = loadPage(templateBody('settings'), SHARED.concat(['settings.js']));
    p.document.dispatchEvent(new p.window.Event('DOMContentLoaded'));
    p.respond('/api/v1/settings', 200, { sections: [
        { id: 'alerts', title: 'Alerts', group: 'Core' }, { id: 'logging', title: 'Logging', group: 'Core' }
    ], groups: ['Core'] });
    await settle();
    p.respond('/api/v1/settings/alerts', 200, settingsSection);
    await settle();
    p.window.CSM.refresh.manual();
    await settle();
    p.document.querySelector('[data-section="logging"]').click();
    await settle();
    p.respond('/api/v1/settings/logging', 200, { etag: 'e2', section: { id: 'logging', title: 'Logging', fields: [] }, values: {} });
    await settle();
    p.respond('/api/v1/settings/alerts', 200, settingsSection);
    await settle();
    assert.equal(p.document.querySelector('.settings-panel-title').textContent.trim(), 'Logging');
});
