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
    page.window.CSM.refresh.manual();
    await settle();
    assert.equal(reloads, 0, name + ': Refresh reloaded the whole page');
    const after = page.requests.filter(r => r.url.includes(endpoint)).length;
    assert.ok(after > before, name + ': Refresh did not load ' + endpoint + ' again');
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
