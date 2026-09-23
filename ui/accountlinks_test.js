// Run with: node --test ui/accountlinks_test.js
// The Account page was reachable only from a dashboard card. Findings,
// finding groups, incidents and the command palette now link to it.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, items, SHARED, settle } = require('./pagekit.js');

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
            finding('perf_load', 'load high', '')
        ],
        check_types: ['webshell', 'perf_load'],
        accounts: ['alice'],
        total: 2
    });
    await settle();
    return page;
}

test('the finding detail links the account to its page', async () => {
    const page = await findingsPage();
    page.document.querySelector('.finding-row[data-account="alice"]').querySelectorAll('td')[2].click();
    await settle();
    page.respond('/api/v1/finding-detail', 200, { actions: [] });
    await settle();
    const panel = page.window.CSM.detailPanel.element();
    assert.ok(panel.querySelector('a[href="/account?name=alice"]'), 'no account link in the finding detail');
});

test('an account group header links to the account and still collapses', async () => {
    const page = await findingsPage();
    const sel = page.document.getElementById('group-by');
    sel.value = 'account';
    sel.dispatchEvent(new page.window.Event('change'));
    await settle();
    const header = page.document.querySelector('.csm-group-header[data-csm-group-key="alice"]');
    const link = header.querySelector('a[href="/account?name=alice"]');
    assert.ok(link, 'no account link in the group header');
    link.click();
    assert.equal(header.classList.contains('collapsed'), false, 'following the link collapsed the group');
    header.querySelector('td').click();
    assert.equal(header.classList.contains('collapsed'), true);
    const unknown = page.document.querySelector('.csm-group-header[data-csm-group-key="(unknown)"]');
    assert.equal(unknown.querySelector('a'), null, 'a placeholder group links to an account');
});

test('an incident with an account links to the account page', async () => {
    const page = loadPage(templateBody('incident'), SHARED.concat(['incident.js']),
        { url: 'https://csm.example.test/incident#inc_1' });
    await settle();
    const incident = { id: 'inc_1', status: 'open', severity: 'HIGH', kind: 'webshell', account: 'alice', timeline: [], findings: [] };
    while (page.pending('/api/v1/incidents?').length) {
        page.respond('/api/v1/incidents?', 200, { items: [incident], total: 1, offset: 0 });
        await settle();
    }
    page.respond('/api/v1/incidents/inc_1', 200, incident);
    await settle();
    const panel = page.window.CSM.detailPanel.element();
    assert.ok(panel.querySelector('a[href="/account?name=alice"]'), 'no account link in the incident detail');
});

test('Threat Intel links the accounts an address targeted', async () => {
    const page = loadPage(templateBody('threat'), SHARED.concat(['threat.js']), {
        url: 'https://csm.example.test/threat?ip=203.0.113.9',
        globals: { Chart: function () { return { destroy() {}, update() {} }; } }
    });
    await settle();
    page.respond('/api/v1/threat/ip?ip=203.0.113.9', 200, {
        ip: '203.0.113.9', verdict: 'malicious', unified_score: 90, local_score: 90, abuse_score: -1,
        attack_record: { event_count: 3, accounts: { alice: 2, 'x<y': 1 }, attack_counts: {} }
    });
    page.respond('/api/v1/threat/events?ip=203.0.113.9', 200, items([]));
    await settle();
    const result = page.document.getElementById('tr-lookup-result');
    assert.ok(result.querySelector('a[href="/account?name=alice"]'), 'no link for a targeted account');
    assert.ok(result.textContent.includes('x<y'), 'a value that is not an account name was dropped');
});

test('Threat Intel labels attack types from the server list', async () => {
    const page = loadPage(templateBody('threat'), SHARED.concat(['threat.js']), {
        url: 'https://csm.example.test/threat?ip=203.0.113.9',
        config: { attackTypes: { brute_force: 'Brute Force', auth_success: 'Authenticated Activity' } },
        globals: { Chart: function () { return { destroy() {}, update() {} }; } }
    });
    await settle();
    page.respond('/api/v1/threat/ip?ip=203.0.113.9', 200, {
        ip: '203.0.113.9', verdict: 'malicious', unified_score: 90, local_score: 90, abuse_score: -1,
        attack_record: { event_count: 3, attack_counts: { brute_force: 2, auth_success: 1 } }
    });
    page.respond('/api/v1/threat/events?ip=203.0.113.9', 200, items([]));
    await settle();
    const text = page.document.getElementById('tr-lookup-result').textContent;
    assert.match(text, /Brute Force: 2/);
    assert.match(text, /Authenticated Activity: 1/);
});

function palette(page) {
    page.window.CSM.palette.show();
    return page.document.getElementById('csm-palette');
}

function paletteLabels(page, query) {
    const input = page.document.querySelector('.csm-palette__input');
    input.value = query;
    input.dispatchEvent(new page.window.Event('input'));
    return Array.from(page.document.querySelectorAll('.csm-palette__row .csm-palette__rowlabel')).map(el => el.textContent);
}

function layoutPage() {
    const nav = '<nav id="csm-nav"><div data-csm-nav-group="overview"><ul>' +
        '<li data-csm-route="dashboard"><a class="nav-link" href="/dashboard"><span class="nav-link-icon"><i class="ti ti-dashboard"></i></span><span class="nav-link-title">Dashboard</span></a></li>' +
        '</ul></div></nav><a href="/sessions" class="btn">Sessions</a>';
    return loadPage(nav, SHARED.concat(['palette.js']));
}

test('the command palette offers Sessions', () => {
    const page = layoutPage();
    assert.ok(palette(page), 'palette did not open');
    assert.ok(paletteLabels(page, 'sess').includes('Sessions'));
});

test('the command palette opens an account typed by name', () => {
    const page = layoutPage();
    palette(page);
    const labels = paletteLabels(page, 'alice');
    assert.ok(labels.includes('Account: alice'), JSON.stringify(labels));
    assert.ok(!paletteLabels(page, 'not an account').some(l => l.indexOf('Account:') === 0));
});
