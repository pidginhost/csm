// Run with: node --test ui/aria_test.js
// Widgets expose their role and state: the Firewall subviews are tabs, the
// History expand buttons say whether details are open, and the connection
// banner can be dismissed until the next outage.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

function key(page, target, k) {
    const ev = new page.window.Event('keydown', { bubbles: true, cancelable: true });
    ev.key = k;
    target.dispatchEvent(ev);
    return ev;
}

test('the Firewall subviews are tabs with panels', async () => {
    const page = loadPage(templateBody('firewall'), SHARED.concat(['firewall.js']));
    await settle();
    const tabs = Array.from(page.document.querySelectorAll('#fw-subview-nav [data-fw-nav]'));
    assert.ok(tabs.length >= 6);
    tabs.forEach(tab => {
        assert.equal(tab.getAttribute('role'), 'tab');
        const panel = page.document.getElementById(tab.getAttribute('aria-controls'));
        assert.ok(panel, 'tab controls no panel: ' + tab.getAttribute('data-fw-nav'));
        assert.equal(panel.getAttribute('role'), 'tabpanel');
        assert.equal(panel.getAttribute('aria-labelledby'), tab.id);
        assert.equal(tab.getAttribute('aria-pressed'), null, 'a tab is not a toggle button');
    });
    assert.equal(tabs[0].getAttribute('aria-selected'), 'true');
    assert.equal(tabs[0].getAttribute('tabindex'), '0');
    assert.equal(tabs[1].getAttribute('tabindex'), '-1');
    tabs[0].focus();
    key(page, tabs[0], 'ArrowRight');
    assert.equal(page.document.activeElement, tabs[1]);
    assert.equal(tabs[1].getAttribute('aria-selected'), 'true');
    assert.equal(tabs[0].getAttribute('aria-selected'), 'false');
    key(page, tabs[1], 'End');
    assert.equal(page.document.activeElement, tabs[tabs.length - 1]);
});

test('History names its details column and reports expanded rows', async () => {
    const page = loadPage(templateBody('findings'), SHARED.concat(['findings.js', 'history.js']),
        { url: 'https://csm.example.test/findings?tab=history' });
    page.document.querySelector('[href="#tab-history"]').dispatchEvent(new page.window.Event('shown.bs.tab'));
    await settle();
    page.respond('/api/v1/history', 200, { findings: [
        { severity: 2, check: 'webshell', message: 'shell', details: 'more', timestamp: '2026-09-22T10:00:00Z' }
    ], total: 1 });
    await settle();
    const ths = page.document.querySelectorAll('#history-table thead th');
    assert.ok(ths[ths.length - 1].textContent.trim(), 'last header is empty');
    const btn = page.document.querySelector('#history-table .expand-btn');
    assert.equal(btn.getAttribute('aria-expanded'), 'false');
    btn.click();
    assert.equal(btn.getAttribute('aria-expanded'), 'true');
});

test('the connection banner can be dismissed until the next outage', () => {
    const page = loadPage('', SHARED);
    // pagekit's shell carries the banner; give it the layout's close button.
    const banner = page.document.getElementById('csm-connection-lost');
    banner.innerHTML = '<button type="button" class="btn-close" data-csm-dismiss-connection aria-label="Dismiss"></button>';
    const conn = page.window.CSM.connection;
    conn.down(); conn.down(); conn.down();
    assert.equal(banner.classList.contains('d-none'), false);
    banner.querySelector('[data-csm-dismiss-connection]').click();
    assert.equal(banner.classList.contains('d-none'), true);
    conn.down();
    assert.equal(banner.classList.contains('d-none'), true, 'the same outage showed the banner again');
    conn.up();
    conn.down(); conn.down(); conn.down();
    assert.equal(banner.classList.contains('d-none'), false, 'a new outage stayed hidden');
});

for (const spec of [
    { page: 'account', url: '/account?name=alice', script: 'account.js', endpoint: '/api/v1/account' },
    { page: 'performance', script: 'performance.js', endpoint: '/api/v1/performance' },
    { page: 'email', script: 'email.js', endpoint: '/api/v1/email/groups?' },
    { page: 'email', script: 'email.js', endpoint: 'kind=auth_failure', tab: '#email-tab-auth', event: 'shown.bs.tab' },
    { page: 'incident', script: 'incident.js', endpoint: '/api/v1/incidents/groups?', tab: '#grouped-tab', event: 'click' },
    { page: 'modsec', script: 'modsec.js', endpoint: '/api/v1/modsec/blocks' }
]) {
    test(spec.page + ' announces a failed list request: ' + spec.endpoint, async () => {
        const page = loadPage('<div id="csm-toasts"></div>' + templateBody(spec.page),
            SHARED.concat([spec.script]), { url: 'https://csm.example.test' + (spec.url || '/' + spec.page) });
        if (spec.tab) page.document.querySelector(spec.tab).dispatchEvent(new page.window.Event(spec.event, { bubbles: true }));
        await settle();
        page.respond(spec.endpoint, 500, { error: 'Temporary failure' });
        await settle();
        const alert = page.document.querySelector('[role="alert"]');
        assert.ok(alert && /failed|could not|unable|failure/i.test(alert.textContent), 'load error is not announced');
    });
}

test('Firewall deep links and programmatic switches keep the selected tab in sync', () => {
    const page = loadPage(templateBody('firewall'), SHARED.concat(['firewall.js']),
        { url: 'https://csm.example.test/firewall?view=allow' });
    function selected(view) {
        const tabs = page.document.querySelectorAll('#fw-subview-nav [data-fw-nav]');
        for (const tab of tabs) {
            const active = tab.getAttribute('data-fw-nav') === view;
            assert.equal(tab.getAttribute('aria-selected'), String(active));
            assert.equal(tab.getAttribute('tabindex'), active ? '0' : '-1');
            assert.equal(page.document.getElementById(tab.getAttribute('aria-controls')).hidden, !active);
        }
    }
    selected('allow');
    page.window.switchFirewallView('blocks');
    selected('blocks');
});
