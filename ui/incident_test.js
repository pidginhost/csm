// Run with: node --test ui/incident_test.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

function incidentPage(overrides = {}) {
    const element = { value: 'all', addEventListener() {}, getAttribute() { return ''; }, setAttribute() {} };
    const context = vm.createContext({
        URLSearchParams,
        window: { location: { search: '', hash: '' }, addEventListener() {} },
        document: {
            getElementById() { return element; },
            querySelectorAll() { return []; },
            querySelector() { return null; }
        },
        CSM: {
            loading() {},
            get() { return new Promise(() => {}); },
            detailPanel: { open() {}, element() { return null; } },
            toast() {},
            fmtDate: String,
            timeAgo: String,
            initTimeAgo() {},
            esc: String,
            attr: String,
            ...overrides
        }
    });
    const source = fs.readFileSync(path.join(__dirname, 'static/js/incident.js'), 'utf8');
    // Expose the page's real closures without duplicating their implementation.
    vm.runInContext(source.replace(/\}\)\(\);\s*$/, 'globalThis.page = { incidentSourceIP, blockIncidentIP, renderIncidentDetail, setIncidentStatus }; })();'), context);
    return context.page;
}

test('incident block target must be unambiguous', () => {
    const page = incidentPage();
    assert.equal(page.incidentSourceIP({ timeline: [
        { remote_ip: '192.0.2.10' }, { remote_ip: '192.0.2.10' }, { remote_ip: '192.0.2.11' }
    ] }), '');
    assert.equal(page.incidentSourceIP({ timeline: [
        { remote_ip: '192.0.2.10' }, { kind: 'truncated' }
    ] }), '');
    assert.equal(page.incidentSourceIP({ timeline: [{ remote_ip: '192.0.2.10' }, { remote_ip: '192.0.2.10' }] }), '192.0.2.10');
    assert.equal(page.incidentSourceIP({ correlation_key: { remote_ip: '192.0.2.10' }, timeline: [{ kind: 'truncated' }] }), '192.0.2.10');
});

test('incident detail only offers Block for one source', () => {
    let footer;
    const page = incidentPage({ detailPanel: {
        open(options) { footer = options.footerHTML; },
        element() { return { querySelectorAll() { return []; }, querySelector() { return null; } }; }
    } });
    const incident = { id: 'inc_test', status: 'open', timeline: [{ remote_ip: '192.0.2.10' }] };
    page.renderIncidentDetail(incident);
    assert.match(footer, /data-csm-block-ip="192\.0\.2\.10"/);
    incident.timeline.push({ remote_ip: '192.0.2.11' });
    page.renderIncidentDetail(incident);
    assert.doesNotMatch(footer, /csm-incident-block-btn/);
});

test('incident block waits for themed confirmation and sends permanent duration', async () => {
    let confirm, request;
    const page = incidentPage({
        confirm(message) { assert.match(message, /192\.0\.2\.10.*permanently/); return new Promise(resolve => { confirm = resolve; }); },
        post(url, body) { request = { url, body }; return Promise.resolve({ status: 'blocked' }); }
    });
    const button = { disabled: false };
    const done = page.blockIncidentIP('inc_test', '192.0.2.10', button);
    assert.equal(request, undefined);
    confirm();
    await done;
    assert.equal(request.url, '/api/v1/block-ip');
    assert.equal(request.body.ip, '192.0.2.10');
    assert.equal(request.body.duration, '0');
    assert.equal(request.body.incident_id, 'inc_test');
});

test('cancelled confirmation is handled without blocking', async () => {
    let called = false;
    const page = incidentPage({
        confirm() { return Promise.reject(new Error('cancelled')); },
        post() { called = true; }
    });
    const button = { disabled: false };
    await page.blockIncidentIP('inc_test', '192.0.2.10', button);
    assert.equal(called, false);
    assert.equal(button.disabled, false);
});

test('failed incident block allows retry', async () => {
    const page = incidentPage({
        confirm() { return Promise.resolve(); },
        post() { return Promise.reject(new Error('unavailable')); }
    });
    const button = { disabled: false };
    await page.blockIncidentIP('inc_test', '192.0.2.10', button);
    assert.equal(button.disabled, false);
});

test('a failed incident block says why and allows a retry', async () => {
    const toasts = [];
    const page = incidentPage({
        confirm() { return Promise.resolve(); },
        post() { return Promise.reject(new Error('firewall engine unavailable')); },
        toast(message, kind) { toasts.push({ message, kind }); }
    });
    const button = { disabled: false };
    await page.blockIncidentIP('inc_test', '192.0.2.10', button);
    assert.equal(button.disabled, false);
    assert.ok(toasts.some(t => t.kind === 'error' && /firewall engine unavailable/.test(t.message)), JSON.stringify(toasts));
});

test('a cancelled incident block shows nothing', async () => {
    const toasts = [];
    const page = incidentPage({
        confirm() { return Promise.reject(new Error('cancelled')); },
        post() { throw new Error('must not post'); },
        toast(message, kind) { toasts.push({ message, kind }); }
    });
    await page.blockIncidentIP('inc_test', '192.0.2.10', { disabled: false });
    assert.deepEqual(toasts, []);
});

test('a failed incident status change says why', async () => {
    const toasts = [];
    const page = incidentPage({
        post() { return Promise.reject(new Error('invalid status transition')); },
        toast(message, kind) { toasts.push({ message, kind }); }
    });
    await page.setIncidentStatus('inc_test', 'resolved');
    assert.ok(toasts.some(t => t.kind === 'error' && /invalid status transition/.test(t.message)), JSON.stringify(toasts));
    assert.ok(!toasts.some(t => t.kind === 'success'));
});
