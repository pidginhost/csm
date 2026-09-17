// Run with: node --test ui/threat_test.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

function stubElement(id) {
    return {
        id: id,
        value: '',
        textContent: '',
        innerHTML: '',
        checked: false,
        listeners: {},
        options: { length: 0 },
        classList: { add() {}, remove() {}, contains() { return false; } },
        addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); },
        getAttribute() { return ''; },
        setAttribute() {},
        removeEventListener() {},
        querySelector() { return null; },
        querySelectorAll() { return []; },
        appendChild() {},
        remove() {},
        dispatchEvent() {}
    };
}

function threatPage(overrides = {}) {
    const elements = {};
    function byId(id) {
        if (!elements[id]) elements[id] = stubElement(id);
        return elements[id];
    }
    const context = vm.createContext({
        console,
        URLSearchParams,
        Event: function Event() {},
        MutationObserver: function MutationObserver() { return { observe() {} }; },
        Chart: function Chart() {},
        window: { location: { search: '', hash: '' }, addEventListener() {} },
        location: { reload() {} },
        setImmediate,
        document: {
            documentElement: { classList: { contains() { return false; } } },
            getElementById: byId,
            querySelectorAll(selector) {
                if (selector === '.bulk-ip-cb:checked') {
                    return [{ getAttribute() { return '192.0.2.20'; } }];
                }
                return [];
            },
            querySelector() { return null; },
            createElement() { return stubElement('created'); }
        },
        CSM: {
            get() { return new Promise(() => {}); },
            post() { return Promise.resolve({}); },
            confirm() { return Promise.resolve(); },
            prompt() { return new Promise(() => {}); },
            toast() {},
            esc: String,
            attr: String,
            fmtDate: String,
            countryFlag: String,
            parseTimestamp: Date.parse,
            loadError() {},
            loading() {},
            applyProgressBars() {},
            exportTable() {},
            urlState: { bind() { return function () {}; }, get() { return ''; } },
            Table: function Table() { return { destroy() {}, applyFilters() {} }; },
            undo: { offer() {} },
            ...overrides
        }
    });
    const source = fs.readFileSync(path.join(__dirname, 'static/js/threat.js'), 'utf8');
    vm.runInContext(source, context);
    return { context, elements, byId };
}

test('lookup explains a permanent threat entry on an unblocked IP', () => {
    const { context } = threatPage();
    const permanent = context.blockStatusRows({ in_threat_db: true, threat_db_permanent: true });
    assert.match(permanent, /Not blocked/);
    assert.match(permanent, /permanent threat entry/);

    const timed = context.blockStatusRows({
        in_threat_db: true,
        threat_db_expires_at: '2026-09-18T10:00:00Z'
    });
    assert.match(timed, /Not blocked/);
    assert.doesNotMatch(timed, /permanent threat entry/);
    assert.match(timed, /2026-09-18T10:00:00Z/);

    const clean = context.blockStatusRows({ in_threat_db: false });
    assert.match(clean, /Not blocked/);
    assert.doesNotMatch(clean, /threat entry/);
});

test('permanent block asks for confirmation and calls the permanent endpoint', async () => {
    let confirmMessage, request;
    const { context } = threatPage({
        confirm(message) { confirmMessage = message; return Promise.resolve(); },
        post(url, body) { request = { url: url, body: body }; return Promise.resolve({ actions: [] }); }
    });
    await context.blockIP('192.0.2.10', true);
    assert.match(confirmMessage, /permanently/i);
    assert.equal(request.url, '/api/v1/threat/block-ip-permanent');
    assert.equal(request.body.ip, '192.0.2.10');
});

test('24h block still calls the 24h endpoint', async () => {
    let request;
    const { context } = threatPage({
        post(url, body) { request = { url: url, body: body }; return Promise.resolve({ actions: [] }); }
    });
    await context.blockIP('192.0.2.11', false);
    assert.equal(request.url, '/api/v1/threat/block-ip');
});

test('cancelled permanent block sends nothing', async () => {
    let called = false;
    const { context } = threatPage({
        confirm() { return Promise.reject(new Error('cancelled')); },
        post() { called = true; return Promise.resolve({}); }
    });
    await context.blockIP('192.0.2.12', true);
    assert.equal(called, false);
});

test('bulk permanent block posts the permanent action', async () => {
    let request;
    const { byId } = threatPage({
        post(url, body) { request = { url: url, body: body }; return Promise.resolve({ count: 1 }); }
    });
    const button = byId('bulk-block-perm-btn');
    const handlers = button.listeners.click || [];
    assert.equal(handlers.length, 1, 'bulk permanent block button is not wired');
    handlers[0].call(button);
    await new Promise(function (resolve) { setImmediate(resolve); });
    assert.equal(request.url, '/api/v1/threat/bulk-action');
    assert.equal(request.body.action, 'block_permanent');
});

test('bulk timed block shows refused permanent blocks', async () => {
    const toasts = [];
    const { context } = threatPage({
        post() { return Promise.resolve({ count: 0, warnings: ['192.0.2.20: permanently blocked; unblock first'] }); },
        toast(message, kind) { toasts.push({ message, kind }); }
    });
    await context.bulkBlock(false);
    assert.ok(toasts.some(t => t.kind === 'warning' && /permanently blocked/.test(t.message)));
    assert.ok(!toasts.some(t => t.kind === 'success'), 'all-refused action must not show success');
});
