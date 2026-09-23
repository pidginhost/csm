// Run with: node --test ui/suppress_test.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const tick = () => new Promise(resolve => setImmediate(resolve));

function suppressSection() {
    const source = fs.readFileSync(path.join(__dirname, 'static/js/findings.js'), 'utf8');
    const start = source.indexOf('// --- Suppress dialog ---');
    const end = source.indexOf('// --- Bulk actions ---');
    assert.ok(start >= 0 && end > start, 'findings.js must keep the suppress dialog in its own section');
    return source.slice(start, end);
}

function dialog(overrides = {}) {
    const elements = {};
    function el(id) {
        if (!elements[id]) elements[id] = {
            id, value: '', checked: false, disabled: false, textContent: '', dataset: {}, listeners: {},
            addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
        };
        return elements[id];
    }
    const requests = [], toasts = [];
    let shown = 0, hidden = 0, refreshed = 0;
    const context = vm.createContext({
        document: { getElementById: el },
        bootstrap: { Modal: { getOrCreateInstance() { return { show() { shown++; }, hide() { hidden++; } }; } } },
        CSM: {
            post(url, body) { requests.push({ url, body }); return Promise.resolve({ status: 'created', id: 'x' }); },
            toast(message, kind) { toasts.push({ message, kind }); },
            ...overrides
        },
        refreshFindings() { refreshed++; }
    });
    const ui = fs.readFileSync(path.join(__dirname, 'static/js/csm-ui.js'), 'utf8');
    vm.runInContext(ui.slice(ui.indexOf('// Suppression scope.'), ui.indexOf('// End suppression scope.')), context);
    vm.runInContext(suppressSection(), context);
    return { context, el, requests, toasts, counts: () => ({ shown, hidden, refreshed }) };
}

function submit(el) {
    const form = el('suppress-finding-form');
    (form.listeners.submit || []).forEach(fn => fn({ preventDefault() {} }));
}

test('a blank pattern never turns into a check-wide rule', () => {
    const { context } = dialog();
    const body = context.CSM.suppressionRequest('webshell', 'path', '   ', '');
    assert.ok(body.error, 'blank pattern with path scope must be refused');
    assert.equal(body.all_paths, undefined);
    assert.equal(body.path_pattern, undefined);
});

test('every-finding scope is sent as an explicit opt-in', () => {
    const { context } = dialog();
    const body = context.CSM.suppressionRequest('webshell', 'all', '/home/a/x.php', 'lab host');
    assert.equal(body.all_paths, true);
    assert.equal(body.path_pattern, undefined, 'the pattern must not travel with the check-wide opt-in');
    assert.equal(body.reason, 'lab host');
});

test('the summary spells out the scope before saving', () => {
    const { context } = dialog();
    assert.match(context.CSM.suppressionSummary('webshell', 'all', ''), /every webshell finding/i);
    assert.match(context.CSM.suppressionSummary('webshell', 'path', '/home/a/*'), /\/home\/a\/\*/);
    assert.doesNotMatch(context.CSM.suppressionSummary('webshell', 'path', '/home/a/*'), /every/i);
});

test('opening the dialog pre-fills the finding path and path scope', () => {
    const { context, el, counts } = dialog();
    context.suppressFinding('webshell', 'YARA rule match: /home/a/public_html/x.php', '');
    assert.equal(counts().shown, 1);
    assert.equal(el('suppress-finding-pattern').value, '/home/a/public_html/x.php');
    assert.equal(el('suppress-finding-scope-path').checked, true);
    assert.equal(el('suppress-finding-scope-all').checked, false);
    assert.equal(el('suppress-finding-check').textContent, 'webshell');
});

// The pattern is a glob. A file named with [, ], * or ? pre-filled as-is
// matched other names or none, so the rule never hid the finding it was made
// from. The pre-filled pattern escapes them, as the server's matcher expects.
test('the pre-filled pattern matches the file literally', () => {
    const { context, el } = dialog();
    context.suppressFinding('webshell', 'found', '/home/a/public_html/[slug]/p?g*.php');
    assert.equal(el('suppress-finding-pattern').value, '/home/a/public_html/\\[slug\\]/p\\?g\\*.php');
    context.suppressFinding('webshell', 'YARA rule match: /home/a/[x].php', '');
    assert.equal(el('suppress-finding-pattern').value, '/home/a/\\[x\\].php');
});

test('submitting with no path and path scope sends nothing', async () => {
    const { context, el, requests } = dialog();
    context.suppressFinding('webshell', 'no path in this message', '');
    submit(el);
    await tick();
    assert.equal(requests.length, 0);
});

test('submitting the check-wide choice posts all_paths and refreshes', async () => {
    const { context, el, requests, counts } = dialog();
    context.suppressFinding('webshell', 'msg', '/home/a/x.php');
    el('suppress-finding-scope-path').checked = false;
    el('suppress-finding-scope-all').checked = true;
    submit(el);
    await tick();
    assert.equal(requests.length, 1);
    assert.equal(requests[0].url, '/api/v1/suppressions');
    assert.equal(requests[0].body.all_paths, true);
    assert.equal(counts().hidden, 1);
    assert.equal(counts().refreshed, 1);
});

test('a refused request keeps the dialog open and shows the reason', async () => {
    const { context, el, toasts, counts } = dialog({
        post() { return Promise.reject(new Error('path_pattern is not a valid glob')); }
    });
    context.suppressFinding('webshell', 'msg', '/home/a/[x');
    submit(el);
    await tick();
    assert.equal(counts().hidden, 0);
    assert.ok(toasts.some(t => t.kind === 'error' && /valid glob/.test(t.message)));
});

function rulesForm(fields) {
    const elements = {};
    function el(id) {
        if (!elements[id]) elements[id] = {
            id, value: '', checked: false, listeners: {},
            addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); }
        };
        return elements[id];
    }
    const requests = [], toasts = [];
    const context = vm.createContext({
        document: { getElementById: el },
        CSM: {
            post(url, body) { requests.push({ url, body }); return Promise.resolve({ status: 'created', id: 'x' }); },
            toast(message, kind) { toasts.push({ message, kind }); }
        },
        loadSuppressions() {}
    });
    const ui = fs.readFileSync(path.join(__dirname, 'static/js/csm-ui.js'), 'utf8');
    vm.runInContext(ui.slice(ui.indexOf('// Suppression scope.'), ui.indexOf('// End suppression scope.')), context);
    const rules = fs.readFileSync(path.join(__dirname, 'static/js/rules.js'), 'utf8');
    vm.runInContext(rules.slice(rules.indexOf('// Create suppression rule from form'),
        rules.indexOf('// Populate check-type datalist')), context);
    Object.keys(fields).forEach(id => {
        if (typeof fields[id] === 'boolean') el(id).checked = fields[id];
        else el(id).value = fields[id];
    });
    (el('suppression-form').listeners.submit || []).forEach(fn => fn({ preventDefault() {} }));
    return { requests, toasts };
}

test('Rules form refuses a blank path unless every path is chosen', async () => {
    const { requests, toasts } = rulesForm({ 'suppress-check': 'webshell', 'suppress-path': '' });
    await tick();
    assert.equal(requests.length, 0);
    assert.ok(toasts.some(t => t.kind === 'error'));
});

test('Rules form sends the check-wide choice explicitly', async () => {
    const { requests } = rulesForm({ 'suppress-check': 'webshell', 'suppress-path': '', 'suppress-all-paths': true });
    await tick();
    assert.equal(requests.length, 1);
    assert.equal(requests[0].body.all_paths, true);
    assert.equal(requests[0].body.path_pattern, undefined);
});

test('Rules form sends a typed pattern', async () => {
    const { requests } = rulesForm({ 'suppress-check': 'webshell', 'suppress-path': '/home/a/*' });
    await tick();
    assert.equal(requests.length, 1);
    assert.equal(requests[0].body.path_pattern, '/home/a/*');
    assert.equal(requests[0].body.all_paths, undefined);
});
