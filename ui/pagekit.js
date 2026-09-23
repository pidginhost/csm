'use strict';
// Runs the real Web UI scripts over fakedom for behavioural tests.
//
//   const page = loadPage('<table id="t">...</table>', RUNTIME.concat(['table.js']));
//   page.window.CSM, page.document, page.requests, page.respond(...)
//
// The shared scripts are loaded exactly as the layout loads them. fetch is a
// recorder: each request waits until the test answers it with respond() or
// fail(), so tests control ordering and failures.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createWindow } = require('./fakedom.js');

const JS_DIR = path.join(__dirname, 'static', 'js');
const TEMPLATE_DIR = path.join(__dirname, 'templates');

// The runtime every other script builds on, in the order layout.html loads it.
const RUNTIME = ['csm-core.js', 'csm-format.js', 'csm-page.js', 'csm-live.js'];

// The shared scripts layout.html loads before every page script, minus the
// vendored Tabler bundle (see bootstrapStub) and the header-only helpers.
const SHARED = RUNTIME.concat(['toast.js', 'csm-ui.js', 'prefs.js', 'table.js']);

// templateBody returns a page template's "content" block with the Go
// template directives removed, so a test runs the page script against the
// markup it ships with. Conditional blocks keep both branches.
function templateBody(name) {
    const text = fs.readFileSync(path.join(TEMPLATE_DIR, name + '.html'), 'utf8');
    const start = text.indexOf('{{define "content"}}');
    if (start < 0) throw new Error('pagekit: ' + name + '.html has no content block');
    const re = /\{\{-?\s*(\w+)?[^}]*\}\}/g;
    re.lastIndex = start + '{{define "content"}}'.length;
    let depth = 1, m, end = -1;
    while ((m = re.exec(text))) {
        const word = m[1] || '';
        if (['if', 'range', 'with', 'block', 'define'].includes(word)) depth++;
        else if (word === 'end' && --depth === 0) { end = m.index; break; }
    }
    if (end < 0) throw new Error('pagekit: unterminated content block in ' + name + '.html');
    return text.slice(start + '{{define "content"}}'.length, end).replace(/\{\{[^}]*\}\}/g, '');
}

function bootstrapStub() {
    const instances = new Map();
    function component(kind) {
        const event = (el, name) => el.dispatchEvent(new el.ownerDocument.defaultView.Event(name + '.bs.' + kind));
        return {
            getOrCreateInstance(el) {
                if (!instances.has(el)) {
                    instances.set(el, {
                        shown: false,
                        show() { if (this.shown) return; event(el, 'show'); this.shown = true; el.classList.add('show'); el.removeAttribute('aria-hidden'); event(el, 'shown'); },
                        hide() { if (!this.shown) return; event(el, 'hide'); this.shown = false; el.classList.remove('show'); el.setAttribute('aria-hidden', 'true'); event(el, 'hidden'); },
                        toggle() { this.shown ? this.hide() : this.show(); },
                        dispose() { instances.delete(el); }
                    });
                }
                return instances.get(el);
            },
            getInstance(el) { return instances.get(el) || null; }
        };
    }
    return { Modal: component('modal'), Tab: component('tab'), Offcanvas: component('offcanvas'), Dropdown: component('dropdown'), Tooltip: component('tooltip'), Collapse: component('collapse') };
}

function source(name) {
    return fs.readFileSync(path.join(JS_DIR, name), 'utf8');
}

function jsonResponse(status, body) {
    const text = typeof body === 'string' ? body : JSON.stringify(body);
    return {
        ok: status >= 200 && status < 300,
        status,
        headers: { get(k) { return k.toLowerCase() === 'content-type' ? 'application/json' : null; } },
        json() { return Promise.resolve().then(() => JSON.parse(text)); },
        text() { return Promise.resolve(text); }
    };
}

function loadPage(bodyHTML, scripts, options = {}) {
    const shell = '<meta name="csrf-token" content="test-csrf">' +
        '<script id="csm-config" type="application/json">' + JSON.stringify(options.config || {}) + '</script>' +
        '<div id="csm-connection-lost" class="d-none"></div>' +
        '<div id="csm-toast-container"></div>' + bodyHTML;
    const window = createWindow(shell, { url: options.url });
    // Page timers (relative-time refresh, pollers, debounces) must not keep
    // the test process alive after the tests finish. A test that waits for
    // one uses its own timer, which keeps the loop running meanwhile.
    window.setInterval = (fn, ms, ...args) => {
        const t = setInterval(fn, ms, ...args);
        if (t && t.unref) t.unref();
        return t;
    };
    window.setTimeout = (fn, ms, ...args) => {
        const t = setTimeout(fn, ms, ...args);
        if (t && t.unref) t.unref();
        return t;
    };
    const requests = [];
    window.fetch = (url, opts = {}) => new Promise((resolve, reject) => {
        const body = opts.body && typeof opts.body === 'string' ? safeJSON(opts.body) : opts.body;
        requests.push({ url: String(url), method: (opts.method || 'GET').toUpperCase(), headers: opts.headers || {}, body, resolve, reject });
    });
    window.AbortController = AbortController;
    window.EventSource = undefined;
    window.bootstrap = bootstrapStub();
    Object.entries(options.storage || {}).forEach(([k, v]) => window.localStorage.setItem(k, v));
    Object.assign(window, options.globals || {});
    const context = vm.createContext(window);
    for (const name of scripts) {
        vm.runInContext(source(name), context, { filename: name });
    }
    const page = {
        window,
        document: window.document,
        requests,
        // Answer the oldest pending request whose URL contains match.
        respond(match, status, body) {
            const i = requests.findIndex(r => !r.settled && r.url.includes(match));
            if (i < 0) throw new Error('pagekit: no pending request for ' + match + '; have ' + requests.map(r => r.url).join(', '));
            requests[i].settled = true;
            requests[i].resolve(jsonResponse(status, body));
            return requests[i];
        },
        fail(match, error) {
            const i = requests.findIndex(r => !r.settled && r.url.includes(match));
            if (i < 0) throw new Error('pagekit: no pending request for ' + match);
            requests[i].settled = true;
            requests[i].reject(error || new TypeError('Failed to fetch'));
            return requests[i];
        },
        pending(match) { return requests.filter(r => !r.settled && (!match || r.url.includes(match))); },
        run(code) { return vm.runInContext(code, context); },
        // load runs one more script, for tests that prepare the page first.
        load(name) { vm.runInContext(source(name), context, { filename: name }); }
    };
    return page;
}

function safeJSON(s) {
    try { return JSON.parse(s); } catch (e) { return s; }
}

// settle lets promise chains and zero-delay timers run.
function settle(rounds = 3) {
    let p = Promise.resolve();
    for (let i = 0; i < rounds; i++) p = p.then(() => new Promise(r => setImmediate(r)));
    return p;
}

// items builds a list response the way the API sends one: the list under
// "items", with its count and any other keys the route adds.
function items(list, extra) {
    return Object.assign({ items: list, total: list.length }, extra || {});
}

module.exports = { loadPage, settle, jsonResponse, templateBody, items, SHARED, RUNTIME };
