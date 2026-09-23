'use strict';
// Runs the real Web UI scripts over fakedom for behavioural tests.
//
//   const page = loadPage('<table id="t">...</table>', ['csrf.js', 'table.js']);
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
    // Page-lifetime intervals (relative-time refresh, pollers) must not keep
    // the test process alive after the tests finish.
    window.setInterval = (fn, ms, ...args) => {
        const t = setInterval(fn, ms, ...args);
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
        run(code) { return vm.runInContext(code, context); }
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

module.exports = { loadPage, settle, jsonResponse };
