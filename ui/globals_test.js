// Run with: node --test ui/globals_test.js
// Every script shares one page, so a helper one script leaves on window can
// collide with another script's (firewall and threat both defined
// whitelistIP with different arguments). Scripts keep their helpers private:
// the shared runtime adds only CSM and CSM_CONFIG, and page scripts add
// nothing.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED } = require('./pagekit.js');

function autoObject() {
    return new Proxy({}, { get(t, k) { if (typeof k === 'symbol') return t[k]; if (!(k in t)) t[k] = autoObject(); return t[k]; } });
}
const chart = function () { return { destroy() {}, update() {}, data: { datasets: [] }, options: {} }; };
chart.defaults = autoObject();
chart.instances = {};

// The shared scripts the layout loads after the runtime.
const LAYOUT = ['shortcuts.js', 'palette.js', 'views.js', 'undo.js', 'layout.js'];

function added(before, page) {
    return Object.keys(page.window).filter(k => !before.has(k)).sort();
}

test('the head theme script adds nothing to window', () => {
    const before = new Set(Object.keys(loadPage('', []).window));
    assert.deepEqual(added(before, loadPage('', ['theme-init.js'])), []);
});

test('the shared scripts add only CSM and CSM_CONFIG to window', () => {
    const before = new Set(Object.keys(loadPage('', []).window));
    const page = loadPage('', ['theme-init.js'].concat(SHARED, LAYOUT));
    assert.deepEqual(added(before, page), ['CSM', 'CSM_CONFIG']);
});

// Page scripts and the template they run on.
const PAGES = {
    'account.js': 'account', 'audit.js': 'audit', 'cleanup-history.js': 'cleanup-history',
    'dashboard.js': 'dashboard', 'email.js': 'email', 'findings.js': 'findings', 'history.js': 'findings',
    'firewall.js': 'firewall', 'hardening.js': 'hardening', 'incident.js': 'incident',
    'modsec-rules.js': 'modsec-rules', 'modsec.js': 'modsec', 'performance.js': 'performance',
    'quarantine.js': 'quarantine', 'rules.js': 'rules', 'settings.js': 'settings', 'threat.js': 'threat',
    'verified-bots.js': 'verified-bots'
};

test('every page script is listed here', () => {
    const shared = new Set(['theme-init.js', 'login.js', 'chart.min.js', 'tabler.min.js'].concat(SHARED, LAYOUT));
    const scripts = fs.readdirSync(path.join(__dirname, 'static', 'js')).filter(f => f.endsWith('.js') && !shared.has(f));
    assert.deepEqual(scripts.sort(), Object.keys(PAGES).sort());
});

for (const [script, template] of Object.entries(PAGES)) {
    test(script + ' adds nothing to window', () => {
        const opts = { url: 'https://csm.example.test/' + template + (template === 'account' ? '?name=alice' : ''), globals: { Chart: chart } };
        const base = loadPage(templateBody(template), ['theme-init.js'].concat(SHARED, LAYOUT), opts);
        const before = new Set(Object.keys(base.window));
        base.load(script);
        assert.deepEqual(added(before, base), []);
    });
}
