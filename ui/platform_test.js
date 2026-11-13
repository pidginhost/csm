// Run with: node --test ui/platform_test.js
// Pages show only what the host supports: the server sends the platform
// features in CSM_CONFIG.features and renders the templates with them.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle, ALL_FEATURES } = require('./pagekit.js');

test('CSM.feature reads the features the server sent', () => {
    const page = loadPage('', SHARED, { config: { features: { mail: true, cpanel: false } } });
    assert.equal(page.window.CSM.feature('mail'), true);
    assert.equal(page.window.CSM.feature('cpanel'), false);
    assert.equal(page.window.CSM.feature('nope'), false);
    assert.equal(loadPage('', SHARED, { config: { features: undefined } }).window.CSM.feature('mail'), false);
});

test('a template keeps the branch its features select', () => {
    const on = templateBody('firewall', ALL_FEATURES), off = templateBody('firewall', {});
    assert.match(on, /cPanel lockout cleanup/);
    assert.doesNotMatch(on, /allow rules and subnet bans\./);
    assert.match(off, /allow rules and subnet bans\./);
    assert.doesNotMatch(off, /cPanel|cPHulk/);
    assert.doesNotMatch(on + off, /\{\{/);
});

function autoObject() {
    return new Proxy({}, { get(t, k) { if (typeof k === 'symbol') return t[k]; if (!(k in t)) t[k] = autoObject(); return t[k]; } });
}
function chart() { return { destroy() {}, update() {} }; }
chart.defaults = autoObject();

test('the dashboard lists Email AV only where it can run', async () => {
    for (const [features, shown] of [[ALL_FEATURES, true], [{ mail: true }, false]]) {
        const page = loadPage(templateBody('dashboard', features), SHARED.concat(['dashboard.js']), { config: { features }, globals: { Chart: chart } });
        await settle();
        const flags = page.document.getElementById('components-feature-flags').textContent;
        assert.match(flags, /Firewall/);
        assert.equal(/Email AV/.test(flags), shown);
    }
});
