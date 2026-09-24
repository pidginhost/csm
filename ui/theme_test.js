// Run with: node --test ui/theme_test.js
// The light theme is complete: blocked browser storage does not break the
// theme, and charts repaint their tooltips, not only their axes, when the
// theme changes.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, SHARED } = require('./pagekit.js');

const blockedStorage = {
    getItem() { throw new Error('SecurityError'); },
    setItem() { throw new Error('SecurityError'); },
    removeItem() { throw new Error('SecurityError'); }
};

test('the theme still applies and toggles when storage is blocked', () => {
    const page = loadPage('<button id="theme-toggle"><i class="ti"></i></button>',
        ['theme-init.js'].concat(SHARED, ['layout.js']), { globals: { localStorage: blockedStorage } });
    const root = page.document.documentElement;
    const before = root.getAttribute('data-bs-theme');
    assert.ok(before === 'light' || before === 'dark', 'no theme applied: ' + before);
    page.document.getElementById('theme-toggle').click();
    assert.notEqual(root.getAttribute('data-bs-theme'), before, 'the toggle did nothing');
});

function fakeChart() {
    return {
        options: { scales: { x: { grid: {}, ticks: {} } }, plugins: { tooltip: {} } },
        updated: 0,
        update() { this.updated++; }
    };
}

test('a theme change repaints chart tooltips as well as axes', () => {
    const chart = fakeChart();
    const Chart = { defaults: {}, instances: { a: chart } };
    const page = loadPage('', SHARED, { globals: { Chart } });
    const root = page.document.documentElement;
    root.className = 'theme-light';
    page.window.CSM.applyChartTheme();
    const light = Object.assign({}, chart.options.plugins.tooltip);
    assert.equal(light.backgroundColor, '#ffffff');
    assert.equal(light.bodyColor, '#1a2234');
    assert.equal(chart.options.scales.x.ticks.color, '#64748b');
    root.className = 'theme-dark';
    page.window.CSM.applyChartTheme();
    assert.equal(chart.options.plugins.tooltip.backgroundColor, '#1e293b');
    assert.equal(chart.options.plugins.tooltip.bodyColor, '#c8d3e0');
    assert.equal(chart.options.scales.x.ticks.color, '#94a3b8');
    assert.equal(chart.updated, 2);
});

test('theme initialization works without storage or matchMedia', () => {
    const page = loadPage('', ['theme-init.js'],
        { globals: { localStorage: blockedStorage, matchMedia: undefined } });
    assert.equal(page.document.documentElement.getAttribute('data-bs-theme'), 'dark');
    assert.equal(page.document.documentElement.className, 'theme-dark');
});

test('an invalid stored theme falls back to the system preference', () => {
    const page = loadPage('', ['theme-init.js'], { storage: { 'csm-theme': 'invalid' },
        globals: { matchMedia: () => ({ matches: true }) } });
    assert.equal(page.document.documentElement.getAttribute('data-bs-theme'), 'light');
    assert.equal(page.document.documentElement.className, 'theme-light');
});
