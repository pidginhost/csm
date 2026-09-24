// Run with: node --test ui/timezone_test.js
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, RUNTIME } = require('./pagekit.js');

function serverTimePage(zone, offsetMinutes) {
    const page = loadPage('', RUNTIME.concat(['prefs.js']));
    const html = page.document.documentElement;
    html.setAttribute('data-csm-server-tz', zone);
    html.setAttribute('data-csm-server-offset', String(offsetMinutes));
    page.window.CSM.prefs.get().timezone = 'server';
    return page;
}

const instant = new Date('2026-09-23T00:00:00Z');

test('server time uses the server zone name', () => {
    const page = serverTimePage('Asia/Tokyo', 540);
    assert.equal(page.window.CSM.prefs.formatDateTime(instant), '2026-09-23 09:00:00');
});

test('server time falls back to the server UTC offset when the zone has no name', () => {
    const page = serverTimePage('', 180);
    assert.equal(page.window.CSM.prefs.formatDateTime(instant), '2026-09-23 03:00:00');
    assert.match(page.window.CSM.fmtDate(instant.toISOString(), { tz: true }), /UTC\+03:00$/);
});

test('a negative offset formats correctly', () => {
    const page = serverTimePage('', -300);
    assert.equal(page.window.CSM.prefs.formatDateTime(instant), '2026-09-22 19:00:00');
});
