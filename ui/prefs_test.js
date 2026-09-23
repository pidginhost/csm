// Run with: node --test ui/prefs_test.js
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, settle } = require('./pagekit.js');

const CACHE = 'csm-prefs';

// Pages render as soon as their data arrives, which can be before the
// server copy of the preferences does. The last known copy is applied
// before any page script runs, so dates are formatted in the operator's
// zone from the first render.
test('the last known preferences apply before the server answers', () => {
    const page = loadPage('', ['csrf.js', 'prefs.js'], {
        storage: { [CACHE]: JSON.stringify({ timezone: 'UTC', density: 'compact' }) }
    });
    assert.equal(page.pending('/api/v1/prefs/user').length, 1, 'server copy still loading');
    assert.equal(page.window.CSM.prefs.get().timezone, 'UTC');
    assert.equal(page.document.documentElement.getAttribute('data-csm-density'), 'compact');
});

test('a server copy that changes the time zone reloads the page once', async () => {
    const page = loadPage('', ['csrf.js', 'prefs.js'], {
        storage: { [CACHE]: JSON.stringify({ timezone: 'local' }) }
    });
    page.respond('/api/v1/prefs/user', 200, { timezone: 'UTC' });
    await settle();
    assert.equal(page.window.location.reloads, 1);
    assert.equal(JSON.parse(page.window.localStorage.getItem(CACHE)).timezone, 'UTC');
});

test('a server copy that matches what rendered does not reload', async () => {
    const page = loadPage('', ['csrf.js', 'prefs.js'], {
        storage: { [CACHE]: JSON.stringify({ timezone: 'UTC' }) }
    });
    page.respond('/api/v1/prefs/user', 200, { timezone: 'UTC', density: 'compact' });
    await settle();
    assert.equal(page.window.location.reloads, 0);
    assert.equal(page.document.documentElement.getAttribute('data-csm-density'), 'compact', 'non-date prefs apply live');
});

test('when the browser cannot store preferences the page never reload-loops', async () => {
    const page = loadPage('', ['csrf.js', 'prefs.js']);
    page.window.localStorage.setItem = () => { throw new Error('QuotaExceededError'); };
    page.respond('/api/v1/prefs/user', 200, { timezone: 'UTC' });
    await settle();
    assert.equal(page.window.location.reloads, 0);
    assert.equal(page.window.CSM.prefs.get().timezone, 'UTC', 'still applied for new renders');
});

test('saving a new time zone re-renders the page; other changes apply live', async () => {
    const page = loadPage('', ['csrf.js', 'prefs.js']);
    page.respond('/api/v1/prefs/user', 200, { timezone: 'local' });
    await settle();

    const density = page.window.CSM.prefs.save({ density: 'compact' });
    page.respond('/api/v1/prefs/user', 200, { timezone: 'local', density: 'compact' });
    await density;
    assert.equal(page.window.location.reloads, 0);

    const zone = page.window.CSM.prefs.save({ timezone: 'Europe/Bucharest' });
    page.respond('/api/v1/prefs/user', 200, { timezone: 'Europe/Bucharest' });
    await zone;
    assert.equal(page.window.location.reloads, 1);
    assert.equal(page.window.CSM.prefs.user, page.window.CSM.prefs.get(), 'CSM.prefs.user tracks saves');
    assert.equal(JSON.parse(page.window.localStorage.getItem(CACHE)).timezone, 'Europe/Bucharest');
});

test('a failed server read keeps the last known preferences', async () => {
    const page = loadPage('', ['csrf.js', 'prefs.js'], {
        storage: { [CACHE]: JSON.stringify({ timezone: 'UTC' }) }
    });
    page.respond('/api/v1/prefs/user', 500, { error: 'Store error' });
    await settle();
    assert.equal(page.window.CSM.prefs.get().timezone, 'UTC');
    assert.equal(page.window.location.reloads, 0);
});

test('a stale cached auto-refresh off follows the server back on', async () => {
    const page = loadPage('', ['csrf.js', 'prefs.js'], {
        storage: { [CACHE]: JSON.stringify({ auto_refresh: 'off' }) }
    });
    assert.equal(page.window.CSM.refresh.enabled, false);
    page.respond('/api/v1/prefs/user', 200, { auto_refresh: 'on' });
    await settle();
    assert.equal(page.window.CSM.refresh.enabled, true);
});

test('a corrupt cache is ignored', () => {
    const page = loadPage('', ['csrf.js', 'prefs.js'], { storage: { [CACHE]: '{not json' } });
    assert.equal(page.window.CSM.prefs.get().timezone, 'local');
});

test('saving a zone only reloads if the cache can be read back', async () => {
    for (const failWrite of [true, false]) {
        const page = loadPage('', ['csrf.js', 'prefs.js']);
        page.respond('/api/v1/prefs/user', 200, { timezone: 'local' });
        await settle();
        page.window.localStorage.setItem = () => {
            if (failWrite) throw new Error('QuotaExceededError');
        };
        const saved = page.window.CSM.prefs.save({ timezone: 'UTC' });
        page.respond('/api/v1/prefs/user', 200, { timezone: 'UTC' });
        await saved;
        assert.equal(page.window.location.reloads, 0);
        assert.equal(page.window.CSM.prefs.user.timezone, 'UTC');
        assert.equal(page.window.CSM.prefs.user, page.window.CSM.prefs.get());
    }
});
