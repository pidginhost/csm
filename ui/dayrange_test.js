// Run with: node --test ui/dayrange_test.js
// A date picked in a filter is a day in the operator's time zone, not the
// browser's and not the server's.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

function zone(tz) {
    return { 'csm-prefs': JSON.stringify({ timezone: tz }) };
}
const CHATHAM = zone('Pacific/Chatham'); // UTC+12:45 in September
const DAY_START = '2026-09-22T11:15:00.000Z';
const NEXT_DAY_START = '2026-09-23T11:15:00.000Z';

function prefsPage(storage) {
    return loadPage('', ['csrf.js', 'prefs.js'], { storage });
}

test('a day starts and ends at midnight in the operator zone', () => {
    const prefs = prefsPage(CHATHAM).window.CSM.prefs;
    assert.equal(new Date(prefs.dayBoundary('2026-09-23', false)).toISOString(), DAY_START);
    assert.equal(new Date(prefs.dayBoundary('2026-09-23', true)).toISOString(), NEXT_DAY_START);
});

test('a day with a clock change keeps its length', () => {
    // Europe/Bucharest leaves summer time on 2026-10-25: that day has 25 hours.
    const prefs = prefsPage(zone('Europe/Bucharest')).window.CSM.prefs;
    assert.equal(new Date(prefs.dayBoundary('2026-10-25', false)).toISOString(), '2026-10-24T21:00:00.000Z');
    assert.equal(new Date(prefs.dayBoundary('2026-10-25', true)).toISOString(), '2026-10-25T22:00:00.000Z');
});

test('server time without a zone name uses the server offset', () => {
    const page = prefsPage(zone('server'));
    page.document.documentElement.setAttribute('data-csm-server-offset', '180');
    assert.equal(new Date(page.window.CSM.prefs.dayBoundary('2026-09-23', false)).toISOString(), '2026-09-22T21:00:00.000Z');
});

test('memoized boundaries follow zone changes within the same page', () => {
    const page = prefsPage(zone('Europe/Bucharest'));
    const prefs = page.window.CSM.prefs;
    const day = '2026-09-23';
    assert.equal(new Date(prefs.dayBoundary(day, false)).toISOString(), '2026-09-22T21:00:00.000Z');
    prefs.get().timezone = 'Pacific/Chatham';
    assert.equal(new Date(prefs.dayBoundary(day, false)).toISOString(), DAY_START);
    prefs.get().timezone = 'server';
    page.document.documentElement.setAttribute('data-csm-server-offset', '180');
    assert.equal(new Date(prefs.dayBoundary(day, false)).toISOString(), '2026-09-22T21:00:00.000Z');
    page.document.documentElement.setAttribute('data-csm-server-offset', '120');
    assert.equal(new Date(prefs.dayBoundary(day, false)).toISOString(), '2026-09-22T22:00:00.000Z');
});

test('browser time uses the browser zone', () => {
    const prefs = prefsPage(zone('local')).window.CSM.prefs;
    assert.equal(prefs.dayBoundary('2026-09-23', false), new Date(2026, 8, 23).getTime());
});

test('a malformed or impossible day is no boundary', () => {
    const prefs = prefsPage(CHATHAM).window.CSM.prefs;
    for (const v of ['', '2026-02-30', '23/09/2026', '2026-9-3']) {
        assert.equal(prefs.dayBoundary(v, false), null, v);
    }
});

test('midnight transitions include exactly the selected calendar day', () => {
    const cases = [
        ['America/Santiago', '2026-09-06', '2026-09-06T04:00:00.000Z', '2026-09-07T03:00:00.000Z'],
        ['America/Havana', '2026-11-01', '2026-11-01T04:00:00.000Z', '2026-11-02T05:00:00.000Z'],
        ['America/Sao_Paulo', '2018-11-04', '2018-11-04T03:00:00.000Z', '2018-11-05T02:00:00.000Z'],
        ['Pacific/Apia', '2011-12-30', '2011-12-30T10:00:00.000Z', '2011-12-30T10:00:00.000Z'],
        ['Europe/Bucharest', '2026-03-29', '2026-03-28T22:00:00.000Z', '2026-03-29T21:00:00.000Z']
    ];
    for (const [tz, day, from, to] of cases) {
        const prefs = prefsPage(zone(tz)).window.CSM.prefs;
        assert.equal(prefs.dayRange(day, day).from, from, tz + ' start');
        assert.equal(prefs.dayRange(day, day).to, to, tz + ' end');
        assert.equal(prefs.dayBoundary(day, false), Date.parse(from));
        assert.equal(prefs.dayBoundary(day, true), Date.parse(to));
    }
});

// Table date filters ask for the same two boundaries once per row. Building
// an Intl formatter is the expensive part, so it happens once per zone.
test('day boundaries do not rebuild a formatter per row', () => {
    const page = prefsPage(zone('Europe/Bucharest'));
    page.run(`
        var RealDTF = Intl.DateTimeFormat;
        window.__built = 0;
        Intl.DateTimeFormat = function(locale, opts) { window.__built++; return new RealDTF(locale, opts); };
    `);
    for (let i = 0; i < 500; i++) {
        page.window.CSM.prefs.dayBoundary('2026-10-25', false);
        page.window.CSM.prefs.dayBoundary('2026-10-25', true);
    }
    const built = page.window.__built;
    assert.ok(built <= 2, 'built ' + built + ' formatters for 1000 lookups');
    assert.equal(new Date(page.window.CSM.prefs.dayBoundary('2026-10-25', true)).toISOString(), '2026-10-25T22:00:00.000Z');
});

test('today is the current day in the operator zone', () => {
    // Between them these zones disagree with any browser zone at any hour.
    for (const tz of ['Pacific/Kiritimati', 'Etc/GMT+12']) {
        const want = new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date());
        assert.equal(prefsPage(zone(tz)).window.CSM.prefs.today(), want, tz);
    }
});

function query(url) {
    return new URL(url, 'https://csm.example.test/').searchParams;
}

test('finding history asks for the chosen days in the operator zone', async () => {
    const page = loadPage(templateBody('findings'), SHARED.concat(['history.js']), {
        storage: CHATHAM,
        url: 'https://csm.example.test/findings?tab=history&from=2026-09-23&to=2026-09-23',
        globals: { bootstrap: undefined }
    });
    await settle();
    const reqs = page.pending('/api/v1/history');
    assert.equal(reqs.length, 1, 'history not requested');
    const q = query(reqs[0].url);
    assert.equal(q.get('from'), DAY_START);
    assert.equal(q.get('to'), NEXT_DAY_START);
});

test('email asks for the chosen days in the operator zone', async () => {
    const page = loadPage(templateBody('email'), SHARED.concat(['email.js']), {
        storage: CHATHAM,
        url: 'https://csm.example.test/email?from=2026-09-23&to=2026-09-23'
    });
    await settle();
    const ranged = page.pending('/api/v1/').filter(r => query(r.url).has('from'));
    assert.ok(ranged.length > 0, 'no date-filtered request');
    for (const r of ranged) {
        assert.equal(query(r.url).get('from'), DAY_START, r.url);
        assert.equal(query(r.url).get('to'), NEXT_DAY_START, r.url);
    }
});

test('email filters default to today in the operator zone', async () => {
    for (const tz of ['Pacific/Kiritimati', 'Etc/GMT+12']) {
        const want = new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date());
        const page = loadPage(templateBody('email'), SHARED.concat(['email.js']), { storage: zone(tz) });
        await settle();
        assert.equal(page.document.getElementById('filter-from').value, want, tz);
        assert.equal(page.document.getElementById('filter-to').value, want, tz);
    }
});

test('quarantine date filters use days in the operator zone', async () => {
    const page = loadPage(templateBody('quarantine'), SHARED.concat(['quarantine.js']), {
        storage: CHATHAM,
        url: 'https://csm.example.test/quarantine?from=2026-09-23&to=2026-09-23'
    });
    const item = (id, at) => ({ id, original_path: '/home/alice/public_html/' + id + '.php', size: 1, quarantined_at: at, reason: 'webshell: test' });
    page.respond('/api/v1/quarantine', 200, [
        item('inside', '2026-09-22T12:00:00Z'),  // 00:45 on the 23rd in Chatham
        item('outside', '2026-09-23T12:00:00Z')  // 00:45 on the 24th in Chatham
    ]);
    await settle();
    const visible = page.document.querySelectorAll('#quarantine-table tbody tr')
        .filter(r => r.style.display !== 'none' && r.getAttribute('data-path'))
        .map(r => r.getAttribute('data-path'));
    assert.deepEqual(visible, ['/home/alice/public_html/inside.php']);
});

test('no page builds day boundaries in the browser zone', () => {
    const dir = path.join(__dirname, 'static/js');
    for (const f of ['audit.js', 'account.js', 'email.js', 'quarantine.js', 'threat.js', 'history.js']) {
        const src = fs.readFileSync(path.join(dir, f), 'utf8');
        assert.ok(!/new Date\(year, month, day\)/.test(src), f + ' builds a browser-zone midnight');
    }
});
