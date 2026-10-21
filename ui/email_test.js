// Run with: node --test ui/email_test.js
// The Email page: one range for the whole page, the headline numbers, the
// mail decisions chart and the rspamd card.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

const DAY = 86400;
const HOUR_MS = 3600 * 1000;
const CHATHAM = { 'csm-prefs': JSON.stringify({ timezone: 'Pacific/Chatham' }) };

function autoObject() {
    return new Proxy({}, { get(t, k) { if (typeof k === 'symbol') return t[k]; if (!(k in t)) t[k] = autoObject(); return t[k]; } });
}

// chartStub records every chart the page builds, so a test reads its bars.
function chartStub() {
    const charts = [];
    function Chart(canvas, config) {
        const c = { canvas, data: config.data, options: config.options, destroy() {}, update() {} };
        charts.push(c);
        return c;
    }
    Chart.defaults = autoObject();
    Chart.instances = {};
    Chart.charts = charts;
    return Chart;
}

function emailPage(opts = {}) {
    const Chart = chartStub();
    const page = loadPage(templateBody('email'), SHARED.concat(['email.js']), {
        url: opts.url || 'https://csm.example.test/email',
        storage: opts.storage || {},
        globals: { Chart }
    });
    page.Chart = Chart;
    return page;
}

// overview is an overview response with every count zero, the given totals
// and any other top-level fields.
function overview(totals, extra) {
    return Object.assign({
        from: '2026-10-20T10:00:00Z', to: '2026-10-21T10:00:00Z', counting_since: '2020-01-01T00:00:00Z',
        uncounted_minutes: 0, gaps: [], series: [], mode: 'enforce', smtp_restricted: false,
        totals: Object.assign({
            scanned: 0, clean: 0, tagged: 0, rejected: 0, would_tag: 0, would_reject: 0, unfiltered: 0,
            scan_errors: 0, rejects: {}, temporary: {}, quarantined: 0, logins_smtp: 0, logins_mailbox: 0
        }, totals),
        queue: { size: 0, unavailable: false, warn: 100, crit: 500, frozen: 0, detail_unavailable: false },
        blocks: { active: 0, in_range: 0, unavailable: false }
    }, extra);
}

function kpi(page, id) {
    const card = page.document.getElementById(id);
    assert.ok(card, 'no #' + id);
    return {
        value: card.querySelector('[data-kpi-value]').textContent.trim(),
        sub: card.querySelector('[data-kpi-sub]').textContent.trim(),
        text: card.textContent
    };
}

function query(url) {
    return new URL(url, 'https://csm.example.test/').searchParams;
}

function daysBefore(day, n) {
    const [y, m, d] = day.split('-').map(Number);
    return new Date(Date.UTC(y, m - 1, d - n)).toISOString().slice(0, 10);
}

// chatham gives the wall-clock parts of ms in Pacific/Chatham.
function chatham(ms) {
    const parts = {};
    new Intl.DateTimeFormat('en-US', { timeZone: 'Pacific/Chatham', hourCycle: 'h23', year: 'numeric', month: '2-digit',
        day: '2-digit', hour: '2-digit', minute: '2-digit' }).formatToParts(new Date(ms)).forEach(p => { parts[p.type] = p.value; });
    return parts;
}

function dataset(chart, label) {
    const ds = chart.data.datasets.find(d => d.label === label);
    assert.ok(ds, 'no ' + label + ' series');
    return Array.from(ds.data); // an array of this realm, for deepEqual
}

test('KPIs show the overview totals', async () => {
    const page = emailPage();
    page.respond('/api/v1/email/overview', 200, overview({
        scanned: 1200, clean: 1100, tagged: 9, rejected: 41, would_reject: 0,
        // A temporary sender verify deferral is retried, and rate limiting
        // only ever defers: neither is a reject the operator should count.
        rejects: { malware: 2, sender_verify: 530, rate_limited: 800 },
        temporary: { sender_verify: 11, rate_limited: 800 },
        quarantined: 1, logins_smtp: 30, logins_mailbox: 12
    }, {
        queue: { size: 18, unavailable: false, warn: 100, crit: 500, frozen: 0, oldest_age_seconds: 4 * DAY, detail_unavailable: false },
        blocks: { active: 5, in_range: 3, unavailable: false }
    }));
    await settle();
    assert.equal(kpi(page, 'kpi-scanned').value, '1,200');
    assert.match(kpi(page, 'kpi-scanned').sub, /91% clean/);
    assert.equal(kpi(page, 'kpi-spam').value, '41');
    assert.doesNotMatch(kpi(page, 'kpi-spam').sub, /would reject/);
    assert.equal(kpi(page, 'kpi-tagged').value, '9');
    assert.equal(kpi(page, 'kpi-malware').value, '3');
    assert.match(kpi(page, 'kpi-malware').sub, /2 rejected at SMTP, 1 quarantined/);
    assert.equal(kpi(page, 'kpi-other').value, '519');
    assert.match(kpi(page, 'kpi-other').sub, /Sender verification 519/);
    assert.doesNotMatch(kpi(page, 'kpi-other').text, /rate/i);
    assert.equal(kpi(page, 'kpi-logins').value, '42');
    assert.match(kpi(page, 'kpi-logins').sub, /3 IPs blocked/);
    assert.equal(kpi(page, 'kpi-queue').value, '18');
    assert.match(kpi(page, 'kpi-queue').sub, /4d/);
    assert.equal(page.document.querySelector('#kpi-queue a').getAttribute('href'), '#email-tab-queue');
    assert.doesNotMatch(page.document.querySelector('#kpi-queue [data-kpi-value]').className, /text-(warning|danger)/,
        'a queue under its warn threshold is not colored');
    assert.match(page.document.getElementById('email-subtitle').textContent, /41 spam rejected and 9 tagged in the last 24 hours/);
});

test('big numbers stay short enough for their card', async () => {
    const page = emailPage();
    page.respond('/api/v1/email/overview', 200, overview({ scanned: 1234567, clean: 1200000, rejected: 99999 }));
    await settle();
    const scanned = page.document.querySelector('#kpi-scanned [data-kpi-value]');
    assert.equal(scanned.textContent, '1.2M');
    assert.equal(scanned.getAttribute('title'), '1,234,567');
    assert.equal(kpi(page, 'kpi-spam').value, '99,999');
});

test('the queue is colored only from its warn threshold and says when it is unknown', async () => {
    const page = emailPage();
    page.respond('/api/v1/email/overview', 200, overview({}, {
        queue: { size: 120, unavailable: false, warn: 100, crit: 500, frozen: 0, detail_unavailable: true }
    }));
    await settle();
    assert.match(page.document.querySelector('#kpi-queue [data-kpi-value]').className, /text-warning/);
    assert.doesNotMatch(kpi(page, 'kpi-queue').sub, /\d+[dhms]/, 'no oldest age when the queue detail is unavailable');

    const down = emailPage();
    down.respond('/api/v1/email/overview', 200, overview({}, {
        queue: { size: 0, unavailable: true, warn: 100, crit: 500, frozen: 0, detail_unavailable: true }
    }));
    await settle();
    assert.match(kpi(down, 'kpi-queue').sub, /queue size unknown/);
    assert.notEqual(kpi(down, 'kpi-queue').value, '0', 'an unreadable queue must not read as empty');
});

test('dry-run shows would reject, never rejected', async () => {
    const page = emailPage();
    page.respond('/api/v1/email/overview', 200, overview({ scanned: 50, clean: 50, rejected: 0, would_reject: 7, would_tag: 2 }, { mode: 'dry-run' }));
    await settle();
    assert.equal(kpi(page, 'kpi-spam').value, '0');
    assert.match(kpi(page, 'kpi-spam').sub, /would reject 7/);
    assert.equal(page.document.querySelector('#kpi-spam .badge').textContent.trim(), 'dry-run');
    assert.match(kpi(page, 'kpi-tagged').sub, /would tag 2/);
});

test('failed logins say when the block count is unavailable', async () => {
    const page = emailPage();
    page.respond('/api/v1/email/overview', 200, overview({ logins_smtp: 1 }, { blocks: { active: 0, in_range: 0, unavailable: true } }));
    await settle();
    assert.match(kpi(page, 'kpi-logins').sub, /block count unavailable/);
});

test('a failed overview shows a load error with retry', async () => {
    const page = emailPage();
    page.fail('/api/v1/email/overview');
    await settle();
    const kpis = page.document.getElementById('email-kpis');
    assert.match(kpis.textContent, /Failed to load mail numbers/);
    kpis.querySelector('.csm-retry-btn').click();
    page.respond('/api/v1/email/overview', 200, overview({ rejected: 4 }));
    await settle();
    assert.doesNotMatch(kpis.textContent, /Failed to load/);
    assert.equal(kpi(page, 'kpi-spam').value, '4');
});

test('the chart sums 15-minute buckets into operator-zone hours', async () => {
    const page = emailPage({ storage: CHATHAM });
    await settle();
    const from = Date.parse(query(page.pending('/api/v1/email/overview')[0].url).get('from'));
    // Chatham hours start at a quarter past the UTC hour, so a UTC hour
    // would split these four buckets across two bars.
    const hour = from + 5 * HOUR_MS;
    const series = [0, 1, 2, 3].map(i => ({ t: (hour + i * 900000) / 1000, clean: 10, tagged: 1, rejected: 2, malware: 1, other: 3 }));
    page.respond('/api/v1/email/overview', 200, overview({}, { series }));
    await settle();
    const chart = page.Chart.charts.at(-1);
    assert.ok(chart, 'no chart');
    const clean = dataset(chart, 'Clean');
    assert.equal(clean.length, 24);
    assert.deepEqual(clean.map((v, i) => v ? i : -1).filter(i => i >= 0), [5]);
    assert.equal(clean[5], 40);
    assert.equal(dataset(chart, 'Tagged')[5], 4);
    assert.equal(dataset(chart, 'Spam rejected')[5], 8);
    assert.equal(dataset(chart, 'Malware')[5], 4);
    assert.equal(dataset(chart, 'Other rejects')[5], 12);
    assert.equal(chart.data.labels[5], chatham(hour).hour + ':00');
});

test('the chart sums days in the operator zone', async () => {
    const page = emailPage({ storage: Object.assign({ 'csm-email-range': '7d' }, CHATHAM) });
    await settle();
    const prefs = page.window.CSM.prefs;
    const yesterday = daysBefore(prefs.today(), 1);
    const start = prefs.dayBoundary(yesterday, false);
    page.respond('/api/v1/email/overview', 200, overview({}, { series: [
        { t: (start - 900000) / 1000, clean: 5, tagged: 0, rejected: 0, malware: 0, other: 0 },
        { t: start / 1000, clean: 7, tagged: 0, rejected: 0, malware: 0, other: 0 },
        { t: (start + 23 * HOUR_MS + 2700000) / 1000, clean: 1, tagged: 0, rejected: 0, malware: 0, other: 0 }
    ] }));
    await settle();
    const chart = page.Chart.charts.at(-1);
    assert.equal(chart.data.labels.length, 7);
    assert.deepEqual(dataset(chart, 'Clean').slice(4, 6), [5, 8]);
});

test('the chart notes time CSM did not count', async () => {
    const page = emailPage();
    await settle();
    const req = page.pending('/api/v1/email/overview')[0];
    const from = Date.parse(query(req.url).get('from'));
    const gapStart = from + 2 * HOUR_MS + 10 * 60000;
    page.respond('/api/v1/email/overview', 200, overview({}, {
        uncounted_minutes: 20,
        gaps: [{ start: new Date(gapStart).toISOString(), end: new Date(gapStart + 20 * 60000).toISOString() }],
        counting_since: new Date(from + HOUR_MS).toISOString()
    }));
    await settle();
    const note = page.document.getElementById('email-chart-note');
    assert.match(note.textContent, /Not counted while CSM was stopped: 20 min/);
    assert.match(note.textContent, /Counting since/);
    const footer = page.Chart.charts.at(-1).options.plugins.tooltip.callbacks.footer;
    assert.match(String(footer([{ dataIndex: 2 }])), /Not counted: 20 min/);
    assert.equal(footer([{ dataIndex: 3 }]), '');
});

test('an empty range says so plainly', async () => {
    const page = emailPage();
    page.respond('/api/v1/email/overview', 200, overview({}));
    await settle();
    assert.equal(page.document.getElementById('email-chart-note').textContent.trim(), '');
    assert.equal(kpi(page, 'kpi-scanned').value, '0');
    assert.match(kpi(page, 'kpi-other').sub, /none/);
    assert.match(kpi(page, 'kpi-queue').sub, /empty/);
    assert.match(page.document.getElementById('email-subtitle').textContent, /No mail scanned in the last 24 hours\. Queue empty\./);

    const fresh = emailPage();
    const ov = overview({});
    delete ov.counting_since;
    fresh.respond('/api/v1/email/overview', 200, ov);
    await settle();
    assert.match(fresh.document.getElementById('email-chart-note').textContent, /Counting has not started/);
});

test('rspamd card says since rspamd started', async () => {
    const page = emailPage();
    page.respond('/api/v1/email/rspamd', 200, {
        status: 'up', mode: 'enforce', available: true, version: '3.11.1', fetched_at: '2026-10-21T10:00:00Z',
        stats: { scanned: 5000, learned: 30, ham_count: 20, spam_count: 10, uptime_seconds: 3 * DAY, version: '3.11.1', actions: {},
            top_rules: [{ symbol: 'BAYES_SPAM', hits: 9 }] }
    });
    await settle();
    const card = page.document.getElementById('email-rspamd').textContent;
    assert.match(card, /since rspamd started 3 days ago/);
    assert.match(card, /BAYES_SPAM/);
    assert.match(card, /5,000/);
    assert.match(card, /3\.11\.1/);
    assert.match(card, /enforce/);
});

test('rspamd shows at most eight rules and tolerates none', async () => {
    const page = emailPage();
    const rules = Array.from({ length: 12 }, (_, i) => ({ symbol: 'RULE_' + i, hits: 100 - i }));
    page.respond('/api/v1/email/rspamd', 200, { status: 'up', mode: 'enforce', available: true,
        stats: { scanned: 1, uptime_seconds: 0, top_rules: rules } });
    await settle();
    const text = page.document.getElementById('email-rspamd').textContent;
    assert.match(text, /RULE_7/);
    assert.doesNotMatch(text, /RULE_8/);

    const empty = emailPage();
    empty.respond('/api/v1/email/rspamd', 200, { status: 'up', mode: 'enforce', available: true,
        stats: { scanned: 1, uptime_seconds: 0, top_rules: null } });
    await settle();
    assert.match(empty.document.getElementById('email-rspamd').textContent, /since rspamd started/);
});

test('rspamd rule names render as text', async () => {
    const page = emailPage();
    page.respond('/api/v1/email/rspamd', 200, { status: 'up', mode: 'enforce', available: true, version: '<b>3</b>',
        stats: { scanned: 1, uptime_seconds: DAY, top_rules: [{ symbol: '<img src=x onerror=alert(1)>', hits: 1 }] } });
    await settle();
    const card = page.document.getElementById('email-rspamd');
    assert.equal(card.querySelectorAll('img').length, 0);
    assert.equal(card.querySelectorAll('b').length, 0);
    assert.match(card.textContent, /<img/);
});

test('rspamd unavailable keeps status and mode', async () => {
    const page = emailPage();
    page.respond('/api/v1/email/rspamd', 200, { status: 'down', mode: 'enforce', available: false, version: '3.11.1',
        reason: "rspamd's controller did not answer" });
    await settle();
    const card = page.document.getElementById('email-rspamd');
    assert.match(card.textContent, /down/);
    assert.match(card.textContent, /enforce/);
    assert.match(card.textContent, /3\.11\.1/);
    assert.match(card.textContent, /rspamd's controller did not answer/);
    assert.ok(card.querySelector('.status-dot'), 'no status dot');
});

test('a failed rspamd read shows a load error', async () => {
    const page = emailPage();
    page.fail('/api/v1/email/rspamd');
    await settle();
    assert.match(page.document.getElementById('email-rspamd').textContent, /Failed to load rspamd/);
});

test('the range select drives every request', async () => {
    const page = emailPage({ storage: CHATHAM });
    await settle();
    const range = page.document.getElementById('email-range');
    assert.equal(range.value, '24h');
    assert.equal(range.querySelector('option[value="custom"]'), null, 'Custom shows only for links with dates');
    const before = page.requests.length;
    range.value = '7d';
    range.dispatchEvent(new page.window.Event('change'));
    await settle();
    const prefs = page.window.CSM.prefs;
    const want = new Date(prefs.dayBoundary(daysBefore(prefs.today(), 6), false)).toISOString();
    const after = page.requests.slice(before);
    const ov = after.find(r => r.url.includes('/api/v1/email/overview'));
    assert.ok(ov, 'no overview request after the change');
    assert.equal(query(ov.url).get('from'), want);
    const groups = after.find(r => r.url.includes('/api/v1/email/groups?'));
    assert.ok(groups, 'no groups request after the change');
    assert.equal(query(groups.url).get('from'), want);
    assert.equal(page.window.localStorage.getItem('csm-email-range'), '7d');

    const again = emailPage({ storage: Object.assign({ 'csm-email-range': '30d' }, CHATHAM) });
    await settle();
    assert.equal(again.document.getElementById('email-range').value, '30d');
    const first = again.pending('/api/v1/email/overview')[0];
    assert.equal(query(first.url).get('from'),
        new Date(prefs.dayBoundary(daysBefore(prefs.today(), 29), false)).toISOString());
});
