// Run with: node --test ui/email_test.js
// The Email page: one range for the whole page, the headline numbers, and
// the job tabs right under them: Overview (the mail decisions chart, the
// rspamd card, the groups that need attention and the protection card),
// Queue, Held mail, Rejects, Sending accounts, Provider delays, Findings.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const { loadPage, templateBody, items, SHARED, settle, jsonResponse } = require('./pagekit.js');

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

// tabPlugin does what Bootstrap's tab plugin does on show(): the tab and
// its pane become active, the other tabs of its list stop being active,
// then shown.bs.tab fires. A tab that is already active does nothing.
function tabPlugin(window) {
    return {
        getOrCreateInstance(btn) {
            return {
                show() {
                    if (btn.classList.contains('active')) return;
                    for (const tab of btn.closest('[role="tablist"]').querySelectorAll('[role="tab"]')) {
                        const on = tab === btn;
                        tab.classList.toggle('active', on);
                        tab.setAttribute('aria-selected', String(on));
                        const pane = window.document.getElementById(tab.getAttribute('aria-controls'));
                        pane.classList.toggle('active', on);
                        pane.classList.toggle('show', on);
                    }
                    btn.dispatchEvent(new window.Event('shown.bs.tab'));
                }
            };
        },
        getInstance() { return null; }
    };
}

function emailPage(opts = {}) {
    const Chart = chartStub();
    const globals = { Chart };
    if (opts.now) {
        globals.Date = class extends Date {
            constructor(...args) { super(...(args.length ? args : [opts.now])); }
            static now() { return Date.parse(opts.now); }
        };
    }
    const page = loadPage(templateBody('email'), SHARED, {
        url: opts.url || 'https://csm.example.test/email',
        storage: opts.storage || {},
        globals
    });
    page.window.bootstrap.Tab = tabPlugin(page.window);
    if (opts.intervals) {
        const interval = page.window.CSM.refresh.interval;
        page.window.CSM.refresh.interval = (fn, ms) => { opts.intervals.push({ fn, ms }); return interval(fn, ms); };
    }
    page.load('email.js');
    page.Chart = Chart;
    return page;
}

const TABS = ['overview', 'queue', 'held', 'rejects', 'sending', 'forwarders', 'delays', 'findings'];

// selectedTab returns the one job tab that is selected, after checking
// that its pane, and only its pane, shows.
function selectedTab(page) {
    const on = TABS.filter(name => page.document.getElementById('email-tab-' + name).getAttribute('aria-selected') === 'true');
    assert.equal(on.length, 1, 'selected tabs: ' + on.join(', '));
    for (const name of TABS) {
        const pane = page.document.getElementById('email-pane-' + name);
        assert.equal(pane.classList.contains('active') && pane.classList.contains('show'), name === on[0], name + ' pane shows with tab ' + on[0]);
    }
    return on[0];
}

function urlTab(page) {
    return new URL(page.window.location.href).searchParams.get('tab');
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
    assert.equal(page.document.querySelector('#kpi-queue a').getAttribute('href'), '?tab=queue');
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
        // The last bucket of yesterday, which is 23 h long on a day the
        // clocks go forward.
        { t: (prefs.dayBoundary(yesterday, true) - 900000) / 1000, clean: 1, tagged: 0, rejected: 0, malware: 0, other: 0 }
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

test('the chart keeps a short stop visible', async () => {
    const page = emailPage();
    await settle();
    const req = page.pending('/api/v1/email/overview')[0];
    const from = Date.parse(query(req.url).get('from'));
    const gapStart = from + 2 * HOUR_MS + 10 * 60000;
    page.respond('/api/v1/email/overview', 200, overview({}, {
        uncounted_minutes: 1,
        gaps: [{ start: new Date(gapStart).toISOString(), end: new Date(gapStart + 1000).toISOString() }]
    }));
    await settle();
    assert.match(page.document.getElementById('email-chart-note').textContent, /Not counted while CSM was stopped: 1 min/);
    const footer = page.Chart.charts.at(-1).options.plugins.tooltip.callbacks.footer;
    assert.equal(footer([{ dataIndex: 2 }]), 'Not counted: 1 min');
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

test('rspamd card shows its counters and its uptime apart', async () => {
    const page = emailPage();
    page.respond('/api/v1/email/rspamd', 200, {
        status: 'up', mode: 'enforce', available: true, version: '3.11.1', fetched_at: '2026-10-21T10:00:00Z',
        stats: { scanned: 5000, learned: 30, ham_count: 4000, spam_count: 1000, uptime_seconds: 3 * DAY, version: '3.11.1', actions: {},
            top_rules: [{ symbol: 'BAYES_SPAM', hits: 9 }] }
    });
    await settle();
    const card = page.document.getElementById('email-rspamd').textContent;
    // rspamd can keep its counters across a restart, so the uptime is not
    // their period.
    assert.match(card, /rspamd counters/);
    assert.match(card, /Uptime 3 days/);
    assert.doesNotMatch(card, /since rspamd started/);
    assert.match(card, /Scanned 5,000 \(spam 1,000, ham 4,000\)/);
    assert.match(card, /Learned 30/);
    assert.match(card, /BAYES_SPAM/);
    assert.match(card, /3\.11\.1/);
    assert.match(card, /enforce/);
});

test('rspamd card does not call scan verdicts learned', async () => {
    const page = emailPage();
    // The shape and the numbers of a production controller: every scanned
    // message is counted as spam or ham, and nothing was ever learned.
    page.respond('/api/v1/email/rspamd', 200, {
        status: 'up', mode: 'enforce', available: true, version: '3.11.1', fetched_at: '2026-10-21T10:00:00Z',
        stats: { scanned: 18370, learned: 0, ham_count: 15605, spam_count: 2765, uptime_seconds: 9 * DAY + 4 * 3600, version: '3.11.1',
            actions: { reject: 2765, 'no action': 15605 }, top_rules: [{ symbol: 'R_SPF_ALLOW', hits: 12000 }] }
    });
    await settle();
    const card = page.document.getElementById('email-rspamd').textContent;
    assert.match(card, /Scanned 18,370 \(spam 2,765, ham 15,605\)/);
    assert.match(card, /Learned 0/);
    assert.doesNotMatch(card, /Learned (ham|spam)/);
    assert.doesNotMatch(card, /Learned 15,605|Learned 2,765/);
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
    assert.match(empty.document.getElementById('email-rspamd').textContent, /Uptime unknown/);
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
    showEmailTab(page, 'rejects');
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
    const rejects = after.find(r => r.url.includes('/api/v1/email/rejects?'));
    assert.ok(rejects, 'no rejects request after the change');
    assert.equal(query(rejects.url).get('from'), want);
    assert.equal(page.window.localStorage.getItem('csm-email-range'), '7d');

    const again = emailPage({ storage: Object.assign({ 'csm-email-range': '30d' }, CHATHAM) });
    await settle();
    assert.equal(again.document.getElementById('email-range').value, '30d');
    const first = again.pending('/api/v1/email/overview')[0];
    assert.equal(query(first.url).get('from'),
        new Date(prefs.dayBoundary(daysBefore(prefs.today(), 29), false)).toISOString());
});

const AT = '2026-10-21T09:58:00Z';

// answerAll answers what the page asks for until it stops asking: bodies
// by URL fragment, every other route an empty list.
async function answerAll(page, bodies) {
    for (let round = 0; round < 8; round++) {
        const pending = page.pending();
        if (pending.length === 0) break;
        for (const req of pending) {
            const hit = Object.keys(bodies).find(k => req.url.includes(k));
            page.respond(req.url, 200, hit ? bodies[hit] : items([]));
        }
        await settle();
    }
}

function group(title, extra) {
    return Object.assign({ kind: 'auth_failure', severity: 'CRITICAL', title, subject: title, summary: 'failed logins', count: 3,
        first_seen: AT, last_seen: AT, ips: ['203.0.113.9'], block_state: 'none', handled: false }, extra);
}

function groupTitles(page) {
    return Array.from(page.document.querySelectorAll('#email-action-groups .csm-summary-list__title')).map(e => e.textContent);
}

// The Rejects filter values: the groups, then each class. other is every
// reason but spam, malware and rate limiting; the class the server calls
// other is unclassified here.
const REJECT_FILTER_VALUES = ['content', 'all', 'other', 'spam', 'malware', 'unknown_recipient', 'sender_verify', 'bad_helo',
    'relay_denied', 'auth_required', 'suspended', 'mailbox_full', 'blocklisted', 'rate_limited', 'unclassified'];

test('rejects default to spam and malware', async () => {
    const page = emailPage();
    showEmailTab(page, 'rejects');
    await settle();
    const ovFrom = query(page.pending('/api/v1/email/overview')[0].url).get('from');
    const req = page.pending('/api/v1/email/rejects')[0];
    assert.ok(req, 'no rejects request');
    const q = query(req.url);
    assert.equal(q.get('class'), 'content');
    assert.equal(q.get('from'), ovFrom);
    assert.ok(Math.abs(Date.parse(q.get('to')) - Date.now()) < 60000, 'the range does not end now');
    page.respond('/api/v1/email/rejects', 200, items([
        { at: AT, class: 'spam', ip: '203.0.113.5', sender: 'a@example.com', recipient: 'b@example.net', detail: 'score 15.2', msg_id: '1abcDE-000001-AB' },
        { at: AT, class: 'malware', ip: '2001:db8::5', sender: 'c@example.com', recipient: 'd@example.net', detail: 'Eicar-Test-Signature' }
    ], { class: 'content', limit: 50, kept_days: 7 }));
    await settle();
    const tbody = page.document.getElementById('email-rejects-tbody');
    const rows = tbody.querySelectorAll('tr');
    assert.equal(rows.length, 2);
    const link = rows[0].querySelector('a');
    assert.equal(link.getAttribute('href'), '/firewall?ip=203.0.113.5');
    assert.equal(link.textContent, '203.0.113.5');
    assert.equal(rows[1].querySelector('a').getAttribute('href'), '/firewall?ip=' + encodeURIComponent('2001:db8::5'));
    assert.match(rows[0].textContent, /score 15\.2/);
    assert.match(rows[0].textContent, /a@example\.com/);
    assert.match(rows[0].textContent, /b@example\.net/);
    assert.match(rows[0].querySelector('.badge').textContent, /^Spam$/);
    assert.match(rows[1].querySelector('.badge').textContent, /^Malware$/);
    assert.equal(rows[0].cells.length, 6);
    assert.ok(Array.from(rows[0].cells).every(td => td.getAttribute('data-label')), 'a cell has no label for the phone layout');
});

test('reject rows show server text as text', async () => {
    const page = emailPage();
    showEmailTab(page, 'rejects');
    await settle();
    page.respond('/api/v1/email/rejects', 200, items([
        { at: AT, class: 'sender_verify', temporary: true, ip: '', sender: '<img src=x onerror=alert(1)>@example.com', recipient: '', detail: '<b>verify</b>' },
        { at: AT, class: 'rate_limited', temporary: true, ip: '198.51.100.7', sender: 's@example.com', detail: 'ratelimited' }
    ], { class: 'all', limit: 50, kept_days: 7 }));
    await settle();
    const tbody = page.document.getElementById('email-rejects-tbody');
    assert.equal(tbody.querySelectorAll('img').length, 0);
    assert.equal(tbody.querySelectorAll('b').length, 0);
    assert.match(tbody.textContent, /<img src=x/);
    const rows = tbody.querySelectorAll('tr');
    assert.equal(rows[0].querySelector('a'), null, 'a row without an IP links nowhere');
    assert.deepEqual(Array.from(rows[0].querySelectorAll('.badge')).map(b => b.textContent), ['Sender verification', 'temporary']);
    assert.equal(rows[1].querySelector('.badge').textContent, 'Rate limited (temporary)');
});

test('rejects empty state names range and filter', async () => {
    const page = emailPage();
    showEmailTab(page, 'rejects');
    await settle();
    page.respond('/api/v1/email/rejects', 200, items([], { class: 'content', limit: 50, kept_days: 7 }));
    await settle();
    const tbody = page.document.getElementById('email-rejects-tbody');
    assert.ok(tbody.querySelector('.csm-empty'), 'not the shared empty state');
    assert.match(tbody.textContent, /No spam or malware rejects in the last 24 hours/);

    const filter = page.document.getElementById('email-rejects-filter');
    assert.deepEqual(Array.from(filter.options).map(o => o.value), REJECT_FILTER_VALUES);
    assert.equal(filter.value, 'content');
    assert.equal(Array.from(filter.options).find(o => o.value === 'rate_limited').textContent, 'Rate limited (temporary)');

    filter.value = 'all';
    filter.dispatchEvent(new page.window.Event('change'));
    await settle();
    assert.equal(query(page.pending('/api/v1/email/rejects')[0].url).get('class'), 'all');
    page.respond('/api/v1/email/rejects', 200, items([], { class: 'all', limit: 50, kept_days: 7 }));
    await settle();
    assert.match(tbody.textContent, /No rejects in the last 24 hours/);

    filter.value = 'sender_verify';
    filter.dispatchEvent(new page.window.Event('change'));
    await settle();
    assert.equal(query(page.pending('/api/v1/email/rejects')[0].url).get('class'), 'sender_verify');
    page.respond('/api/v1/email/rejects', 200, items([], { class: 'sender_verify', limit: 50, kept_days: 7 }));
    await settle();
    assert.match(tbody.textContent, /No rejects for Sender verification in the last 24 hours/);
});

test('a failed rejects load shows a load error with retry', async () => {
    const page = emailPage();
    showEmailTab(page, 'rejects');
    await settle();
    page.respond('/api/v1/email/rejects', 401, { error: 'Unauthorized' });
    await settle();
    const tbody = page.document.getElementById('email-rejects-tbody');
    assert.match(tbody.textContent, /Failed to load rejects/);
    tbody.querySelector('.csm-retry-btn').click();
    page.respond('/api/v1/email/rejects', 200, items([{ at: AT, class: 'spam', ip: '203.0.113.5', detail: 'score 15.2' }], { kept_days: 7 }));
    await settle();
    assert.doesNotMatch(tbody.textContent, /Failed to load/);
    assert.match(tbody.textContent, /score 15\.2/);
});

test('the rejects list loads when its tab opens and refreshes only while it is open', async () => {
    const rejects = page => page.requests.filter(r => r.url.includes('/api/v1/email/rejects'));
    const page = emailPage();
    await settle();
    assert.equal(rejects(page).length, 0, 'the page read the rejects before their tab opened');
    // The timers, the refresh button and a new range leave a closed tab alone.
    page.window.CSM.refresh.manual();
    await settle();
    page.document.getElementById('email-refresh').click();
    await settle();
    changeValue(page, page.document.getElementById('email-range'), '7d');
    await settle();
    assert.equal(rejects(page).length, 0, 'a closed Rejects tab was read');

    showEmailTab(page, 'rejects');
    await settle();
    assert.equal(rejects(page).length, 1, 'opening Rejects did not read them');
    assert.equal(query(rejects(page)[0].url).get('from'), query(page.pending('/api/v1/email/overview').at(-1).url).get('from'));
    page.respond('/api/v1/email/rejects', 200, items([], { kept_days: 7 }));
    await settle();
    page.window.CSM.refresh.manual();
    await settle();
    assert.equal(rejects(page).length, 2, 'the timers do not refresh the open Rejects tab');
    page.respond('/api/v1/email/rejects', 200, items([], { kept_days: 7 }));
    await settle();

    showEmailTab(page, 'overview');
    page.window.CSM.refresh.manual();
    await settle();
    assert.equal(rejects(page).length, 2, 'the timers read a closed Rejects tab');
    showEmailTab(page, 'rejects');
    await settle();
    assert.equal(rejects(page).length, 3, 'reopening Rejects did not read them again');

    // An address that opens Rejects reads them once.
    const linked = emailPage({ url: 'https://csm.example.test/email?tab=rejects' });
    await settle();
    assert.equal(rejects(linked).length, 1);
});

test('handled groups hide behind a toggle', async () => {
    const page = emailPage();
    await settle();
    page.respond('/api/v1/email/groups?', 200, items([
        group('A', { block_state: 'some', ips: ['203.0.113.9', '203.0.113.10'] }),
        group('B', { block_state: 'all', handled: true })
    ], { handled_count: 1, limit: 50, truncated: false, blocks_unavailable: false }));
    await settle();
    assert.deepEqual(groupTitles(page), ['A']);
    const list = page.document.getElementById('email-action-groups');
    assert.match(list.textContent, /partly blocked/);
    assert.match(page.document.getElementById('email-groups-count').textContent, /^1 group$/);
    const toggle = page.document.getElementById('email-groups-handled');
    assert.equal(toggle.hidden, false);
    assert.equal(toggle.textContent.trim(), 'Show handled (1)');
    assert.equal(toggle.getAttribute('aria-pressed'), 'false');
    toggle.click();
    assert.deepEqual(groupTitles(page), ['A', 'B']);
    assert.equal(toggle.getAttribute('aria-pressed'), 'true');
    assert.equal(toggle.textContent.trim(), 'Show handled (1)', 'a pressed toggle keeps its name; aria-pressed carries the state');
    const items_ = list.querySelectorAll('.csm-summary-list__item');
    assert.match(items_[1].textContent, /\bblocked\b/);
    assert.equal(items_[1].querySelector('.csm-summary-list__sev'), null, 'a handled group still carries alarm styling');
    assert.ok(items_[0].querySelector('.csm-summary-list__sev'), 'an open group lost its severity');
    toggle.click();
    assert.deepEqual(groupTitles(page), ['A']);
});

test('groups show their block state, and say once when it is unknown', async () => {
    const page = emailPage();
    await settle();
    page.respond('/api/v1/email/groups?', 200, items([
        group('none', { block_state: 'none' }),
        group('noip', { kind: 'spam_outbreak', block_state: 'no_ip', ips: [] })
    ], { handled_count: 0 }));
    await settle();
    const rows = page.document.querySelectorAll('#email-action-groups .csm-summary-list__item');
    assert.match(rows[0].textContent, /not blocked/);
    assert.doesNotMatch(rows[1].textContent, /blocked/);
    assert.equal(page.document.getElementById('email-groups-handled').hidden, true, 'a toggle with nothing to show');

    const down = emailPage();
    await settle();
    down.respond('/api/v1/email/groups?', 200, items([group('x', { block_state: '' }), group('y', { block_state: '' })],
        { handled_count: 0, blocks_unavailable: true }));
    await settle();
    const list = down.document.getElementById('email-action-groups');
    assert.doesNotMatch(Array.from(list.querySelectorAll('.csm-summary-list__item')).map(r => r.textContent).join(' '), /blocked/);
    assert.equal(list.textContent.match(/Block state unavailable/g).length, 1);
});

test('at most eight groups show before Show all', async () => {
    const page = emailPage();
    await settle();
    page.respond('/api/v1/email/groups?', 200, items(Array.from({ length: 10 }, (_, i) => group('g' + i)), { handled_count: 0 }));
    await settle();
    assert.equal(groupTitles(page).length, 8);
    const more = page.document.getElementById('email-groups-more');
    assert.equal(more.hidden, false);
    assert.equal(more.textContent.trim(), 'Show all');
    more.click();
    assert.equal(groupTitles(page).length, 10);
    assert.equal(more.hidden, true);
});

test('nothing needs you when every group is handled', async () => {
    const page = emailPage();
    await settle();
    page.respond('/api/v1/email/groups?', 200, items([
        group('B', { block_state: 'all', handled: true }),
        group('C', { block_state: 'all', handled: true })
    ], { handled_count: 2 }));
    await settle();
    const list = page.document.getElementById('email-action-groups');
    assert.deepEqual(groupTitles(page), []);
    assert.ok(list.querySelector('.csm-empty'), 'not the shared empty state');
    assert.match(list.textContent, /Nothing needs you\.\s*2 groups already handled\./);
    assert.equal(page.document.getElementById('email-groups-count').textContent, '');
    assert.equal(page.document.getElementById('email-groups-handled').textContent.trim(), 'Show handled (2)');
});

test('a failed groups load shows a load error with retry', async () => {
    const page = emailPage();
    await settle();
    page.fail('/api/v1/email/groups?');
    await settle();
    const list = page.document.getElementById('email-action-groups');
    assert.match(list.textContent, /Failed to load what needs attention/);
    list.querySelector('.csm-retry-btn').click();
    page.respond('/api/v1/email/groups?', 200, items([group('A')], { handled_count: 0 }));
    await settle();
    assert.doesNotMatch(list.textContent, /Failed to load/);
    assert.deepEqual(groupTitles(page), ['A']);
});

test('protection card lists four plain lines', async () => {
    const page = emailPage();
    await answerAll(page, {
        '/api/v1/email/overview': overview({}, { mode: 'enforce', smtp_restricted: true }),
        '/api/v1/email/rspamd': { status: 'up', mode: 'enforce', available: false },
        '/api/v1/email/av/status': { enabled: true, clamd_available: true, clamd_socket: '/run/clamd.sock', yarax_available: false,
            yarax_rule_count: 4321, watcher_mode: 'permission', quarantined: 0 },
        '/api/v1/email/stats': { queue_size: 2, queue_warn: 100, queue_crit: 500, frozen_count: 0, smtp_block: true,
            smtp_allow_users: ['alice'], smtp_ports: [25], port_flood: [{ port: 25, proto: 'tcp', hits: 10, window_seconds: 60 }], top_senders: [] }
    });
    const card = page.document.getElementById('email-protection');
    assert.ok(card, 'no #email-protection');
    const lines = ['prot-antispam', 'prot-av', 'prot-smtp', 'prot-watcher'].map(id => {
        const el = card.querySelector('#' + id);
        assert.ok(el, 'no #' + id);
        assert.ok(el.querySelector('.status-dot'), id + ' has no status dot');
        return el.textContent.replace(/\s+/g, ' ').trim();
    });
    assert.match(lines[0], /Antispam.*enforce, rspamd up/);
    assert.match(lines[1], /Antivirus.*ClamAV up, YARA-X down/);
    assert.match(lines[2], /Outbound SMTP.*restricted/);
    assert.match(lines[3], /Watcher.*permission/);
    assert.match(card.querySelector('#prot-av .status-dot').className, /status-yellow/);
    assert.doesNotMatch(card.textContent, /threshold|allowed users|rules\)|4321|alice/i);
    assert.equal(page.document.getElementById('email-protection-state'), null, 'the old settings card is still there');
    assert.equal(page.document.getElementById('email-status-strip'), null, 'the old status strip is still there');
});

test('protection says when antispam is off or rspamd is down', async () => {
    const page = emailPage();
    await answerAll(page, {
        '/api/v1/email/overview': overview({}, { mode: 'dry-run', smtp_restricted: false }),
        '/api/v1/email/rspamd': { status: 'down', mode: 'dry-run', available: false },
        '/api/v1/email/av/status': { enabled: false, clamd_available: false, yarax_available: false, watcher_mode: 'disabled' }
    });
    const text = id => page.document.getElementById(id).textContent.replace(/\s+/g, ' ');
    assert.match(text('prot-antispam'), /dry-run, rspamd down/);
    assert.match(page.document.querySelector('#prot-antispam .status-dot').className, /status-red/);
    assert.match(text('prot-smtp'), /open/);
    assert.match(text('prot-av'), /\boff\b/);

    const off = emailPage();
    await answerAll(off, {
        '/api/v1/email/overview': overview({}, { mode: 'off' }),
        '/api/v1/email/rspamd': { status: 'off', mode: 'off', available: false, reason: 'antispam is off' }
    });
    assert.match(off.document.getElementById('prot-antispam').textContent, /\boff\b/);
    assert.doesNotMatch(off.document.getElementById('prot-antispam').textContent, /rspamd/);
});

test('the page never downloads the blocked list', async () => {
    const page = emailPage();
    const bodies = {
        '/api/v1/email/stats': { queue_size: 0, queue_warn: 100, queue_crit: 500, frozen_count: 0, smtp_block: true,
            smtp_allow_users: [], smtp_ports: [25], port_flood: [], top_senders: [] },
        '/api/v1/email/overview': overview({})
    };
    await answerAll(page, bodies);
    page.document.getElementById('email-refresh').click();
    await answerAll(page, bodies);
    const urls = page.requests.map(r => r.url);
    assert.ok(urls.filter(u => u.includes('/api/v1/email/overview')).length >= 2, 'no refresh round ran');
    assert.deepEqual(urls.filter(u => u.includes('/api/v1/blocked-ips')), []);
});

// ---------- Fold-ins: rejects paging, groups count, Show all ----------

function reject(i) {
    return { at: AT, class: 'spam', ip: '203.0.113.5', sender: 's' + i + '@example.com', recipient: 'r@example.net', detail: 'row ' + i };
}

function rejectsShowing(page) {
    return page.document.getElementById('email-rejects-table-controls').textContent;
}

test('rejects keep their page across a refresh with the same filter and range', async () => {
    const page = emailPage();
    showEmailTab(page, 'rejects');
    await settle();
    page.respond('/api/v1/email/rejects', 200, items(Array.from({ length: 25 }, (_, i) => reject(i)), { kept_days: 7 }));
    await settle();
    page.document.querySelector('#email-rejects-table-controls [data-page="3"]').click();
    assert.match(rejectsShowing(page), /Showing 21.25 of 25/);

    page.document.getElementById('email-refresh').click();
    await settle();
    page.respond('/api/v1/email/rejects', 200, items(Array.from({ length: 25 }, (_, i) => reject(i)), { kept_days: 7 }));
    await settle();
    assert.match(rejectsShowing(page), /Showing 21.25 of 25/, 'a refresh sent the operator back to page 1');

    page.document.getElementById('email-refresh').click();
    await settle();
    page.respond('/api/v1/email/rejects', 200, items(Array.from({ length: 12 }, (_, i) => reject(i)), { kept_days: 7 }));
    await settle();
    assert.match(rejectsShowing(page), /Showing 11.12 of 12/, 'the kept page is not clamped to the new page count');

    const filter = page.document.getElementById('email-rejects-filter');
    filter.value = 'all';
    filter.dispatchEvent(new page.window.Event('change'));
    await settle();
    page.respond('/api/v1/email/rejects', 200, items(Array.from({ length: 25 }, (_, i) => reject(i)), { kept_days: 7 }));
    await settle();
    assert.match(rejectsShowing(page), /Showing 1.10 of 25/, 'a new filter kept the old page');
});

test('a failed groups reload clears the group count', async () => {
    const page = emailPage();
    await settle();
    page.respond('/api/v1/email/groups?', 200, items([group('A'), group('B')], { handled_count: 0 }));
    await settle();
    const count = page.document.getElementById('email-groups-count');
    assert.equal(count.textContent, '2 groups');
    page.document.getElementById('email-refresh').click();
    await settle();
    page.fail('/api/v1/email/groups?');
    await settle();
    assert.match(page.document.getElementById('email-action-groups').textContent, /Failed to load what needs attention/);
    assert.equal(count.textContent, '', 'the count still reports groups the error hides');
});

test('Show all keeps keyboard focus and resets with the range', async () => {
    const page = emailPage();
    await settle();
    page.respond('/api/v1/email/groups?', 200, items(Array.from({ length: 10 }, (_, i) => group('g' + i)), { handled_count: 0 }));
    await settle();
    const more = page.document.getElementById('email-groups-more');
    more.focus();
    more.click();
    assert.equal(more.hidden, true);
    const rows = page.document.querySelectorAll('#email-action-groups .csm-summary-list__item');
    assert.equal(page.document.activeElement, rows[8], 'focus stayed on the hidden button');

    const range = page.document.getElementById('email-range');
    range.value = '7d';
    range.dispatchEvent(new page.window.Event('change'));
    await settle();
    page.respond('/api/v1/email/groups?', 200, items(Array.from({ length: 10 }, (_, i) => group('g' + i)), { handled_count: 0 }));
    await settle();
    assert.equal(groupTitles(page).length, 8, 'Show all outlived the range change');
    assert.equal(more.hidden, false);
});

// ---------- Tabs ----------

const CHECKS = { checks: [
    { name: 'mail_bruteforce', kind: 'auth_failure' },
    { name: 'smtp_bruteforce', kind: 'auth_failure' },
    { name: 'mail_queue', kind: 'queue_alert' },
    { name: 'email_dkim_failure', kind: '' }
] };

function historyQuery(page) {
    const reqs = page.pending('/api/v1/history?');
    assert.equal(reqs.length, 1, 'expected one findings request, have ' + reqs.length);
    return query(reqs[0].url);
}

function changeValue(page, el, value) {
    el.value = value;
    el.dispatchEvent(new page.window.Event('change'));
}

test('eight job tabs sit right under the headline cards', async () => {
    const page = emailPage();
    await settle();
    const doc = page.document;
    const strip = doc.getElementById('email-tabs');
    assert.equal(doc.getElementById('email-kpis').nextElementSibling, strip, 'something sits between the cards and the tabs');
    assert.equal(strip.getAttribute('role'), 'tablist');
    const tabs = Array.from(strip.querySelectorAll('[role="tab"]'));
    assert.deepEqual(tabs.map(b => b.id), TABS.map(name => 'email-tab-' + name));
    assert.deepEqual(tabs.map(b => b.textContent.replace(/\s+/g, ' ').trim()),
        ['Overview', 'Queue', 'Held mail', 'Rejects', 'Sending accounts', 'Forwarders', 'Provider delays', 'Findings']);
    for (const name of TABS) {
        const tab = doc.getElementById('email-tab-' + name);
        const pane = doc.getElementById('email-pane-' + name);
        assert.ok(pane, 'no pane for ' + name);
        assert.equal(tab.getAttribute('aria-controls'), pane.id);
        assert.equal(pane.getAttribute('role'), 'tabpanel');
        assert.equal(pane.getAttribute('aria-labelledby'), tab.id);
        const badge = tab.querySelector('[data-tab-count]');
        if (name === 'overview') {
            assert.equal(badge, null, 'Overview carries a count');
            continue;
        }
        assert.ok(badge, name + ' has no count badge');
        assert.equal(badge.hidden, true, name + ' shows a count before its data');
        assert.equal(badge.textContent, '');
    }
    for (const old of ['auth', 'quarantine', 'outbound', 'deliverability']) {
        assert.equal(doc.getElementById('email-tab-' + old), null, 'the old ' + old + ' tab is still there');
        assert.equal(doc.getElementById('email-pane-' + old), null, 'the old ' + old + ' pane is still there');
    }
    // Sending accounts: the SMTP firewall line, the accounts, then the
    // abuse events. No inner tabs. The forwarders have their own tab.
    const sending = doc.getElementById('email-pane-sending');
    assert.equal(sending.querySelectorAll('.nav-link').length, 0, 'Sending accounts still has inner tabs');
    // Held forward copies moved to Held mail.
    assert.equal(sending.contains(doc.getElementById('email-held-table')), false, 'held copies are still under Sending accounts');
    const html = sending.innerHTML;
    assert.equal(sending.contains(doc.getElementById('email-fwd-table')), false, 'the forwarders are still under Sending accounts');
    const order = ['email-sending-firewall', 'email-sending-table', 'email-abuse-events'].map(id => html.indexOf('id="' + id + '"'));
    assert.ok(order.every(i => i >= 0), 'a Sending accounts section is missing: ' + order);
    assert.deepEqual(order.slice().sort((a, b) => a - b), order, 'the Sending accounts sections are out of order');
    // On a phone the tab bar scrolls sideways instead of wrapping.
    assert.ok(strip.classList.contains('csm-tabs-scroll'));
    const css = fs.readFileSync(path.join(__dirname, 'static/css/csm.css'), 'utf8');
    const rule = css.match(/@media \(max-width: [\d.]+px\) \{\s*\.csm-tabs-scroll \{([^}]*)\}/);
    assert.ok(rule, 'no narrow-screen .csm-tabs-scroll rule');
    assert.match(rule[1], /flex-wrap: nowrap/);
    assert.match(rule[1], /overflow-x: auto/);
});

test('Overview opens first and holds the chart, rspamd, needs attention and protection', async () => {
    const page = emailPage();
    await settle();
    const doc = page.document;
    assert.equal(selectedTab(page), 'overview');
    assert.equal(urlTab(page), null);
    const overview = doc.getElementById('email-pane-overview');
    for (const id of ['email-decisions-chart', 'email-rspamd', 'email-action-groups', 'email-protection']) {
        assert.ok(overview.contains(doc.getElementById(id)), '#' + id + ' is not on Overview');
    }
    // Every other job keeps what it showed before, in its own tab.
    for (const [tab, id] of [['queue', 'queue-health'], ['queue', 'queue-composition'], ['held', 'email-held-summary'], ['held', 'email-held-table'],
        ['rejects', 'email-rejects-table'], ['sending', 'email-sending-firewall'], ['forwarders', 'email-fwd-table'],
        ['delays', 'email-deliv-providers'], ['delays', 'email-deliv-ips'], ['findings', 'email-table']]) {
        assert.ok(doc.getElementById('email-pane-' + tab).contains(doc.getElementById(id)), '#' + id + ' is not in ' + tab);
    }
    assert.equal(overview.contains(doc.getElementById('email-rejects-table')), false, 'the rejects list is still on Overview');
});

test('each headline card opens the tab that explains its number', async () => {
    for (const [card, href, tab, loads, address] of [
        ['kpi-scanned', '?tab=overview', 'overview'],
        ['kpi-tagged', '?tab=overview', 'overview'],
        ['kpi-spam', '?tab=rejects', 'rejects'],
        ['kpi-other', '?tab=rejects', 'rejects'],
        ['kpi-malware', '?tab=held', 'held', '/api/v1/email/quarantine'],
        // The address keeps the Auth failures filter, so a reload keeps it.
        ['kpi-logins', '?tab=auth', 'findings', null, 'auth'],
        ['kpi-queue', '?tab=queue', 'queue', '/api/v1/email/queue-composition']
    ]) {
        const page = emailPage({ url: 'https://csm.example.test/email?tab=delays' });
        await settle();
        assert.equal(selectedTab(page), 'delays');
        const link = page.document.querySelector('#' + card + ' a.card');
        assert.ok(link, card + ' is not a link');
        // The address opens the same tab in a new browser tab.
        assert.equal(link.getAttribute('href'), href, card);
        const newTab = new page.window.Event('click', { bubbles: true, cancelable: true, ctrlKey: true });
        link.dispatchEvent(newTab);
        assert.equal(newTab.defaultPrevented, false, card + ' blocked opening its tab in a new browser tab');
        assert.equal(selectedTab(page), 'delays', card + ' switched tabs on a click meant for a new browser tab');
        // Held mail is read with the page for its count; opening it reads
        // it once more.
        const before = loads ? page.pending(loads).length : 0;
        const click = new page.window.Event('click', { bubbles: true, cancelable: true });
        link.dispatchEvent(click);
        assert.equal(click.defaultPrevented, true, card + ' left the page');
        await settle();
        assert.equal(selectedTab(page), tab, card);
        assert.equal(urlTab(page), address || (tab === 'overview' ? null : tab), card + ' address');
        if (loads) assert.equal(page.pending(loads).length, before + 1, card + ' did not load its tab');
    }
});

test('the reject cards open Rejects on their reason', async () => {
    // Other reasons asks for every class but spam, malware and rate limiting.
    const others = 'unknown_recipient,sender_verify,bad_helo,relay_denied,auth_required,suspended,mailbox_full,blocklisted,other';
    for (const [card, cls, asked] of [['kpi-spam', 'spam', 'spam'], ['kpi-other', 'other', others]]) {
        const page = emailPage();
        await settle();
        page.document.querySelector('#' + card + ' a').click();
        await settle();
        assert.equal(selectedTab(page), 'rejects');
        assert.equal(page.document.getElementById('email-rejects-filter').value, cls);
        const reqs = page.pending('/api/v1/email/rejects');
        assert.equal(reqs.length, 1, card + ' did not reload the rejects');
        assert.equal(query(reqs[0].url).get('class'), asked);
    }
});

test('Failed logins opens Findings with the Auth failures chip on', async () => {
    const page = emailPage();
    await settle();
    page.respond('/api/v1/history?', 200, items([]));
    page.respond('/api/v1/email/checks', 200, CHECKS);
    await settle();
    page.document.querySelector('#kpi-logins a').click();
    await settle();
    assert.equal(selectedTab(page), 'findings');
    assert.equal(page.document.getElementById('email-filter-auth').getAttribute('aria-pressed'), 'true');
    assert.equal(historyQuery(page).get('checks'), 'mail_bruteforce,smtp_bruteforce');
});

test('old tab names in the address open the job tab that took them over', async () => {
    for (const [old, tab] of [['quarantine', 'held'], ['outbound', 'sending'], ['senders', 'sending'], ['outbound-abuse', 'sending'],
        ['forwarders', 'forwarders'], ['deliverability', 'delays'], ['findings', 'findings'], ['queue', 'queue'], ['held', 'held'],
        ['rejects', 'rejects'], ['sending', 'sending'], ['delays', 'delays'], ['overview', 'overview'], ['no-such-tab', 'overview']]) {
        const page = emailPage({ url: 'https://csm.example.test/email?tab=' + old });
        await settle();
        assert.equal(selectedTab(page), tab, old);
        // The address names the tab by its job, without a new history entry.
        assert.equal(urlTab(page), tab === 'overview' ? null : tab, old + ' address');
        assert.deepEqual(page.window.history.entries.filter(e => e[0] === 'push'), [], old + ' added a history entry');
    }
});

test('an old Auth tab link opens Findings filtered to auth failures', async () => {
    const page = emailPage({ url: 'https://csm.example.test/email?tab=auth' });
    await settle();
    assert.equal(selectedTab(page), 'findings');
    assert.equal(urlTab(page), 'auth');
    assert.equal(page.pending('/api/v1/history?').length, 0, 'findings loaded before the auth checks were known');
    page.respond('/api/v1/email/checks', 200, CHECKS);
    await settle();
    const chip = page.document.getElementById('email-filter-auth');
    assert.equal(chip.getAttribute('aria-pressed'), 'true');
    assert.equal(historyQuery(page).get('checks'), 'mail_bruteforce,smtp_bruteforce');

    // Without the check list the chip cannot filter; the findings load
    // unfiltered and the chip says so.
    const failed = emailPage({ url: 'https://csm.example.test/email?tab=auth' });
    await settle();
    failed.fail('/api/v1/email/checks');
    await settle();
    assert.equal(failed.document.getElementById('email-filter-auth').getAttribute('aria-pressed'), 'false');
    assert.equal(historyQuery(failed).get('checks'), null);
    assert.equal(urlTab(failed), 'findings', 'the address keeps a filter the page dropped');
});

test('a picked tab goes in the address, and Back and Forward reopen tabs', async () => {
    const page = emailPage();
    await settle();
    showEmailTab(page, 'queue');
    await settle();
    assert.deepEqual(page.window.history.entries.at(-1), ['push', 'https://csm.example.test/email?tab=queue']);
    showEmailTab(page, 'overview');
    await settle();
    assert.deepEqual(page.window.history.entries.at(-1), ['push', 'https://csm.example.test/email']);
    const pushes = page.window.history.entries.length;

    page.window.location._set('https://csm.example.test/email?tab=queue');
    page.window.dispatchEvent(new page.window.Event('popstate'));
    await settle();
    assert.equal(selectedTab(page), 'queue');
    page.window.location._set('https://csm.example.test/email?tab=quarantine');
    page.window.dispatchEvent(new page.window.Event('popstate'));
    await settle();
    assert.equal(selectedTab(page), 'held');
    page.window.location._set('https://csm.example.test/email');
    page.window.dispatchEvent(new page.window.Event('popstate'));
    await settle();
    assert.equal(selectedTab(page), 'overview');
    assert.deepEqual(page.window.history.entries.slice(pushes).filter(e => e[0] === 'push'), [], 'walking history added entries');
});

test('the Queue tab counts the queue once its size is known', async () => {
    const badge = (page, name) => page.document.querySelector('#email-tab-' + name + ' [data-tab-count]');
    const page = emailPage();
    await settle();
    assert.equal(badge(page, 'queue').hidden, true, 'a count before the overview answered');
    page.respond('/api/v1/email/overview', 200, overview({}, { queue: { size: 18, unavailable: false, warn: 100, crit: 500, frozen: 0, detail_unavailable: false } }));
    await settle();
    assert.equal(badge(page, 'queue').hidden, false);
    assert.equal(badge(page, 'queue').textContent, '18');
    assert.doesNotMatch(badge(page, 'queue').className, /badge-warning/, 'a queue under its warn threshold is colored');
    for (const name of ['held', 'sending', 'forwarders', 'delays', 'findings']) {
        assert.equal(badge(page, name).hidden, true, name + ' shows a count nothing set');
    }
    // Rejects count from the same overview.
    assert.equal(badge(page, 'rejects').textContent, '0');

    // The badge takes the card's color: amber from warn, red from crit.
    for (const [queue, text, color] of [
        [{ size: 1234, unavailable: false, warn: 100, crit: 500 }, '1,234', 'badge-critical'],
        [{ size: 500, unavailable: false, warn: 100, crit: 500 }, '500', 'badge-critical'],
        [{ size: 499, unavailable: false, warn: 100, crit: 500 }, '499', 'badge-warning'],
        [{ size: 100, unavailable: false, warn: 100, crit: 500 }, '100', 'badge-warning'],
        [{ size: 600, unavailable: false, warn: 100, crit: 0 }, '600', 'badge-warning'],
        [{ size: 99, unavailable: false, warn: 100, crit: 500 }, '99', ''],
        [{ size: 0, unavailable: false, warn: 100, crit: 500 }, '0', ''],
        [{ size: 0, unavailable: true, warn: 100, crit: 500 }, '?', '']
    ]) {
        const p = emailPage();
        p.respond('/api/v1/email/overview', 200, overview({}, { queue: Object.assign({ frozen: 0, detail_unavailable: false }, queue) }));
        await settle();
        const b = badge(p, 'queue');
        assert.equal(b.hidden, false);
        assert.equal(b.textContent, text);
        const shown = (b.className.match(/badge-(warning|critical)/g) || []).join(' ');
        assert.equal(shown, color, text + ': ' + b.className);
        if (color) assert.match(p.document.querySelector('#kpi-queue [data-kpi-value]').className, color === 'badge-critical' ? /text-danger/ : /text-warning/, text + ': the card disagrees');
    }

    const failed = emailPage();
    failed.fail('/api/v1/email/overview');
    await settle();
    assert.equal(badge(failed, 'queue').hidden, false);
    assert.equal(badge(failed, 'queue').textContent, '?', 'a failed read left a queue count that looks known');
});

test('phones hide finding details until their row is expanded', () => {
    // Row cards turn every row into a block, details rows included, unless
    // the phone block hides the closed ones again.
    const css = fs.readFileSync(path.join(__dirname, 'static/css/csm.css'), 'utf8');
    const blocks = css.split('@media').filter(b => b.includes('.csm-table-rowcard tbody tr {'));
    assert.equal(blocks.length, 1, 'no single row-card phone block');
    assert.match(blocks[0], /\.csm-table-rowcard tbody tr\.details-row:not\(\.show\) \{\s*display: none;\s*\}/);
});

test('findings use the email scope and the header range', async () => {
    const page = emailPage({ storage: CHATHAM });
    await settle();
    const doc = page.document;
    assert.equal(doc.getElementById('filter-from'), null);
    assert.equal(doc.getElementById('filter-to'), null);
    const ov = query(page.pending('/api/v1/email/overview')[0].url);
    const q = historyQuery(page);
    assert.equal(q.get('scope'), 'email');
    assert.equal(q.get('checks'), null, 'the default request names checks');
    assert.equal(q.get('from'), ov.get('from'));
    assert.ok(Math.abs(Date.parse(q.get('to')) - Date.parse(ov.get('to'))) < 1000, 'the findings range does not end with the overview');
    page.respond('/api/v1/history?', 200, items([]));
    await settle();
    assert.match(doc.getElementById('email-tbody').textContent, /No email findings in the last 24 hours/);
    assert.ok(doc.querySelector('#email-tbody .csm-empty'), 'not the shared empty state');

    changeValue(page, doc.getElementById('email-range'), '7d');
    await settle();
    const prefs = page.window.CSM.prefs;
    assert.equal(historyQuery(page).get('from'), new Date(prefs.dayBoundary(daysBefore(prefs.today(), 6), false)).toISOString());
});

test('a truncated findings page says so once', async () => {
    const page = emailPage();
    await settle();
    const row = { severity: 'HIGH', check: 'mail_bruteforce', message: 'm', timestamp: AT };
    page.respond('/api/v1/history?', 200, items([row], { total: 400, limit: 250, truncated: true }));
    await settle();
    const pane = page.document.getElementById('email-pane-findings');
    assert.equal(pane.querySelectorAll('.csm-truncation-note').length, 1);
    changeValue(page, page.document.getElementById('filter-severity'), '1');
    await settle();
    page.respond('/api/v1/history?', 200, items([row], { total: 400, limit: 250, truncated: true }));
    await settle();
    assert.equal(pane.querySelectorAll('.csm-truncation-note').length, 1, 'a reload stacked a second note');
    changeValue(page, page.document.getElementById('filter-severity'), '2');
    await settle();
    page.respond('/api/v1/history?', 200, items([row], { total: 1, limit: 250, truncated: false }));
    await settle();
    assert.equal(pane.querySelectorAll('.csm-truncation-note').length, 0);
});

test('the severity filter keeps old dates out of the address', async () => {
    const page = emailPage({ url: 'https://csm.example.test/email?from=2026-09-23&to=2026-09-23' });
    await settle();
    const doc = page.document;
    changeValue(page, doc.getElementById('email-range'), '24h');
    await settle();
    changeValue(page, doc.getElementById('filter-severity'), '2');
    await settle();
    const url = new URL(page.window.location.href);
    assert.equal(url.searchParams.get('severity'), '2');
    assert.equal(url.searchParams.get('from'), null, 'the severity filter wrote the old from day back');
    assert.equal(url.searchParams.get('to'), null, 'the severity filter wrote the old to day back');
});

test('the auth chip filters to auth failure checks', async () => {
    const page = emailPage();
    await settle();
    const doc = page.document;
    const check = doc.getElementById('filter-check');
    const chip = doc.getElementById('email-filter-auth');
    assert.deepEqual(Array.from(check.options).map(o => o.textContent.trim()), ['All email checks']);
    assert.equal(chip.disabled, true, 'the chip works before the check list is known');
    page.respond('/api/v1/history?', 200, items([]));
    page.respond('/api/v1/email/checks', 200, CHECKS);
    await settle();
    assert.deepEqual(Array.from(check.options).map(o => o.value), ['', 'mail_bruteforce', 'smtp_bruteforce', 'mail_queue', 'email_dkim_failure']);
    assert.equal(chip.disabled, false);
    assert.equal(chip.textContent.trim(), 'Auth failures');
    assert.equal(chip.getAttribute('aria-pressed'), 'false');

    chip.click();
    await settle();
    assert.equal(historyQuery(page).get('checks'), 'mail_bruteforce,smtp_bruteforce');
    assert.equal(chip.getAttribute('aria-pressed'), 'true');
    assert.equal(chip.textContent.trim(), 'Auth failures');
    page.respond('/api/v1/history?', 200, items([]));
    await settle();

    // A check picked from the list replaces the chip.
    changeValue(page, check, 'mail_queue');
    await settle();
    assert.equal(historyQuery(page).get('checks'), 'mail_queue');
    assert.equal(chip.getAttribute('aria-pressed'), 'false');
    page.respond('/api/v1/history?', 200, items([]));
    await settle();

    // And the chip replaces the picked check.
    chip.click();
    await settle();
    assert.equal(historyQuery(page).get('checks'), 'mail_bruteforce,smtp_bruteforce');
    assert.equal(check.value, '');
    page.respond('/api/v1/history?', 200, items([]));
    await settle();

    chip.click();
    await settle();
    assert.equal(historyQuery(page).get('checks'), null, 'the chip turned off still filters');
});

test('a check from the address filters before the check list answers', async () => {
    const page = emailPage({ url: 'https://csm.example.test/email?check=mail_queue' });
    await settle();
    assert.equal(historyQuery(page).get('checks'), 'mail_queue');
    page.respond('/api/v1/email/checks', 200, CHECKS);
    await settle();
    assert.equal(page.document.getElementById('filter-check').value, 'mail_queue');
});

test('Sending accounts loads the SMTP firewall when first shown', async () => {
    const page = emailPage();
    await answerAll(page, { '/api/v1/email/overview': overview({}) });
    page.window.CSM.refresh.manual();
    await answerAll(page, { '/api/v1/email/overview': overview({}) });
    const stats = () => page.requests.filter(r => r.url.includes('/api/v1/email/stats'));
    assert.equal(stats().length, 0, 'the page read the SMTP firewall before the Sending accounts tab opened');
    const tab = page.document.getElementById('email-tab-sending');
    tab.dispatchEvent(new page.window.Event('shown.bs.tab'));
    await settle();
    assert.equal(stats().length, 1);
    page.respond('/api/v1/email/stats', 200, { queue_size: 0, queue_warn: 100, queue_crit: 500, frozen_count: 0, smtp_block: true,
        smtp_allow_users: ['alice', 'bob'], smtp_ports: [25, 587], port_flood: [{ port: 25, proto: 'tcp', hits: 10, window_seconds: 60 }],
        top_senders: [{ domain: 'shop.example.com', count: 12 }] });
    await settle();
    const fw = page.document.getElementById('email-sending-firewall');
    assert.equal(fw.children.length, 1, 'the SMTP firewall is more than one line');
    assert.match(flat(fw), /restricted/i);
    assert.match(flat(fw), /alice, bob/);
    assert.match(flat(fw), /Port 25: 10 \/ 60s/);
    tab.dispatchEvent(new page.window.Event('shown.bs.tab'));
    await settle();
    assert.equal(stats().length, 1, 'opening the tab again read the SMTP firewall again');
});

test('the queue tab draws its warn and crit marks on the size bar', async () => {
    const page = emailPage();
    page.respond('/api/v1/email/overview', 200, overview({}, {
        queue: { size: 120, unavailable: false, warn: 100, crit: 500, frozen: 2, oldest_age_seconds: 4 * DAY, detail_unavailable: false }
    }));
    await settle();
    const doc = page.document;
    doc.getElementById('email-tab-queue').dispatchEvent(new page.window.Event('shown.bs.tab'));
    await settle();
    const health = doc.getElementById('queue-health');
    const warn = health.querySelector('[data-queue-mark="warn"]');
    const crit = health.querySelector('[data-queue-mark="crit"]');
    assert.ok(warn && crit, 'no warn and crit marks on the bar');
    // The bar runs a quarter past crit, so crit sits at 80%.
    assert.equal(warn.style.left, '16%');
    assert.equal(crit.style.left, '80%');
    assert.equal(flat(health.querySelector('.csm-queue-bar__labels')), 'warn 100, crit 500');
    const bar = health.querySelector('.progress-bar');
    assert.equal(bar.getAttribute('aria-valuenow'), '19');
    assert.equal(bar.getAttribute('aria-valuetext'), '120 messages, warn 100, crit 500');
    assert.match(bar.className, /bg-warning/);
    const text = health.textContent.replace(/\s+/g, ' ');
    // The summary line beside the bar gives the count and the oldest age.
    assert.doesNotMatch(text, /oldest/, 'the bar repeats the summary line');
    assert.doesNotMatch(text, /threshold/i, 'the thresholds are rows again');

    page.respond('/api/v1/email/queue-composition', 200, { total: 120, real: 100, bounce: 20, frozen: 2, flushable_backscatter: 0,
        oldest_age_seconds: 4 * DAY, top_recipients: [{ address: 'stuck@example.net', count: 7 }] });
    await settle();
    const comp = doc.getElementById('queue-composition').textContent.replace(/\s+/g, ' ');
    assert.match(comp, /Real mail\s*100/);
    assert.match(comp, /Backscatter\s*20 \(17%\)/);
    assert.match(comp, /stuck@example\.net/);
    const pane = doc.getElementById('email-pane-queue');
    assert.equal(pane.querySelectorAll('.justify-content-between, .ms-auto').length, 0, 'a label and its value sit at opposite edges');

    const down = emailPage();
    down.respond('/api/v1/email/overview', 200, overview({}, {
        queue: { size: 0, unavailable: true, warn: 100, crit: 500, frozen: 0, detail_unavailable: true }
    }));
    await settle();
    const h = down.document.getElementById('queue-health');
    // The summary line says the size is unknown, with Retry; the size box
    // does not say it again.
    assert.equal(h.parentElement.hidden, true, 'the size box shows for an unreadable queue');
    assert.doesNotMatch(h.textContent, /Queue size unknown/, 'the size box repeats the summary error');
    assert.equal(h.querySelector('.progress-bar'), null, 'an unreadable queue draws an empty bar');
});

test('the email page has no hard-coded check list', () => {
    const src = fs.readFileSync(path.join(__dirname, 'static/js/email.js'), 'utf8');
    assert.equal(/'mail_bruteforce'/.test(src), false, 'email.js still names checks');
    assert.equal(/EMAIL_CHECKS/.test(src), false, 'email.js still holds a check list');
    const tmpl = fs.readFileSync(path.join(__dirname, 'templates/email.html'), 'utf8');
    assert.equal(/value="mail_bruteforce"/.test(tmpl), false, 'email.html still lists checks');
});

// showEmailTab opens a tab the way a click on it does: through the tab
// plugin.
function showEmailTab(page, name) {
    page.window.bootstrap.Tab.getOrCreateInstance(page.document.getElementById('email-tab-' + name)).show();
}

test('an older outbound response cannot replace the selected range', async () => {
    const page = emailPage();
    showEmailTab(page, 'sending');
    await settle();
    const old = page.pending('/api/v1/email/relay-abuse?')[0];
    changeValue(page, page.document.getElementById('email-range'), '7d');
    await settle();
    const recent = page.pending('/api/v1/email/relay-abuse?').at(-1);
    assert.notEqual(recent.url, old.url);
    page.respond(recent.url, 200, items([{ severity: 'HIGH', path_label: 'Current range', trigger_count: 2, detected_at: AT }]));
    await settle();
    page.respond(old.url, 200, items([]));
    await settle();
    assert.match(page.document.getElementById('email-abuse-events').textContent, /Current range/);
});

test('changing range while outbound is hidden invalidates its pending request', async () => {
    const page = emailPage();
    showEmailTab(page, 'sending');
    await settle();
    const old = page.pending('/api/v1/email/relay-abuse?')[0];
    showEmailTab(page, 'findings');
    changeValue(page, page.document.getElementById('email-range'), '7d');
    page.respond(old.url, 200, items([]));
    await settle();
    showEmailTab(page, 'sending');
    await settle();
    const requests = page.pending('/api/v1/email/relay-abuse?');
    assert.equal(requests.length, 1, 'the hidden response marked the new range loaded');
    assert.equal(query(requests[0].url).get('from'), query(page.pending('/api/v1/email/overview').at(-1).url).get('from'));
});

test('failed status refreshes do not leave healthy protection or an old chart visible', async () => {
    const page = emailPage();
    const bodies = {
        '/api/v1/email/overview': overview({ scanned: 10, clean: 10 }, { smtp_restricted: true }),
        '/api/v1/email/rspamd': { status: 'up', mode: 'enforce', available: false },
        '/api/v1/email/av/status': { enabled: true, clamd_available: true, yarax_available: true, watcher_mode: 'permission' }
    };
    await answerAll(page, bodies);
    page.document.getElementById('email-refresh').click();
    await settle();
    for (const route of ['overview', 'rspamd', 'av/status']) page.fail('/api/v1/email/' + route);
    await settle();
    const doc = page.document;
    assert.doesNotMatch(doc.getElementById('email-subtitle').textContent, /Mail flowing|Queue empty/);
    assert.equal(doc.getElementById('email-decisions-chart').hidden, true, 'old chart is still visible');
    for (const id of ['prot-antispam', 'prot-smtp', 'prot-av', 'prot-watcher']) {
        assert.ok(doc.getElementById(id).querySelector('.csm-load-error'), id + ' still reports the previous state');
    }
    doc.getElementById('email-refresh').click();
    await answerAll(page, bodies);
    assert.equal(doc.getElementById('email-decisions-chart').hidden, false);
    assert.equal(doc.getElementById('email-protection').querySelectorAll('.csm-load-error').length, 0);
    assert.match(doc.getElementById('email-subtitle').textContent, /Mail flowing/);
});

test('old rspamd and AV responses cannot overwrite newer health', async () => {
    for (const oldFails of [false, true]) {
        const page = emailPage();
        await settle();
        const oldRspamd = page.pending('/api/v1/email/rspamd')[0];
        const oldAV = page.pending('/api/v1/email/av/status')[0];
        oldRspamd.settled = oldAV.settled = true;
        page.document.getElementById('email-refresh').click();
        await settle();
        await answerAll(page, {
            '/api/v1/email/overview': overview({}),
            '/api/v1/email/rspamd': { status: 'down', mode: 'enforce', available: false },
            '/api/v1/email/av/status': { enabled: true, clamd_available: false, yarax_available: false, watcher_mode: 'disabled' }
        });
        if (oldFails) {
            oldRspamd.reject(new Error('Old request failed'));
            oldAV.reject(new Error('Old request failed'));
        } else {
            const { jsonResponse } = require('./pagekit.js');
            oldRspamd.resolve(jsonResponse(200, { status: 'up', mode: 'enforce', available: false }));
            oldAV.resolve(jsonResponse(200, { enabled: true, clamd_available: true, yarax_available: true, watcher_mode: 'permission' }));
        }
        await settle();
        assert.match(page.document.getElementById('email-rspamd').textContent, /rspamd down/);
        assert.match(page.document.getElementById('prot-antispam').textContent, /rspamd down/);
        assert.match(page.document.getElementById('prot-av').textContent, /ClamAV down, YARA-X down/);
    }
});

test('a failed rspamd refresh marks its protection status unknown', async () => {
    const page = emailPage();
    await answerAll(page, {
        '/api/v1/email/overview': overview({}),
        '/api/v1/email/rspamd': { status: 'up', mode: 'enforce', available: false }
    });
    page.document.getElementById('email-refresh').click();
    await settle();
    page.fail('/api/v1/email/rspamd');
    await settle();
    const line = page.document.getElementById('prot-antispam');
    assert.match(line.textContent, /unknown|unavailable/i);
    assert.doesNotMatch(line.querySelector('.status-dot').className, /status-green/);
});

test('custom date links normalize reversed days before requesting and charting', async () => {
    const page = emailPage({ url: 'https://csm.example.test/email?from=2026-10-21&to=2026-10-19',
        storage: { 'csm-prefs': JSON.stringify({ timezone: 'Etc/UTC' }) } });
    await settle();
    const params = query(page.pending('/api/v1/email/overview')[0].url);
    assert.equal(params.get('from'), '2026-10-19T00:00:00.000Z');
    assert.equal(params.get('to'), '2026-10-22T00:00:00.000Z');
    page.respond('/api/v1/email/overview', 200, overview({}, { series: [{ t: Date.parse('2026-10-20T12:00:00Z') / 1000, clean: 3 }] }));
    await settle();
    assert.deepEqual(Array.from(page.Chart.charts[0].data.labels), ['10-19', '10-20', '10-21']);
    assert.deepEqual(dataset(page.Chart.charts[0], 'Clean'), [0, 3, 0]);
});

test('daily bars include every quarter-hour of short and long DST days', async () => {
    for (const [day, hours] of [['2026-03-29', 23], ['2026-10-25', 25]]) {
        const page = emailPage({ url: 'https://csm.example.test/email?from=' + day + '&to=' + day,
            storage: { 'csm-prefs': JSON.stringify({ timezone: 'Europe/Bucharest' }) } });
        await settle();
        const q = query(page.pending('/api/v1/email/overview')[0].url);
        const from = Date.parse(q.get('from')), to = Date.parse(q.get('to'));
        assert.equal(to - from, hours * HOUR_MS);
        const series = Array.from({ length: hours * 4 }, (_, i) => ({ t: (from + i * 900000) / 1000, clean: 1 }));
        page.respond('/api/v1/email/overview', 200, overview({}, { series }));
        await settle();
        assert.deepEqual(dataset(page.Chart.charts[0], 'Clean'), [hours * 4]);
    }
});

test('long custom ranges bound chart work without dropping counts', async () => {
    const page = emailPage({ url: 'https://csm.example.test/email?from=2026-01-01&to=2026-12-31',
        storage: { 'csm-prefs': JSON.stringify({ timezone: 'Etc/UTC' }) } });
    page.respond('/api/v1/email/overview', 200, overview({}, { series: [
        { t: Date.parse('2026-01-01T00:00:00Z') / 1000, clean: 2 },
        { t: Date.parse('2026-12-31T23:45:00Z') / 1000, clean: 3 }
    ] }));
    await settle();
    const counts = dataset(page.Chart.charts[0], 'Clean');
    assert.ok(counts.length <= 30, 'a long date link built ' + counts.length + ' daily bars');
    assert.equal(counts[0], 2);
    assert.equal(counts.at(-1), 3);
    assert.equal(counts.reduce((a, b) => a + b, 0), 5);
});

test('recipient and check names remain text in every email view', async () => {
    const page = emailPage();
    const payload = '<img src=x onerror=alert(1)>';
    showEmailTab(page, 'rejects');
    await settle();
    page.respond('/api/v1/email/rejects', 200, items([{ at: AT, class: 'spam', recipient: payload + '@example.net' }]));
    page.respond('/api/v1/email/checks', 200, { checks: [{ name: payload, kind: 'auth_failure' }] });
    page.respond('/api/v1/history?', 200, items([{ timestamp: AT, check: payload, message: 'Synthetic finding', severity: 'HIGH' }]));
    await settle();
    for (const id of ['email-rejects-tbody', 'filter-check', 'email-tbody']) {
        const el = page.document.getElementById(id);
        assert.equal(el.querySelectorAll('img').length, 0, id + ' interpreted server text as markup');
        assert.ok(el.textContent.includes(payload), id + ' lost the literal server text');
    }
});

test('hour bars realign on both sides of a half-hour DST transition', async () => {
    for (const [now, transition, labels] of [
        ['2026-10-04T02:00:00Z', '2026-10-03T15:30:00Z', ['01:00', '02:30', '03:00']],
        ['2026-04-05T02:00:00Z', '2026-04-04T15:00:00Z', ['01:00', '01:30', '02:00']]
    ]) {
        const page = emailPage({ now, storage: { 'csm-prefs': JSON.stringify({ timezone: 'Australia/Lord_Howe' }) } });
        await settle();
        const start = Date.parse(transition);
        // One full hour before the jump, one half-hour after, then a full hour.
        const series = Array.from({ length: 10 }, (_, i) => ({ t: (start - HOUR_MS + i * 900000) / 1000, clean: 1 }));
        page.respond('/api/v1/email/overview', 200, overview({}, { series }));
        await settle();
        const chart = page.Chart.charts[0];
        const filled = dataset(chart, 'Clean').map((v, i) => [chart.data.labels[i], v]).filter(row => row[1]);
        assert.deepEqual(filled, labels.map((label, i) => [label, i === 1 ? 2 : 4]));
    }
});

// ---------- Queue tab ----------

const QID = ['1aB2cD-000001-Ab', '1aB2cD-000002-Ab', '1aB2cD-000003-Ab'];

// queueMsg is one queued message as the queue list sends it.
function queueMsg(id, extra) {
    return Object.assign({
        id, arrived: AT, age_seconds: 1800, size: 1536, sender: 'shop@example.com', local_user: '',
        frozen: false, bounce: false, recipients: ['first@example.net'], recipient_count: 1, delivered: 0,
        reason: { class: 'refused', text: 'connection refused', raw: 'H=mx.example.net [192.0.2.25]: Connection refused' }
    }, extra);
}

// queueList is a queue list page holding list, with whole-queue counts
// that fit it unless extra says otherwise.
function queueList(list, extra) {
    return Object.assign({
        items: list, total: list.length, page: 1, limit: 25, unavailable: false, queued: list.length, listed_at: AT,
        frozen: list.filter(m => m.frozen).length, backscatter: list.filter(m => m.bounce).length,
        oldest_seconds: list.length ? list[0].age_seconds : undefined
    }, extra);
}

function flat(el) {
    return el.textContent.replace(/\s+/g, ' ').trim();
}

// queueOverview is an overview whose live queue holds size messages.
function queueOverview(size, extra) {
    return overview({}, { queue: Object.assign({ size, unavailable: false, warn: 100, crit: 500, frozen: 0, detail_unavailable: false }, extra) });
}

// queuePage opens the Queue tab, answers the overview with a live queue
// size that fits the list, answers the list, and records toasts.
async function queuePage(list, extra) {
    const page = emailPage();
    showEmailTab(page, 'queue');
    await settle();
    const q = queueList(list, extra);
    page.respond('/api/v1/email/overview', 200, queueOverview(q.queued, { frozen: q.frozen, oldest_age_seconds: q.oldest_seconds }));
    page.respond('/api/v1/email/queue?', 200, q);
    await settle();
    page.toasts = [];
    page.window.CSM.toast = (message, type) => page.toasts.push([message, type]);
    return page;
}

// stubConfirm answers every confirm with ok (or cancel) and records what
// it asked.
function stubConfirm(page, ok = true) {
    const asked = [];
    page.window.CSM.confirm = (message, opts) => {
        asked.push({ message, opts: opts || {} });
        return ok ? Promise.resolve() : Promise.reject();
    };
    return asked;
}

function queueRows(page) {
    return Array.from(page.document.getElementById('email-queue-tbody').children).filter(tr => !tr.classList.contains('details-row'));
}

function queueRow(page, id) {
    const row = queueRows(page).find(tr => tr.getAttribute('data-queue-id') === id);
    assert.ok(row, 'no row for ' + id);
    return row;
}

function requestCount(page, match) {
    return page.requests.filter(r => r.url.includes(match)).length;
}

test('the Queue tab sums up the queue in one sentence beside the backscatter flush', async () => {
    const page = emailPage();
    showEmailTab(page, 'queue');
    await settle();
    const reqs = page.pending('/api/v1/email/queue?');
    assert.equal(reqs.length, 1, 'the Queue tab did not ask for the queue list');
    const q = query(reqs[0].url);
    assert.deepEqual([q.get('page'), q.get('limit'), q.get('filter'), q.get('q')], ['1', '25', 'all', '']);
    page.respond('/api/v1/email/overview', 200, queueOverview(21, { frozen: 4, oldest_age_seconds: 3 * DAY + 7 * 3600 }));
    page.respond('/api/v1/email/queue?', 200, queueList([queueMsg(QID[0])],
        { total: 21, queued: 21, frozen: 4, backscatter: 6, oldest_seconds: 3 * DAY + 7 * 3600 }));
    page.respond('/api/v1/email/queue-composition', 200, { total: 21, real: 15, bounce: 6, frozen: 4, flushable_backscatter: 3, top_recipients: [] });
    await settle();
    const summary = page.document.getElementById('email-queue-summary');
    assert.match(flat(summary), /^21 queued, 4 frozen, oldest 3d 7h\. 6 are bounces to senders that do not exist \(backscatter\)\./);
    const flush = summary.querySelector('#flush-backscatter-btn');
    assert.ok(flush, 'no backscatter flush in the summary line');
    assert.match(flat(flush), /Flush 3 frozen backscatter message\(s\)/);
    assert.equal(page.document.querySelectorAll('#flush-backscatter-btn').length, 1, 'a second flush button');

    const asked = stubConfirm(page);
    const overviews = requestCount(page, '/api/v1/email/overview');
    flush.click();
    await settle();
    assert.equal(asked.length, 1);
    assert.equal(asked[0].opts.danger, true);
    const post = page.pending('/api/v1/email/queue/flush-backscatter');
    assert.equal(post.length, 1);
    assert.equal(post[0].method, 'POST');
    page.respond('/api/v1/email/queue/flush-backscatter', 200, { removed: 3 });
    await settle();
    assert.equal(page.pending('/api/v1/email/queue?').length, 1, 'the list did not reload after the flush');
    assert.equal(page.pending('/api/v1/email/queue-composition').length, 1, 'the flush count did not reload');
    assert.equal(requestCount(page, '/api/v1/email/overview'), overviews + 1, 'the queue size did not reload');
});

test('the backscatter flush keeps the focus while the queue numbers stay the same', async () => {
    const page = await queuePage([queueMsg(QID[0], { bounce: true, frozen: true })], { queued: 1, frozen: 1, backscatter: 1 });
    page.respond('/api/v1/email/queue-composition', 200, { total: 1, real: 0, bounce: 1, frozen: 1, flushable_backscatter: 1, top_recipients: [] });
    await settle();
    const flush = page.document.getElementById('flush-backscatter-btn');
    flush.focus();
    // The 30 s timer answers the overview and the list with the same numbers.
    page.window.CSM.refresh.manual();
    await settle();
    page.respond('/api/v1/email/overview', 200, queueOverview(1, { frozen: 1, oldest_age_seconds: 1800 }));
    page.respond('/api/v1/email/queue?', 200, queueList([queueMsg(QID[0], { bounce: true, frozen: true })], { queued: 1, frozen: 1, backscatter: 1 }));
    await settle();
    assert.equal(page.document.getElementById('flush-backscatter-btn'), flush, 'the summary was rebuilt');
    assert.equal(page.document.activeElement, flush, 'the flush button lost the focus');
    // New numbers still show.
    page.window.CSM.refresh.manual();
    await settle();
    page.respond('/api/v1/email/overview', 200, queueOverview(2, { frozen: 1 }));
    await settle();
    assert.match(flat(page.document.getElementById('email-queue-summary')), /^2 queued, 1 frozen/);
});

test('the queue summary words one bounce, no bounces and a queue with no dated message', async () => {
    for (const [extra, want] of [
        [{ queued: 2, frozen: 0, backscatter: 1, oldest_seconds: 90 }, '2 queued, 0 frozen, oldest 1m 30s. 1 is a bounce to a sender that does not exist (backscatter).'],
        [{ queued: 1, frozen: 1, backscatter: 0, oldest_seconds: 3600 }, '1 queued, 1 frozen, oldest 1h.'],
        [{ queued: 1234, frozen: 0, backscatter: 0, oldest_seconds: undefined }, '1,234 queued, 0 frozen.']
    ]) {
        const page = await queuePage([queueMsg(QID[0])], extra);
        assert.equal(flat(page.document.getElementById('email-queue-summary')), want);
    }
});

test('queue rows read oldest first with age, sender, recipients, size, reason and state', async () => {
    const many = Array.from({ length: 50 }, (_, i) => 'r' + i + '@example.net');
    const page = await queuePage([
        queueMsg(QID[0], { age_seconds: 3 * DAY + 7 * 3600, size: 2048, sender: '', bounce: true, frozen: true,
            recipients: ['ghost@example.net'], reason: { class: 'frozen', text: 'frozen: undeliverable bounce', raw: 'Frozen (delivery error message)' } }),
        queueMsg(QID[1], { age_seconds: 5 * 3600, size: 512, sender: 'news@example.com', local_user: 'shopuser',
            recipients: many, recipient_count: 120, reason: { class: 'rate_limited', text: 'rate limited', raw: '451 4.7.0 Too many messages from 203.0.113.7' } }),
        queueMsg(QID[2], { age_seconds: 1800 })
    ]);
    const doc = page.document;
    assert.deepEqual(Array.from(doc.querySelectorAll('#email-queue-table thead th')).map(flat),
        ['Age', 'From', 'To', 'Size', 'Why stuck', 'State', 'Actions']);
    assert.deepEqual(queueRows(page).map(r => r.getAttribute('data-queue-id')), QID, 'rows are not in the server order, oldest first');
    const [bounce, login, plain] = queueRows(page).map(r => Array.from(r.children).slice(0, 6).map(flat));
    assert.deepEqual(bounce, ['3d 7h', 'bounce', 'ghost@example.net', '2.0 KB', 'frozen: undeliverable bounce', 'Frozen']);
    assert.deepEqual(login, ['5h', 'news@example.com (shopuser)', 'r0@example.net +119 more', '512 B', 'rate limited', 'Queued']);
    assert.deepEqual(plain, ['30m', 'shop@example.com', 'first@example.net', '1.5 KB', 'connection refused', 'Queued']);
    // The raw SMTP text waits in the row's closed details.
    assert.doesNotMatch(flat(queueRow(page, QID[1])), /451 4\.7\.0/);
    const details = queueRow(page, QID[1]).nextElementSibling;
    assert.ok(details && details.classList.contains('details-row'), 'no details row under the message');
    assert.equal(details.classList.contains('show'), false);
    // Phones get one card per message.
    assert.ok(doc.getElementById('email-queue-table').classList.contains('csm-table-rowcard'));
    // The count is the listing's, which can trail the live size: it says when.
    const asOf = page.window.CSM.prefs.formatDateTime(new Date(AT)).slice(11);
    assert.equal(flat(doc.getElementById('email-queue-count')), '3 messages as of ' + asOf);
});

test('the queue list count follows each listing, even when the rows stay the same', async () => {
    const page = await queuePage([queueMsg(QID[0])]);
    const row = queueRow(page, QID[0]);
    const later = '2026-10-21T09:59:30Z';
    await queueTick(page, [queueMsg(QID[0])], { listed_at: later });
    assert.equal(queueRow(page, QID[0]), row, 'the unchanged rows were drawn again');
    assert.equal(flat(page.document.getElementById('email-queue-count')),
        '1 message as of ' + page.window.CSM.prefs.formatDateTime(new Date(later)).slice(11));
});

test('queue rows keep sender, recipient and reason as text', async () => {
    const payload = '<img src=x onerror=alert(1)>';
    const page = await queuePage([queueMsg(QID[0], { sender: payload + '@example.com', local_user: payload,
        recipients: [payload + '@example.net'], reason: { class: 'other', text: payload, raw: payload } })]);
    const tbody = page.document.getElementById('email-queue-tbody');
    assert.equal(tbody.querySelectorAll('img').length, 0, 'server text became markup');
    for (const want of [payload + '@example.com', '(' + payload + ')', payload + '@example.net']) {
        assert.ok(tbody.textContent.includes(want), 'lost ' + want);
    }
    const asked = stubConfirm(page, false);
    queueRow(page, QID[0]).querySelector('[data-queue-action="delete"]').click();
    await settle();
    assert.ok(asked[0].message.includes(payload + '@example.net'), 'the confirm lost the recipient');
});

test('expanding a queued message shows every recipient, the error and its delivery log as text', async () => {
    const payload = '<img src=x onerror=alert(1)>';
    const page = await queuePage([queueMsg(QID[0]), queueMsg(QID[1], { recipients: ['r0@example.net', 'r1@example.net'], recipient_count: 120 })]);
    const row = queueRow(page, QID[1]);
    const btn = row.querySelector('.expand-btn');
    assert.ok(btn, 'no expand button');
    btn.click();
    await settle();
    const detailURL = '/api/v1/email/queue/' + QID[1];
    let reqs = page.pending(detailURL);
    assert.equal(reqs.length, 1, 'expanding did not read the message');
    assert.equal(reqs[0].method, 'GET');
    const all = Array.from({ length: 120 }, (_, i) => 'r' + i + '@example.net');
    all[7] = payload + '@example.net';
    const log = ['2026-10-21 09:00:01 r0@example.net R=dkim_lookuphost T=remote_smtp defer (-44) H=mx.example.net [192.0.2.25]: ' +
        'SMTP error from remote mail server after RCPT TO:<r0@example.net>: 451 4.7.0 Try again later', payload];
    const detail = Object.assign(queueMsg(QID[1]), { recipients: all, recipient_count: 120, delivered: 3,
        reason: { class: 'rate_limited', text: 'rate limited', raw: '451 4.7.0 ' + payload }, msglog: log });
    page.respond(detailURL, 200, detail);
    await settle();
    let details = row.nextElementSibling;
    assert.ok(details.classList.contains('show'), 'the details did not open');
    for (const r of all) assert.ok(details.textContent.includes(r), 'missing recipient ' + r);
    assert.match(flat(details), /Undelivered recipients \(120\)/);
    assert.match(flat(details), /Already delivered: 3/);
    assert.ok(details.textContent.includes('451 4.7.0 ' + payload), 'the full error text is missing');
    const pre = details.querySelector('pre');
    assert.ok(pre, 'no delivery log');
    assert.equal(pre.textContent, log.join('\n'));
    assert.equal(details.querySelectorAll('img, script').length, 0, 'server text became markup');

    // A refresh keeps the message open and reads it again.
    page.document.getElementById('email-refresh').click();
    await settle();
    page.respond('/api/v1/email/queue?', 200, queueList([queueMsg(QID[0]), queueMsg(QID[1])]));
    await settle();
    details = queueRow(page, QID[1]).nextElementSibling;
    assert.ok(details.classList.contains('show'), 'a refresh closed the open message');
    assert.equal(page.pending(detailURL).length, 1, 'the open message was not read again');
    page.respond(detailURL, 200, detail);
    await settle();
    assert.equal(details.querySelector('pre').textContent, log.join('\n'));

    // Closing asks for nothing; opening again reads the message afresh.
    const again = queueRow(page, QID[1]).querySelector('.expand-btn');
    again.click();
    await settle();
    assert.equal(details.classList.contains('show'), false);
    assert.equal(page.pending(detailURL).length, 0);
    again.click();
    await settle();
    page.respond(detailURL, 500, { error: 'Failed to read the message from the queue: exim timed out' });
    await settle();
    assert.match(flat(details), /exim timed out/);
    details.querySelector('.csm-retry-btn').click();
    await settle();
    reqs = page.pending(detailURL);
    assert.equal(reqs.length, 1, 'Retry did not read the message again');
    page.respond(detailURL, 404, { error: 'Message is not in the queue' });
    await settle();
    assert.match(flat(details), /No longer in the queue/);
});

test('each queue action names the message and its first recipient, then posts to its route', async () => {
    for (const [action, label, okLabel, danger, words] of [
        ['thaw', 'Thaw', 'Thaw', false, /^Thaw message 1aB2cD-000002-Ab to r0@example\.net and 119 more\?/],
        ['retry', 'Retry', 'Retry now', false, /^Try delivering message 1aB2cD-000002-Ab to r0@example\.net and 119 more now\?/],
        ['bounce', 'Return', 'Return to sender', true, /^Give up on message 1aB2cD-000002-Ab to r0@example\.net and 119 more and return it to its sender\?/],
        ['delete', 'Delete', 'Delete', true, /^Delete message 1aB2cD-000002-Ab to r0@example\.net and 119 more\? No bounce is sent/]
    ]) {
        const page = await queuePage([queueMsg(QID[0]), queueMsg(QID[1], { frozen: true, recipients: ['r0@example.net'], recipient_count: 120 })]);
        const asked = stubConfirm(page);
        const btn = queueRow(page, QID[1]).querySelector('[data-queue-action="' + action + '"]');
        assert.equal(flat(btn), label);
        const overviews = requestCount(page, '/api/v1/email/overview');
        btn.click();
        await settle();
        assert.equal(asked.length, 1, action + ' did not ask first');
        assert.match(asked[0].message, words);
        assert.equal(asked[0].opts.okLabel, okLabel);
        assert.equal(!!asked[0].opts.danger, danger, action + ' danger');
        const posts = page.pending('/api/v1/email/queue/' + QID[1] + '/' + action);
        assert.equal(posts.length, 1, action + ' did not post to its route');
        assert.equal(posts[0].method, 'POST');
        assert.ok(Object.prototype.hasOwnProperty.call(posts[0].headers, 'X-CSRF-Token'), action + ' posted without the CSRF header');
        assert.equal(page.requests.filter(r => r.method === 'POST').length, 1, action + ' posted elsewhere too');
        page.respond('/api/v1/email/queue/' + QID[1] + '/' + action, 200, { outcome: 'unchanged' });
        await settle();
        assert.equal(page.pending('/api/v1/email/queue?').length, 1, 'the list did not reload after ' + action);
        assert.equal(requestCount(page, '/api/v1/email/overview'), overviews + 1, 'the queue size did not reload after ' + action);
    }

    // Cancel posts nothing. A bounce returned to its null sender makes no
    // new bounce, and the confirm says so.
    const page = await queuePage([queueMsg(QID[0], { sender: '', bounce: true })]);
    const asked = stubConfirm(page, false);
    queueRow(page, QID[0]).querySelector('[data-queue-action="bounce"]').click();
    await settle();
    assert.match(asked[0].message, /^Give up on message 1aB2cD-000001-Ab to first@example\.net and return it to its sender\? It is a bounce itself, so exim sends no new bounce\./);
    assert.equal(page.requests.filter(r => r.method === 'POST').length, 0);
});

test('queue action outcomes read as plain toasts', async () => {
    for (const [action, status, body, toast] of [
        ['delete', 200, { outcome: 'removed' }, ['Deleted', 'success']],
        ['bounce', 200, { outcome: 'bounced' }, ['Returned to sender', 'success']],
        ['retry', 200, { outcome: 'attempt_started' }, ['Delivery attempt started', 'success']],
        ['thaw', 200, { outcome: 'thawed' }, ['Thawed', 'success']],
        ['delete', 409, { error: 'Message is no longer in the queue', outcome: 'gone' }, ['No longer in the queue', 'info']],
        ['thaw', 200, { outcome: 'unchanged' }, ['Nothing changed', 'warning']],
        ['delete', 500, { error: 'Queue action failed: exim -Mrm: exit status 1', outcome: 'unchanged' },
            ['Nothing changed: Queue action failed: exim -Mrm: exit status 1', 'warning']],
        // The action ran, but the queue could not be read afterwards.
        ['bounce', 500, { error: 'Queue action failed: exim -Mg: exit status 1\nthe outcome could not be read back: exim -bp timed out', outcome: 'unchanged' },
            ['Outcome unknown: Queue action failed: exim -Mg: exit status 1\nthe outcome could not be read back: exim -bp timed out. Refresh to check.', 'warning']],
        ['retry', 503, { error: 'Queue actions need systemd-run: not found', outcome: 'unchanged' }, ['Queue actions need systemd-run on this server.', 'error']]
    ]) {
        const page = await queuePage([queueMsg(QID[0], { frozen: true })]);
        stubConfirm(page);
        queueRow(page, QID[0]).querySelector('[data-queue-action="' + action + '"]').click();
        await settle();
        page.respond('/api/v1/email/queue/' + QID[0] + '/' + action, status, body);
        await settle();
        assert.deepEqual(page.toasts, [toast], action + ' ' + status);
        assert.equal(page.pending('/api/v1/email/queue?').length, 1, 'the list did not reload after ' + action + ' ' + status);
    }
});

test('Thaw shows only on frozen messages', async () => {
    const page = await queuePage([queueMsg(QID[0], { frozen: true }), queueMsg(QID[1])]);
    const actions = id => Array.from(queueRow(page, id).querySelectorAll('[data-queue-action]')).map(b => b.getAttribute('data-queue-action'));
    assert.deepEqual(actions(QID[0]), ['thaw', 'retry', 'bounce', 'delete']);
    assert.deepEqual(actions(QID[1]), ['retry', 'bounce', 'delete']);
});

test('a message exim cannot read shows why, an unknown size and only Delete', async () => {
    const page = await queuePage([
        queueMsg(QID[0], { sender: '', size: 0, recipients: [], recipient_count: 0, unreadable: 'spool format error: size=37',
            reason: { class: 'unreadable', text: 'exim cannot read this message', raw: 'spool format error: size=37' } }),
        queueMsg(QID[1], { size: 0, frozen: true, unreadable: 'spool data file missing',
            reason: { class: 'unreadable', text: 'exim cannot read this message', raw: 'spool data file missing' } })
    ]);
    const [envelopeless, noData] = queueRows(page).map(r => Array.from(r.children).slice(0, 6).map(flat));
    assert.deepEqual(envelopeless, ['30m', '--', '--', '--', 'exim cannot read this message', 'Unreadable']);
    assert.deepEqual(noData, ['30m', 'shop@example.com', 'first@example.net', '--', 'exim cannot read this message', 'Unreadable']);
    for (const id of QID.slice(0, 2)) {
        assert.deepEqual(Array.from(queueRow(page, id).querySelectorAll('[data-queue-action]')).map(b => b.getAttribute('data-queue-action')), ['delete']);
    }
});

test('the queue composition counts messages exim cannot read', async () => {
    const page = await queuePage([queueMsg(QID[0])]);
    page.respond('/api/v1/email/queue-composition', 200, { total: 3, real: 1, bounce: 1, frozen: 0, flushable_backscatter: 0, unreadable: 1, top_recipients: [] });
    await settle();
    const comp = flat(page.document.getElementById('queue-composition'));
    assert.match(comp, /Unreadable\s*1/);
});

test('an unreadable queue says the size is unknown, with Retry', async () => {
    const page = emailPage();
    showEmailTab(page, 'queue');
    await settle();
    page.respond('/api/v1/email/queue?', 200, { unavailable: true, items: [], page: 1, limit: 25 });
    await settle();
    const doc = page.document;
    const summary = doc.getElementById('email-queue-summary');
    assert.match(flat(summary), /Queue size unknown/);
    assert.doesNotMatch(flat(summary), /\d+ queued|queue is empty/i, 'an unreadable queue reads as a count');
    assert.equal(doc.getElementById('email-queue-list').hidden, true, 'the list shows under an unreadable queue');
    summary.querySelector('.csm-retry-btn').click();
    await settle();
    assert.equal(page.pending('/api/v1/email/queue?').length, 1, 'Retry did not read the queue again');
    page.fail('/api/v1/email/queue?', new Error('Mail queue is not available on this host'));
    await settle();
    assert.match(flat(summary), /Queue size unknown/);
    assert.match(flat(summary), /Mail queue is not available on this host/);
    summary.querySelector('.csm-retry-btn').click();
    await settle();
    page.respond('/api/v1/email/overview', 200, queueOverview(1));
    page.respond('/api/v1/email/queue?', 200, queueList([queueMsg(QID[0])]));
    await settle();
    assert.equal(doc.getElementById('email-queue-list').hidden, false);
    assert.match(flat(summary), /^1 queued/);
});

test('a queue list behind the known queue size says the list is refreshing, not that the size is unknown', async () => {
    const page = emailPage();
    showEmailTab(page, 'queue');
    await settle();
    page.respond('/api/v1/email/queue?', 200, { unavailable: true, items: [], page: 1, limit: 25 });
    await settle();
    const summary = page.document.getElementById('email-queue-summary');
    // The card counts the queue: the size is known, the list is behind it.
    page.respond('/api/v1/email/overview', 200, queueOverview(2, { detail_unavailable: true }));
    await settle();
    assert.equal(kpi(page, 'kpi-queue').value, '2');
    assert.match(flat(summary), /Queue list refreshing/);
    assert.doesNotMatch(flat(summary), /size unknown/i);
    assert.equal(summary.querySelectorAll('.csm-load-error').length, 1, 'not one error state');
    summary.querySelector('.csm-retry-btn').click();
    await settle();
    page.respond('/api/v1/email/queue?', 200, queueList([queueMsg(QID[0]), queueMsg(QID[1])]));
    await settle();
    assert.match(flat(summary), /^2 queued/);
    // A failed list read says the list failed; the size is still known.
    page.document.getElementById('email-refresh').click();
    await settle();
    page.fail('/api/v1/email/queue?', new Error('HTTP 502'));
    await settle();
    assert.match(flat(summary), /Failed to load the queue list/);
    assert.match(flat(summary), /HTTP 502/);
    assert.doesNotMatch(flat(summary), /size unknown/i);
});

test('an empty queue says so', async () => {
    const page = await queuePage([]);
    assert.equal(flat(page.document.getElementById('email-queue-summary')), 'The queue is empty.');
    assert.equal(page.document.getElementById('email-queue-list').hidden, true);
});

test('the queue summary counts the live queue size the card and the tab show', async () => {
    const page = emailPage();
    showEmailTab(page, 'queue');
    await settle();
    page.respond('/api/v1/email/overview', 200, queueOverview(21, { frozen: 4 }));
    // The list counts from a listing up to a minute old.
    page.respond('/api/v1/email/queue?', 200, queueList([queueMsg(QID[0])], { queued: 8, frozen: 4 }));
    await settle();
    const doc = page.document;
    const summary = doc.getElementById('email-queue-summary');
    assert.match(flat(summary), /^21 queued, 4 frozen/);
    assert.equal(kpi(page, 'kpi-queue').value, '21');
    assert.equal(doc.querySelector('#email-tab-queue [data-tab-count]').textContent, '21');

    // The next overview moves the summary with the card, before the list.
    doc.getElementById('email-refresh').click();
    await settle();
    page.respond('/api/v1/email/overview', 200, queueOverview(22, { frozen: 4 }));
    await settle();
    assert.match(flat(summary), /^22 queued/);
    assert.equal(kpi(page, 'kpi-queue').value, '22');

    // When the overview cannot say, the size is unknown; the list's own
    // count does not stand in for it, and the messages stay.
    doc.getElementById('email-refresh').click();
    await settle();
    page.fail('/api/v1/email/overview', new Error('HTTP 502'));
    await settle();
    assert.match(flat(summary), /Queue size unknown/);
    assert.match(flat(summary), /HTTP 502/);
    assert.doesNotMatch(flat(summary), /\d+ queued/);
    assert.equal(doc.getElementById('email-queue-list').hidden, false, 'the messages hid with the size');
    page.respond('/api/v1/email/queue?', 200, queueList([queueMsg(QID[0])], { queued: 8 }));
    await settle();
    assert.doesNotMatch(flat(summary), /\d+ queued/, 'the list count stood in for the unknown size');
});

test('a queue action with no answer has an unknown outcome', async () => {
    for (const [error, words] of [
        [Object.assign(new Error('signal is aborted without reason'), { name: 'AbortError' }), 'no answer within a minute'],
        [new TypeError('Failed to fetch'), 'Failed to fetch']
    ]) {
        const page = await queuePage([queueMsg(QID[0])]);
        stubConfirm(page);
        const delays = [];
        const realTimeout = page.window.setTimeout;
        page.window.setTimeout = (fn, ms, ...args) => { delays.push(ms); return realTimeout(fn, ms, ...args); };
        queueRow(page, QID[0]).querySelector('[data-queue-action="delete"]').click();
        await settle();
        page.window.setTimeout = realTimeout;
        // exim can take most of a minute; the request waits that long.
        assert.ok(delays.includes(60000), 'the action keeps the default timeout: ' + delays.join(', '));
        page.fail('/api/v1/email/queue/' + QID[0] + '/delete', error);
        await settle();
        assert.deepEqual(page.toasts, [['Outcome unknown: ' + words + '. Refresh to check.', 'warning']]);
        assert.equal(page.pending('/api/v1/email/queue?').length, 1, 'the list did not reload');
    }
});

test('a failed queue reload drops the old count, and says so once', async () => {
    const page = await queuePage([queueMsg(QID[0])], { queued: 21 });
    const summary = page.document.getElementById('email-queue-summary');
    assert.match(flat(summary), /^21 queued/);
    page.document.getElementById('email-refresh').click();
    await settle();
    page.fail('/api/v1/email/queue?', new Error('HTTP 502'));
    await settle();
    // The card still counts 21; the list is what failed.
    assert.match(flat(summary), /Failed to load the queue list/);
    assert.doesNotMatch(flat(summary), /size unknown/i);
    // Hidden text comes back while Retry reads the queue again.
    assert.doesNotMatch(summary.textContent, /21 queued/, 'the old count hides under the error');
    summary.querySelector('.csm-retry-btn').click();
    await settle();
    assert.doesNotMatch(flat(summary), /21 queued/, 'Retry shows the old count');
    // The summary says it; no toast says it again.
    assert.deepEqual(page.toasts, []);
});

// detailOf is the expanded message's answer, with its delivery log.
function detailOf(id, extra) {
    return Object.assign(queueMsg(id), { recipients: ['first@example.net'], recipient_count: 1, delivered: 3,
        msglog: ['2026-10-21 09:00:01 first@example.net R=dkim_lookuphost T=remote_smtp defer (-44): Connection refused'] }, extra);
}

// queueTick reads the queue again, as the 30 s timer does, and answers
// the list with list.
async function queueTick(page, list, extra) {
    page.document.getElementById('email-refresh').click();
    await settle();
    page.respond('/api/v1/email/queue?', 200, queueList(list, extra));
    await settle();
}

test('an unchanged queue page keeps its rows, the focus and the open message', async () => {
    const page = await queuePage([queueMsg(QID[0]), queueMsg(QID[1])]);
    const doc = page.document;
    const row = queueRow(page, QID[1]);
    row.querySelector('.expand-btn').click();
    await settle();
    page.respond('/api/v1/email/queue/' + QID[1], 200, detailOf(QID[1]));
    await settle();
    const retry = row.querySelector('[data-queue-action="retry"]');
    retry.focus();
    // Thirty seconds on, the same messages, each half a minute older.
    await queueTick(page, [queueMsg(QID[0], { age_seconds: 1830 }), queueMsg(QID[1], { age_seconds: 1830 })]);
    assert.equal(queueRow(page, QID[1]), row, 'the rows were rebuilt');
    assert.equal(doc.activeElement, retry, 'the focus left the row');
    assert.ok(row.nextElementSibling.classList.contains('show'), 'the open message closed');
    assert.match(flat(row.nextElementSibling), /Already delivered: 3/);
    assert.equal(page.pending('/api/v1/email/queue/' + QID[1]).length, 0, 'the open message was read again');
    // The ages still move on.
    assert.equal(flat(row.children[0]), '30m 30s');
});

test('a rebuilt queue page gives the focus back and keeps open messages on screen', async () => {
    const page = await queuePage([queueMsg(QID[0]), queueMsg(QID[1])]);
    const doc = page.document;
    queueRow(page, QID[1]).querySelector('.expand-btn').click();
    await settle();
    page.respond('/api/v1/email/queue/' + QID[1], 200, detailOf(QID[1]));
    await settle();
    const old = queueRow(page, QID[1]).querySelector('[data-queue-action="delete"]');
    old.focus();
    // The first message left and a new one arrived.
    await queueTick(page, [queueMsg(QID[1]), queueMsg(QID[2])]);
    const row = queueRow(page, QID[1]);
    const del = row.querySelector('[data-queue-action="delete"]');
    assert.notEqual(del, old, 'the page was not rebuilt');
    assert.equal(doc.activeElement, del, 'the focus did not come back to Delete');
    const details = row.nextElementSibling;
    assert.ok(details.classList.contains('show'), 'the open message closed');
    // The details stay as they were while they are read again.
    assert.match(flat(details), /Already delivered: 3/);
    assert.doesNotMatch(flat(details), /Loading/);
    assert.equal(page.pending('/api/v1/email/queue/' + QID[1]).length, 1, 'the open message was not read again');
    page.respond('/api/v1/email/queue/' + QID[1], 200, detailOf(QID[1], { delivered: 4 }));
    await settle();
    assert.match(flat(details), /Already delivered: 4/);
});

test('a message keeps every action disabled while one runs, across a rebuild', async () => {
    const page = await queuePage([queueMsg(QID[0]), queueMsg(QID[1], { frozen: true })]);
    stubConfirm(page);
    const disabled = id => Array.from(queueRow(page, id).querySelectorAll('[data-queue-action]')).map(b => b.disabled);
    queueRow(page, QID[1]).querySelector('[data-queue-action="delete"]').click();
    await settle();
    assert.deepEqual(disabled(QID[1]), [true, true, true, true], 'actions stay open while one runs');
    assert.deepEqual(disabled(QID[0]), [false, false, false]);
    // A tick rebuilds the page while the delete still runs.
    await queueTick(page, [queueMsg(QID[0]), queueMsg(QID[1], { frozen: true }), queueMsg(QID[2])]);
    assert.deepEqual(disabled(QID[1]), [true, true, true, true], 'a rebuild opened the actions of a running delete');
    assert.deepEqual(disabled(QID[2]), [false, false, false]);
    page.respond('/api/v1/email/queue/' + QID[1] + '/delete', 200, { outcome: 'unchanged' });
    await settle();
    assert.deepEqual(disabled(QID[1]), [false, false, false, false], 'the actions stayed shut after the delete answered');
});

test('the queue filter, search and pages ask the server', async () => {
    const page = await queuePage([queueMsg(QID[0])], { total: 60, queued: 60 });
    const doc = page.document;
    const pager = doc.getElementById('email-queue-pager');
    assert.equal(pager.hidden, false);
    assert.equal(flat(doc.getElementById('email-queue-page')), 'Page 1 of 3');
    assert.equal(doc.getElementById('email-queue-prev').disabled, true);
    doc.getElementById('email-queue-next').click();
    await settle();
    assert.equal(query(page.pending('/api/v1/email/queue?')[0].url).get('page'), '2');
    page.respond('/api/v1/email/queue?', 200, queueList([queueMsg(QID[1])], { total: 60, queued: 60, page: 2 }));
    await settle();
    assert.equal(flat(doc.getElementById('email-queue-page')), 'Page 2 of 3');

    // A page emptied by an action falls back to the last page that has rows.
    doc.getElementById('email-queue-next').click();
    await settle();
    page.respond('/api/v1/email/queue?', 200, queueList([], { total: 50, queued: 50, page: 3 }));
    await settle();
    assert.equal(query(page.pending('/api/v1/email/queue?')[0].url).get('page'), '2');
    page.respond('/api/v1/email/queue?', 200, queueList([queueMsg(QID[1])], { total: 50, queued: 50, page: 2 }));
    await settle();
    assert.equal(flat(doc.getElementById('email-queue-page')), 'Page 2 of 2');

    changeValue(page, doc.getElementById('email-queue-filter'), 'frozen');
    await settle();
    let q = query(page.pending('/api/v1/email/queue?')[0].url);
    assert.deepEqual([q.get('filter'), q.get('page')], ['frozen', '1']);
    page.respond('/api/v1/email/queue?', 200, queueList([], { total: 0, queued: 60 }));
    await settle();
    assert.match(flat(doc.getElementById('email-queue-tbody')), /No queued messages match/);
    assert.equal(doc.getElementById('email-queue-list').hidden, false, 'a filter with no match hid the list');
    assert.equal(pager.hidden, true);
    assert.match(flat(doc.getElementById('email-queue-summary')), /^60 queued/);

    const search = doc.getElementById('email-queue-search');
    search.value = 'Example.NET';
    search.dispatchEvent(new page.window.Event('input'));
    await new Promise(r => setTimeout(r, 400));
    await settle();
    q = query(page.pending('/api/v1/email/queue?')[0].url);
    assert.deepEqual([q.get('q'), q.get('filter'), q.get('page')], ['Example.NET', 'frozen', '1']);
});

test('an older queue page cannot replace a newer one', async () => {
    const page = await queuePage([queueMsg(QID[0])], { total: 60, queued: 60 });
    const doc = page.document;
    doc.getElementById('email-queue-next').click();
    await settle();
    changeValue(page, doc.getElementById('email-queue-filter'), 'frozen');
    await settle();
    const [old, recent] = page.pending('/api/v1/email/queue?');
    page.respond(recent.url, 200, queueList([queueMsg(QID[2], { frozen: true })], { queued: 60 }));
    await settle();
    page.respond(old.url, 200, queueList([queueMsg(QID[1])], { total: 60, queued: 60, page: 2 }));
    await settle();
    assert.deepEqual(queueRows(page).map(r => r.getAttribute('data-queue-id')), [QID[2]]);
});

test('the queue size bar speaks its size and thresholds, and its labels share one line', async () => {
    for (const [queue, valuetext, at] of [
        // 16% and 80%: the line ends at the crit mark.
        [{ size: 21, warn: 100, crit: 500 }, '21 messages, warn 100, crit 500', { right: '20%' }],
        [{ size: 1, warn: 400, crit: 500 }, '1 message, warn 400, crit 500', { right: '20%' }],
        // 2% and 10%: the line starts at the warn mark.
        [{ size: 5000, warn: 100, crit: 500 }, '5,000 messages, warn 100, crit 500', { left: '2%' }],
        // Above crit the scale grows: 8% and 33%, labels would still meet.
        [{ size: 6000, warn: 500, crit: 2000 }, '6,000 messages, warn 500, crit 2,000', { left: '8%' }],
        [{ size: 21, warn: 100, crit: 0 }, '21 messages, warn 100', { right: '20%' }]
    ]) {
        const page = emailPage();
        page.respond('/api/v1/email/overview', 200, overview({}, { queue: Object.assign({ unavailable: false, frozen: 0, detail_unavailable: false }, queue) }));
        await settle();
        const health = page.document.getElementById('queue-health');
        assert.equal(health.querySelector('.progress-bar').getAttribute('aria-valuetext'), valuetext);
        const marks = [['warn', queue.warn], ['crit', queue.crit]].filter(m => m[1] > 0);
        assert.deepEqual(Array.from(health.querySelectorAll('[data-queue-mark]')).map(m => m.getAttribute('data-queue-mark')), marks.map(m => m[0]));
        // A label under each mark prints over the other once the marks
        // close up, so every label goes on one line.
        assert.equal(health.querySelectorAll('.csm-queue-mark__label').length, 0, valuetext + ': a label still sits under its mark');
        const lines = health.querySelectorAll('.csm-queue-bar__labels');
        assert.equal(lines.length, 1, valuetext + ': not one labels line');
        assert.equal(flat(lines[0]), marks.map(m => m[0] + ' ' + CSMnum(m[1])).join(', '));
        assert.deepEqual({ left: lines[0].style.left || undefined, right: lines[0].style.right || undefined }, Object.assign({ left: undefined, right: undefined }, at));
    }
});

function CSMnum(n) {
    return n.toLocaleString('en-US');
}

test('the open tab scrolls into the strip, and stays there as counts widen the tabs', async () => {
    const page = emailPage();
    await settle();
    const doc = page.document;
    const strip = doc.getElementById('email-tabs');
    const findings = doc.getElementById('email-tab-findings');
    // A phone strip from 8 to 382 px with Findings beyond its right edge.
    // The Queue count, once it shows, pushes the tabs after it 34 px right.
    const queueBadge = doc.querySelector('#email-tab-queue [data-tab-count]');
    const shift = () => queueBadge.textContent ? 34 : 0;
    strip.scrollLeft = 0;
    strip.getBoundingClientRect = () => ({ left: 8, right: 382 });
    findings.getBoundingClientRect = () => ({ left: 700 + shift() - strip.scrollLeft, right: 802 + shift() - strip.scrollLeft });
    let pageScrolls = 0;
    findings.scrollIntoView = () => { pageScrolls++; };
    doc.querySelector('#kpi-logins a').click();
    await settle();
    assert.equal(strip.scrollLeft, 420, 'Findings is not scrolled into the strip');
    page.respond('/api/v1/email/overview', 200, overview({}, { queue: { size: 21, unavailable: false, warn: 100, crit: 500, frozen: 0, detail_unavailable: false } }));
    await settle();
    assert.equal(doc.querySelector('#email-tab-queue [data-tab-count]').textContent, '21');
    assert.equal(strip.scrollLeft, 454, 'a count pushed the open tab out of the strip');
    // The strip scrolls; the page, which polls these counts, does not.
    assert.equal(pageScrolls, 0);
    // A tab left of the strip's view comes back to its left edge.
    strip.scrollLeft = 900;
    doc.querySelector('#kpi-logins a').click();
    await settle();
    assert.equal(strip.scrollLeft, 726);
});

test('count updates leave a strip the operator scrolled alone', async () => {
    const page = emailPage({ url: 'https://csm.example.test/email?tab=findings' });
    await settle();
    const doc = page.document;
    const strip = doc.getElementById('email-tabs');
    const findings = doc.getElementById('email-tab-findings');
    const queueBadge = doc.querySelector('#email-tab-queue [data-tab-count]');
    const shift = () => queueBadge.textContent ? 34 : 0;
    strip.getBoundingClientRect = () => ({ left: 8, right: 382 });
    findings.getBoundingClientRect = () => ({ left: 700 + shift() - strip.scrollLeft, right: 802 + shift() - strip.scrollLeft });
    const answer = size => page.respond('/api/v1/email/overview', 200, overview({}, { queue: { size, unavailable: false, warn: 100, crit: 500, frozen: 0, detail_unavailable: false } }));
    // The operator scrolled back to the start, away from the open tab.
    strip.scrollLeft = 0;
    answer(21);
    await settle();
    assert.equal(queueBadge.textContent, '21');
    assert.equal(strip.scrollLeft, 0, 'a new count pulled the strip back to the open tab');
    // A poll that brings the same count moves nothing, even with the open
    // tab half out of view.
    strip.scrollLeft = 400;
    doc.getElementById('email-refresh').click();
    await settle();
    answer(21);
    await settle();
    assert.equal(strip.scrollLeft, 400, 'an unchanged count moved the strip');
});

test('the refresh button reads the open Queue tab again', async () => {
    const page = await queuePage([queueMsg(QID[0])]);
    page.document.getElementById('email-refresh').click();
    await settle();
    assert.equal(page.pending('/api/v1/email/queue?').length, 1, 'refresh did not read the queue list');
});

// ---------- Tab chip, counts and address ----------

test('Failed logins cannot press a chip that has no auth checks to filter on', async () => {
    for (const checks of [null, { checks: [{ name: 'mail_queue', kind: 'queue_alert' }] }]) {
        const page = emailPage();
        await settle();
        if (checks) page.respond('/api/v1/email/checks', 200, checks);
        else page.fail('/api/v1/email/checks');
        page.respond('/api/v1/history?', 200, items([]));
        await settle();
        page.document.querySelector('#kpi-logins a').click();
        await settle();
        const chip = page.document.getElementById('email-filter-auth');
        const label = checks ? 'no auth checks' : 'check list failed';
        assert.equal(selectedTab(page), 'findings', label);
        assert.equal(chip.disabled, true, label);
        assert.equal(chip.getAttribute('aria-pressed'), 'false', label + ': a pressed chip the operator cannot clear');
        assert.equal(chip.classList.contains('active'), false, label);
        assert.equal(historyQuery(page).get('checks'), null, label);
        assert.equal(urlTab(page), 'findings', label);
    }
});

// spoken is the text a screen reader gets from el: hidden and aria-hidden
// parts left out.
function spoken(el) {
    const walk = n => n.nodeType === 3 ? n.nodeValue || n.textContent :
        n.nodeType === 1 && !n.hidden && n.getAttribute('aria-hidden') !== 'true' ? n.childNodes.map(walk).join('') : '';
    return walk(el).replace(/\s+/g, ' ').trim();
}

test('tab counts read as words, with their level, to a screen reader', async () => {
    const tab = page => page.document.getElementById('email-tab-queue');
    const page = emailPage();
    await settle();
    assert.equal(spoken(tab(page)), 'Queue', 'a count before the overview answered');
    for (const [queue, words] of [
        [{ size: 99 }, 'Queue 99 queued'],
        [{ size: 118 }, 'Queue 118 queued, at or above warning level'],
        [{ size: 1234 }, 'Queue 1,234 queued, at or above critical level'],
        [{ size: 500 }, 'Queue 500 queued, at or above critical level'],
        [{ size: 0, unavailable: true }, 'Queue count unknown']
    ]) {
        const p = emailPage();
        p.respond('/api/v1/email/overview', 200, overview({}, { queue: Object.assign({ unavailable: false, warn: 100, crit: 500, frozen: 0, detail_unavailable: false }, queue) }));
        await settle();
        assert.equal(spoken(tab(p)), words);
        // The badge still shows the number; its words are for screen readers.
        assert.equal(p.document.querySelector('#email-tab-queue [data-tab-count]').getAttribute('aria-hidden'), 'true');
    }
    const failed = emailPage();
    failed.fail('/api/v1/email/overview');
    await settle();
    assert.equal(spoken(tab(failed)), 'Queue count unknown');
});

test('the Auth failures filter stays in the address across a reload', async () => {
    const page = emailPage();
    await settle();
    page.respond('/api/v1/email/checks', 200, CHECKS);
    page.respond('/api/v1/history?', 200, items([]));
    await settle();
    page.document.querySelector('#kpi-logins a').click();
    await settle();
    assert.equal(urlTab(page), 'auth');

    const reloaded = emailPage({ url: page.window.location.href });
    await settle();
    assert.equal(selectedTab(reloaded), 'findings');
    reloaded.respond('/api/v1/email/checks', 200, CHECKS);
    await settle();
    const chip = reloaded.document.getElementById('email-filter-auth');
    assert.equal(chip.getAttribute('aria-pressed'), 'true', 'the reload dropped the Auth failures filter');
    assert.equal(historyQuery(reloaded).get('checks'), 'mail_bruteforce,smtp_bruteforce');
    assert.equal(urlTab(reloaded), 'auth');
    reloaded.respond('/api/v1/history?', 200, items([]));
    await settle();

    // Turning the chip off on Findings names the plain tab, in place; on
    // again names auth.
    const before = reloaded.window.history.entries.length;
    chip.click();
    await settle();
    assert.equal(urlTab(reloaded), 'findings');
    reloaded.respond('/api/v1/history?', 200, items([]));
    await settle();
    chip.click();
    await settle();
    assert.equal(urlTab(reloaded), 'auth');
    assert.deepEqual(reloaded.window.history.entries.slice(before).filter(e => e[0] === 'push'), [], 'the chip added history entries');
});

test('Back keeps the address on the range and filters the page shows', async () => {
    const page = emailPage({ url: 'https://csm.example.test/email?from=2026-10-19&to=2026-10-21' });
    await settle();
    const doc = page.document;
    assert.equal(doc.getElementById('email-range').value, 'custom');
    const customEntry = page.window.location.href;
    showEmailTab(page, 'queue');
    await settle();
    changeValue(page, doc.getElementById('email-range'), '24h');
    await settle();
    assert.equal(new URL(page.window.location.href).searchParams.get('from'), null);

    // Back to the Overview entry, which still names the custom days.
    page.window.location._set(customEntry);
    page.window.dispatchEvent(new page.window.Event('popstate'));
    await settle();
    assert.equal(selectedTab(page), 'overview');
    assert.equal(doc.getElementById('email-range').value, '24h');
    let url = new URL(page.window.location.href);
    assert.equal(url.searchParams.get('from'), null, 'the address names a range the page does not show');
    assert.equal(url.searchParams.get('to'), null);

    // A findings filter set after an entry was left comes back with Back.
    const overviewEntry = page.window.location.href;
    showEmailTab(page, 'queue');
    await settle();
    changeValue(page, doc.getElementById('filter-severity'), '2');
    await settle();
    page.window.location._set(overviewEntry);
    page.window.dispatchEvent(new page.window.Event('popstate'));
    await settle();
    url = new URL(page.window.location.href);
    assert.equal(selectedTab(page), 'overview');
    assert.equal(url.searchParams.get('severity'), '2', 'the address lost the severity the findings show');
});

// ---------- Held mail ----------

const MID = ['1hEld1-000001-Ab', '1hEld1-000002-Ab', '1hEld1-000003-Ab'];
const FID = ['1792300000.M1P2.csm', '1792300001.M2P2.csm', '1792300002.M3P2.csm'];

function hoursAgo(h) {
    return new Date(Date.now() - h * HOUR_MS).toISOString();
}

// malwareItem is one message the email AV quarantined, as the quarantine
// list sends it.
function malwareItem(id, extra) {
    return Object.assign({ message_id: id, direction: 'inbound', from: 'billing@example.com', to: ['user@example.net'],
        subject: 'Invoice overdue', quarantined_at: hoursAgo(1), original_spool_dir: '/var/spool/exim/input',
        findings: [{ filename: 'invoice.zip', engine: 'clamav', signature: 'Win.Trojan.Agent', severity: 'critical' }],
        partial_scan: false, engines_used: ['clamav'], size: 20480 }, extra);
}

// forwardItem is one forward copy the guard held, as the held list sends
// it: a bounce to a local address that forwards outside.
function forwardItem(id, extra) {
    return Object.assign({ id, forwarder: 'info@example.com', recipient: 'owner@example.net', sender: '',
        reasons: ['bounce_backscatter'], subject: 'Undelivered Mail Returned to Sender', held_at: hoursAgo(2), size: 3072 }, extra);
}

// heldPage opens Held mail from its address and answers the overview,
// the quarantine and the held copies when given; null leaves one pending.
async function heldPage(malware, forward, ov) {
    const page = emailPage({ url: 'https://csm.example.test/email?tab=held' });
    await settle();
    if (ov) page.respond('/api/v1/email/overview', 200, ov);
    if (malware) page.respond('/api/v1/email/quarantine', 200, items(malware));
    if (forward) page.respond('/api/v1/email/held', 200, items(forward));
    await settle();
    page.toasts = [];
    page.window.CSM.toast = (message, type) => page.toasts.push([message, type]);
    return page;
}

function heldRows(page) {
    return Array.from(page.document.getElementById('email-held-tbody').children).filter(tr => tr.hasAttribute('data-kind'));
}

function heldRow(page, id) {
    const row = heldRows(page).find(tr => tr.getAttribute('data-held-id') === id);
    assert.ok(row, 'no row for ' + id);
    return row;
}

function heldCell(row, label) {
    const td = row.querySelector('[data-label="' + label + '"]');
    assert.ok(td, 'no ' + label + ' cell');
    return flat(td);
}

function heldBadge(page) {
    return page.document.querySelector('#email-tab-held [data-tab-count]');
}

test('Held mail lists malware and forward copies together, newest first, as each store answers', async () => {
    const page = await heldPage(null, null);
    const doc = page.document;
    assert.deepEqual(Array.from(doc.querySelectorAll('#email-held-table thead th')).map(flat),
        ['', 'Held', 'Kind', 'From', 'To', 'Subject', 'Why held', 'Size', 'Actions']);
    assert.match(flat(doc.getElementById('email-held-tbody')), /Loading/);
    assert.equal(page.pending('/api/v1/email/quarantine').length, 1, 'Held mail did not read the quarantine');
    assert.equal(page.pending('/api/v1/email/held').length, 1, 'Held mail did not read the held copies');
    // The held copies answer first and show before the quarantine does.
    page.respond('/api/v1/email/held', 200, items([forwardItem(FID[0], { held_at: hoursAgo(2) })]));
    await settle();
    assert.deepEqual(heldRows(page).map(r => r.getAttribute('data-held-id')), [FID[0]]);
    page.respond('/api/v1/email/quarantine', 200, items([malwareItem(MID[0], { quarantined_at: hoursAgo(3) }),
        malwareItem(MID[1], { quarantined_at: hoursAgo(1) })]));
    await settle();
    assert.deepEqual(heldRows(page).map(r => [r.getAttribute('data-kind'), r.getAttribute('data-held-id')]),
        [['malware', MID[1]], ['forward', FID[0]], ['malware', MID[0]]]);
    assert.deepEqual(heldRows(page).map(r => flat(r.querySelector('[data-label="Kind"] .badge'))), ['Malware', 'Forward copy', 'Malware']);
    assert.doesNotMatch(flat(doc.getElementById('email-held-tbody')), /Loading/);
    // Phones get one card per item.
    assert.ok(doc.getElementById('email-held-table').classList.contains('csm-table-rowcard'));
    // The kind filter shows one kind at a time.
    changeValue(page, doc.getElementById('email-held-filter'), 'forward');
    const shown = () => heldRows(page).filter(r => r.style.display !== 'none').map(r => r.getAttribute('data-held-id'));
    assert.deepEqual(shown(), [FID[0]]);
    changeValue(page, doc.getElementById('email-held-filter'), 'malware');
    assert.deepEqual(shown(), [MID[1], MID[0]]);
});

test('each held row says when, what, who to and why', async () => {
    const at = hoursAgo(0.5);
    const page = await heldPage([
        malwareItem(MID[0], { quarantined_at: at, direction: 'outbound', from: 'shop@example.com', to: ['a@example.net', 'b@example.net', 'c@example.net'],
            subject: 'Your order', findings: [
                { filename: 'a.zip', engine: 'clamav', signature: 'Win.Trojan.Agent', severity: 'critical' },
                { filename: 'b.zip', engine: 'yara', signature: 'Eicar_Test_File', severity: 'high' },
                { filename: 'c.zip', engine: 'clamav', signature: 'Win.Trojan.Agent', severity: 'critical' }] })
    ], [
        forwardItem(FID[0], { subject: '' }),
        forwardItem(FID[1], { sender: 'news@example.net', reasons: ['bad_sender_ip'], subject: '\u00cenc\u0103 o ofert\u0103', held_at: hoursAgo(3) }),
        forwardItem(FID[2], { sender: 'promo@example.org', reasons: ['spam_flagged'], subject: 'Offer', held_at: hoursAgo(4) })
    ]);
    const malware = heldRow(page, MID[0]);
    // The time sorts by its instant; the cell reads how long ago.
    assert.equal(malware.querySelector('[data-label="Held"]').getAttribute('data-timestamp'), at);
    assert.equal(heldCell(malware, 'Held'), '30m ago');
    assert.equal(heldCell(malware, 'Kind'), 'Malware outgoing');
    assert.equal(heldCell(malware, 'From'), 'shop@example.com');
    assert.equal(heldCell(malware, 'To'), 'a@example.net +2 more');
    assert.equal(heldCell(malware, 'Subject'), 'Your order');
    assert.equal(heldCell(malware, 'Why held'), 'Win.Trojan.Agent, Eicar_Test_File found by clamav, yara');
    assert.equal(heldCell(malware, 'Size'), '20.0 KB');
    assert.deepEqual(Array.from(malware.querySelectorAll('[data-label="Actions"] button')).map(flat), ['Release', 'Delete']);

    const bounce = heldRow(page, FID[0]);
    assert.equal(heldCell(bounce, 'Kind'), 'Forward copy');
    assert.equal(heldCell(bounce, 'From'), 'bounce');
    assert.equal(heldCell(bounce, 'To'), 'owner@example.net via info@example.com');
    assert.equal(heldCell(bounce, 'Subject'), '--');
    assert.equal(heldCell(bounce, 'Why held'), 'Held forward to external address a bounce (backscatter)');
    assert.equal(heldCell(bounce, 'Size'), '3.0 KB');

    const listed = heldRow(page, FID[1]);
    assert.equal(heldCell(listed, 'From'), 'news@example.net');
    // The server decodes encoded subjects; the page shows them as they come.
    assert.equal(heldCell(listed, 'Subject'), '\u00cenc\u0103 o ofert\u0103');
    assert.equal(heldCell(listed, 'Why held'), 'Held forward to external address sent from a listed bad IP');
    const spam = heldRow(page, FID[2]);
    assert.equal(heldCell(spam, 'Why held'), 'Held forward to external address tagged as spam');
    // Only malware takes part in bulk actions.
    assert.ok(malware.querySelector('.email-quar-cb'));
    assert.equal(bounce.querySelector('input[type="checkbox"]'), null);
});

test('a held mail store that fails shows its own error row, and the other store still shows', async () => {
    const page = await heldPage(null, [forwardItem(FID[0])]);
    const tbody = page.document.getElementById('email-held-tbody');
    page.fail('/api/v1/email/quarantine', new Error('HTTP 502'));
    await settle();
    const error = tbody.children[0].querySelector('.csm-load-error');
    assert.ok(error, 'no error row on top of the list');
    assert.match(flat(error), /Failed to load the mail quarantine/);
    assert.match(flat(error), /HTTP 502/);
    assert.deepEqual(heldRows(page).map(r => r.getAttribute('data-held-id')), [FID[0]], 'the held copies hid with the failed quarantine');
    assert.equal(heldBadge(page).textContent, '?');
    assert.equal(spoken(page.document.getElementById('email-tab-held')), 'Held mail count unknown');
    assert.deepEqual(page.toasts, [], 'a toast repeats the error row');
    error.querySelector('.csm-retry-btn').click();
    await settle();
    assert.equal(page.pending('/api/v1/email/quarantine').length, 1, 'Retry did not read the quarantine again');
    assert.equal(page.pending('/api/v1/email/held').length, 0, 'Retry read the held copies too');
    page.respond('/api/v1/email/quarantine', 200, items([malwareItem(MID[0])]));
    await settle();
    assert.equal(tbody.querySelector('.csm-load-error'), null);
    assert.equal(heldRows(page).length, 2);
    assert.equal(heldBadge(page).textContent, '2');

    const other = await heldPage([malwareItem(MID[0])], null);
    other.fail('/api/v1/email/held', new Error('HTTP 502'));
    await settle();
    const otherTbody = other.document.getElementById('email-held-tbody');
    assert.match(flat(otherTbody.children[0]), /Failed to load held forward copies/);
    assert.deepEqual(heldRows(other).map(r => r.getAttribute('data-held-id')), [MID[0]]);
});

test('the held mail summary repeats the Malware card and links its SMTP rejects to Rejects', async () => {
    const ov = overview({ rejects: { malware: 80, spam: 5 }, temporary: { malware: 2 }, quarantined: 3 });
    const page = await heldPage([malwareItem(MID[0]), malwareItem(MID[1])], [forwardItem(FID[0])], ov);
    const doc = page.document;
    const summary = doc.getElementById('email-held-summary');
    assert.equal(flat(summary), 'Malware stopped in this range: 81 (78 rejected at SMTP, 3 quarantined). Held now: 3 (2 malware, 1 forward copy).');
    assert.equal(kpi(page, 'kpi-malware').value, '81');
    assert.equal(kpi(page, 'kpi-malware').sub, '78 rejected at SMTP, 3 quarantined');
    const link = summary.querySelector('a');
    assert.equal(flat(link), '78 rejected at SMTP');
    assert.equal(link.getAttribute('href'), '?tab=rejects');
    link.click();
    await settle();
    assert.equal(selectedTab(page), 'rejects');
    assert.equal(doc.getElementById('email-rejects-filter').value, 'malware');
    const reqs = page.pending('/api/v1/email/rejects');
    assert.equal(reqs.length, 1, 'the link did not load the malware rejects');
    assert.equal(query(reqs[0].url).get('class'), 'malware');

    for (const [malware, forward, want] of [
        [[malwareItem(MID[0])], [forwardItem(FID[0]), forwardItem(FID[1])], 'Held now: 3 (1 malware, 2 forward copies).'],
        [[], [], 'Nothing is held now.']
    ]) {
        // Before the overview answers, the line says what is held.
        const p = await heldPage(malware, forward);
        assert.equal(flat(p.document.getElementById('email-held-summary')), want);
    }
});

test('each kind of held mail asks in its own words before release or delete', async () => {
    for (const [id, action, message, okLabel, danger] of [
        [MID[0], 'release', 'Deliver this message to its original recipients? It contained Win.Trojan.Agent, Eicar_Test_File.', 'Deliver', true],
        [FID[0], 'release', 'Send this held copy to owner@example.net?', 'Send', false],
        [MID[0], 'delete', 'Delete permanently. This cannot be undone.', 'Delete', true],
        [FID[0], 'delete', 'Delete permanently. This cannot be undone.', 'Delete', true]
    ]) {
        const page = await heldPage([malwareItem(MID[0], { findings: [
            { filename: 'a.zip', engine: 'clamav', signature: 'Win.Trojan.Agent', severity: 'critical' },
            { filename: 'b.zip', engine: 'yara', signature: 'Eicar_Test_File', severity: 'high' }] })], [forwardItem(FID[0])]);
        const asked = stubConfirm(page, false);
        heldRow(page, id).querySelector('[data-held-action="' + action + '"]').click();
        await settle();
        assert.equal(asked.length, 1, id + ' ' + action + ' did not ask');
        assert.equal(asked[0].message, message);
        assert.equal(asked[0].opts.okLabel, okLabel);
        assert.equal(!!asked[0].opts.danger, danger, id + ' ' + action + ' danger');
        assert.equal(page.requests.filter(r => r.method !== 'GET').length, 0, 'a cancelled confirm still acted');
    }
});

test('release and delete go to the store that holds the item, then read it again', async () => {
    for (const [id, action, method, url, store, other, toast] of [
        [MID[0], 'release', 'POST', '/api/v1/email/quarantine/' + MID[0] + '/release', '/api/v1/email/quarantine', '/api/v1/email/held', 'Released'],
        [MID[0], 'delete', 'DELETE', '/api/v1/email/quarantine/' + MID[0], '/api/v1/email/quarantine', '/api/v1/email/held', 'Deleted'],
        [FID[0], 'release', 'POST', '/api/v1/email/held/' + FID[0] + '/release', '/api/v1/email/held', '/api/v1/email/quarantine', 'Released'],
        [FID[0], 'delete', 'DELETE', '/api/v1/email/held/' + FID[0], '/api/v1/email/held', '/api/v1/email/quarantine', 'Deleted']
    ]) {
        const page = await heldPage([malwareItem(MID[0])], [forwardItem(FID[0])]);
        stubConfirm(page);
        const btn = heldRow(page, id).querySelector('[data-held-action="' + action + '"]');
        btn.click();
        await settle();
        const sent = page.requests.filter(r => r.method !== 'GET');
        assert.equal(sent.length, 1, id + ' ' + action + ' sent ' + sent.length + ' requests');
        assert.equal(sent[0].method, method);
        assert.equal(sent[0].url, url);
        assert.ok(Object.prototype.hasOwnProperty.call(sent[0].headers, 'X-CSRF-Token'), 'sent without the CSRF header');
        assert.equal(btn.disabled, true, 'the button stays open while the request runs');
        page.respond(url, 200, {});
        await settle();
        assert.deepEqual(page.toasts, [[toast, 'success']]);
        assert.equal(page.pending(store).filter(r => r.method === 'GET').length, 1, 'the store was not read again after ' + action);
        assert.equal(page.pending(other).length, 0, 'the other store was read again');
    }
});

test('a refused release toasts the server error, and the copy stays held', async () => {
    const page = await heldPage([], [forwardItem(FID[0])]);
    stubConfirm(page);
    heldRow(page, FID[0]).querySelector('[data-held-action="release"]').click();
    await settle();
    const error = 'Failed to release held forward: held message does not record a safe single sender and recipient';
    page.respond('/api/v1/email/held/' + FID[0] + '/release', 500, { error });
    await settle();
    assert.deepEqual(page.toasts, [['Release failed: ' + error, 'error']]);
    page.respond('/api/v1/email/held', 200, items([forwardItem(FID[0])]));
    await settle();
    assert.deepEqual(heldRows(page).map(r => r.getAttribute('data-held-id')), [FID[0]]);
});

test('held mail keeps server text as text, in the rows and the confirms', async () => {
    const payload = '<img src=x onerror=alert(1)>';
    const page = await heldPage([malwareItem(MID[0], { from: payload + '@example.com', to: [payload + '@example.net'], subject: payload,
        findings: [{ filename: 'x', engine: payload, signature: payload, severity: 'high' }] })],
    [forwardItem(FID[0], { sender: payload + '@example.net', forwarder: payload + '@example.com', recipient: payload + '@example.net', subject: payload, reasons: [payload] })]);
    const tbody = page.document.getElementById('email-held-tbody');
    assert.equal(tbody.querySelectorAll('img').length, 0, 'server text became markup');
    assert.ok(heldCell(heldRow(page, MID[0]), 'Why held').includes(payload), 'lost the virus name');
    assert.ok(heldCell(heldRow(page, FID[0]), 'To').includes('via ' + payload + '@example.com'), 'lost the forwarder');
    const asked = stubConfirm(page, false);
    heldRow(page, MID[0]).querySelector('[data-held-action="release"]').click();
    heldRow(page, FID[0]).querySelector('[data-held-action="release"]').click();
    await settle();
    assert.equal(asked[0].message, 'Deliver this message to its original recipients? It contained ' + payload + '.');
    assert.equal(asked[1].message, 'Send this held copy to ' + payload + '@example.net?');
});

test('malware keeps bulk select; forward copies act one at a time', async () => {
    const page = await heldPage([malwareItem(MID[0], { quarantined_at: hoursAgo(1) }), malwareItem(MID[1], { quarantined_at: hoursAgo(3) })],
        [forwardItem(FID[0])]);
    const doc = page.document;
    const boxes = Array.from(doc.querySelectorAll('#email-held-tbody .email-quar-cb'));
    assert.deepEqual(boxes.map(b => b.closest('tr').getAttribute('data-kind')), ['malware', 'malware']);
    const release = doc.getElementById('email-quar-bulk-release');
    assert.equal(release.classList.contains('d-none'), true, 'bulk release shows with nothing selected');
    doc.getElementById('email-quar-select-all').click();
    assert.equal(release.classList.contains('d-none'), false);
    assert.match(flat(release), /Release 2 message\(s\)/);
    const asked = stubConfirm(page);
    release.click();
    await settle();
    assert.equal(asked.length, 1);
    // Releasing delivers malware, so it asks the way one row's Release does.
    assert.equal(asked[0].message, 'Deliver these 2 messages to their original recipients? They contained malware.');
    assert.equal(asked[0].opts.okLabel, 'Deliver');
    assert.equal(asked[0].opts.danger, true);
    page.respond('/api/v1/email/quarantine/' + MID[0] + '/release', 200, {});
    await settle();
    page.respond('/api/v1/email/quarantine/' + MID[1] + '/release', 200, {});
    await settle();
    assert.deepEqual(page.toasts, [['Released 2 of 2', 'success']]);
    assert.equal(page.requests.filter(r => r.method === 'POST' && r.url.includes('/api/v1/email/held/')).length, 0, 'bulk touched a forward copy');
    assert.equal(page.pending('/api/v1/email/quarantine').length, 1, 'the quarantine was not read again');

    const one = await heldPage([malwareItem(MID[0])], []);
    one.document.querySelector('#email-held-tbody .email-quar-cb').click();
    const askedOne = stubConfirm(one, false);
    one.document.getElementById('email-quar-bulk-release').click();
    await settle();
    assert.equal(askedOne[0].message, 'Deliver this message to its original recipients? It contained malware.');
    assert.equal(askedOne[0].opts.danger, true);
    assert.equal(one.requests.filter(r => r.method !== 'GET').length, 0, 'a cancelled bulk release still acted');
});

// heldTick runs the timers on an open Held mail tab and answers both
// stores' reads, leaving any action in flight pending.
async function heldTick(page, malware, forward) {
    page.window.CSM.refresh.manual();
    await settle();
    for (const [route, list] of [['/api/v1/email/quarantine', malware], ['/api/v1/email/held', forward]]) {
        const read = page.pending(route).find(r => r.method === 'GET');
        read.settled = true;
        read.resolve(jsonResponse(200, items(list)));
    }
    await settle();
}

test('an unchanged held mail answer keeps the rows, the focus and the selection', async () => {
    const malware = [malwareItem(MID[0], { quarantined_at: hoursAgo(1) }), malwareItem(MID[1], { quarantined_at: hoursAgo(3) })];
    const forward = [forwardItem(FID[0])];
    const page = await heldPage(malware, forward);
    const doc = page.document;
    const rows = heldRows(page);
    heldRow(page, MID[1]).querySelector('.email-quar-cb').click();
    const del = heldRow(page, FID[0]).querySelector('[data-held-action="delete"]');
    del.focus();
    await heldTick(page, malware, forward);
    assert.deepEqual(heldRows(page), rows, 'the rows were rebuilt');
    assert.equal(doc.activeElement, del, 'the focus left Delete');
    assert.equal(heldRow(page, MID[1]).querySelector('.email-quar-cb').checked, true, 'the selection was dropped');
    assert.match(flat(doc.getElementById('email-quar-bulk-release')), /Release 1 message\(s\)/);
    assert.equal(doc.getElementById('email-quar-bulk-release').classList.contains('d-none'), false, 'the bulk buttons hid');
});

test('a held mail answer that changes the list keeps the selection and the focus', async () => {
    const malware = [malwareItem(MID[0], { quarantined_at: hoursAgo(1) }), malwareItem(MID[1], { quarantined_at: hoursAgo(3) })];
    const page = await heldPage(malware, []);
    const doc = page.document;
    heldRow(page, MID[1]).querySelector('.email-quar-cb').click();
    heldRow(page, MID[0]).querySelector('[data-held-action="release"]').focus();
    const before = heldRows(page);
    await heldTick(page, malware.concat([malwareItem(MID[2], { quarantined_at: hoursAgo(0.2) })]), []);
    assert.deepEqual(heldRows(page).map(r => r.getAttribute('data-held-id')), [MID[2], MID[0], MID[1]]);
    assert.notEqual(heldRow(page, MID[0]), before[0], 'a new item did not rebuild the rows');
    assert.equal(heldRow(page, MID[1]).querySelector('.email-quar-cb').checked, true, 'the selection was dropped');
    assert.equal(heldRow(page, MID[0]).querySelector('.email-quar-cb').checked, false);
    assert.match(flat(doc.getElementById('email-quar-bulk-release')), /Release 1 message\(s\)/);
    assert.equal(doc.activeElement, heldRow(page, MID[0]).querySelector('[data-held-action="release"]'), 'the focus did not come back to Release');
});

test('typing a held mail search survives a store answer', async () => {
    const wait = ms => new Promise(r => setTimeout(r, ms));
    const malware = [malwareItem(MID[0], { from: 'billing@example.com' }), malwareItem(MID[1], { from: 'news@example.net' })];
    for (const changed of [false, true]) {
        const page = await heldPage(malware, []);
        // A search the table saved earlier must not come back over the typing.
        page.window.localStorage.setItem('csm-email-held', JSON.stringify({ search: 'billing' }));
        const search = page.document.getElementById('email-held-search');
        search.value = 'news';
        search.dispatchEvent(new page.window.Event('input'));
        // A store answers before the address takes the search.
        await heldTick(page, changed ? malware.concat([malwareItem(MID[2], { from: 'news@example.net' })]) : malware, []);
        await wait(400);
        const label = changed ? 'changed answer' : 'same answer';
        assert.equal(search.value, 'news', label + ': the search box was cleared');
        assert.equal(new URL(page.window.location.href).searchParams.get('email_held_q'), 'news', label + ': the address lost the search');
        const shown = heldRows(page).filter(r => r.style.display !== 'none').map(r => r.getAttribute('data-held-id'));
        assert.deepEqual(shown, changed ? [MID[2], MID[1]] : [MID[1]], label + ': the rows do not follow the search');
    }
});

test('a held item keeps its actions closed while one runs, across a rebuild', async () => {
    const page = await heldPage([malwareItem(MID[0])], [forwardItem(FID[0])]);
    stubConfirm(page);
    heldRow(page, FID[0]).querySelector('[data-held-action="release"]').click();
    await settle();
    const buttons = () => Array.from(heldRow(page, FID[0]).querySelectorAll('[data-held-action]'));
    assert.deepEqual(buttons().map(b => b.disabled), [true, true]);
    // A new item rebuilds the rows while the release runs.
    await heldTick(page, [malwareItem(MID[0]), malwareItem(MID[1], { quarantined_at: hoursAgo(0.5) })], [forwardItem(FID[0])]);
    assert.deepEqual(buttons().map(b => b.disabled), [true, true], 'a rebuild opened the actions of a running release');
    buttons()[0].click();
    await settle();
    assert.equal(page.requests.filter(r => r.method === 'POST').length, 1, 'a second release went out');
    // Refused: the copy stays, and its actions open again.
    page.respond('/api/v1/email/held/' + FID[0] + '/release', 500, { error: 'refused' });
    await settle();
    page.respond('/api/v1/email/held', 200, items([forwardItem(FID[0])]));
    await settle();
    assert.deepEqual(buttons().map(b => b.disabled), [false, false], 'the actions stayed closed after the release failed');
});

test('a held mail store that fails again after Retry shows its error again', async () => {
    const page = await heldPage(null, [forwardItem(FID[0])]);
    const tbody = page.document.getElementById('email-held-tbody');
    page.fail('/api/v1/email/quarantine', new Error('HTTP 502'));
    await settle();
    const rows = heldRows(page);
    tbody.querySelector('.csm-retry-btn').click();
    await settle();
    page.fail('/api/v1/email/quarantine', new Error('HTTP 502'));
    await settle();
    assert.match(flat(tbody.children[0]), /Failed to load the mail quarantine/, 'the second failure shows no error');
    assert.equal(tbody.querySelectorAll('.csm-load-error').length, 1);
    assert.equal(tbody.children.length, rows.length + 1, 'an old error row stayed behind');
    assert.deepEqual(heldRows(page), rows, 'the held copies were rebuilt');
});

test('the held mail summary says when it has nothing to count', async () => {
    const page = emailPage({ url: 'https://csm.example.test/email?tab=held' });
    await settle();
    const summary = page.document.getElementById('email-held-summary');
    assert.match(flat(summary), /Loading held mail/);
    page.fail('/api/v1/email/overview');
    await settle();
    assert.match(flat(summary), /Loading held mail/, 'the counts were called unavailable while the stores load');
    page.fail('/api/v1/email/quarantine');
    page.respond('/api/v1/email/held', 200, items([forwardItem(FID[0])]));
    await settle();
    assert.equal(flat(summary), 'Held mail counts unavailable.');
});

test('the held mail search fits a phone', () => {
    const search = emailPage().document.getElementById('email-held-search');
    assert.equal(search.getAttribute('placeholder'), 'Search sender, recipient, subject');
});

test('the page range scopes held mail and names what it hides', async () => {
    const page = await heldPage([malwareItem(MID[0], { quarantined_at: hoursAgo(1) }), malwareItem(MID[1], { quarantined_at: hoursAgo(30) })],
        [forwardItem(FID[0], { held_at: hoursAgo(2) }), forwardItem(FID[1], { held_at: hoursAgo(50) })]);
    const doc = page.document;
    const summary = doc.getElementById('email-held-summary');
    assert.deepEqual(heldRows(page).map(r => r.getAttribute('data-held-id')), [MID[0], FID[0]]);
    assert.match(flat(summary), /2 older held items; widen the range\.$/);
    // The count is what is held now, in the range or not.
    assert.equal(heldBadge(page).textContent, '4');
    assert.match(flat(summary), /Held now: 4 \(2 malware, 2 forward copies\)\./);
    const before = requestCount(page, '/api/v1/email/quarantine');
    changeValue(page, doc.getElementById('email-range'), '7d');
    await settle();
    assert.deepEqual(heldRows(page).map(r => r.getAttribute('data-held-id')), [MID[0], FID[0], MID[1], FID[1]]);
    assert.doesNotMatch(flat(summary), /older held/);
    assert.equal(requestCount(page, '/api/v1/email/quarantine'), before, 'the range read the quarantine again');

    const one = await heldPage([malwareItem(MID[0], { quarantined_at: hoursAgo(30) })], []);
    assert.match(flat(one.document.getElementById('email-held-summary')), /1 older held item; widen the range\.$/);
    assert.match(flat(one.document.getElementById('email-held-tbody')), /Nothing held in this range/);
});

test('the Held mail count is what is held now, read with the page', async () => {
    const page = emailPage();
    await settle();
    // The count shows on every tab, so the page reads both stores at once.
    assert.equal(page.pending('/api/v1/email/quarantine').length, 1);
    assert.equal(page.pending('/api/v1/email/held').length, 1);
    page.respond('/api/v1/email/quarantine', 200, items([malwareItem(MID[0]), malwareItem(MID[1])]));
    await settle();
    assert.equal(heldBadge(page).hidden, true, 'a count before both stores answered');
    page.respond('/api/v1/email/held', 200, items([forwardItem(FID[0])]));
    await settle();
    assert.equal(heldBadge(page).hidden, false);
    assert.equal(heldBadge(page).textContent, '3');
    assert.equal(spoken(page.document.getElementById('email-tab-held')), 'Held mail 3 held');
    // Opening the tab reads both again, once.
    showEmailTab(page, 'held');
    await settle();
    assert.equal(page.pending('/api/v1/email/quarantine').length, 1);
    assert.equal(page.pending('/api/v1/email/held').length, 1);
    // The refresh button on another tab keeps the count fresh.
    const fresh = emailPage();
    await settle();
    fresh.respond('/api/v1/email/quarantine', 200, items([]));
    fresh.respond('/api/v1/email/held', 200, items([]));
    await settle();
    assert.equal(heldBadge(fresh).textContent, '0');
    fresh.document.getElementById('email-refresh').click();
    await settle();
    assert.equal(fresh.pending('/api/v1/email/quarantine').length, 1, 'refresh did not read the quarantine');
    assert.equal(fresh.pending('/api/v1/email/held').length, 1, 'refresh did not read the held copies');
    // The timers read both stores on every tab: the count on a closed tab,
    // the list too while Held mail is open.
    fresh.respond('/api/v1/email/quarantine', 200, items([]));
    fresh.respond('/api/v1/email/held', 200, items([]));
    await settle();
    fresh.window.CSM.refresh.manual();
    await settle();
    assert.equal(fresh.pending('/api/v1/email/quarantine').length, 1, 'the timers did not read the closed tab count');
    assert.equal(fresh.pending('/api/v1/email/held').length, 1, 'the timers did not read the closed tab count');
    await answerAll(fresh, {});
    showEmailTab(fresh, 'held');
    await settle();
    await answerAll(fresh, {});
    fresh.window.CSM.refresh.manual();
    await settle();
    assert.equal(fresh.pending('/api/v1/email/quarantine').length, 1, 'the timers did not read the open Held mail tab');
    fresh.respond('/api/v1/email/quarantine', 200, items([malwareItem(MID[0])]));
    fresh.respond('/api/v1/email/held', 200, items([]));
    await settle();
    assert.deepEqual(heldRows(fresh).map(r => r.getAttribute('data-held-id')), [MID[0]], 'the open tab did not draw its list');
});

// ---------- Rejects counts ----------

// filterLabels maps each Rejects filter value to the label it shows.
function filterLabels(page) {
    const out = {};
    for (const o of page.document.getElementById('email-rejects-filter').options) out[o.value] = flat(o);
    return out;
}

test('the rejects filter counts each reason from the overview, as the cards do', async () => {
    const page = emailPage();
    await settle();
    const tab = page.document.getElementById('email-tab-rejects');
    assert.equal(tab.querySelector('[data-tab-count]').hidden, true, 'a count before the overview answered');
    assert.equal(filterLabels(page).spam, 'Spam rejected at SMTP', 'a count before the overview answered');
    page.respond('/api/v1/email/overview', 200, overview({
        rejects: { spam: 3, malware: 2, sender_verify: 5, other: 1, rate_limited: 4, unknown_recipient: 0 },
        temporary: { spam: 2, sender_verify: 1, rate_limited: 4 }
    }));
    await settle();
    const labels = filterLabels(page);
    assert.deepEqual(Object.keys(labels), REJECT_FILTER_VALUES);
    assert.equal(labels.content, 'Spam and malware (3)');
    assert.equal(labels.all, 'All reasons (8)');
    assert.equal(labels.other, 'Other reasons (5)');
    assert.equal(labels.spam, 'Spam rejected at SMTP (1)');
    assert.equal(labels.malware, 'Malware (2)');
    assert.equal(labels.sender_verify, 'Sender verification (4)');
    assert.equal(labels.unknown_recipient, 'Unknown recipient (0)');
    assert.equal(labels.unclassified, 'Unclassified (1)');
    // Rate limiting only defers, so it has no permanent count.
    assert.equal(labels.rate_limited, 'Rate limited (temporary)');
    // The cards and the tab say the same numbers.
    assert.equal(kpi(page, 'kpi-other').value, '5');
    assert.equal(kpi(page, 'kpi-malware').value, '2');
    assert.equal(tab.querySelector('[data-tab-count]').textContent, '8');
    assert.equal(spoken(tab), 'Rejects 8 rejected');

    const failed = emailPage();
    failed.fail('/api/v1/email/overview');
    await settle();
    assert.equal(failed.document.querySelector('#email-tab-rejects [data-tab-count]').textContent, '?');
    assert.equal(filterLabels(failed).all, 'All reasons');
});

test('Other reasons lists every reason but spam, malware and rate limiting', async () => {
    const page = emailPage();
    await settle();
    page.document.querySelector('#kpi-other a').click();
    await settle();
    const req = page.pending('/api/v1/email/rejects')[0];
    assert.equal(query(req.url).get('class'), 'unknown_recipient,sender_verify,bad_helo,relay_denied,auth_required,suspended,mailbox_full,blocklisted,other');
    page.respond('/api/v1/email/rejects', 200, items([], { kept_days: 7 }));
    await settle();
    const tbody = page.document.getElementById('email-rejects-tbody');
    assert.match(flat(tbody), /No rejects for other reasons in the last 24 hours/);
    assert.match(flat(tbody), /Rejects are kept for 7 days\./);
    // The class the server calls other is Unclassified, on its own.
    changeValue(page, page.document.getElementById('email-rejects-filter'), 'unclassified');
    await settle();
    assert.equal(query(page.pending('/api/v1/email/rejects')[0].url).get('class'), 'other');
    page.respond('/api/v1/email/rejects', 200, items([{ at: AT, class: 'other', detail: 'policy text' }], { kept_days: 7 }));
    await settle();
    assert.equal(flat(tbody.querySelector('.badge')), 'Unclassified');
});

// ---------- Sending accounts ----------

function senders(accounts, extra) {
    return Object.assign({ accounts, total: accounts.reduce((n, a) => n + a.messages, 0), unresolved: 0, abuse_events: 0 }, extra);
}

function abuseEvent(extra) {
    return Object.assign({ path: 'volume', path_label: 'High volume script', severity: 'HIGH', source_ip: '203.0.113.30', cp_user: '',
        trigger_count: 40, detected_at: AT, sites: [] }, extra);
}

const FIREWALL = { smtp_block: true, smtp_allow_users: ['root'], smtp_ports: [25], port_flood: [], top_senders: [] };

// sendingPage opens Sending accounts from its address and answers what it
// reads; every route not given gets an empty list.
async function sendingPage(bodies, url) {
    const page = emailPage({ url: url || 'https://csm.example.test/email?tab=sending' });
    await settle();
    await answerAll(page, Object.assign({ '/api/v1/email/stats': FIREWALL }, bodies));
    return page;
}

function sendingRows(page) {
    return Array.from(page.document.querySelectorAll('#email-sending-tbody tr')).filter(r => r.querySelector('[data-label="Account"]'));
}

test('Sending accounts lists each account with its share and the abuse it is flagged for', async () => {
    const page = await sendingPage({
        '/api/v1/email/overview': overview({}),
        '/api/v1/email/senders': senders([{ account: 'shopuser', messages: 300 }, { account: 'blogger', messages: 100 }, { account: 'quiet', messages: 1 }],
            { total: 501, unresolved: 100, abuse_events: 4,
                abuse_by_account: { shopuser: { 'High volume script': 2, 'Suspicious headers': 1 }, 'gone-account': { 'High volume script': 1 } } }),
        '/api/v1/email/relay-abuse': items([
            abuseEvent({ cp_user: 'shopuser' }), abuseEvent({ cp_user: 'shopuser' }),
            abuseEvent({ cp_user: 'shopuser', path: 'header', path_label: 'Suspicious headers' }),
            abuseEvent({ cp_user: '' }), abuseEvent({ cp_user: 'gone-account' })
        ], { total: 5, limit: 20, truncated: false })
    });
    const doc = page.document;
    assert.deepEqual(Array.from(doc.querySelectorAll('#email-sending-table thead th')).map(flat), ['Account', 'Messages', 'Share', 'Flags', 'Actions']);
    const rows = sendingRows(page);
    assert.deepEqual(rows.map(r => flat(r.querySelector('[data-label="Account"]'))), ['shopuser', 'blogger', 'quiet']);
    assert.deepEqual(rows.map(r => flat(r.querySelector('[data-label="Messages"]'))), ['300', '100', '1']);
    assert.deepEqual(rows.map(r => flat(r.querySelector('[data-label="Share"]'))), ['60%', '20%', '<1%']);
    assert.deepEqual(Array.from(rows[0].querySelectorAll('[data-label="Flags"] .badge')).map(flat), ['High volume script (2)', 'Suspicious headers']);
    assert.match(Array.from(rows[0].querySelectorAll('[data-label="Flags"] .badge'))[0].className, /bg-red-lt/);
    assert.equal(flat(rows[1].querySelector('[data-label="Flags"]')), '--');
    assert.equal(flat(doc.getElementById('email-sending-summary')), '501 messages sent in the last 24 hours, 100 of them from senders not matched to an account.');
    assert.ok(doc.getElementById('email-sending-table').classList.contains('csm-table-rowcard'), 'no row cards on phones');
    // The tab counts the abuse events of the range.
    const tab = doc.getElementById('email-tab-sending');
    assert.equal(tab.querySelector('[data-tab-count]').textContent, '4');
    assert.equal(spoken(tab), 'Sending accounts 4 abuse events');
});

test('the flags count every abuse event of the range, not only the listed ones', async () => {
    // One busy account fills the newest events the list shows; the other
    // account's older event still flags its row.
    const page = await sendingPage({
        '/api/v1/email/senders': senders([{ account: 'busyacct', messages: 900 }, { account: 'quietacct', messages: 4 }],
            { abuse_events: 26, abuse_by_account: { busyacct: { 'High volume script': 25 }, quietacct: { 'Suspicious headers': 1 } } }),
        '/api/v1/email/relay-abuse': items(Array.from({ length: 20 }, () => abuseEvent({ cp_user: 'busyacct' })), { total: 26, limit: 20, truncated: true })
    });
    assert.deepEqual(sendingRows(page).map(r => flat(r.querySelector('[data-label="Flags"]'))), ['High volume script (25)', 'Suspicious headers']);
});

test('View findings opens Findings searched for the account', async () => {
    const page = await sendingPage({ '/api/v1/email/senders': senders([{ account: 'shopuser', messages: 3 }]) });
    const link = sendingRows(page)[0].querySelector('[data-label="Actions"] a');
    assert.equal(flat(link), 'View findings');
    assert.equal(link.getAttribute('href'), '?tab=findings&search=shopuser');
    const newTab = new page.window.Event('click', { bubbles: true, cancelable: true, ctrlKey: true });
    link.dispatchEvent(newTab);
    assert.equal(newTab.defaultPrevented, false, 'a click meant for a new browser tab was taken');
    assert.equal(selectedTab(page), 'sending');
    link.click();
    await settle();
    assert.equal(selectedTab(page), 'findings');
    assert.equal(page.document.getElementById('email-search').value, 'shopuser');
    const url = new URL(page.window.location.href);
    assert.equal(url.searchParams.get('tab'), 'findings');
    assert.equal(url.searchParams.get('search'), 'shopuser');
});

test('the accounts table says since when sends are counted', async () => {
    const since = new Date(Date.now() - 2 * HOUR_MS).toISOString();
    const page = await sendingPage({
        '/api/v1/email/overview': overview({}, { counting_since: since }),
        '/api/v1/email/senders': senders([])
    });
    const doc = page.document;
    assert.match(flat(doc.getElementById('email-sending-tbody')), /No mail sent by an account in the last 24 hours/);
    assert.ok(doc.querySelector('#email-sending-tbody .csm-empty'), 'not the shared empty state');
    assert.equal(flat(doc.getElementById('email-sending-summary')),
        '0 messages sent in the last 24 hours. Counting since ' + page.window.CSM.fmtDate(since) + '.');
    // No abuse events, no count.
    assert.equal(doc.querySelector('#email-tab-sending [data-tab-count]').hidden, true);

    // Once rows come, the note stays only while counting began inside the range.
    const old = await sendingPage({
        '/api/v1/email/overview': overview({}, { counting_since: '2020-01-01T00:00:00Z' }),
        '/api/v1/email/senders': senders([{ account: 'shopuser', messages: 2 }])
    });
    assert.doesNotMatch(flat(old.document.getElementById('email-sending-summary')), /Counting/);
    const recent = await sendingPage({
        '/api/v1/email/overview': overview({}, { counting_since: since }),
        '/api/v1/email/senders': senders([{ account: 'shopuser', messages: 2 }])
    });
    assert.match(flat(recent.document.getElementById('email-sending-summary')), /Counting since/);
});

test('abuse event counts read as more only when the server capped them', async () => {
    const page = await sendingPage({
        '/api/v1/email/senders': senders([], { abuse_events: 5000, abuse_events_truncated: true }),
        '/api/v1/email/relay-abuse': items([abuseEvent()], { total: 5000, limit: 20, truncated: true, total_truncated: true })
    });
    const tab = page.document.getElementById('email-tab-sending');
    assert.equal(tab.querySelector('[data-tab-count]').textContent, '5,000+');
    assert.equal(spoken(tab), 'Sending accounts 5,000 or more abuse events');
    assert.equal(flat(page.document.getElementById('email-abuse-count')), '5,000+ events');
    // The server says when it capped a count; the page knows no cap of its own.
    const exact = await sendingPage({
        '/api/v1/email/senders': senders([], { abuse_events: 5000 }),
        '/api/v1/email/relay-abuse': items([abuseEvent()], { total: 5000, limit: 20, truncated: true })
    });
    assert.equal(exact.document.querySelector('#email-tab-sending [data-tab-count]').textContent, '5,000');
    assert.equal(spoken(exact.document.getElementById('email-tab-sending')), 'Sending accounts 5,000 abuse events');
    assert.equal(flat(exact.document.getElementById('email-abuse-count')), '5,000 events');
    const capped = await sendingPage({
        '/api/v1/email/senders': senders([], { abuse_events: 8000, abuse_events_truncated: true }),
        '/api/v1/email/relay-abuse': items([abuseEvent()], { total: 8000, limit: 20, truncated: true, total_truncated: true })
    });
    assert.equal(capped.document.querySelector('#email-tab-sending [data-tab-count]').textContent, '8,000+');
    assert.equal(flat(capped.document.getElementById('email-abuse-count')), '8,000+ events');
    const below = await sendingPage({ '/api/v1/email/relay-abuse': items([abuseEvent()], { total: 21, limit: 20, truncated: true }) });
    assert.equal(flat(below.document.getElementById('email-abuse-count')), '21 events');
});

test('the abuse events keep their script breakdown and Block 24h', async () => {
    const page = await sendingPage({
        '/api/v1/email/relay-abuse': items([abuseEvent({ cp_user: 'shopuser', sites: [
            { site: 'shop.example.com', script: '/wp-content/plugins/x/mail.php', hits: 40, last_seen: AT, sample_subject: 'You won' }] })],
        { total: 1, limit: 20, truncated: false })
    });
    const doc = page.document;
    const body = doc.getElementById('email-abuse-events');
    assert.match(flat(body), /High volume script/);
    assert.match(flat(body), /shopuser/);
    const toggle = body.querySelector('.oab-toggle');
    assert.equal(flat(toggle), 'Sites (1)');
    const sites = doc.getElementById(toggle.getAttribute('data-target'));
    assert.ok(sites.classList.contains('d-none'), 'the breakdown shows before it is opened');
    toggle.click();
    assert.equal(sites.classList.contains('d-none'), false);
    const cells = Array.from(sites.querySelectorAll('tbody td')).map(flat);
    assert.deepEqual([cells[0], cells[1], cells[2], cells[4]], ['shop.example.com', '/wp-content/plugins/x/mail.php', '40', 'You won']);
    const asked = stubConfirm(page);
    body.querySelector('.oab-block').click();
    await settle();
    assert.match(asked[0].message, /^Block 203\.0\.113\.30 in the firewall for 24 hours\?/);
    assert.equal(asked[0].opts.danger, true);
    const post = page.pending('/api/v1/block-ip')[0];
    assert.deepEqual([post.method, post.body.ip, post.body.duration], ['POST', '203.0.113.30', '24h']);
});

// forwardersPage opens the Forwarders tab and answers what it asks for.
async function forwardersPage(bodies) {
    const page = emailPage({ url: 'https://csm.example.test/email?tab=forwarders' });
    await settle();
    await answerAll(page, bodies);
    return page;
}

function forwarder(source, dests, extra) {
    dests = dests.map(d => typeof d === 'string' ? { address: d, domain: d.split('@')[1], provider: 'external' } : d);
    return Object.assign({ source, domain: source.split('@')[1], owner: 'alice', destinations: dests,
        providers: Array.from(new Set(dests.map(d => d.provider))).sort(), keep_local: false, forward_only: true,
        has_external: dests.some(d => d.provider !== 'local'), has_free_provider: false }, extra);
}

test('the Forwarders tab lists them, counting the outside ones on the tab', async () => {
    const local = { address: 'x@example.com', domain: 'example.com', provider: 'local' };
    const page = await forwardersPage({ '/api/v1/email/forwarders': items([forwarder('a@example.com', ['x@example.net']),
        forwarder('b@example.com', [local], { has_external: false, keep_local: true, forward_only: false }), forwarder('c@example.com', ['y@example.net'])]) });
    const doc = page.document;
    assert.equal(selectedTab(page), 'forwarders');
    assert.equal(doc.getElementById('email-pane-forwarders').contains(doc.getElementById('email-fwd-table')), true);
    assert.equal(doc.querySelector('#email-pane-forwarders details'), null, 'the forwarders are still collapsed');
    const badge = doc.querySelector('#email-tab-forwarders [data-tab-count]');
    assert.equal(badge.hidden, false);
    assert.equal(badge.textContent, '2');
    assert.equal(flat(doc.querySelector('#email-tab-forwarders [data-tab-count-text]')), '2 outside forwarders');
    // The list starts on the outside ones, which the count names.
    assert.equal(doc.getElementById('email-fwd-filter').value, 'external');
    assert.equal(flat(doc.getElementById('email-fwd-count')), '2 of 3');

    const failed = emailPage({ url: 'https://csm.example.test/email?tab=forwarders' });
    await settle();
    failed.fail('/api/v1/email/forwarders', new Error('HTTP 502'));
    await settle();
    assert.equal(failed.document.querySelector('#email-tab-forwarders [data-tab-count]').textContent, '?');
    assert.match(flat(failed.document.getElementById('email-fwd-tbody')), /Failed to load forwarders/);
});

test('Sending accounts no longer reads the forwarders', async () => {
    const page = await sendingPage({});
    assert.equal(page.requests.filter(r => r.url.includes('/api/v1/email/forwarders')).length, 0);
});

// fwdDeleteButtons returns the delete buttons of the forwarders on screen.
function fwdDeleteButtons(page) {
    return Array.from(page.document.querySelectorAll('#email-fwd-tbody button[data-fwd-delete]'));
}

test('each destination of a forwarder has its own delete button', async () => {
    const page = await forwardersPage({ '/api/v1/email/forwarders': items([forwarder('a@example.com', ['x@example.net', 'y@example.org'])]) });
    const buttons = fwdDeleteButtons(page);
    assert.equal(buttons.length, 2);
    assert.deepEqual(buttons.map(b => b.getAttribute('aria-label')),
        ['Delete forwarder from a@example.com to x@example.net', 'Delete forwarder from a@example.com to y@example.org']);
});

test('the default address has no delete button', async () => {
    const page = await forwardersPage({ '/api/v1/email/forwarders': items([forwarder('*@example.com', ['x@example.net'])]) });
    assert.equal(fwdDeleteButtons(page).length, 0);
    assert.match(flat(page.document.getElementById('email-fwd-tbody')), /x@example\.net/);
});

test('deleting a forwarder asks first, posts the pair, and reads the list again', async () => {
    const page = await forwardersPage({ '/api/v1/email/forwarders': items([forwarder('a@example.com', ['x@example.net', 'y@example.org'])]) });
    page.toasts = [];
    page.window.CSM.toast = (message, type) => page.toasts.push([message, type]);
    const asked = stubConfirm(page);
    const reads = () => page.requests.filter(r => r.url.includes('/api/v1/email/forwarders') && r.method !== 'POST').length;
    const before = reads();
    fwdDeleteButtons(page)[1].click();
    await settle();
    assert.equal(asked.length, 1);
    assert.match(asked[0].message, /^Delete the forwarder from a@example\.com to y@example\.org\?/);
    assert.equal(asked[0].opts.danger, true);
    assert.equal(asked[0].opts.okLabel, 'Delete');
    const post = page.pending('/api/v1/email/forwarders/delete')[0];
    assert.ok(post, 'no delete request');
    assert.equal(post.method, 'POST');
    assert.deepEqual(post.body, { source: 'a@example.com', destination: 'y@example.org' });
    assert.equal(fwdDeleteButtons(page)[1].disabled, true, 'the button is live while the delete runs');
    page.respond('/api/v1/email/forwarders/delete', 200, { ok: true });
    await settle();
    assert.deepEqual(page.toasts, [['Forwarder deleted', 'success']]);
    assert.equal(reads(), before + 1, 'the list was not read again');
});

test('a declined delete sends nothing', async () => {
    const page = await forwardersPage({ '/api/v1/email/forwarders': items([forwarder('a@example.com', ['x@example.net'])]) });
    stubConfirm(page, false);
    fwdDeleteButtons(page)[0].click();
    await settle();
    assert.equal(page.pending('/api/v1/email/forwarders/delete').length, 0);
    assert.equal(fwdDeleteButtons(page)[0].disabled, false);
});

test('declining a forwarder delete preserves keyboard focus', async () => {
    const page = await forwardersPage({ '/api/v1/email/forwarders': items([forwarder('a@example.com', ['x@example.net'])]) });
    const layout = fs.readFileSync(path.join(__dirname, 'templates', 'layout.html'), 'utf8');
    const start = layout.indexOf('<div class="modal fade" id="csm-confirm-modal"');
    const end = layout.indexOf('<div class="modal fade" id="csm-prefs-modal"');
    assert.ok(start > 0 && end > start);
    const dialogs = page.document.createElement('div');
    dialogs.innerHTML = layout.slice(start, end);
    page.document.body.appendChild(dialogs);
    const button = fwdDeleteButtons(page)[0];
    button.focus();
    button.click();
    const cancel = page.document.getElementById('csm-confirm-cancel');
    assert.equal(page.document.activeElement, cancel);
    cancel.click();
    await settle();
    assert.equal(page.document.contains(button), true, 'the focused opener was replaced');
    assert.equal(page.document.activeElement, button);
    assert.equal(button.disabled, false);
    assert.equal(page.pending('/api/v1/email/forwarders/delete').length, 0);
});

for (const oldReply of ['success', 'failure']) {
    test('a late inventory ' + oldReply + ' cannot replace the list after a forwarder delete', async () => {
        const route = '/api/v1/email/forwarders';
        const before = items([forwarder('a@example.com', ['x@example.net', 'y@example.org'])]);
        const page = await forwardersPage({ [route]: before });
        page.document.getElementById('email-refresh').click();
        await settle();
        const old = page.pending(route).find(r => r.method === 'GET');
        assert.ok(old, 'no inventory read before deletion');
        stubConfirm(page);
        fwdDeleteButtons(page)[1].click();
        await settle();
        page.respond(route + '/delete', 200, { ok: true });
        await settle();
        const current = page.pending(route).find(r => r.method === 'GET' && r !== old);
        assert.ok(current, 'no inventory read after deletion');
        current.settled = true;
        current.resolve(jsonResponse(200, items([forwarder('a@example.com', ['x@example.net'])])));
        await settle();
        old.settled = true;
        if (oldReply === 'success') old.resolve(jsonResponse(200, before));
        else old.reject(new Error('old inventory failed'));
        await settle();
        assert.deepEqual(fwdDeleteButtons(page).map(b => b.getAttribute('data-dest')), ['x@example.net']);
        assert.doesNotMatch(flat(page.document.getElementById('email-fwd-tbody')), /Failed to load/);
        assert.equal(flat(page.document.querySelector('#email-tab-forwarders [data-tab-count]')), '1');
    });
}

test('a refused delete toasts the server error and keeps the row', async () => {
    const page = await forwardersPage({ '/api/v1/email/forwarders': items([forwarder('a@example.com', ['x@example.net'])]) });
    page.toasts = [];
    page.window.CSM.toast = (message, type) => page.toasts.push([message, type]);
    stubConfirm(page);
    fwdDeleteButtons(page)[0].click();
    await settle();
    page.respond('/api/v1/email/forwarders/delete', 500, { error: 'cPanel said no' });
    await settle();
    assert.equal(page.toasts.length, 1);
    assert.match(page.toasts[0][0], /^Delete failed: .*cPanel said no/);
    assert.equal(page.toasts[0][1], 'error');
    assert.equal(fwdDeleteButtons(page)[0].disabled, false);
});

test('abuse events and forwarders turn into labelled cards on phones', async () => {
    const fwd = { source: 'a@example.com', domain: 'example.com', owner: 'alice', destinations: [{ address: 'x@example.net', domain: 'example.net', provider: 'external' }],
        providers: ['external'], keep_local: true, forward_only: false, has_external: true, has_free_provider: false };
    const page = await sendingPage({
        '/api/v1/email/relay-abuse': items([abuseEvent({ cp_user: 'shopuser', sites: [
            { site: 'shop.example.com', script: '/mail.php', hits: 40, last_seen: AT, sample_subject: 'You won' }] })],
        { total: 1, limit: 20, truncated: false })
    });
    const doc = page.document;
    const labels = row => Array.from(row.children).map(td => td.getAttribute('data-label'));
    const abuse = doc.querySelector('#email-abuse-events table');
    assert.ok(abuse.classList.contains('csm-table-rowcard'), 'abuse events scroll sideways on phones');
    assert.deepEqual(labels(abuse.querySelector('tr[data-abuse-key]')), ['Severity', 'Type', 'Source IP', 'Account', 'Count', 'Detected', 'Actions']);
    const sites = doc.getElementById(abuse.querySelector('.oab-toggle').getAttribute('data-target'));
    assert.deepEqual(labels(sites.querySelector('tbody tr')), ['Site', 'Script', 'Hits', 'Last seen', 'Sample subject']);
    const fwdPage = await forwardersPage({ '/api/v1/email/forwarders': items([fwd]) });
    const fwdTable = fwdPage.document.getElementById('email-fwd-table');
    assert.ok(fwdTable.classList.contains('csm-table-rowcard'), 'forwarders scroll sideways on phones');
    assert.deepEqual(labels(fwdPage.document.querySelector('#email-fwd-tbody tr')), ['Source', 'Owner', 'Destinations', 'Providers', 'Local copy']);
});

test('an old outbound abuse link reads each Sending accounts source once', async () => {
    const count = (page, route) => page.requests.filter(r => r.url.includes(route)).length;
    const page = emailPage({ url: 'https://csm.example.test/email?tab=outbound-abuse' });
    await settle();
    assert.equal(selectedTab(page), 'sending');
    for (const route of ['/api/v1/email/relay-abuse', '/api/v1/email/senders', '/api/v1/email/stats']) {
        assert.equal(count(page, route), 1, route);
    }
    await answerAll(page, { '/api/v1/email/stats': FIREWALL });
    // Opening the tab again reads only the accounts, for a fresh count.
    showEmailTab(page, 'overview');
    showEmailTab(page, 'sending');
    await settle();
    assert.deepEqual(['/api/v1/email/relay-abuse', '/api/v1/email/senders', '/api/v1/email/stats'].map(r => count(page, r)), [1, 2, 1]);
});

test('the Sending accounts count is read with the page and follows the range', async () => {
    const count = (page, route) => page.requests.filter(r => r.url.includes(route)).length;
    const page = emailPage();
    await settle();
    // The count shows on every tab; the rest waits for the tab.
    assert.equal(count(page, '/api/v1/email/senders'), 1);
    for (const route of ['/api/v1/email/relay-abuse', '/api/v1/email/stats', '/api/v1/email/forwarders']) assert.equal(count(page, route), 0, route);
    page.respond('/api/v1/email/senders', 200, senders([], { abuse_events: 2 }));
    await settle();
    assert.equal(page.document.querySelector('#email-tab-sending [data-tab-count]').textContent, '2');
    // The timers read the count of a closed tab, and only the count; a new
    // range reads it again.
    page.window.CSM.refresh.manual();
    await settle();
    assert.equal(count(page, '/api/v1/email/senders'), 2, 'the timers did not read the closed tab count');
    for (const route of ['/api/v1/email/relay-abuse', '/api/v1/email/stats', '/api/v1/email/forwarders']) assert.equal(count(page, route), 0, route);
    page.respond('/api/v1/email/senders', 200, senders([], { abuse_events: 3 }));
    await settle();
    assert.equal(page.document.querySelector('#email-tab-sending [data-tab-count]').textContent, '3');
    changeValue(page, page.document.getElementById('email-range'), '7d');
    await settle();
    const req = page.pending('/api/v1/email/senders')[0];
    assert.ok(req, 'a new range did not read the count again');
    assert.equal(query(req.url).get('from'), query(page.pending('/api/v1/email/overview').at(-1).url).get('from'));
    page.respond('/api/v1/email/senders', 404, { error: 'Not found' });
    await settle();
    assert.equal(page.document.querySelector('#email-tab-sending [data-tab-count]').textContent, '?');
});

test('an open Sending accounts tab refreshes and keeps the focus when nothing changed', async () => {
    const bodies = { '/api/v1/email/senders': senders([{ account: 'shopuser', messages: 3 }]),
        '/api/v1/email/relay-abuse': items([abuseEvent({ cp_user: 'shopuser' })], { total: 1, limit: 20, truncated: false }) };
    const page = await sendingPage(bodies);
    const link = sendingRows(page)[0].querySelector('a');
    link.focus();
    const toggleRow = page.document.querySelector('#email-abuse-events tbody tr');
    const before = page.requests.length;
    page.window.CSM.refresh.manual();
    await settle();
    const asked = page.requests.slice(before).map(r => r.url);
    for (const route of ['/api/v1/email/senders', '/api/v1/email/relay-abuse', '/api/v1/email/stats']) {
        assert.ok(asked.some(u => u.includes(route)), 'the timers did not read ' + route);
    }
    await answerAll(page, Object.assign({ '/api/v1/email/stats': FIREWALL }, bodies));
    assert.equal(page.document.activeElement, link, 'the focus left View findings');
    assert.equal(page.document.querySelector('#email-abuse-events tbody tr'), toggleRow, 'the abuse events were drawn again');
});

test('sending accounts, abuse events and forwarders keep server text as text', async () => {
    const payload = '<img src=x onerror=alert(1)>';
    const page = await sendingPage({
        '/api/v1/email/senders': senders([{ account: payload, messages: 3 }], { abuse_events: 1, abuse_by_account: { [payload]: { [payload]: 1 } } }),
        '/api/v1/email/relay-abuse': items([abuseEvent({ cp_user: payload, path_label: payload, sites: [
            { site: payload, script: '/' + payload, hits: 1, last_seen: AT, sample_subject: payload }] })], { total: 1, limit: 20, truncated: false }),
        '/api/v1/email/forwarders': items([{ source: payload + '@example.com', domain: 'example.com', owner: payload,
            destinations: [{ address: payload + '@example.net', domain: 'example.net', provider: 'external' }], providers: [payload],
            keep_local: true, forward_only: false, has_external: true, has_free_provider: false }])
    });
    const doc = page.document;
    showEmailTab(page, 'forwarders');
    await settle();
    await answerAll(page, { '/api/v1/email/forwarders': items([{ source: payload + '@example.com', domain: 'example.com', owner: payload,
        destinations: [{ address: payload + '@example.net', domain: 'example.net', provider: 'external' }], providers: [payload],
        keep_local: true, forward_only: false, has_external: true, has_free_provider: false }]) });
    assert.equal(fwdDeleteButtons(page)[0].getAttribute('aria-label'), 'Delete forwarder from ' + payload + '@example.com to ' + payload + '@example.net');
    for (const id of ['email-sending-tbody', 'email-abuse-events', 'email-fwd-tbody']) {
        const el = doc.getElementById(id);
        assert.equal(el.querySelectorAll('img').length, 0, id + ' interpreted server text as markup');
        assert.ok(el.textContent.includes(payload), id + ' lost the literal server text');
    }
    assert.equal(sendingRows(page)[0].querySelector('a').getAttribute('href'), '?tab=findings&search=' + encodeURIComponent(payload));

    const failed = emailPage({ url: 'https://csm.example.test/email?tab=sending' });
    await settle();
    failed.respond('/api/v1/email/senders', 500, { error: payload });
    await settle();
    const tbody = failed.document.getElementById('email-sending-tbody');
    assert.match(flat(tbody), /Failed to load sending accounts/);
    assert.ok(tbody.textContent.includes(payload));
    assert.equal(tbody.querySelectorAll('img').length, 0);
});

// ---------- Rejects and Sending accounts review fixes ----------

test('temporary rejects are listed with a tag, under a note that the counts are permanent', async () => {
    const page = emailPage({ url: 'https://csm.example.test/email?tab=rejects' });
    await settle();
    page.respond('/api/v1/email/rejects', 200, items([
        { at: AT, class: 'sender_verify', temporary: true, sender: 'a@example.com', detail: 'try later' },
        { at: AT, class: 'sender_verify', temporary: false, sender: 'b@example.com' },
        { at: AT, class: 'rate_limited', temporary: true, sender: 'c@example.com' }
    ], { kept_days: 7 }));
    await settle();
    const rows = Array.from(page.document.querySelectorAll('#email-rejects-tbody tr'));
    assert.deepEqual(rows.map(r => Array.from(r.querySelectorAll('[data-label="Reason"] .badge')).map(flat)),
        [['Sender verification', 'temporary'], ['Sender verification'], ['Rate limited (temporary)']]);
    const note = page.document.getElementById('email-rejects-note');
    assert.ok(page.document.getElementById('email-pane-rejects').contains(note), 'the note is not on the Rejects tab');
    assert.equal(flat(note), 'Counts are permanent rejects; temporary ones are listed and tagged.');
});

test('the rejects note says the list holds fewer days than a longer range', async () => {
    const page = emailPage({ url: 'https://csm.example.test/email?tab=rejects' });
    await settle();
    page.respond('/api/v1/email/rejects', 200, items([], { kept_days: 7 }));
    await settle();
    const note = page.document.getElementById('email-rejects-note');
    const base = 'Counts are permanent rejects; temporary ones are listed and tagged.';
    assert.equal(flat(note), base);
    for (const [range, text] of [['30d', base + ' The list holds the last 7 days only.'], ['7d', base]]) {
        changeValue(page, page.document.getElementById('email-range'), range);
        await settle();
        page.respond('/api/v1/email/rejects', 200, items([], { kept_days: 7 }));
        await settle();
        assert.equal(flat(note), text, range);
    }
});

test('a search in the address filters the findings rows', async () => {
    const page = emailPage({ url: 'https://csm.example.test/email?tab=findings&search=shopuser',
        storage: { 'csm-email-table': JSON.stringify({ search: 'stale' }) } });
    await settle();
    page.respond('/api/v1/history?', 200, items([
        { severity: 2, check: 'email_spam_outbreak', account: 'shopuser', message: 'outbreak', timestamp: AT },
        { severity: 1, check: 'mail_bruteforce', account: 'blogger', message: 'logins', timestamp: AT }
    ]));
    await settle();
    assert.equal(page.document.getElementById('email-search').value, 'shopuser');
    const shown = Array.from(page.document.querySelectorAll('#email-tbody tr')).filter(r => r.style.display !== 'none');
    assert.deepEqual(shown.map(r => flat(r.cells[2])), ['shopuser']);
});

test('a changed accounts answer keeps the page, the sort and the focus', async () => {
    const accounts = more => Array.from({ length: 30 }, (_, i) => ({ account: 'user' + String(i).padStart(2, '0'), messages: 100 + i + more }));
    const page = await sendingPage({ '/api/v1/email/senders': senders(accounts(0)) });
    const doc = page.document;
    const shown = () => sendingRows(page).filter(r => r.style.display !== 'none').map(r => flat(r.querySelector('[data-label="Account"]')));
    // Sort by account name, then go to page 2.
    doc.querySelectorAll('#email-sending-table thead th')[0].click();
    Array.from(doc.querySelectorAll('#email-sending-table-controls [data-page]')).find(b => flat(b) === '2').click();
    const page2 = ['user25', 'user26', 'user27', 'user28', 'user29'];
    assert.deepEqual(shown(), page2);
    const link = sendingRows(page).find(r => flat(r.querySelector('[data-label="Account"]')) === 'user27').querySelector('[data-findings-account]');
    link.focus();
    page.window.CSM.refresh.manual();
    await answerAll(page, { '/api/v1/email/senders': senders(accounts(5)), '/api/v1/email/stats': FIREWALL });
    assert.notEqual(sendingRows(page)[0].querySelector('[data-label="Messages"]').textContent, '100', 'the new counts did not show');
    assert.deepEqual(shown(), page2, 'the poll lost the page or the sort');
    assert.equal(doc.activeElement.getAttribute('data-findings-account'), 'user27', 'the poll lost the focus');
});

test('the accounts summary says when only the busiest accounts are listed', async () => {
    const page = await sendingPage({
        '/api/v1/email/overview': overview({}),
        '/api/v1/email/senders': senders([{ account: 'shopuser', messages: 50 }, { account: 'blogger', messages: 40 }], { total: 120, unresolved: 10 })
    });
    assert.equal(flat(page.document.getElementById('email-sending-summary')),
        '120 messages sent in the last 24 hours, 10 of them from senders not matched to an account. Busiest 2 accounts shown.');
    const whole = await sendingPage({
        '/api/v1/email/senders': senders([{ account: 'shopuser', messages: 50 }], { total: 60, unresolved: 10 })
    });
    assert.doesNotMatch(flat(whole.document.getElementById('email-sending-summary')), /Busiest/);
});

test('a range change drops the abuse flags of the old range', async () => {
    const page = await sendingPage({
        '/api/v1/email/senders': senders([{ account: 'shopuser', messages: 3 }], { abuse_events: 1, abuse_by_account: { shopuser: { 'High volume script': 1 } } }),
        '/api/v1/email/relay-abuse': items([abuseEvent({ cp_user: 'shopuser' })], { total: 1, limit: 20, truncated: false })
    });
    const flags = () => flat(sendingRows(page)[0].querySelector('[data-label="Flags"]'));
    assert.equal(flags(), 'High volume script');
    changeValue(page, page.document.getElementById('email-range'), '7d');
    await settle();
    page.respond('/api/v1/email/senders', 200, senders([{ account: 'shopuser', messages: 9 }]));
    await settle();
    assert.equal(flags(), '--', 'the account kept the flag of the old range');
});

test('the Flags column keeps its distance from Share, but not on phone row cards', async () => {
    const page = await sendingPage({ '/api/v1/email/senders': senders([{ account: 'shopuser', messages: 3 }]) });
    for (const el of [page.document.querySelectorAll('#email-sending-table thead th')[3], sendingRows(page)[0].querySelector('[data-label="Flags"]')]) {
        assert.ok(el.classList.contains('ps-md-3'), el.tagName + ' lacks ps-md-3');
        assert.equal(el.classList.contains('ps-3'), false, el.tagName + ' pads the phone row card');
    }
});

test('an unchanged held mail summary keeps its link and the focus', async () => {
    const page = emailPage({ url: 'https://csm.example.test/email?tab=held' });
    await settle();
    const ov = overview({ rejects: { malware: 2 }, quarantined: 1 });
    page.respond('/api/v1/email/overview', 200, ov);
    page.respond('/api/v1/email/quarantine', 200, items([]));
    page.respond('/api/v1/email/held', 200, items([]));
    await settle();
    const link = page.document.querySelector('#email-held-summary a');
    link.focus();
    page.window.CSM.refresh.manual();
    await answerAll(page, { '/api/v1/email/overview': ov });
    assert.equal(page.document.querySelector('#email-held-summary a'), link, 'the summary was rebuilt');
    assert.equal(page.document.activeElement, link);
});

test('Other reasons asks for the reasons the overview counts, as the Other rejects card does', async () => {
    const page = emailPage();
    await settle();
    page.respond('/api/v1/email/overview', 200, overview({
        rejects: { spam: 4, malware: 1, rate_limited: 3, sender_verify: 2, bad_helo: 1 }, temporary: { rate_limited: 3 }
    }));
    await settle();
    assert.equal(kpi(page, 'kpi-other').value, '3');
    page.document.querySelector('#kpi-other a').click();
    await settle();
    assert.equal(query(page.pending('/api/v1/email/rejects')[0].url).get('class'), 'sender_verify,bad_helo');

    // A class this build does not know, kept from an older one, is left
    // out: the server would refuse the whole list.
    const old = emailPage();
    await settle();
    old.respond('/api/v1/email/overview', 200, overview({ rejects: { sender_verify: 2, retired_class: 4 } }));
    await settle();
    old.document.querySelector('#kpi-other a').click();
    await settle();
    assert.equal(query(old.pending('/api/v1/email/rejects')[0].url).get('class'), 'sender_verify');

    // No other reason in the range: nothing to ask for.
    const none = emailPage();
    await settle();
    none.respond('/api/v1/email/overview', 200, overview({ rejects: { spam: 1 } }));
    await settle();
    none.document.querySelector('#kpi-other a').click();
    await settle();
    assert.equal(none.pending('/api/v1/email/rejects').length, 0);
    const tbody = none.document.getElementById('email-rejects-tbody');
    assert.ok(tbody.querySelector('.csm-empty'), 'not the shared empty state');
    assert.match(flat(tbody), /No rejects for other reasons in the last 24 hours/);
});

test('a forwarders link opens the Forwarders tab and reads the list', async () => {
    const page = emailPage({ url: 'https://csm.example.test/email?tab=forwarders' });
    await settle();
    assert.equal(selectedTab(page), 'forwarders');
    assert.equal(page.pending('/api/v1/email/forwarders').length, 1);
});

// ---------- Provider delays ----------

// deferrals is a deferrals response with nothing deferred, read from 20,000
// log lines, and any other fields.
function deferrals(extra) {
    return Object.assign({ deferrals: 0, providers: [], outbound_ips: [], lines: 20000,
        window_start: '2026-10-21T08:00:00Z', window_end: '2026-10-21T10:00:00Z' }, extra);
}

const DELAYS = deferrals({
    deferrals: 9,
    providers: [
        { provider: 'gmail', deferrals: 5, reasons: [{ code: 'rate_limit', count: 4 }], last_seen: '2026-10-21T09:58:00Z',
            sample: '421-4.7.28 [198.51.100.7] Our system has detected an unusual rate of unsolicited mail' },
        { provider: 'yahoo', deferrals: 3, reasons: [{ code: 'TSS04', count: 2 }, { code: 'spamhaus', count: 1 }], last_seen: '2026-10-21T09:00:00Z',
            sample: '421 4.7.0 [TSS04] Messages from 198.51.100.7 temporarily deferred' },
        { provider: 'external', deferrals: 1, reasons: [{ code: 'greylist', count: 1 }], last_seen: '2026-10-21T08:30:00Z', sample: '' }
    ],
    outbound_ips: [
        { ip: '198.51.100.7', deferrals: 8, providers: [{ provider: 'gmail', count: 5 }, { provider: 'yahoo', count: 3 }],
            reasons: [{ code: 'rate_limit', count: 4 }, { code: 'TSS04', count: 2 }, { code: 'spamhaus', count: 1 }], last_seen: '2026-10-21T09:58:00Z' }
    ]
});

// delaysPage opens Provider delays from its address and answers its read.
async function delaysPage(body) {
    const page = emailPage({ url: 'https://csm.example.test/email?tab=delays' });
    await settle();
    page.respond('/api/v1/email/deferrals', 200, body);
    await settle();
    return page;
}

function delayRows(page, id) {
    return Array.from(page.document.querySelectorAll('#' + id + '-body tr')).filter(r => !r.classList.contains('details-row'));
}

function badgeTexts(row) {
    return Array.from(row.querySelectorAll('[data-label="Reason"] .badge')).map(flat);
}

test('Provider delays lists each provider: deferred, last seen and why in plain words, the sample on expand', async () => {
    const page = await delaysPage(DELAYS);
    const doc = page.document;
    assert.deepEqual(Array.from(doc.querySelectorAll('#email-deliv-providers thead th')).map(flat), ['Provider', 'Deferred', 'Last seen', 'Reason']);
    const rows = delayRows(page, 'email-deliv-providers');
    assert.deepEqual(rows.map(r => flat(r.querySelector('[data-label="Provider"]'))), ['Google', 'Yahoo', 'Other domains']);
    assert.deepEqual(rows.map(r => flat(r.querySelector('[data-label="Deferred"]'))), ['5', '3', '1']);
    assert.equal(flat(rows[0].querySelector('[data-label="Last seen"]')), page.window.CSM.fmtDate('2026-10-21T09:58:00Z'));
    // A deferral no reason was read from counts as other.
    assert.deepEqual(rows.map(badgeTexts), [['rate limited (4)', 'other'], ['code TSS04 (2)', 'blocklisted (Spamhaus)'], ['greylisted']]);
    // No Risk column, and a provider carries no color of its own.
    assert.equal(rows[0].querySelector('[data-label="Provider"] .badge'), null);
    // The sample error shows on expand, as text.
    const expand = rows[0].querySelector('.expand-btn');
    assert.ok(expand, 'no expand button for the sample');
    const details = rows[0].nextElementSibling;
    assert.ok(details.classList.contains('details-row'));
    assert.equal(details.classList.contains('show'), false);
    expand.click();
    assert.equal(details.classList.contains('show'), true);
    assert.equal(flat(details.querySelector('.subheader')), 'Sample error');
    assert.equal(flat(details.querySelector('.font-monospace')), '421-4.7.28 [198.51.100.7] Our system has detected an unusual rate of unsolicited mail');
    assert.equal(rows[2].querySelector('.expand-btn'), null, 'a provider with no sample has something to expand');
    assert.ok(doc.getElementById('email-deliv-providers').classList.contains('csm-table-rowcard'), 'no row cards on phones');
});

test('Our sending IPs lists each IP with the providers deferring it and why', async () => {
    const page = await delaysPage(DELAYS);
    const doc = page.document;
    const html = doc.getElementById('email-pane-delays').innerHTML;
    assert.ok(html.indexOf('id="email-deliv-providers"') < html.indexOf('Our sending IPs'), 'the providers do not come first');
    assert.ok(html.indexOf('Our sending IPs') < html.indexOf('id="email-deliv-ips"'));
    assert.deepEqual(Array.from(doc.querySelectorAll('#email-deliv-ips thead th')).map(flat), ['Sending IP', 'Deferred', 'Last seen', 'Deferred by', 'Reason']);
    const rows = delayRows(page, 'email-deliv-ips');
    assert.equal(rows.length, 1);
    assert.equal(flat(rows[0].querySelector('[data-label="Sending IP"]')), '198.51.100.7');
    assert.equal(flat(rows[0].querySelector('[data-label="Deferred"]')), '8');
    assert.equal(flat(rows[0].querySelector('[data-label="Last seen"]')), page.window.CSM.fmtDate('2026-10-21T09:58:00Z'));
    assert.equal(flat(rows[0].querySelector('[data-label="Deferred by"]')), 'Google 5, Yahoo 3');
    assert.deepEqual(badgeTexts(rows[0]), ['rate limited (4)', 'code TSS04 (2)', 'blocklisted (Spamhaus)', 'other']);
    assert.ok(doc.getElementById('email-deliv-ips').classList.contains('csm-table-rowcard'), 'no row cards on phones');
});

test('Provider delays says how many log lines it read, and since when', async () => {
    const page = await delaysPage(DELAYS);
    const doc = page.document;
    assert.equal(flat(doc.getElementById('email-deliv-summary')), '9 outbound deferrals across 3 providers and 1 sending IP.');
    assert.equal(flat(doc.getElementById('email-deliv-scope')),
        'From the last 20,000 log lines (since ' + page.window.CSM.fmtDate('2026-10-21T08:00:00Z') + ')');
    const empty = await delaysPage(deferrals({ lines: 0, window_start: undefined, window_end: undefined }));
    assert.equal(flat(empty.document.getElementById('email-deliv-summary')), 'No outbound deferrals seen in the recent log window.');
    assert.equal(flat(empty.document.getElementById('email-deliv-scope')), 'No mail log lines read.');
    for (const id of ['email-deliv-providers-body', 'email-deliv-ips-body']) {
        assert.ok(empty.document.querySelector('#' + id + ' .csm-empty'), id + ' does not show the shared empty state');
    }
});

test('delay reasons are colored by what they mean: blocked red, rate limited amber, greylisted grey, the rest neutral', async () => {
    const codes = ['spamhaus', 'blocked', 'complaint', 'rate_limit', 'greylist', 'mailbox_full', 'retry_wait', 'host_not_found', 'refused', 'TSS04'];
    const page = await delaysPage(deferrals({ deferrals: codes.length, providers: [{ provider: 'gmail', deferrals: codes.length,
        reasons: codes.map(code => ({ code, count: 1 })), last_seen: AT, sample: 'x' }] }));
    const badges = Array.from(delayRows(page, 'email-deliv-providers')[0].querySelectorAll('[data-label="Reason"] .badge'));
    const color = b => b.classList.contains('bg-red-lt') ? 'red' : b.classList.contains('bg-yellow-lt') ? 'amber' :
        b.classList.contains('bg-secondary-lt') ? 'grey' : 'neutral';
    assert.deepEqual(badges.map(b => [flat(b), color(b)]), [
        ['blocklisted (Spamhaus)', 'red'], ['blocked', 'red'], ['user complaints', 'red'], ['rate limited', 'amber'], ['greylisted', 'grey'],
        ['mailbox full', 'neutral'], ['retry time not reached', 'neutral'], ['server not found or unreachable', 'neutral'],
        ['refused', 'neutral'], ['code TSS04', 'neutral']]);
    for (const b of badges.slice(5)) assert.doesNotMatch(b.className, /\bbg-/, flat(b) + ' carries a color');
});

test('the Provider delays count is the providers deferring now, read with the page', async () => {
    const page = emailPage();
    await settle();
    const tab = page.document.getElementById('email-tab-delays');
    assert.equal(tab.querySelector('[data-tab-count]').hidden, true, 'a count before the deferrals answered');
    assert.equal(page.pending('/api/v1/email/deferrals').length, 1, 'the count was not read with the page');
    page.respond('/api/v1/email/deferrals', 200, DELAYS);
    await settle();
    assert.equal(tab.querySelector('[data-tab-count]').textContent, '3');
    assert.equal(spoken(tab), 'Provider delays 3 providers deferring');
    // A closed tab reads its count every minute; an open one reads on
    // opening and every minute.
    const rows = page.document.getElementById('email-deliv-providers-body').innerHTML;
    page.window.CSM.refresh.manual();
    await settle();
    assert.equal(page.pending('/api/v1/email/deferrals').length, 1, 'the closed tab count was not read');
    page.respond('/api/v1/email/deferrals', 200, deferrals({ deferrals: 4, providers: DELAYS.providers.slice(0, 2) }));
    await settle();
    assert.equal(tab.querySelector('[data-tab-count]').textContent, '2');
    assert.equal(page.document.getElementById('email-deliv-providers-body').innerHTML, rows, 'the hidden tables were drawn again');
    await answerAll(page, {});
    showEmailTab(page, 'delays');
    await settle();
    assert.equal(page.pending('/api/v1/email/deferrals').length, 1, 'opening the tab did not read it');
    page.respond('/api/v1/email/deferrals', 200, deferrals({ deferrals: 1, providers: [DELAYS.providers[2]] }));
    await settle();
    assert.equal(tab.querySelector('[data-tab-count]').textContent, '1');
    page.window.CSM.refresh.manual();
    await settle();
    assert.equal(page.pending('/api/v1/email/deferrals').length, 1, 'the open tab did not poll');

    const failed = emailPage();
    await settle();
    failed.fail('/api/v1/email/deferrals');
    await settle();
    assert.equal(failed.document.querySelector('#email-tab-delays [data-tab-count]').textContent, '?');
});

test('the minute timer keeps the header and the hidden tab counts fresh without drawing hidden tables', async () => {
    const page = emailPage({ url: 'https://csm.example.test/email?tab=findings' });
    await settle();
    await answerAll(page, {
        '/api/v1/email/overview': overview({ scanned: 10, clean: 10 }),
        '/api/v1/email/rspamd': { status: 'up', available: false },
        '/api/v1/email/quarantine': items([malwareItem(MID[0])]),
        '/api/v1/email/held': items([]),
        '/api/v1/email/senders': senders([{ account: 'shopuser', messages: 3 }], { abuse_events: 1 }),
        '/api/v1/email/deferrals': DELAYS
    });
    const doc = page.document;
    const badges = () => ['held', 'sending', 'delays'].map(name => doc.querySelector('#email-tab-' + name + ' [data-tab-count]').textContent);
    const TABLES = ['email-held-tbody', 'email-sending-tbody', 'email-deliv-providers-body', 'email-deliv-ips-body'];
    const tables = () => TABLES.map(id => doc.getElementById(id).innerHTML);
    assert.deepEqual(badges(), ['1', '1', '3']);
    const drawn = tables();
    assert.doesNotMatch(flat(doc.getElementById('email-subtitle')), /rspamd is down/);

    page.window.CSM.refresh.manual();
    await settle();
    await answerAll(page, {
        '/api/v1/email/overview': overview({ scanned: 10, clean: 10 }),
        '/api/v1/email/rspamd': { status: 'down', available: false },
        '/api/v1/email/quarantine': items([malwareItem(MID[0]), malwareItem(MID[1])]),
        '/api/v1/email/held': items([forwardItem(FID[0])]),
        '/api/v1/email/senders': senders([{ account: 'shopuser', messages: 9 }, { account: 'blogger', messages: 2 }], { abuse_events: 4 }),
        '/api/v1/email/deferrals': deferrals({ deferrals: 1, providers: [DELAYS.providers[2]] })
    });
    assert.match(flat(doc.getElementById('email-subtitle')), /rspamd is down/);
    assert.deepEqual(badges(), ['3', '4', '1']);
    assert.deepEqual(tables(), drawn, 'a hidden table was drawn again');
    // A count that cannot be read says so, on a hidden tab too.
    page.window.CSM.refresh.manual();
    await settle();
    for (const route of ['/api/v1/email/held', '/api/v1/email/senders', '/api/v1/email/deferrals']) page.fail(route, new Error('HTTP 502'));
    await answerAll(page, {});
    assert.deepEqual(badges(), ['?', '?', '?']);
    assert.deepEqual(tables(), drawn, 'a failed count drew a hidden table');
});

test('an unchanged delays answer keeps the rows; a changed one keeps the open sample and the focus', async () => {
    const page = await delaysPage(DELAYS);
    const first = delayRows(page, 'email-deliv-providers')[0];
    const expand = first.querySelector('.expand-btn');
    expand.click();
    expand.focus();
    page.window.CSM.refresh.manual();
    await answerAll(page, { '/api/v1/email/deferrals': DELAYS });
    assert.equal(delayRows(page, 'email-deliv-providers')[0], first, 'an unchanged answer rebuilt the rows');
    const changed = JSON.parse(JSON.stringify(DELAYS));
    changed.deferrals = 10;
    changed.providers[0].deferrals = 6;
    page.window.CSM.refresh.manual();
    await answerAll(page, { '/api/v1/email/deferrals': changed });
    const row = delayRows(page, 'email-deliv-providers')[0];
    assert.notEqual(row, first, 'a changed answer kept the old rows');
    assert.equal(flat(row.querySelector('[data-label="Deferred"]')), '6');
    assert.equal(row.nextElementSibling.classList.contains('show'), true, 'the open sample closed');
    assert.equal(page.document.activeElement, row.querySelector('.expand-btn'), 'the focus was lost');
});

test('provider delays keep server text as text', async () => {
    const evil = '<img src=x onerror=alert(1)>';
    const page = await delaysPage(deferrals({ deferrals: 2,
        providers: [{ provider: evil, deferrals: 2, reasons: [{ code: evil, count: 2 }], last_seen: AT, sample: '<b>sample</b>' }],
        outbound_ips: [{ ip: evil, deferrals: 2, providers: [{ provider: evil, count: 2 }], reasons: [{ code: evil, count: 2 }], last_seen: AT }] }));
    const pane = page.document.getElementById('email-pane-delays');
    assert.equal(pane.querySelectorAll('img').length, 0);
    assert.equal(pane.querySelectorAll('b').length, 0);
    assert.match(pane.textContent, /<img src=x onerror=alert\(1\)>/);
    assert.match(pane.textContent, /<b>sample<\/b>/);
});

// ---------- Findings polish ----------

test('an unknown check from the address stays on offer, so the select names what the table filters', async () => {
    const page = emailPage({ url: 'https://csm.example.test/email?tab=findings&check=email_retired_check' });
    await settle();
    assert.equal(historyQuery(page).get('checks'), 'email_retired_check');
    page.respond('/api/v1/email/checks', 200, CHECKS);
    await settle();
    const check = page.document.getElementById('filter-check');
    assert.equal(check.value, 'email_retired_check');
    assert.equal(Array.from(check.options).filter(o => o.value === 'email_retired_check').length, 1);
    assert.deepEqual(Array.from(check.options).map(o => o.value).slice(0, 5), ['', 'mail_bruteforce', 'smtp_bruteforce', 'mail_queue', 'email_dkim_failure']);
});

test('the Findings count is the findings in the range', async () => {
    const page = emailPage();
    await settle();
    const tab = page.document.getElementById('email-tab-findings');
    assert.equal(tab.querySelector('[data-tab-count]').hidden, true, 'a count before the findings answered');
    page.respond('/api/v1/history?', 200, items([{ severity: 1, check: 'mail_bruteforce', message: 'm', timestamp: AT }], { total: 312, limit: 250, truncated: true }));
    await settle();
    assert.equal(tab.querySelector('[data-tab-count]').textContent, '312');
    assert.equal(spoken(tab), 'Findings 312 findings');
    changeValue(page, page.document.getElementById('filter-severity'), '2');
    await settle();
    page.respond('/api/v1/history?', 200, items([], { total: 0 }));
    await settle();
    assert.equal(tab.querySelector('[data-tab-count]').textContent, '0');
    changeValue(page, page.document.getElementById('filter-severity'), '1');
    await settle();
    page.fail('/api/v1/history?');
    await settle();
    assert.equal(tab.querySelector('[data-tab-count]').textContent, '?');
});

test('an older SMTP firewall answer cannot replace a newer one', async () => {
    const page = emailPage({ url: 'https://csm.example.test/email?tab=sending' });
    await settle();
    page.window.CSM.refresh.manual();
    await settle();
    const [older, newer] = page.pending('/api/v1/email/stats');
    assert.ok(newer, 'the timer did not read the SMTP firewall again');
    newer.settled = true;
    newer.resolve(jsonResponse(200, Object.assign({}, FIREWALL, { smtp_block: false })));
    await settle();
    older.settled = true;
    older.resolve(jsonResponse(200, FIREWALL));
    await settle();
    const fw = flat(page.document.getElementById('email-sending-firewall'));
    assert.match(fw, /Outbound SMTP\s*open/);
    assert.doesNotMatch(fw, /restricted/);
});

// ---------- One empty state and one error state ----------

// Each tab's list: where it shows, what fails it, and what answers it
// empty when the default empty list would not.
const LIST_STATES = [
    { tab: 'overview', fails: '/api/v1/email/groups?', host: 'email-action-groups' },
    { tab: 'queue', fails: '/api/v1/email/queue?', host: 'email-queue-summary',
        bodies: { '/api/v1/email/overview': queueOverview(0), '/api/v1/email/queue?': queueList([]) } },
    { tab: 'held', fails: '/api/v1/email/quarantine', host: 'email-held-tbody' },
    { tab: 'rejects', fails: '/api/v1/email/rejects', host: 'email-rejects-tbody' },
    { tab: 'sending', fails: '/api/v1/email/senders', host: 'email-sending-tbody', bodies: { '/api/v1/email/senders': senders([]) } },
    { tab: 'delays', fails: '/api/v1/email/deferrals', host: 'email-deliv-providers-body', bodies: { '/api/v1/email/deferrals': deferrals() } },
    { tab: 'findings', fails: '/api/v1/history?', host: 'email-tbody' }
];

// drive answers what the page asks for until it stops asking, failing what
// fails matches.
async function drive(page, bodies, fails) {
    for (let round = 0; round < 8; round++) {
        const pending = page.pending();
        if (pending.length === 0) break;
        for (const req of pending) {
            if (fails && req.url.includes(fails)) {
                page.fail(req.url, new Error('HTTP 502'));
                continue;
            }
            const hit = Object.keys(bodies).find(k => req.url.includes(k));
            page.respond(req.url, 200, hit ? bodies[hit] : items([]));
        }
        await settle();
    }
}

// shownEmpty returns the shared empty states in host that show: a load
// error hides what the host held before.
function shownEmpty(host) {
    return Array.from(host.querySelectorAll('.csm-empty')).filter(el => {
        for (let n = el; n && n !== host; n = n.parentNode) if (n.hidden) return false;
        return true;
    });
}

test('every tab shows the one empty state and the one error state with Retry', async () => {
    const src = fs.readFileSync(path.join(__dirname, 'static/js/email.js'), 'utf8');
    assert.match(src, /var buildEmpty = CSM\.emptyStateNode;/);
    assert.doesNotMatch(src, /csm-empty|csm-load-error/, 'email.js draws an empty or error state of its own');
    for (const c of LIST_STATES) {
        const empty = emailPage({ url: 'https://csm.example.test/email?tab=' + c.tab });
        await settle();
        await drive(empty, c.bodies || {});
        const host = empty.document.getElementById(c.host);
        assert.ok(empty.document.getElementById('email-pane-' + c.tab).contains(host), c.host + ' is not on ' + c.tab);
        assert.equal(shownEmpty(host).length, 1, c.tab + ': no shared empty state in #' + c.host + ': ' + flat(host));
        assert.equal(host.querySelector('.csm-load-error'), null, c.tab + ': an error state with nothing failed');

        const failed = emailPage({ url: 'https://csm.example.test/email?tab=' + c.tab });
        await settle();
        await drive(failed, c.bodies || {}, c.fails);
        const error = failed.document.getElementById(c.host).querySelector('.csm-load-error');
        assert.ok(error, c.tab + ': no shared error state in #' + c.host);
        assert.match(error.textContent, /HTTP 502/, c.tab + ': the reason is missing');
        assert.ok(error.querySelector('.csm-retry-btn'), c.tab + ': no Retry');
        assert.equal(shownEmpty(failed.document.getElementById(c.host)).length, 0, c.tab + ': a failed list reads as empty');
    }
});

test('an empty queue says so once, in the shared empty state', async () => {
    const page = await queuePage([]);
    page.respond('/api/v1/email/queue-composition', 200, { total: 0, real: 0, bounce: 0, frozen: 0, flushable_backscatter: 0, top_recipients: [] });
    await settle();
    const pane = page.document.getElementById('email-pane-queue');
    assert.deepEqual(shownEmpty(pane).map(flat), ['The queue is empty.']);
    // Once the queue fills, the composition shows again.
    page.document.getElementById('email-refresh').click();
    await answerAll(page, { '/api/v1/email/overview': queueOverview(3), '/api/v1/email/queue?': queueList([queueMsg(QID[0])], { queued: 3 }),
        '/api/v1/email/queue-composition': { total: 3, real: 3, bounce: 0, frozen: 0, flushable_backscatter: 0, top_recipients: [] } });
    assert.equal(page.document.getElementById('queue-composition').parentElement.hidden, false);
    assert.match(flat(page.document.getElementById('queue-composition')), /Real mail/);
});

// ---------- Findings summary under the Auth failures chip ----------

test('Findings under the Auth failures chip repeats the Failed logins number and the alerts raised', async () => {
    const page = emailPage({ url: 'https://csm.example.test/email?tab=auth' });
    await settle();
    const summary = page.document.getElementById('email-findings-summary');
    assert.ok(page.document.getElementById('email-pane-findings').contains(summary), 'the summary is not on Findings');
    page.respond('/api/v1/email/overview', 200, overview({ logins_smtp: 300, logins_mailbox: 138 }));
    page.respond('/api/v1/email/checks', 200, CHECKS);
    await settle();
    assert.equal(kpi(page, 'kpi-logins').value, '438');
    page.respond('/api/v1/history?', 200, items([{ severity: 2, check: 'mail_bruteforce', message: 'm', timestamp: AT }], { total: 12, limit: 250 }));
    await settle();
    assert.equal(summary.hidden, false);
    assert.equal(flat(summary), 'Failed login attempts in this range: 438. Alerts raised: 12.');
    assert.equal(summary.children.length, 0, 'the summary holds markup');

    // Without the chip there is no such line.
    page.document.getElementById('email-filter-auth').click();
    await settle();
    page.respond('/api/v1/history?', 200, items([], { total: 40 }));
    await settle();
    assert.equal(summary.hidden, true);
    assert.equal(flat(summary), '');
});

test('the Failed logins card opens Findings with its number repeated', async () => {
    const page = emailPage();
    await settle();
    page.respond('/api/v1/email/overview', 200, overview({ logins_smtp: 5, logins_mailbox: 2 }));
    page.respond('/api/v1/email/checks', 200, CHECKS);
    page.respond('/api/v1/history?', 200, items([], { total: 99 }));
    await settle();
    const summary = page.document.getElementById('email-findings-summary');
    assert.equal(summary.hidden, true, 'a summary without the chip');
    page.document.querySelector('#kpi-logins a').click();
    await settle();
    page.respond('/api/v1/history?', 200, items([], { total: 0 }));
    await settle();
    assert.equal(flat(summary), 'Failed login attempts in this range: 7. Alerts raised: 0.');
});

// ---------- Fix round 2 ----------

test('Other reasons asks again when a new range counts other reasons', async () => {
    const page = emailPage({ url: 'https://csm.example.test/email?tab=rejects' });
    await settle();
    page.respond('/api/v1/email/overview', 200, overview({ rejects: { spam: 3 } }));
    page.respond('/api/v1/email/rejects', 200, items([], { kept_days: 7 }));
    await settle();
    changeValue(page, page.document.getElementById('email-rejects-filter'), 'other');
    await settle();
    assert.equal(page.pending('/api/v1/email/rejects').length, 0, 'asked with no other reason counted');
    changeValue(page, page.document.getElementById('email-range'), '30d');
    await settle();
    page.respond('/api/v1/email/overview', 200, overview({ rejects: { spam: 40, sender_verify: 12 } }));
    await settle();
    const reqs = page.pending('/api/v1/email/rejects');
    assert.equal(reqs.length, 1, 'the new range did not ask for its reasons');
    assert.equal(query(reqs[0].url).get('class'), 'sender_verify');
    page.respond('/api/v1/email/rejects', 200, items([{ at: AT, class: 'sender_verify', sender: 'a@example.com', detail: 'verify failed' }], { kept_days: 7 }));
    await settle();
    assert.match(flat(page.document.getElementById('email-rejects-tbody')), /verify failed/);
    // The same classes on the next overview ask nothing more.
    page.document.getElementById('email-refresh').click();
    await settle();
    page.respond('/api/v1/email/rejects', 200, items([{ at: AT, class: 'sender_verify', sender: 'a@example.com', detail: 'verify failed' }], { kept_days: 7 }));
    page.respond('/api/v1/email/overview', 200, overview({ rejects: { spam: 40, sender_verify: 12 } }));
    await settle();
    assert.equal(page.pending('/api/v1/email/rejects').length, 0, 'an unchanged class list asked again');
});

test('each Deferred by entry keeps its provider and count together', async () => {
    const page = await delaysPage(DELAYS);
    const cell = delayRows(page, 'email-deliv-ips')[0].querySelector('[data-label="Deferred by"]');
    assert.deepEqual(Array.from(cell.querySelectorAll('.text-nowrap')).map(flat), ['Google 5', 'Yahoo 3']);
    assert.equal(flat(cell), 'Google 5, Yahoo 3');
});

test('an unknown queue size says so once on the Queue tab, with Retry', async () => {
    for (const fails of [false, true]) {
        const page = emailPage();
        showEmailTab(page, 'queue');
        await settle();
        if (fails) page.fail('/api/v1/email/overview', new Error('HTTP 502'));
        else page.respond('/api/v1/email/overview', 200, overview({}, { queue: { size: 0, unavailable: true, warn: 100, crit: 500, frozen: 0, detail_unavailable: true } }));
        page.respond('/api/v1/email/queue?', 200, queueList([queueMsg(QID[0])]));
        await settle();
        const pane = page.document.getElementById('email-pane-queue');
        const label = fails ? 'failed overview' : 'unreadable queue';
        assert.equal(pane.querySelectorAll('.csm-load-error').length, 1, label + ': not one error state');
        assert.equal(shownEmpty(pane).length, 0, label + ': an empty state beside the error');
        assert.equal((pane.textContent.match(/Queue size unknown/g) || []).length, 1, label + ': said more than once');
        assert.ok(page.document.querySelector('#email-queue-summary .csm-retry-btn'), label + ': no Retry');
    }
});

test('the queue summary takes frozen and oldest from the overview, as the Queue card does', async () => {
    const page = emailPage();
    showEmailTab(page, 'queue');
    await settle();
    page.respond('/api/v1/email/overview', 200, queueOverview(30, { frozen: 3, oldest_age_seconds: 4 * DAY }));
    page.respond('/api/v1/email/queue?', 200, queueList([queueMsg(QID[0])], { queued: 28, frozen: 1, oldest_seconds: 2 * DAY }));
    await settle();
    const summary = page.document.getElementById('email-queue-summary');
    assert.equal(kpi(page, 'kpi-queue').sub, 'oldest 4d, 3 frozen');
    assert.match(flat(summary), /^30 queued, 3 frozen, oldest 4d\./);
    // Without the queue detail both say the oldest is unknown.
    page.document.getElementById('email-refresh').click();
    await settle();
    page.respond('/api/v1/email/overview', 200, queueOverview(30, { frozen: 0, detail_unavailable: true }));
    await settle();
    assert.equal(kpi(page, 'kpi-queue').sub, 'oldest unknown');
    assert.match(flat(summary), /^30 queued, oldest unknown\./);
});

// Refreshes must preserve work in progress, including when the data changes.
test('reject refreshes keep unchanged rows and restore link focus after changes', async () => {
    const page = emailPage({ url: 'https://csm.example.com/email?tab=rejects' });
    const list = Array.from({ length: 15 }, (_, i) => ({ at: AT, class: 'spam', ip: '192.0.2.1', detail: 'reject ' + i }));
    page.respond('/api/v1/email/rejects', 200, items(list, { kept_days: 7 }));
    await settle();
    const table = () => page.window.CSM._tableInstances.find(t => t.opts.tableId === 'email-rejects-table');
    page.document.querySelector('#email-rejects-table-controls [data-page="2"]').click();
    const row = table().allRows[11].row;
    row.querySelector('a').focus();
    page.window.CSM.refresh.manual();
    page.respond('/api/v1/email/rejects', 200, items(list, { kept_days: 7 }));
    await settle();
    assert.equal(table().allRows[11].row, row, 'unchanged rows were rebuilt');
    assert.equal(page.document.activeElement, row.querySelector('a'));
    page.window.CSM.refresh.manual();
    page.respond('/api/v1/email/rejects', 200, items(list.concat({ at: AT, class: 'spam', detail: 'new' }), { kept_days: 7 }));
    await settle();
    assert.equal(table().currentPage, 2);
    assert.equal(page.document.activeElement, table().allRows[11].row.querySelector('a'), 'changed rows lost focus');
});

test('Findings refresh on opening and poll only while visible', async () => {
    const page = emailPage();
    const count = () => requestCount(page, '/api/v1/history?');
    page.respond('/api/v1/history?', 200, items([]));
    await settle();
    const initial = count();
    page.window.CSM.refresh.manual();
    assert.equal(count(), initial, 'hidden Findings polled');
    showEmailTab(page, 'findings');
    assert.equal(count(), initial + 1, 'opening Findings left the initial results stale');
    page.window.CSM.refresh.manual();
    assert.equal(count(), initial + 2, 'visible Findings did not poll');
    showEmailTab(page, 'queue');
    const overviewCalls = ['/api/v1/email/groups?', '/api/v1/email/av/status'].map(p => requestCount(page, p));
    const rspamdCalls = requestCount(page, '/api/v1/email/rspamd');
    page.window.CSM.refresh.manual();
    assert.equal(count(), initial + 2);
    assert.deepEqual(['/api/v1/email/groups?', '/api/v1/email/av/status'].map(p => requestCount(page, p)), overviewCalls,
        'hidden Overview content polled');
    // The header names rspamd's state on every tab.
    assert.equal(requestCount(page, '/api/v1/email/rspamd'), rspamdCalls + 1, 'the header rspamd state did not refresh');
});

test('Findings refresh keeps rows, open details and focused controls', async () => {
    const page = emailPage({ url: 'https://csm.example.com/email?tab=findings' });
    const list = [{ check: 'email_av', severity: 'HIGH', message: 'message', details: 'details', timestamp: AT }];
    for (const req of page.pending('/api/v1/history?')) { req.settled = true; req.resolve(jsonResponse(200, items(list))); }
    await settle();
    const body = page.document.getElementById('email-tbody');
    const row = body.firstElementChild;
    const btn = row.querySelector('.expand-btn');
    btn.click(); btn.focus();
    page.document.getElementById('email-refresh').click();
    page.respond('/api/v1/history?', 200, items(list));
    await settle();
    assert.equal(body.firstElementChild, row, 'unchanged findings were rebuilt');
    assert.equal(page.document.activeElement, btn);
    page.document.getElementById('email-refresh').click();
    page.respond('/api/v1/history?', 200, items(list.concat({ check: 'email_av', severity: 'HIGH', message: 'new', timestamp: AT })));
    await settle();
    const restored = body.querySelector('.expand-btn');
    assert.equal(restored.getAttribute('aria-expanded'), 'true');
    assert.equal(page.document.activeElement, restored);
});

test('a held custom range excludes items at and after its end', async () => {
    const page = emailPage({ url: 'https://csm.example.com/email?tab=held&from=2026-10-20&to=2026-10-20',
        storage: { 'csm-prefs': JSON.stringify({ timezone: 'UTC' }) } });
    page.respond('/api/v1/email/quarantine', 200, items([
        malwareItem(MID[0], { quarantined_at: '2026-10-20T12:00:00Z' }),
        malwareItem(MID[1], { quarantined_at: '2026-10-21T00:00:00Z' })
    ]));
    page.respond('/api/v1/email/held', 200, items([forwardItem(FID[0], { held_at: '2026-10-22T12:00:00Z' })]));
    await settle();
    assert.deepEqual(heldRows(page).map(r => r.getAttribute('data-held-id')), [MID[0]]);
    assert.match(flat(page.document.getElementById('email-held-summary')), /2.*outside.*range/i);
});

test('held mail a server clock ahead of the browser just held shows in the rolling ranges', async () => {
    const now = '2026-10-21T10:00:00Z', ahead = '2026-10-21T10:02:00Z';
    for (const range of ['24h', '7d', '30d']) {
        const page = emailPage({ now, url: 'https://csm.example.test/email?tab=held', storage: { 'csm-email-range': range } });
        await settle();
        page.respond('/api/v1/email/quarantine', 200, items([malwareItem(MID[0], { quarantined_at: ahead })]));
        page.respond('/api/v1/email/held', 200, items([forwardItem(FID[0], { held_at: ahead })]));
        await settle();
        assert.deepEqual(heldRows(page).map(r => r.getAttribute('data-held-id')).sort(), [FID[0], MID[0]].sort(), range + ' hid what was just held');
        assert.doesNotMatch(flat(page.document.getElementById('email-held-summary')), /outside/, range);
    }
});

test('a queued message updates changed recipients even when their count stays equal', async () => {
    const m = queueMsg(QID[0], { recipients: ['first@example.net'], recipient_count: 1 });
    const page = await queuePage([m]);
    page.window.CSM.refresh.manual();
    page.respond('/api/v1/email/queue?', 200, queueList([Object.assign({}, m, { recipients: ['next@example.net'] })]));
    await settle();
    assert.match(flat(queueRow(page, QID[0])), /next@example.net/);
    assert.doesNotMatch(flat(queueRow(page, QID[0])), /first@example.net/);
});

test('older queue detail reads cannot replace the refreshed delivery log', async () => {
    const m = queueMsg(QID[0]);
    const page = await queuePage([m]);
    queueRow(page, QID[0]).querySelector('.expand-btn').click();
    await settle();
    const old = page.pending('/api/v1/email/queue/' + QID[0])[0];
    page.window.CSM.refresh.manual();
    page.respond('/api/v1/email/queue?', 200, queueList([Object.assign({}, m, { frozen: !m.frozen })]));
    await settle();
    const fresh = page.pending('/api/v1/email/queue/' + QID[0]).at(-1);
    assert.notEqual(fresh, old);
    fresh.settled = true; fresh.resolve(jsonResponse(200, { id: QID[0], msglog: ['new delivery log'] }));
    await settle();
    old.settled = true; old.resolve(jsonResponse(200, { id: QID[0], msglog: ['old delivery log'] }));
    await settle();
    const text = flat(queueRow(page, QID[0]).nextElementSibling);
    assert.match(text, /new delivery log/);
    assert.doesNotMatch(text, /old delivery log/);
});

test('bulk held actions lock every selected item across refreshes', async () => {
    const malware = [malwareItem(MID[0]), malwareItem(MID[1])];
    const page = await heldPage(malware, []);
    stubConfirm(page);
    heldRow(page, MID[0]).querySelector('.email-quar-cb').click();
    heldRow(page, MID[1]).querySelector('.email-quar-cb').click();
    page.document.getElementById('email-quar-bulk-release').click();
    await settle();
    await heldTick(page, malware.concat(malwareItem(MID[2])), []);
    for (const id of MID.slice(0, 2)) {
        const row = heldRow(page, id);
        assert.equal(row.querySelector('[data-held-action="delete"]').disabled, true, 'bulk item can be deleted mid-release');
        assert.equal(row.querySelector('.email-quar-cb').disabled, true, 'bulk item can be selected again');
    }
    assert.equal(page.document.getElementById('email-quar-bulk-delete').disabled, true);
    page.document.getElementById('email-quar-bulk-release').click();
    await settle();
    assert.equal(page.requests.filter(r => r.method === 'POST').length, 1, 'duplicate bulk release started');
});

test('changed abuse events keep open sites, focus and pending block state', async () => {
    const event = abuseEvent({ source_ip: '192.0.2.5', sites: [{ site: 'example.com', script: '/send.php', hits: 1, last_seen: AT }] });
    const page = await sendingPage({ '/api/v1/email/relay-abuse': items([event]) });
    stubConfirm(page);
    const body = page.document.getElementById('email-abuse-events');
    body.querySelector('.oab-toggle').click();
    body.querySelector('.oab-block').click();
    await settle();
    body.querySelector('.oab-toggle').focus();
    page.window.CSM.refresh.manual();
    page.respond('/api/v1/email/relay-abuse', 200, items([abuseEvent({ detected_at: '2026-10-21T12:00:00Z' }), event]));
    await settle();
    const block = body.querySelector('.oab-block[data-ip="192.0.2.5"]');
    assert.equal(block.disabled, true, 'a refresh reopened a pending block');
    const toggle = block.parentElement.querySelector('.oab-toggle');
    assert.equal(page.document.activeElement, toggle);
    assert.equal(page.document.getElementById(toggle.getAttribute('data-target')).classList.contains('d-none'), false);
    page.respond('/api/v1/block-ip', 200, {});
    await settle();
    assert.equal(block.textContent, 'Blocked', 'the completion updated a detached button');
});

test('a backscatter flush stays busy across queue summary changes and reports uncertainty', async () => {
    const page = await queuePage([queueMsg(QID[0], { bounce: true, frozen: true })]);
    page.respond('/api/v1/email/queue-composition', 200, { total: 1, flushable_backscatter: 1 });
    await settle();
    stubConfirm(page);
    const options = [];
    const post = page.window.CSM.post;
    page.window.CSM.post = (url, body, opts) => { options.push(opts); return post(url, body, opts); };
    page.document.getElementById('flush-backscatter-btn').click();
    await settle();
    assert.equal(options[0].timeoutMs, 60000);
    page.window.CSM.refresh.manual();
    page.respond('/api/v1/email/overview', 200, queueOverview(2));
    await settle();
    const btn = page.document.getElementById('flush-backscatter-btn');
    assert.equal(btn.disabled, true);
    btn.click();
    await settle();
    assert.equal(requestCount(page, '/api/v1/email/queue/flush-backscatter'), 1);
    page.respond('/api/v1/email/queue/flush-backscatter', 500, { error: 'the outcome could not be read back' });
    await settle();
    assert.match(page.toasts.at(-1)[0], /^Outcome unknown:/);
    assert.equal(btn.disabled, false);
});

test('a successful queue reply without an outcome cannot claim nothing changed', async () => {
    const page = await queuePage([queueMsg(QID[0])]);
    stubConfirm(page);
    queueRow(page, QID[0]).querySelector('[data-queue-action="retry"]').click();
    await settle();
    page.respond('/api/v1/email/queue/' + QID[0] + '/retry', 200, {});
    await settle();
    assert.match(page.toasts.at(-1)[0], /^Outcome unknown:/);
});

test('queue lists and composition poll once a minute while headline counts poll every 30 seconds', async () => {
    const intervals = [];
    const page = emailPage({ url: 'https://csm.example.com/email?tab=queue', intervals });
    page.respond('/api/v1/email/queue-composition', 200, { total: 1, flushable_backscatter: 1 });
    await settle();
    const before = page.requests.length;
    intervals.filter(t => t.ms === 30000).forEach(t => t.fn());
    const fast = page.requests.slice(before).map(r => r.url);
    assert.ok(fast.some(u => u.includes('/api/v1/email/overview')));
    assert.equal(fast.some(u => u.includes('/api/v1/email/queue?')), false, 'queue list polls twice a minute');
    const listReads = requestCount(page, '/api/v1/email/queue?');
    intervals.filter(t => t.ms === 60000).forEach(t => t.fn());
    assert.equal(requestCount(page, '/api/v1/email/queue?'), listReads + 1);
    assert.equal(requestCount(page, '/api/v1/email/queue-composition'), 2, 'composition remained the initial snapshot');
    assert.equal(intervals.length, 3);
});

test('Findings retains a saved search but does not resurrect a search just cleared', async () => {
    const page = emailPage({ url: 'https://csm.example.com/email?tab=findings',
        storage: { 'csm-email-table': JSON.stringify({ search: 'first' }) } });
    const rows = ['first', 'second'].map(message => ({ check: 'email_av', severity: 'HIGH', message, timestamp: AT }));
    page.respond('/api/v1/history?', 200, items(rows));
    await settle();
    const input = page.document.getElementById('email-search');
    assert.equal(input.value, 'first');
    input.value = '';
    input.dispatchEvent(new page.window.Event('input'));
    page.document.getElementById('email-refresh').click();
    page.respond('/api/v1/history?', 200, items(rows.concat({ check: 'email_av', severity: 'HIGH', message: 'third', timestamp: AT })));
    await settle();
    assert.equal(input.value, '');
    assert.equal(Array.from(page.document.querySelectorAll('#email-tbody tr')).filter(r => r.style.display !== 'none').length, 3);
});

test('sending table keeps its page, sort and pager focus without browser storage', async () => {
    const accounts = n => Array.from({ length: 30 }, (_, i) => ({ account: 'user' + String(i).padStart(2, '0'), messages: i + n }));
    const page = await sendingPage({ '/api/v1/email/senders': senders(accounts(1)) });
    page.window.localStorage.setItem = () => { throw new Error('storage unavailable'); };
    const doc = page.document;
    doc.querySelectorAll('#email-sending-table thead th')[0].click();
    doc.querySelector('#email-sending-table-controls [data-page="2"]').click();
    doc.querySelector('#email-sending-table-controls [data-page="1"]').focus();
    page.window.CSM.refresh.manual();
    page.respond('/api/v1/email/senders', 200, senders(accounts(2)));
    await settle();
    const table = page.window.CSM._tableInstances.find(t => t.opts.tableId === 'email-sending-table');
    assert.equal(table.currentPage, 2);
    assert.equal(table.sortColumn, 0);
    assert.equal(doc.activeElement, doc.querySelector('#email-sending-table-controls [data-page="1"]'));
});

test('queue composition ignores old replies and keeps unchanged recipient rows', async () => {
    const page = await queuePage([queueMsg(QID[0])]);
    const old = page.pending('/api/v1/email/queue-composition')[0];
    const data = { total: 1, bounce: 1, frozen: 1, flushable_backscatter: 1, oldest_age_seconds: 60,
        top_recipients: [{ address: 'user@example.net', count: 1 }] };
    page.document.getElementById('email-refresh').click();
    const fresh = page.pending('/api/v1/email/queue-composition').at(-1);
    fresh.settled = true; fresh.resolve(jsonResponse(200, data));
    await settle();
    old.settled = true; old.resolve(jsonResponse(200, Object.assign({}, data, { flushable_backscatter: 9 })));
    await settle();
    assert.match(flat(page.document.getElementById('flush-backscatter-btn')), /Flush 1 /);
    const row = page.document.querySelector('#queue-composition tbody tr');
    page.document.getElementById('email-refresh').click();
    page.respond('/api/v1/email/queue-composition', 200, Object.assign({}, data, { oldest_age_seconds: 120 }));
    await settle();
    assert.equal(page.document.querySelector('#queue-composition tbody tr'), row, 'unshown age rebuilt an unchanged table');
});
