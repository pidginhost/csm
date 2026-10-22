// Run with: node --test ui/email_test.js
// The Email page: one range for the whole page, the headline numbers, and
// the job tabs right under them: Overview (the mail decisions chart, the
// rspamd card, the groups that need attention and the protection card),
// Queue, Held mail, Rejects, Sending accounts, Provider delays, Findings.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const { loadPage, templateBody, items, SHARED, settle } = require('./pagekit.js');

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
    page.load('email.js');
    page.Chart = Chart;
    return page;
}

const TABS = ['overview', 'queue', 'held', 'rejects', 'sending', 'delays', 'findings'];

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

test('rejects default to spam and malware', async () => {
    const page = emailPage();
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
    assert.equal(rows[0].querySelector('.badge').textContent, 'Sender verification (temporary)');
    assert.equal(rows[1].querySelector('.badge').textContent, 'Rate limited (temporary)');
});

test('rejects empty state names range and filter', async () => {
    const page = emailPage();
    await settle();
    page.respond('/api/v1/email/rejects', 200, items([], { class: 'content', limit: 50, kept_days: 7 }));
    await settle();
    const tbody = page.document.getElementById('email-rejects-tbody');
    assert.ok(tbody.querySelector('.csm-empty'), 'not the shared empty state');
    assert.match(tbody.textContent, /No spam or malware rejects in the last 24 hours/);

    const filter = page.document.getElementById('email-rejects-filter');
    assert.deepEqual(Array.from(filter.options).map(o => o.value), ['content', 'all', 'spam', 'malware', 'unknown_recipient',
        'sender_verify', 'bad_helo', 'relay_denied', 'auth_required', 'suspended', 'mailbox_full', 'blocklisted', 'rate_limited', 'other']);
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

test('seven job tabs sit right under the headline cards', async () => {
    const page = emailPage();
    await settle();
    const doc = page.document;
    const strip = doc.getElementById('email-tabs');
    assert.equal(doc.getElementById('email-kpis').nextElementSibling, strip, 'something sits between the cards and the tabs');
    assert.equal(strip.getAttribute('role'), 'tablist');
    const tabs = Array.from(strip.querySelectorAll('[role="tab"]'));
    assert.deepEqual(tabs.map(b => b.id), TABS.map(name => 'email-tab-' + name));
    assert.deepEqual(tabs.map(b => b.textContent.replace(/\s+/g, ' ').trim()),
        ['Overview', 'Queue', 'Held mail', 'Rejects', 'Sending accounts', 'Provider delays', 'Findings']);
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
    // Sending accounts keeps the Outbound sections as they were.
    const sending = doc.getElementById('email-pane-sending');
    assert.deepEqual(Array.from(sending.querySelectorAll('.nav-link')).map(b => b.id),
        ['email-tab-senders', 'email-tab-outbound-abuse', 'email-tab-forwarders']);
    assert.deepEqual(Array.from(sending.querySelectorAll('.nav-link')).map(b => b.textContent.replace(/\s+/g, ' ').trim()),
        ['Senders', 'Abuse', 'Forwarders and held']);
    assert.match(doc.getElementById('email-pane-senders').textContent, /last 500 log lines/);
    assert.ok(sending.contains(doc.getElementById('smtp-firewall')), 'the SMTP firewall block is not in the Sending accounts tab');
    const html = sending.innerHTML;
    assert.ok(html.indexOf('id="smtp-firewall"') < html.indexOf('id="email-tab-senders"'), 'the SMTP firewall block is not above the outbound sections');
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
    for (const [tab, id] of [['queue', 'queue-health'], ['queue', 'queue-composition'], ['held', 'quarantine-table'],
        ['rejects', 'email-rejects-table'], ['sending', 'smtp-firewall'], ['sending', 'email-fwd-table'], ['sending', 'email-held-table'],
        ['delays', 'email-deliv-providers'], ['delays', 'email-deliv-ips'], ['findings', 'email-table']]) {
        assert.ok(doc.getElementById('email-pane-' + tab).contains(doc.getElementById(id)), '#' + id + ' is not in ' + tab);
    }
    assert.equal(overview.contains(doc.getElementById('email-rejects-table')), false, 'the rejects list is still on Overview');
});

test('each headline card opens the tab that explains its number', async () => {
    for (const [card, href, tab, loads] of [
        ['kpi-scanned', '?tab=overview', 'overview'],
        ['kpi-tagged', '?tab=overview', 'overview'],
        ['kpi-spam', '?tab=rejects', 'rejects'],
        ['kpi-other', '?tab=rejects', 'rejects'],
        ['kpi-malware', '?tab=held', 'held', '/api/v1/email/quarantine'],
        ['kpi-logins', '?tab=auth', 'findings'],
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
        const click = new page.window.Event('click', { bubbles: true, cancelable: true });
        link.dispatchEvent(click);
        assert.equal(click.defaultPrevented, true, card + ' left the page');
        await settle();
        assert.equal(selectedTab(page), tab, card);
        assert.equal(urlTab(page), tab === 'overview' ? null : tab, card + ' address');
        if (loads) assert.equal(page.pending(loads).length, 1, card + ' did not load its tab');
    }
});

test('the reject cards open Rejects on their reason', async () => {
    for (const [card, cls] of [['kpi-spam', 'spam'], ['kpi-other', 'other']]) {
        const page = emailPage();
        await settle();
        page.respond('/api/v1/email/rejects', 200, items([], { kept_days: 7 }));
        await settle();
        page.document.querySelector('#' + card + ' a').click();
        await settle();
        assert.equal(selectedTab(page), 'rejects');
        assert.equal(page.document.getElementById('email-rejects-filter').value, cls);
        const reqs = page.pending('/api/v1/email/rejects');
        assert.equal(reqs.length, 1, card + ' did not reload the rejects');
        assert.equal(query(reqs[0].url).get('class'), cls);
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
        ['forwarders', 'sending'], ['deliverability', 'delays'], ['findings', 'findings'], ['queue', 'queue'], ['held', 'held'],
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
    assert.equal(urlTab(page), 'findings');
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
    for (const name of ['held', 'rejects', 'sending', 'delays', 'findings']) {
        assert.equal(badge(page, name).hidden, true, name + ' shows a count nothing set');
    }

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
    const fw = page.document.getElementById('smtp-firewall').textContent.replace(/\s+/g, ' ');
    assert.match(fw, /restricted/i);
    assert.match(fw, /alice, bob/);
    assert.match(fw, /Port 25: 10 \/ 60s/);
    assert.match(page.document.getElementById('top-senders').textContent, /shop\.example\.com/);
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
    assert.match(warn.textContent, /warn 100/);
    assert.match(crit.textContent, /crit 500/);
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
    assert.match(h.textContent, /Queue size unknown/);
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
    showEmailTab(page, 'outbound-abuse');
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
    assert.match(page.document.getElementById('outbound-abuse-body').textContent, /Current range/);
});

test('changing range while outbound is hidden invalidates its pending request', async () => {
    const page = emailPage();
    showEmailTab(page, 'sending');
    showEmailTab(page, 'outbound-abuse');
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
        items: list, total: list.length, page: 1, limit: 25, unavailable: false, queued: list.length,
        frozen: list.filter(m => m.frozen).length, backscatter: list.filter(m => m.bounce).length,
        oldest_seconds: list.length ? list[0].age_seconds : undefined
    }, extra);
}

function flat(el) {
    return el.textContent.replace(/\s+/g, ' ').trim();
}

// queuePage opens the Queue tab, answers its list, and records toasts.
async function queuePage(list, extra) {
    const page = emailPage();
    showEmailTab(page, 'queue');
    await settle();
    page.respond('/api/v1/email/queue?', 200, queueList(list, extra));
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
    assert.equal(flat(doc.getElementById('email-queue-count')), '3 messages');
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
    page.respond('/api/v1/email/queue?', 200, queueList([queueMsg(QID[0])]));
    await settle();
    assert.equal(doc.getElementById('email-queue-list').hidden, false);
    assert.match(flat(summary), /^1 queued/);
});

test('an empty queue says so', async () => {
    const page = await queuePage([]);
    assert.equal(flat(page.document.getElementById('email-queue-summary')), 'The queue is empty.');
    assert.equal(page.document.getElementById('email-queue-list').hidden, true);
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

test('the queue size bar speaks its size and thresholds, and close labels share one line', async () => {
    for (const [queue, valuetext, apart, at] of [
        [{ size: 21, warn: 100, crit: 500 }, '21 messages, warn 100, crit 500', true],
        // 64% and 80%: the line ends at the crit mark.
        [{ size: 1, warn: 400, crit: 500 }, '1 message, warn 400, crit 500', false, { right: '20%' }],
        // 2% and 10%: the line starts at the warn mark.
        [{ size: 5000, warn: 100, crit: 500 }, '5,000 messages, warn 100, crit 500', false, { left: '2%' }],
        [{ size: 21, warn: 100, crit: 0 }, '21 messages, warn 100', true]
    ]) {
        const page = emailPage();
        page.respond('/api/v1/email/overview', 200, overview({}, { queue: Object.assign({ unavailable: false, frozen: 0, detail_unavailable: false }, queue) }));
        await settle();
        const health = page.document.getElementById('queue-health');
        assert.equal(health.querySelector('.progress-bar').getAttribute('aria-valuetext'), valuetext);
        const marks = [['warn', queue.warn], ['crit', queue.crit]].filter(m => m[1] > 0);
        const line = health.querySelector('.csm-queue-bar__labels');
        if (apart) {
            assert.equal(line, null, valuetext + ': labels share a line though their marks are apart');
            assert.deepEqual(Array.from(health.querySelectorAll('.csm-queue-mark__label')).map(flat), marks.map(m => m[0] + ' ' + CSMnum(m[1])));
        } else {
            // Marks within a fifth of the bar of each other would print one
            // label over the other.
            assert.equal(health.querySelectorAll('.csm-queue-mark__label').length, 0, valuetext + ': labels still sit under close marks');
            assert.ok(line, valuetext + ': no shared label line');
            assert.equal(flat(line), marks.map(m => m[0] + ' ' + CSMnum(m[1])).join(', '));
            assert.deepEqual({ left: line.style.left || undefined, right: line.style.right || undefined }, Object.assign({ left: undefined, right: undefined }, at));
        }
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
    // A phone strip from 8 to 382 px with Findings beyond its right edge;
    // shift is how far counts loaded since pushed the tabs right.
    let shift = 0;
    strip.scrollLeft = 0;
    strip.getBoundingClientRect = () => ({ left: 8, right: 382 });
    findings.getBoundingClientRect = () => ({ left: 700 + shift - strip.scrollLeft, right: 802 + shift - strip.scrollLeft });
    let pageScrolls = 0;
    findings.scrollIntoView = () => { pageScrolls++; };
    doc.querySelector('#kpi-logins a').click();
    await settle();
    assert.equal(strip.scrollLeft, 420, 'Findings is not scrolled into the strip');
    shift = 34;
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

test('the refresh button and the queue timer read the open Queue tab again', async () => {
    const page = await queuePage([queueMsg(QID[0])]);
    page.document.getElementById('email-refresh').click();
    await settle();
    assert.equal(page.pending('/api/v1/email/queue?').length, 1, 'refresh did not read the queue list');
    const src = fs.readFileSync(path.join(__dirname, 'static/js/email.js'), 'utf8');
    const timer = src.match(/CSM\.refresh\.interval\(function\(\) \{([\s\S]*?)\}, 30000\)/);
    assert.ok(timer, 'no 30 s timer');
    assert.match(timer[1], /activeTab\('email-tabs'\) === 'queue'\) loadQueue\(\)/, 'the 30 s timer does not read the open Queue tab');
});
