// CSM Email Security page.
// Layout: range header, headline numbers, then the job tabs right under
// them: Overview (mail decisions chart and rspamd, needs attention and
// protection), Queue, Held mail, Rejects, Sending accounts, Provider
// delays, Findings. Each headline card opens the tab that explains it.
(function() {
    'use strict';

    var EMAIL_FINDINGS_LIMIT = 250; // first viewport row cap from the plan
    var _emailExportData = [];
    var emailTable = null;
    var _emailFindingsLoadSeq = 0;
    var _findingsSig = '';
    var _findingsPending = false;
    var forwardersLoaded = false;
    var _forwarders = [];
    var outboundAbuseLoaded = false;
    var _outboundAbuseSeq = 0;
    var _abuseBlocks = Object.create(null);
    var _abuseSig = '';  // what the abuse events on screen show
    var queueCompositionLoaded = false;
    var _queueCompositionSeq = 0;
    var _queueCompositionSig = '';

    // ---------- Filter state from URL ----------
    var today = CSM.prefs.today();
    var sevEl = document.getElementById('filter-severity');
    var checkEl = document.getElementById('filter-check');
    var searchEl = document.getElementById('email-search');
    var _findingsSearchEdited = false;
    if (searchEl) searchEl.addEventListener('input', function() { _findingsSearchEdited = true; });
    var authChip = document.getElementById('email-filter-auth');
    if (sevEl && CSM.urlState.get('severity')) sevEl.value = CSM.urlState.get('severity');
    // A linked check filters at once; the check list fills in around it.
    if (checkEl && CSM.urlState.get('check')) {
        checkEl.appendChild(checkOption(CSM.urlState.get('check')));
        checkEl.value = CSM.urlState.get('check');
    }
    if (searchEl && CSM.urlState.get('search')) searchEl.value = CSM.urlState.get('search');

    // ---------- Range ----------

    var RANGE_KEY = 'csm-email-range';
    var RANGE_WORDS = { '24h': 'in the last 24 hours', '7d': 'in the last 7 days', '30d': 'in the last 30 days' };
    var rangeEl = document.getElementById('email-range');

    function knownRange(key) {
        return Object.prototype.hasOwnProperty.call(RANGE_WORDS, key);
    }

    // Links from before the range select carry days in from/to; they open a
    // Custom range over those days. A missing side is today, as the old date
    // inputs had it.
    var linkFrom = CSM.urlState.get('from') || '';
    var linkTo = CSM.urlState.get('to') || '';
    var customRange = null;
    if (linkFrom || linkTo) {
        linkFrom = linkFrom || today;
        linkTo = linkTo || today;
        if (linkFrom > linkTo) {
            var swap = linkFrom;
            linkFrom = linkTo;
            linkTo = swap;
        }
        var linked = CSM.prefs.dayRange(linkFrom, linkTo);
        if (linked.from && linked.to) {
            customRange = { from: Date.parse(linked.from), to: Date.parse(linked.to),
                label: linkFrom === linkTo ? linkFrom : linkFrom + ' to ' + linkTo };
        }
    }
    if (rangeEl) {
        if (customRange) {
            var customOpt = document.createElement('option');
            customOpt.value = 'custom';
            customOpt.textContent = customRange.label;
            rangeEl.appendChild(customOpt);
            rangeEl.value = 'custom';
        } else {
            var stored = null;
            try { stored = window.localStorage.getItem(RANGE_KEY); } catch (e) { /* storage unavailable */ }
            rangeEl.value = knownRange(stored) ? stored : '24h';
        }
    }

    // daysBefore returns the day n days before day, both YYYY-MM-DD.
    function daysBefore(day, n) {
        var p = day.split('-');
        return new Date(Date.UTC(+p[0], +p[1] - 1, +p[2] - n)).toISOString().slice(0, 10);
    }

    // hourStart returns the start of the operator-zone hour holding ms.
    function hourStart(ms) {
        ms = Math.floor(ms / 1000) * 1000;
        var wall = CSM.prefs.formatDateTime(new Date(ms));
        var start = ms - (+wall.slice(14, 16) * 60 + +wall.slice(17, 19)) * 1000;
        // A half-hour clock change can begin or repeat only part of an
        // hour. Do not cross that transition while finding its start.
        var offset = Date.parse(wall.replace(' ', 'T') + 'Z') - ms;
        var lo = start, hi = ms;
        while (lo < hi) {
            var at = CSM.prefs.formatDateTime(new Date(lo));
            if (Date.parse(at.replace(' ', 'T') + 'Z') - lo === offset) return lo;
            var mid = lo + Math.floor((hi - lo) / 2000) * 1000;
            at = CSM.prefs.formatDateTime(new Date(mid));
            if (Date.parse(at.replace(' ', 'T') + 'Z') - mid === offset) hi = mid;
            else lo = mid + 1000;
        }
        return hi;
    }

    // currentRange returns the selected range: the last 24 operator-zone
    // hours, the last 7 or 30 operator-zone days up to now, or the days of
    // a Custom link.
    function currentRange() {
        var key = rangeEl ? rangeEl.value : '24h';
        var now = Date.now();
        if (key === 'custom' && customRange) {
            return { key: key, from: new Date(customRange.from), to: new Date(customRange.to) };
        }
        if (key === '7d' || key === '30d') {
            var first = daysBefore(CSM.prefs.today(), key === '7d' ? 6 : 29);
            return { key: key, from: new Date(CSM.prefs.dayBoundary(first, false)), to: new Date(now) };
        }
        return { key: '24h', from: new Date(hourStart(hourStart(now) - 23 * 3600000)), to: new Date(now) };
    }

    function rangeQuery(range, base) {
        return (base ? base + '&' : '') + 'from=' + encodeURIComponent(range.from.toISOString()) +
            '&to=' + encodeURIComponent(range.to.toISOString());
    }

    function rangeWords(range) {
        return range.key === 'custom' ? 'for ' + customRange.label : RANGE_WORDS[range.key];
    }

    // ---------- Headline numbers ----------

    // Labels for the reject classes the overview counts.
    var REJECT_CLASS_LABELS = {
        spam: 'Spam',
        malware: 'Malware',
        unknown_recipient: 'Unknown recipient',
        sender_verify: 'Sender verification',
        bad_helo: 'Bad HELO',
        relay_denied: 'Relay denied',
        auth_required: 'Auth required',
        suspended: 'Suspended account',
        mailbox_full: 'Mailbox full',
        blocklisted: 'Blocklisted',
        rate_limited: 'Rate limited (temporary)',
        other: 'Unclassified'
    };

    function rejectClassLabel(cls) {
        return Object.prototype.hasOwnProperty.call(REJECT_CLASS_LABELS, cls) ? REJECT_CLASS_LABELS[cls] : cls;
    }

    var MODE_BADGES = { 'enforce': 'bg-green-lt', 'dry-run': 'bg-yellow-lt', 'off': 'bg-secondary-lt' };

    function modeBadgeClass(mode) {
        return 'badge ' + (Object.prototype.hasOwnProperty.call(MODE_BADGES, mode) ? MODE_BADGES[mode] : 'bg-secondary-lt');
    }

    var num = function(n) { return CSM.formatNumber(n || 0); };

    var _overview = null;
    var _overviewErr = null; // why the last overview failed, if it did
    var _overviewRange = null;
    var _overviewSeq = 0;
    var _rspamd = null;
    var _rspamdSeq = 0;

    function loadOverview() {
        var range = currentRange();
        var seq = ++_overviewSeq;
        CSM.get('/api/v1/email/overview?' + rangeQuery(range))
            .then(function(ov) {
                if (seq !== _overviewSeq) return;
                _overview = ov;
                _overviewErr = null;
                _overviewRange = range;
                CSM.clearLoadError(document.getElementById('email-kpis'));
                CSM.clearLoadError(document.getElementById('email-decisions-chart').parentElement);
                renderKPIs(ov);
                renderQueueHealth(ov.queue || {});
                renderChart(ov, range);
                renderSubtitle();
                renderProtection();
                renderQueueSummary();
                renderHeldSummary();
                renderRejectsCounts();
                renderSendersSummary();
                renderFindingsSummary();
                // A new range can count other reasons the list did not ask for.
                if (activeTab('email-tabs') === 'rejects' && rejectsFilter && rejectsFilter.value === 'other' &&
                    rejectsQuery('other') !== _rejectsClasses) loadRejects();
            })
            .catch(function(err) {
                if (seq !== _overviewSeq) return;
                _overview = null;
                _overviewErr = err;
                _overviewRange = null;
                document.getElementById('email-subtitle').textContent = 'Mail numbers unavailable.';
                CSM.loadError(document.getElementById('email-kpis'), loadOverview, { title: 'Failed to load mail numbers', error: err });
                renderQueueHealth({ unavailable: true });
                setTabCount('queue', '?');
                CSM.loadError(document.getElementById('email-decisions-chart').parentElement, loadOverview, { title: 'Mail decisions unavailable', error: err });
                document.getElementById('email-chart-note').textContent = '';
                ['prot-antispam', 'prot-smtp'].forEach(function(id) {
                    CSM.loadError(document.getElementById(id), loadOverview, { title: 'Protection status unavailable', error: err });
                });
                renderQueueSummary();
                renderHeldSummary();
                renderRejectsCounts();
                renderSendersSummary();
                renderFindingsSummary();
            });
    }

    // setKPI fills one headline card. Seven cards share a row, so a count
    // of six figures or more is shortened ("1.2M") and the exact count goes
    // in the title.
    function setKPI(id, value, sub, valueClass) {
        var card = document.getElementById(id);
        if (!card) return;
        var v = card.querySelector('[data-kpi-value]');
        var text = value, title = '';
        if (typeof value === 'number') {
            text = num(value);
            if (value >= 100000) {
                title = text;
                text = value.toLocaleString(undefined, { notation: 'compact', maximumFractionDigits: 1 });
            }
        }
        v.textContent = text;
        if (title) v.setAttribute('title', title); else v.removeAttribute('title');
        v.className = 'h1 mb-0' + (valueClass ? ' ' + valueClass : '');
        card.querySelector('[data-kpi-sub]').textContent = sub;
    }

    // otherReason reports whether a reject class is one of the other
    // reasons: every class but spam, malware and rate limiting, which only
    // ever defers.
    function otherReason(cls) {
        return cls !== 'spam' && cls !== 'malware' && cls !== 'rate_limited';
    }

    // otherRejects sums the permanent rejects for the other reasons, the
    // same count the chart's Other rejects series shows: a temporary reject
    // defers the message, which comes back and is decided later.
    function otherRejects(t) {
        var rejects = t.rejects || {}, temporary = t.temporary || {};
        var out = { total: 0, top: '', topCount: 0 };
        Object.keys(rejects).forEach(function(cls) {
            if (!otherReason(cls)) return;
            var n = (rejects[cls] || 0) - (temporary[cls] || 0);
            if (n <= 0) return;
            out.total += n;
            if (n > out.topCount) { out.top = cls; out.topCount = n; }
        });
        return out;
    }

    // malwareStopped splits the malware stopped in a range: permanently
    // rejected at SMTP time, and quarantined after it was accepted.
    function malwareStopped(t) {
        var rejects = t.rejects || {}, temporary = t.temporary || {};
        return { smtp: (rejects.malware || 0) - (temporary.malware || 0), quarantined: t.quarantined || 0 };
    }

    function renderKPIs(ov) {
        var t = ov.totals || {};
        var scanned = t.scanned || 0;
        var scannedSub = scanned > 0 ? Math.floor((t.clean || 0) / scanned * 100) + '% clean' : 'nothing scanned';
        if (t.scan_errors > 0) scannedSub += ', ' + num(t.scan_errors) + ' scan errors';
        setKPI('kpi-scanned', scanned, scannedSub);

        setKPI('kpi-spam', t.rejected || 0, t.would_reject > 0 ? 'would reject ' + num(t.would_reject) : 'at SMTP time');
        var badge = document.querySelector('#kpi-spam [data-kpi-badge]');
        if (badge) {
            badge.className = modeBadgeClass(ov.mode);
            badge.textContent = ov.mode || '';
        }
        setKPI('kpi-tagged', t.tagged || 0, t.would_tag > 0 ? 'would tag ' + num(t.would_tag) : 'delivered, marked as spam');

        var malware = malwareStopped(t);
        setKPI('kpi-malware', malware.smtp + malware.quarantined,
            num(malware.smtp) + ' rejected at SMTP, ' + num(malware.quarantined) + ' quarantined');

        var other = otherRejects(t);
        setKPI('kpi-other', other.total, other.top ? rejectClassLabel(other.top) + ' ' + num(other.topCount) : 'none');

        var blocks = ov.blocks || {};
        var blocked = blocks.in_range || 0;
        setKPI('kpi-logins', (t.logins_smtp || 0) + (t.logins_mailbox || 0),
            blocks.unavailable ? 'block count unavailable' : num(blocked) + (blocked === 1 ? ' IP blocked' : ' IPs blocked'));

        renderQueueKPI(ov.queue || {});
    }

    // The queue is colored from the thresholds the mail_queue check alerts
    // on, so the card, the Queue tab count and the alert agree.
    function renderQueueKPI(q) {
        if (q.unavailable) {
            setKPI('kpi-queue', '--', 'queue size unknown', 'text-warning');
            setTabCount('queue', '?');
            return;
        }
        var size = q.size || 0;
        var level = queueLevel(q);
        var sub;
        if (size === 0) sub = 'empty';
        else if (q.detail_unavailable) sub = 'oldest unknown';
        else {
            sub = q.oldest_age_seconds != null ? 'oldest ' + CSM.formatDuration(q.oldest_age_seconds) : 'no dated message';
            if (q.frozen > 0) sub += ', ' + num(q.frozen) + ' frozen';
        }
        setKPI('kpi-queue', size, sub, { crit: 'text-danger', warn: 'text-warning' }[level]);
        setTabCount('queue', size, level);
    }

    // queueLevel returns 'crit' or 'warn' when the queue size is at or over
    // that threshold, else ''.
    function queueLevel(q) {
        var size = q.size || 0;
        if (q.crit > 0 && size >= q.crit) return 'crit';
        if (q.warn > 0 && size >= q.warn) return 'warn';
        return '';
    }

    // stateLine says in one sentence how mail is doing over the range.
    function stateLine(ov, rs, range) {
        var parts = [];
        if (rs && rs.status === 'down') parts.push('rspamd is down.');
        else if (ov.mode === 'off') parts.push('Antispam is off.');
        var t = ov.totals || {};
        var words = rangeWords(range);
        if (!t.scanned) {
            parts.push('No mail scanned ' + words + '.');
        } else if (ov.mode === 'dry-run') {
            parts.push('Mail flowing. Dry run: ' + num(t.would_reject) + ' would be rejected and ' + num(t.would_tag) + ' tagged ' + words + '.');
        } else {
            parts.push('Mail flowing. ' + num(t.rejected) + ' spam rejected and ' + num(t.tagged) + ' tagged ' + words + '.');
        }
        var q = ov.queue || {};
        if (q.unavailable) parts.push('Queue size unknown.');
        else if (!q.size) parts.push('Queue empty.');
        else if (q.oldest_age_seconds != null && !q.detail_unavailable) parts.push('Queue ' + num(q.size) + ', oldest ' + CSM.formatDuration(q.oldest_age_seconds) + '.');
        else parts.push('Queue ' + num(q.size) + '.');
        return parts.join(' ');
    }

    function renderSubtitle() {
        var el = document.getElementById('email-subtitle');
        if (el && _overview) el.textContent = stateLine(_overview, _rspamd, _overviewRange);
    }

    // ---------- Mail decisions chart ----------

    var decisionsChart = null;
    var _chartGapMinutes = [];

    // chartPeriods returns the bars of a range: operator-zone hours for 24
    // hours, operator-zone days otherwise. Each hour starts on the local
    // clock, including partial hours at daylight saving transitions. Long
    // custom links group days to keep chart work within the 30-day view's
    // bar budget without cutting any of the requested range.
    function chartPeriods(range) {
        var from = range.from.getTime(), to = range.to.getTime();
        var periods = [];
        if (range.key === '24h') {
            for (var t = from; t < to;) {
                var end = hourStart(t + 3600000);
                periods.push({ start: t, end: end, label: CSM.prefs.formatDateTime(new Date(t)).slice(11, 16) });
                t = end;
            }
            return periods;
        }
        var day = CSM.prefs.formatDateTime(range.from).slice(0, 10);
        var last = CSM.prefs.formatDateTime(new Date(to - 1)).slice(0, 10);
        var days = Math.round((Date.parse(last) - Date.parse(day)) / 86400000) + 1;
        var step = Math.max(1, Math.ceil(days / 30));
        var labelStart = day.slice(0, 4) === last.slice(0, 4) ? 5 : 0;
        for (var start = from; days > 0; days -= step) {
            var lastDay = daysBefore(day, -Math.min(step - 1, days - 1));
            var next = Math.min(CSM.prefs.dayBoundary(lastDay, true), to);
            var label = day.slice(labelStart);
            if (lastDay !== day) label += ' to ' + lastDay.slice(labelStart);
            if (next > start) periods.push({ start: start, end: next, label: label });
            day = daysBefore(lastDay, -1);
            start = next;
        }
        return periods;
    }

    var SERIES_KEYS = ['clean', 'tagged', 'rejected', 'malware', 'other'];

    // groupSeries sums the 15-minute buckets, sorted by time, into periods.
    function groupSeries(series, periods) {
        var out = {};
        SERIES_KEYS.forEach(function(k) { out[k] = periods.map(function() { return 0; }); });
        var j = 0;
        (series || []).forEach(function(p) {
            var ms = p.t * 1000;
            while (j < periods.length && ms >= periods[j].end) j++;
            if (j === periods.length || ms < periods[j].start) return;
            SERIES_KEYS.forEach(function(k) { out[k][j] += p[k] || 0; });
        });
        return out;
    }

    function gapMinutes(gaps, period) {
        var ms = 0;
        (gaps || []).forEach(function(g) {
            var s = Math.max(Date.parse(g.start), period.start);
            var e = Math.min(Date.parse(g.end), period.end);
            if (e > s) ms += e - s;
        });
        return ms > 0 ? Math.max(1, Math.round(ms / 60000)) : 0;
    }

    function themeColor(name, fallback) {
        var v = getComputedStyle(document.documentElement).getPropertyValue(name);
        return (v && v.trim()) || fallback;
    }

    function renderChartNote(ov, range) {
        var note = document.getElementById('email-chart-note');
        if (!note) return;
        var parts = [];
        if (!ov.counting_since) parts.push('Counting has not started.');
        else if (Date.parse(ov.counting_since) > range.from.getTime()) parts.push('Counting since ' + CSM.fmtDate(ov.counting_since) + '.');
        if (ov.uncounted_minutes > 0) parts.push('Not counted while CSM was stopped: ' + num(ov.uncounted_minutes) + ' min.');
        note.textContent = parts.join(' ');
    }

    function renderChart(ov, range) {
        renderChartNote(ov, range);
        var canvas = document.getElementById('email-decisions-chart');
        if (!canvas || typeof Chart === 'undefined') return;
        var periods = chartPeriods(range);
        var sums = groupSeries(ov.series, periods);
        _chartGapMinutes = periods.map(function(p) { return gapMinutes(ov.gaps, p); });
        var data = {
            labels: periods.map(function(p) { return p.label; }),
            datasets: [
                { label: 'Clean', data: sums.clean, backgroundColor: themeColor('--csm-success', '#2fb344') },
                { label: 'Tagged', data: sums.tagged, backgroundColor: themeColor('--csm-warning', '#f59f00') },
                { label: 'Spam rejected', data: sums.rejected, backgroundColor: themeColor('--csm-high', '#f76707') },
                { label: 'Malware', data: sums.malware, backgroundColor: themeColor('--csm-critical', '#d63939') },
                { label: 'Other rejects', data: sums.other, backgroundColor: themeColor('--csm-secondary', '#6c757d') }
            ]
        };
        if (decisionsChart) {
            decisionsChart.data = data;
            decisionsChart.update();
            return;
        }
        CSM.applyChartTheme();
        var theme = CSM.chartTheme();
        decisionsChart = new Chart(canvas, {
            type: 'bar',
            data: data,
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: 'index', intersect: false },
                plugins: {
                    legend: { position: 'top', labels: { boxWidth: 10, boxHeight: 10 } },
                    tooltip: Object.assign({}, theme.tooltip, {
                        borderWidth: 1,
                        callbacks: {
                            footer: function(items) {
                                var n = items.length ? _chartGapMinutes[items[0].dataIndex] : 0;
                                return n > 0 ? 'Not counted: ' + n + ' min' : '';
                            }
                        }
                    })
                },
                scales: {
                    x: { stacked: true, grid: { display: false }, ticks: { maxRotation: 0, autoSkip: true } },
                    y: { stacked: true, beginAtZero: true, grid: { color: theme.grid }, ticks: { precision: 0 } }
                }
            }
        });
    }

    // ---------- rspamd card ----------

    var STATUS_DOTS = { up: 'status-green', down: 'status-red' };

    function node(tag, cls, text) {
        var el = document.createElement(tag);
        if (cls) el.className = cls;
        if (text != null) el.textContent = text;
        return el;
    }

    // uptimeWords words rspamd's uptime. rspamd can keep its counters
    // across a restart, so the uptime shows apart from them, not as their
    // period.
    function uptimeWords(seconds) {
        if (!(seconds > 0)) return 'Uptime unknown';
        var n, unit;
        if (seconds >= 86400) { n = Math.floor(seconds / 86400); unit = 'day'; }
        else if (seconds >= 3600) { n = Math.floor(seconds / 3600); unit = 'hour'; }
        else { n = Math.max(1, Math.floor(seconds / 60)); unit = 'minute'; }
        return 'Uptime ' + n + ' ' + unit + (n === 1 ? '' : 's');
    }

    function loadRspamd() {
        var seq = ++_rspamdSeq;
        CSM.get('/api/v1/email/rspamd')
            .then(function(r) {
                if (seq !== _rspamdSeq) return;
                _rspamd = r;
                renderRspamd(r);
                renderSubtitle();
                renderProtection();
            })
            .catch(function(err) {
                if (seq !== _rspamdSeq) return;
                _rspamd = { status: 'unknown' };
                renderSubtitle();
                renderProtection();
                CSM.loadError(document.getElementById('email-rspamd'), loadRspamd, { title: 'Failed to load rspamd status', error: err });
            });
    }

    function renderRspamd(r) {
        var card = document.getElementById('email-rspamd');
        if (!card) return;
        r = r || {};
        card.replaceChildren();
        var status = r.status || 'unknown';
        var head = node('div', 'd-flex align-items-center flex-wrap gap-2 mb-2');
        head.appendChild(node('span', 'status-dot ' + (Object.prototype.hasOwnProperty.call(STATUS_DOTS, status) ? STATUS_DOTS[status] : '')));
        head.appendChild(node('span', 'fw-bold', 'rspamd ' + status));
        if (r.mode) head.appendChild(node('span', modeBadgeClass(r.mode), r.mode));
        if (r.version) head.appendChild(node('span', 'text-muted small ms-auto', 'version ' + r.version));
        card.appendChild(head);

        var s = r.stats;
        if (!r.available || !s) {
            card.appendChild(node('div', 'text-muted small', 'Stats unavailable' + (r.reason ? ': ' + r.reason : '') + '.'));
            return;
        }
        card.appendChild(node('div', 'text-muted small mb-2', uptimeWords(s.uptime_seconds) + '.'));
        card.appendChild(node('div', 'subheader mb-1', 'rspamd counters'));
        // spam_count and ham_count are scan verdicts; learned is what the
        // classifier was taught.
        card.appendChild(node('div', null, 'Scanned ' + num(s.scanned) + ' (spam ' + num(s.spam_count) + ', ham ' + num(s.ham_count) + ')'));
        card.appendChild(node('div', 'mb-2', 'Learned ' + num(s.learned)));

        var rules = (Array.isArray(s.top_rules) ? s.top_rules : []).slice(0, 8);
        if (rules.length === 0) return;
        card.appendChild(node('div', 'subheader mb-1', 'Top rules'));
        var list = node('div', 'list-group list-group-flush');
        rules.forEach(function(rule) {
            var row = node('div', 'list-group-item py-1 px-0 d-flex gap-2');
            row.appendChild(node('span', 'font-monospace small text-truncate', rule.symbol));
            row.appendChild(node('span', 'ms-auto small text-muted', num(rule.hits)));
            list.appendChild(row);
        });
        card.appendChild(list);
    }

    // rangeURL is what the address carries for the selected range: the
    // days of a Custom link, nothing for the others.
    function rangeURL() {
        return rangeEl && rangeEl.value === 'custom' ? { from: linkFrom, to: linkTo } : { from: '', to: '' };
    }

    if (rangeEl) {
        rangeEl.addEventListener('change', function() {
            if (rangeEl.value !== 'custom') {
                try { window.localStorage.setItem(RANGE_KEY, rangeEl.value); } catch (e) { /* storage unavailable */ }
            }
            CSM.urlState.set(rangeURL());
            loadOverview();
            if (activeTab('email-tabs') === 'rejects') loadRejects();
            _showAllGroups = false;
            loadActionGroups();
            loadFindings();
            outboundAbuseLoaded = false;
            ++_outboundAbuseSeq;
            loadSenders();
            if (activeTab('email-tabs') === 'sending') loadOutboundAbuse();
            renderHeld();
        });
    }

    // A theme change repaints the axes and tooltip, and the series colors
    // with them.
    new MutationObserver(function(mutations) {
        mutations.forEach(function(m) {
            if (m.attributeName !== 'class') return;
            CSM.applyChartTheme();
            if (decisionsChart && _overview) renderChart(_overview, _overviewRange);
        });
    }).observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });

    // ---------- Recent rejects ----------

    var REJECT_BADGES = { spam: 'bg-orange-lt', malware: 'bg-red-lt' };
    // The filter offers content, all, other (every other reason, what the
    // Other rejects card counts), then each class. The unclassified class
    // takes its own value there, since other names the group.
    var REJECT_FILTER_LABELS = { content: 'Spam and malware', all: 'All reasons', other: 'Other reasons', spam: 'Spam rejected at SMTP' };
    var rejectsFilter = document.getElementById('email-rejects-filter');
    var rejectsTable = null;
    var _rejectsSeq = 0;
    // The filter and range the table shows; a refresh of the same pair
    // keeps the operator's page.
    var _rejectsKey = '';
    // The class list the table last asked for.
    var _rejectsClasses = null;
    var _rejectsSig = '';

    if (rejectsFilter) {
        ['other'].concat(Object.keys(REJECT_CLASS_LABELS).map(rejectsValue)).forEach(function(value) {
            var opt = node('option', null, rejectsLabel(value));
            opt.value = value;
            rejectsFilter.appendChild(opt);
        });
        rejectsFilter.addEventListener('change', loadRejects);
    }

    // rejectsValue is the filter value of a reject class.
    function rejectsValue(cls) {
        return cls === 'other' ? 'unclassified' : cls;
    }

    // rejectsQuery is the class parameter a filter value asks for. Other
    // reasons asks for the classes the overview counted, the ones the Other
    // rejects card sums, and every class the page knows until it answers. A
    // counted class this build does not know, kept from an older one, stays
    // out: the server refuses a list naming it.
    function rejectsQuery(value) {
        if (value === 'other') {
            var counted = _overview && _overview.totals && _overview.totals.rejects;
            return Object.keys(counted || REJECT_CLASS_LABELS).filter(function(cls) {
                return otherReason(cls) && Object.prototype.hasOwnProperty.call(REJECT_CLASS_LABELS, cls);
            }).join(',');
        }
        return value === 'unclassified' ? 'other' : value;
    }

    function rejectsLabel(value) {
        return Object.prototype.hasOwnProperty.call(REJECT_FILTER_LABELS, value) ? REJECT_FILTER_LABELS[value] : rejectClassLabel(rejectsQuery(value));
    }

    // renderRejectsCounts puts the permanent rejects of the range in the
    // filter and on the Rejects tab. They come from the overview the cards
    // show, so the three agree. Rate limiting only defers, so it has none.
    function renderRejectsCounts() {
        var counts = null;
        if (_overview) {
            var t = _overview.totals || {}, rejects = t.rejects || {}, temporary = t.temporary || {};
            var permanent = function(cls) { return Math.max(0, (rejects[cls] || 0) - (temporary[cls] || 0)); };
            counts = { content: permanent('spam') + permanent('malware'), all: 0, other: otherRejects(t).total };
            Object.keys(rejects).forEach(function(cls) { counts.all += permanent(cls); });
            Object.keys(REJECT_CLASS_LABELS).forEach(function(cls) {
                if (cls !== 'rate_limited') counts[rejectsValue(cls)] = permanent(cls);
            });
        }
        if (rejectsFilter) {
            Array.from(rejectsFilter.options).forEach(function(opt) {
                var n = counts && Object.prototype.hasOwnProperty.call(counts, opt.value) ? counts[opt.value] : null;
                opt.textContent = rejectsLabel(opt.value) + (n == null ? '' : ' (' + num(n) + ')');
            });
        }
        setTabCount('rejects', counts ? counts.all : _overviewErr ? '?' : null);
    }

    function resetRejectsTable() {
        if (rejectsTable) rejectsTable.destroy();
        rejectsTable = null;
    }

    function loadRejects() {
        var tbody = document.getElementById('email-rejects-tbody');
        if (!tbody) return;
        var cls = rejectsFilter ? rejectsFilter.value : 'content';
        var range = currentRange();
        var key = cls + '|' + range.key;
        var seq = ++_rejectsSeq;
        var classes = rejectsQuery(cls);
        _rejectsClasses = classes;
        var what = cls === 'content' ? 'spam or malware rejects' : cls === 'all' ? 'rejects' :
            cls === 'other' ? 'rejects for other reasons' : 'rejects for ' + rejectClassLabel(classes);
        // The range counted no other reason, so there is nothing to list.
        if (!classes) {
            _rejectsKey = key;
            renderRejectsNote(range, 0);
            renderRejects([], 'No ' + what + ' ' + rangeWords(range), 0, 1);
            return;
        }
        CSM.get('/api/v1/email/rejects?' + rangeQuery(range, 'class=' + encodeURIComponent(classes) + '&limit=50'))
            .then(function(data) {
                if (seq !== _rejectsSeq) return;
                var page = rejectsTable && key === _rejectsKey ? rejectsTable.currentPage : 1;
                _rejectsKey = key;
                renderRejectsNote(range, data.kept_days);
                renderRejects(data.items, 'No ' + what + ' ' + rangeWords(range), data.kept_days, page);
            })
            .catch(function(err) {
                if (seq !== _rejectsSeq) return;
                _rejectsSig = '';
                resetRejectsTable();
                CSM.loadError(tbody, loadRejects, { title: 'Failed to load rejects', error: err });
            });
    }

    // renderRejectsNote says what the filter counts cover, and when the list
    // holds fewer days than the range.
    function renderRejectsNote(range, keptDays) {
        var note = document.getElementById('email-rejects-note');
        if (!note) return;
        var text = 'Counts are permanent rejects; temporary ones are listed and tagged.';
        if (keptDays > 0 && range.to.getTime() - range.from.getTime() > keptDays * 86400000) {
            text += ' The list holds the last ' + keptDays + ' days only.';
        }
        note.textContent = text;
    }

    // rejectCell returns a labeled cell holding text, or a muted dash when
    // the reject line named nothing.
    function rejectCell(label, text, cls) {
        var td = node('td', cls);
        td.setAttribute('data-label', label);
        if (text) td.textContent = text;
        else td.appendChild(node('span', 'text-muted', '--'));
        return td;
    }

    // emptyRow fills a table body with the shared empty state.
    function emptyRow(tbody, cols, icon, title, reason) {
        var td = node('td');
        td.setAttribute('colspan', String(cols));
        td.appendChild(buildEmpty(icon, title, reason));
        var tr = node('tr');
        tr.appendChild(td);
        tbody.replaceChildren(tr);
    }

    function renderRejects(items, emptyTitle, keptDays, page) {
        var tbody = document.getElementById('email-rejects-tbody');
        if (!tbody) return;
        items = Array.isArray(items) ? items : [];
        var sig = JSON.stringify([items, emptyTitle, keptDays, _rejectsKey]);
        if (sig === _rejectsSig) return;
        _rejectsSig = sig;
        var active = document.activeElement;
        var focused = active && tbody.contains(active) ? active.closest('tr').getAttribute('data-reject-key') : null;
        var state = tableState(rejectsTable);
        resetRejectsTable();
        tbody.replaceChildren();
        if (items.length === 0) {
            emptyRow(tbody, 6, 'mail-check', emptyTitle, keptDays > 0 ? 'Rejects are kept for ' + keptDays + ' days.' : '');
            return;
        }
        items.forEach(function(r) {
            var row = node('tr');
            row.setAttribute('data-reject-key', JSON.stringify(r));
            row.appendChild(rejectCell('Time', CSM.fmtDate(r.at), 'text-nowrap'));
            var reason = rejectCell('Reason');
            reason.replaceChildren(node('span', 'badge ' + (Object.prototype.hasOwnProperty.call(REJECT_BADGES, r.class) ? REJECT_BADGES[r.class] : 'bg-secondary-lt'),
                rejectClassLabel(r.class)));
            // The counts leave temporary rejects out; rate limiting says
            // so in its label.
            if (r.temporary && r.class !== 'rate_limited') {
                reason.appendChild(document.createTextNode(' '));
                reason.appendChild(node('span', 'badge badge-outline text-secondary', 'temporary'));
            }
            row.appendChild(reason);
            row.appendChild(rejectCell('Sender', r.sender, 'csm-break-word'));
            row.appendChild(rejectCell('Recipient', r.recipient));
            var ip = rejectCell('Source IP', '', 'text-nowrap');
            if (r.ip) {
                var link = node('a', 'font-monospace', r.ip);
                link.href = '/firewall?ip=' + encodeURIComponent(r.ip);
                link.title = 'Firewall state for this IP';
                ip.replaceChildren(link);
            }
            row.appendChild(ip);
            row.appendChild(rejectCell('Detail', r.detail, 'text-wrap csm-break-word'));
            tbody.appendChild(row);
        });
        rejectsTable = new CSM.Table({
            tableId: 'email-rejects-table',
            perPage: 10,
            persistPerPage: false,
            sortable: false,
            mobileRowCard: true
        });
        if (state) state.page = page;
        restoreTableState(rejectsTable, state);
        if (focused !== null) {
            tbody.querySelectorAll('tr').forEach(function(row) {
                var link = row.querySelector('a');
                if (link && row.getAttribute('data-reject-key') === focused) link.focus();
            });
        }
    }

    // Persistence may be unavailable, and a saved page can predate a
    // filter change. A rebuild carries the current table state in memory.
    function tableState(table) {
        if (!table) return null;
        var active = document.activeElement;
        return { page: table.currentPage, perPage: table.perPage, column: table.sortColumn, asc: table.sortAsc,
            control: active && table.controlsEl && table.controlsEl.contains(active) ? active.textContent : null };
    }

    function restoreTableState(table, state) {
        if (!table || !state) return;
        table.currentPage = state.page;
        table.perPage = state.perPage;
        table.sortColumn = state.column;
        table.sortAsc = state.asc;
        table.table.querySelectorAll('thead th').forEach(function(th, i) {
            th.classList.toggle('sort-asc', i === state.column && state.asc);
            th.classList.toggle('sort-desc', i === state.column && !state.asc);
            if (th.hasAttribute('aria-sort')) th.setAttribute('aria-sort', i !== state.column ? 'none' : state.asc ? 'ascending' : 'descending');
        });
        table.applyFilters();
        if (state.control !== null && table.controlsEl) {
            table.controlsEl.querySelectorAll('button').forEach(function(btn) {
                if (!btn.disabled && btn.textContent === state.control) btn.focus();
            });
        }
    }

    // ---------- Protection ----------

    var _av = null;
    var _avSeq = 0;
    var MODE_STATES = { 'enforce': 'ok', 'dry-run': 'warn', 'off': 'off' };
    var PROTECTION_DOTS = { ok: 'status-green', warn: 'status-yellow', bad: 'status-red', off: 'status-secondary' };

    function setProtection(id, state, text) {
        var line = document.getElementById(id);
        if (!line) return;
        CSM.clearLoadError(line);
        line.querySelector('.status-dot').className = 'status-dot ' + PROTECTION_DOTS[state];
        line.querySelector('[data-prot-value]').textContent = text;
    }

    // renderProtection says, one line each, whether antispam, antivirus,
    // the outbound SMTP restriction and the spool watcher are on.
    function renderProtection() {
        if (_overview) {
            var mode = _overview.mode || 'unknown';
            var spam = Object.prototype.hasOwnProperty.call(MODE_STATES, mode) ? MODE_STATES[mode] : 'off';
            var spamText = mode;
            if (mode !== 'off' && _rspamd && _rspamd.status) {
                spamText += ', rspamd ' + _rspamd.status;
                if (_rspamd.status === 'down') spam = 'bad';
                else if (_rspamd.status !== 'up') spam = 'warn';
            }
            setProtection('prot-antispam', spam, spamText);
            setProtection('prot-smtp', _overview.smtp_restricted ? 'ok' : 'off', _overview.smtp_restricted ? 'restricted' : 'open');
        }
        if (_av) {
            var up = (_av.clamd_available ? 1 : 0) + (_av.yarax_available ? 1 : 0);
            setProtection('prot-av', !_av.enabled ? 'off' : ['bad', 'warn', 'ok'][up],
                _av.enabled ? 'ClamAV ' + (_av.clamd_available ? 'up' : 'down') + ', YARA-X ' + (_av.yarax_available ? 'up' : 'down') : 'off');
            var watcher = _av.watcher_mode || 'disabled';
            setProtection('prot-watcher', watcher === 'disabled' ? 'off' : 'ok', watcher);
        }
    }

    // ---------- Sending accounts tab: SMTP firewall ----------

    // The stats call reads the SMTP firewall settings and the last 500 log
    // lines, so it runs only once the Sending accounts tab opens.
    var statsLoaded = false;
    var _statsSeq = 0;

    function loadEmailStats() {
        statsLoaded = true;
        var seq = ++_statsSeq;
        CSM.get('/api/v1/email/stats')
            .then(function(data) {
                if (seq !== _statsSeq) return;
                renderSMTPFirewall(data);
            })
            .catch(function(err) {
                if (seq !== _statsSeq) return;
                statsLoaded = false;
                CSM.loadError(document.getElementById('email-sending-firewall'), loadEmailStats, { title: 'Failed to load the SMTP firewall', error: err });
            });
    }

    function emailDateQuery(base) {
        return rangeQuery(currentRange(), base);
    }

    // renderQueueHealth draws the queue size on a bar that runs a quarter
    // past the crit threshold, with the warn and crit marks on the bar. The
    // summary line beside it gives the count and the oldest age. An unknown
    // size has no bar; the summary says so, with Retry.
    function renderQueueHealth(q) {
        var el = document.getElementById('queue-health');
        if (!el) return;
        el.parentElement.hidden = !!q.unavailable;
        if (q.unavailable) {
            el.replaceChildren();
            return;
        }
        var size = q.size || 0;
        var scale = Math.max(size, (q.crit || q.warn || 1) * 1.25);
        var color = { crit: 'bg-danger', warn: 'bg-warning' }[queueLevel(q)] || 'bg-green';
        var marks = [['warn', q.warn], ['crit', q.crit]].filter(function(m) { return m[1] > 0; }).map(function(m) {
            return { name: m[0], label: m[0] + ' ' + num(m[1]), at: Math.round(m[1] / scale * 100) };
        });

        var wrap = node('div', 'csm-queue-bar');
        var track = node('div', 'progress');
        var bar = node('div', 'progress-bar ' + color);
        bar.setAttribute('aria-label', 'Queue size against the crit threshold');
        bar.setAttribute('aria-valuetext', [num(size) + (size === 1 ? ' message' : ' messages')]
            .concat(marks.map(function(m) { return m.label; })).join(', '));
        CSM.setProgressBar(bar, size / scale * 100);
        track.appendChild(bar);
        wrap.appendChild(track);
        marks.forEach(function(m) {
            var mark = node('div', 'csm-queue-mark csm-queue-mark--' + m.name);
            mark.setAttribute('data-queue-mark', m.name);
            mark.style.left = m.at + '%';
            wrap.appendChild(mark);
        });
        // A label under each mark prints over the other once the marks
        // close up, as they do above crit where the scale grows, so the
        // labels share one line. It ends at the right mark, or starts at
        // the left one when the marks sit in the left half.
        if (marks.length > 0) {
            var ats = marks.map(function(m) { return m.at; });
            var line = node('div', 'csm-queue-bar__labels', marks.map(function(m) { return m.label; }).join(', '));
            var right = Math.max.apply(null, ats);
            if (right > 50) line.style.right = (100 - right) + '%';
            else line.style.left = Math.min.apply(null, ats) + '%';
            wrap.appendChild(line);
        }
        el.replaceChildren(wrap);
    }

    // fact is one label and value of a compact line.
    function fact(label, value) {
        var el = node('span');
        el.appendChild(node('span', 'text-muted me-1', label));
        el.appendChild(node('span', null, value));
        return el;
    }

    // renderSMTPFirewall says on one line whether outbound SMTP is
    // restricted, who may still send, and the SMTP port flood limits.
    function renderSMTPFirewall(data) {
        var el = document.getElementById('email-sending-firewall');
        if (!el) return;
        var line = node('div', 'd-flex flex-wrap align-items-center column-gap-3 row-gap-1');
        var state = node('span', 'd-inline-flex align-items-center gap-2');
        state.appendChild(node('span', 'status-dot ' + (data.smtp_block ? 'status-green' : 'status-secondary')));
        state.appendChild(node('span', 'text-muted', 'Outbound SMTP'));
        state.appendChild(node('strong', null, data.smtp_block ? 'restricted' : 'open'));
        line.appendChild(state);
        if (data.smtp_block) {
            line.appendChild(fact('Ports', (data.smtp_ports || []).join(', ') || 'none'));
            line.appendChild(fact('Allowed users', (data.smtp_allow_users || []).join(', ') || 'none'));
        }
        var limits = (data.port_flood || []).map(function(pf) {
            return 'Port ' + pf.port + ': ' + pf.hits + ' / ' + pf.window_seconds + 's';
        });
        line.appendChild(fact('Port limits', limits.join(', ') || 'none'));
        el.replaceChildren(line);
    }

    // ---------- Sending accounts tab: accounts ----------

    // The server counts outbound abuse events up to this many.
    var ABUSE_EVENTS_CAP = 5000;
    var _senders = null;
    var _sendersErr = null;
    var _sendersSeq = 0;
    // What the account rows on screen show; a poll that shows the same
    // leaves them, and the focus, alone.
    var _sendersSig = '';
    var sendersTable = null;

    // abuseCount words a number of abuse events; at the cap there may be
    // more.
    function abuseCount(n) {
        return n >= ABUSE_EVENTS_CAP ? num(ABUSE_EVENTS_CAP) + '+' : num(n);
    }

    // loadSenders reads what each hosting account sent in the range, and
    // how many outbound abuse events the range holds, which the tab counts.
    // The table has its own error state, so no toast repeats it.
    function loadSenders() {
        var seq = ++_sendersSeq;
        CSM.get('/api/v1/email/senders?' + emailDateQuery(), { silent: true })
            .then(function(data) {
                if (seq !== _sendersSeq) return;
                _senders = data;
                _sendersErr = null;
                renderSenders();
            })
            .catch(function(err) {
                if (seq !== _sendersSeq) return;
                _senders = null;
                _sendersErr = err;
                renderSenders();
            });
    }

    // renderSenders counts the abuse events on the tab, shown only when
    // there are any, and lists the accounts busiest first: messages, share
    // of all outbound mail, and flags from the abuse events naming them.
    function renderSenders() {
        var events = _senders ? _senders.abuse_events || 0 : 0;
        setTabCount('sending', _senders ? (events > 0 ? events : null) : _sendersErr ? '?' : null);
        renderSendersSummary();
        var tbody = document.getElementById('email-sending-tbody');
        if (!tbody) return;
        if (_sendersErr) {
            _sendersSig = '';
            resetSendersTable();
            CSM.loadError(tbody, loadSenders, { title: 'Failed to load sending accounts', error: _sendersErr });
            return;
        }
        if (!_senders) return;
        var accounts = Array.isArray(_senders.accounts) ? _senders.accounts : [];
        var flags = abuseFlags();
        var range = currentRange();
        var sig = JSON.stringify([accounts, _senders.total, flags, rangeWords(range)]);
        if (sig === _sendersSig) return;
        _sendersSig = sig;
        var active = document.activeElement;
        var focused = active && tbody.contains(active) ? active.getAttribute('data-findings-account') : null;
        var state = tableState(sendersTable);
        resetSendersTable();
        if (accounts.length === 0) {
            emptyRow(tbody, 5, 'send', 'No mail sent by an account ' + rangeWords(range), '');
            return;
        }
        tbody.replaceChildren();
        accounts.forEach(function(a) { tbody.appendChild(senderRow(a, _senders.total, flags[a.account] || [])); });
        // The saved state brings back the page and the sort the operator
        // picked, which a poll with new counts would otherwise reset.
        sendersTable = new CSM.Table({
            tableId: 'email-sending-table',
            perPage: 25,
            persistPerPage: false,
            search: false,
            sortable: true,
            stateKey: 'csm-email-senders',
            mobileRowCard: true
        });
        restoreTableState(sendersTable, state);
        if (focused !== null) {
            var links = tbody.querySelectorAll('[data-findings-account]');
            for (var i = 0; i < links.length; i++) {
                if (links[i].getAttribute('data-findings-account') === focused) links[i].focus();
            }
        }
    }

    function resetSendersTable() {
        if (sendersTable) sendersTable.destroy();
        sendersTable = null;
    }

    // senderRow builds one account's row. Account names and abuse kinds
    // come from the server, so all of it is text.
    function senderRow(a, total, flags) {
        var tr = node('tr');
        tr.appendChild(rejectCell('Account', a.account, 'csm-break-word'));
        var messages = queueCell('Messages', 'text-end text-nowrap');
        messages.setAttribute('data-sort', String(a.messages));
        messages.textContent = num(a.messages);
        tr.appendChild(messages);
        var share = queueCell('Share', 'text-end text-nowrap');
        share.setAttribute('data-sort', String(a.messages));
        var pct = total > 0 ? a.messages / total * 100 : 0;
        share.textContent = total > 0 ? (pct < 1 ? '<1%' : Math.round(pct) + '%') : '--';
        tr.appendChild(share);
        var flagged = queueCell('Flags', 'ps-md-3');
        if (flags.length === 0) flagged.appendChild(node('span', 'text-muted', '--'));
        flags.forEach(function(f) {
            flagged.appendChild(node('span', 'badge bg-red-lt me-1', f.label + (f.count > 1 ? ' (' + num(f.count) + ')' : '')));
        });
        tr.appendChild(flagged);
        var actions = queueCell('Actions', 'text-end');
        var link = node('a', 'btn btn-sm btn-ghost-secondary text-nowrap', 'View findings');
        link.href = '?tab=findings&search=' + encodeURIComponent(a.account);
        link.setAttribute('data-findings-account', a.account);
        link.setAttribute('aria-label', 'View findings for ' + a.account);
        actions.appendChild(link);
        tr.appendChild(actions);
        return tr;
    }

    // abuseFlags lists, for each account, the kinds of abuse event naming
    // it with how many events, from the server's count over every event of
    // the range, not only the ones the list below shows.
    function abuseFlags() {
        var out = Object.create(null);
        var byAccount = _senders && _senders.abuse_by_account || {};
        Object.keys(byAccount).forEach(function(account) {
            var kinds = byAccount[account] || {};
            out[account] = Object.keys(kinds).map(function(label) { return { label: label, count: kinds[label] }; });
        });
        return out;
    }

    // renderSendersSummary says how much mail went out in the range, and
    // since when sends are counted while the table has no rows or the
    // counting began inside the range.
    function renderSendersSummary() {
        var el = document.getElementById('email-sending-summary');
        if (!el) return;
        if (!_senders) {
            el.textContent = '';
            return;
        }
        var range = currentRange();
        var total = _senders.total || 0;
        var text = num(total) + (total === 1 ? ' message' : ' messages') + ' sent ' + rangeWords(range);
        if (_senders.unresolved > 0) text += ', ' + num(_senders.unresolved) + ' of them from senders not matched to an account';
        text += '.';
        // The server lists the busiest accounts only; the total counts all.
        var accounts = Array.isArray(_senders.accounts) ? _senders.accounts : [];
        var listed = accounts.reduce(function(n, a) { return n + a.messages; }, _senders.unresolved || 0);
        if (listed < total) text += ' Busiest ' + num(accounts.length) + ' accounts shown.';
        var empty = accounts.length === 0;
        if (_overview && !_overview.counting_since) text += ' Counting has not started.';
        else if (_overview && (empty || Date.parse(_overview.counting_since) > range.from.getTime())) {
            text += ' Counting since ' + CSM.fmtDate(_overview.counting_since) + '.';
        }
        el.textContent = text;
    }

    // A View findings link opens Findings searched for its account. A click
    // meant for a new browser tab follows the link's address instead.
    var sendingBody = document.getElementById('email-sending-tbody');
    if (sendingBody) {
        sendingBody.addEventListener('click', function(e) {
            var link = e.target.closest('[data-findings-account]');
            if (!link || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
            e.preventDefault();
            if (searchEl) {
                searchEl.value = link.getAttribute('data-findings-account');
                searchEl.dispatchEvent(new Event('input'));
            }
            selectTab('findings');
            syncEmailURL();
        });
    }

    // ---------- AV status (Protection card) ----------

    function loadAVStatus() {
        var seq = ++_avSeq;
        CSM.get('/api/v1/email/av/status', { silent: true })
            .then(function(data) {
                if (seq !== _avSeq) return;
                _av = data;
                renderProtection();
            })
            .catch(function(err) {
                if (seq !== _avSeq) return;
                _av = null;
                ['prot-av', 'prot-watcher'].forEach(function(id) {
                    CSM.loadError(document.getElementById(id), loadAVStatus, { title: 'Antivirus status unavailable', error: err });
                });
            });
    }

    // ---------- Needs attention ----------

    function kindLabel(kind) {
        switch (kind) {
            case 'compromised_account': return 'Compromised';
            case 'spam_outbreak':       return 'Spam outbreak';
            case 'auth_failure':        return 'Auth failures';
            case 'queue_alert':         return 'Queue alert';
            case 'malware':             return 'Malware';
        }
        return kind;
    }

    function ageLabel(iso) {
        if (!iso) return '';
        if (CSM.timeAgo) return CSM.timeAgo(iso);
        return iso;
    }

    // At most this many groups show until the operator asks for all.
    var GROUPS_SHOWN = 8;
    var BLOCK_CHIPS = { all: 'blocked', some: 'partly blocked', none: 'not blocked' };
    var _groups = null;
    var _groupsSeq = 0;
    var _showHandled = false;
    var _showAllGroups = false;

    function loadActionGroups() {
        var seq = ++_groupsSeq;
        CSM.get('/api/v1/email/groups?' + emailDateQuery('limit=50'))
            .then(function(data) {
                if (seq !== _groupsSeq) return;
                _groups = data;
                renderActionGroups();
            })
            .catch(function(err) {
                if (seq !== _groupsSeq) return;
                // A toggle on stale groups would paint over the error.
                _groups = null;
                ['email-groups-handled', 'email-groups-more'].forEach(function(id) {
                    var btn = document.getElementById(id);
                    if (btn) btn.hidden = true;
                });
                var countEl = document.getElementById('email-groups-count');
                if (countEl) countEl.textContent = '';
                CSM.loadError(document.getElementById('email-action-groups'), loadActionGroups, { title: 'Failed to load what needs attention', error: err });
            });
    }

    var buildEmpty = CSM.emptyStateNode;

    function plural(n, word) {
        return n + ' ' + word + (n === 1 ? '' : 's');
    }

    // renderActionGroups lists the groups that need the operator. The server
    // puts unhandled groups first; handled ones (every IP already blocked)
    // show only when the operator asks for them.
    function renderActionGroups() {
        var el = document.getElementById('email-action-groups');
        if (!el || !_groups) return;
        var groups = Array.isArray(_groups.items) ? _groups.items : [];
        var handled = _groups.handled_count || 0;
        var shown = _showHandled ? groups : groups.filter(function(g) { return !g.handled; });

        var open = (_groups.total != null ? _groups.total : groups.length) - handled;
        var countEl = document.getElementById('email-groups-count');
        if (countEl) countEl.textContent = open > 0 ? plural(open, 'group') : '';
        var toggle = document.getElementById('email-groups-handled');
        if (toggle) {
            toggle.hidden = handled === 0;
            toggle.textContent = 'Show handled (' + handled + ')';
            toggle.setAttribute('aria-pressed', String(_showHandled));
            toggle.classList.toggle('active', _showHandled);
        }

        el.replaceChildren();
        if (_groups.blocks_unavailable) {
            el.appendChild(node('div', 'text-muted small px-3 py-2', 'Block state unavailable: CSM could not read the firewall state.'));
        }
        if (shown.length === 0) {
            el.appendChild(handled > 0
                ? buildEmpty('circle-check', 'Nothing needs you.', plural(handled, 'group') + ' already handled.')
                : buildEmpty('circle-check', 'Nothing needs you.', 'No mail alerts ' + rangeWords(currentRange()) + '.'));
        }
        var limit = _showAllGroups ? shown.length : Math.min(shown.length, GROUPS_SHOWN);
        shown.slice(0, limit).forEach(function(g) { el.appendChild(groupItem(g)); });
        var more = document.getElementById('email-groups-more');
        if (more) more.hidden = shown.length <= limit;
        CSM.truncationNote(el, _groups.truncated, 'email findings');
    }

    // groupItem builds one row. A handled group carries no severity, so a
    // routine blocked attacker does not read as an alarm.
    function groupItem(g) {
        var statusHTML = '<span class="badge bg-secondary-lt">' + CSM.esc(kindLabel(g.kind)) + '</span>';
        if (Object.prototype.hasOwnProperty.call(BLOCK_CHIPS, g.block_state)) {
            statusHTML += ' <span class="badge badge-outline text-secondary">' + BLOCK_CHIPS[g.block_state] + '</span>';
        }
        return CSM.summaryItem({
            severity: g.handled ? null : g.severity,
            title: g.title,
            meta: g.summary,
            count: g.count,
            age: ageLabel(g.last_seen),
            statusHTML: statusHTML,
            onClick: function() { openGroupDetail(g); }
        });
    }

    var handledToggle = document.getElementById('email-groups-handled');
    if (handledToggle) {
        handledToggle.addEventListener('click', function() {
            _showHandled = !_showHandled;
            renderActionGroups();
        });
    }
    var moreGroups = document.getElementById('email-groups-more');
    if (moreGroups) {
        moreGroups.addEventListener('click', function() {
            _showAllGroups = true;
            renderActionGroups();
            // The button hides itself; focus moves to the first group it
            // revealed, so the keyboard does not fall back to the page top.
            var next = document.querySelectorAll('#email-action-groups .csm-summary-list__item')[GROUPS_SHOWN];
            if (next) next.focus();
        });
    }

    function openGroupDetail(g) {
        var bodyHTML = '';
        bodyHTML += '<dl class="row mb-2"><dt class="col-4 text-muted">Kind</dt><dd class="col-8">' + CSM.esc(kindLabel(g.kind)) + '</dd>';
        bodyHTML += '<dt class="col-4 text-muted">Subject</dt><dd class="col-8">' + CSM.esc(g.subject) + '</dd>';
        bodyHTML += '<dt class="col-4 text-muted">Hits</dt><dd class="col-8">' + g.count + '</dd>';
        bodyHTML += '<dt class="col-4 text-muted">First seen</dt><dd class="col-8">' + CSM.fmtDate(g.first_seen) + '</dd>';
        bodyHTML += '<dt class="col-4 text-muted">Last seen</dt><dd class="col-8">' + CSM.fmtDate(g.last_seen) + '</dd></dl>';

        if (g.top_ips && g.top_ips.length > 0) {
            bodyHTML += '<div class="mb-2"><div class="subheader">Top source IPs</div><div class="font-monospace small">';
            for (var i = 0; i < g.top_ips.length; i++) {
                bodyHTML += '<div>' + CSM.esc(g.top_ips[i]) + '</div>';
            }
            bodyHTML += '</div></div>';
        }
        if (g.domains && g.domains.length > 0) {
            bodyHTML += '<div class="mb-2"><div class="subheader">Domains</div><div class="font-monospace small">' + g.domains.map(CSM.esc).join(', ') + '</div></div>';
        }
        if (g.message_ids && g.message_ids.length > 0) {
            bodyHTML += '<div class="mb-2"><div class="subheader">Message IDs</div><div class="font-monospace small">' + g.message_ids.map(CSM.esc).join(', ') + '</div></div>';
        }
        if (g.sample_findings && g.sample_findings.length > 0) {
            bodyHTML += '<div class="mb-2"><div class="subheader">Sample findings</div>';
            for (var s = 0; s < g.sample_findings.length; s++) {
                var f = g.sample_findings[s];
                bodyHTML += '<div class="mb-2 border-start border-2 ps-2 small">';
                bodyHTML += '<div>' + CSM.severityBadge(f.severity) + ' <code>' + CSM.esc(f.check) + '</code></div>';
                bodyHTML += '<div class="text-muted">' + CSM.fmtDate(f.timestamp) + '</div>';
                bodyHTML += '<div>' + CSM.esc(f.message || '') + '</div>';
                bodyHTML += '</div>';
            }
            bodyHTML += '</div>';
        }

        CSM.detailPanel.open({
            title: 'Email group: ' + g.title,
            bodyHTML: bodyHTML,
        });
    }

    // ---------- Findings tab (table) ----------

    // checkLabel words a check name the way the table's Type column does.
    function checkLabel(name) {
        return name.replace(/_/g, ' ').replace(/realtime$/, '').replace(/^email /, '').trim();
    }

    function checkOption(name) {
        var opt = node('option', null, checkLabel(name));
        opt.value = name;
        return opt;
    }

    // The auth failure checks, from the server's email check list, and
    // whether that list is still to answer.
    var _authChecks = [];
    var _checksPending = true;

    // loadEmailChecks fills the check list from the server's email check
    // list, grouped by kind. Until it answers the list offers only All
    // email checks, and the Auth failures chip cannot be pressed.
    function loadEmailChecks() {
        CSM.get('/api/v1/email/checks')
            .then(function(data) {
                var checks = Array.isArray(data.checks) ? data.checks : [];
                _authChecks = checks.filter(function(c) { return c.kind === 'auth_failure'; }).map(function(c) { return c.name; });
                checksReady();
                if (!checkEl) return;
                var picked = checkEl.value;
                Array.from(checkEl.children).slice(1).forEach(function(c) { c.remove(); });
                var groups = {};
                checks.forEach(function(c) {
                    if (!groups[c.kind]) {
                        groups[c.kind] = node('optgroup');
                        groups[c.kind].label = c.kind ? kindLabel(c.kind) : 'Other checks';
                        checkEl.appendChild(groups[c.kind]);
                    }
                    groups[c.kind].appendChild(checkOption(c.name));
                });
                checkEl.value = picked;
                // A linked check the list does not name stays on offer, so
                // the select names what the table filters on.
                if (picked && checkEl.value !== picked) {
                    checkEl.appendChild(checkOption(picked));
                    checkEl.value = picked;
                }
            })
            // The request toasts; the list keeps All email checks.
            .catch(checksReady);
    }

    // checksReady runs once the check list answered or failed. A chip
    // turned on before then, by a Failed logins link, held the findings
    // back; with no auth checks to name it cannot filter, so it turns off.
    function checksReady() {
        var held = _checksPending && authOn();
        _checksPending = false;
        if (authChip) authChip.disabled = _authChecks.length === 0;
        if (_authChecks.length === 0 && authOn()) {
            setAuthChip(false);
            syncEmailURL();
        }
        if (held) loadFindings();
    }

    function authOn() {
        return !!authChip && authChip.getAttribute('aria-pressed') === 'true';
    }

    function setAuthChip(on) {
        if (!authChip) return;
        authChip.setAttribute('aria-pressed', String(on));
        authChip.classList.toggle('active', on);
    }

    // applyAuthChip turns the Auth failures chip on or off and reloads the
    // findings. On, it replaces a picked check.
    function applyAuthChip(on) {
        // With no auth checks known, the chip cannot filter or be cleared.
        if (on && !_checksPending && _authChecks.length === 0) on = false;
        setAuthChip(on);
        if (on && checkEl) checkEl.value = '';
        syncEmailURL();
        loadFindings();
    }

    // findingsChecks returns the checks the table asks for: the auth
    // failure checks while the chip is on, else the picked check, else
    // none, which the server reads as every email check.
    function findingsChecks() {
        if (authOn()) return _authChecks.join(',');
        return checkEl ? checkEl.value : '';
    }

    function loadFindings() {
        // Unfiltered findings must not show under a pressed chip, so wait
        // for the check list; checksReady loads them.
        if (_checksPending && authOn()) {
            ++_emailFindingsLoadSeq;
            return;
        }
        var range = currentRange();
        var sev = sevEl ? sevEl.value : '';
        var checks = findingsChecks();
        var auth = authOn();
        _authAlerts = null;
        renderFindingsSummary();
        var params = 'scope=email&limit=' + EMAIL_FINDINGS_LIMIT;
        if (checks) params += '&checks=' + encodeURIComponent(checks);
        if (sev) params += '&severity=' + encodeURIComponent(sev);
        var seq = ++_emailFindingsLoadSeq;
        _findingsPending = true;
        CSM.get('/api/v1/history?' + rangeQuery(range, params))
            .then(function(data) {
                if (seq !== _emailFindingsLoadSeq) return;
                _findingsPending = false;
                var findings = data.items;
                setTabCount('findings', data.total);
                _authAlerts = auth ? data.total || 0 : null;
                renderFindingsSummary();
                renderFindingsTable(findings, 'No email findings ' + rangeWords(range));
                var label = document.getElementById('email-total-label');
                if (label) {
                    label.textContent = findings.length + ' / ' + data.total;
                }
                var note = document.getElementById('email-findings-note');
                if (note) note.replaceChildren();
                CSM.truncationNote(note, data.truncated, 'email findings');
            })
            .catch(function(err) {
                if (seq !== _emailFindingsLoadSeq) return;
                _findingsPending = false;
                setTabCount('findings', '?');
                _findingsSig = '';
                resetEmailFindingsTable();
                clearEmailFindingsState();
                CSM.loadError(document.getElementById('email-tbody'), loadFindings, { title: 'Failed to load email findings', error: err });
            });
    }

    // The findings the Auth failures chip matched in the range, once they
    // answered; null otherwise.
    var _authAlerts = null;

    // renderFindingsSummary shows, under the Auth failures chip, the Failed
    // logins card's number beside the alerts the chip lists: attempts are
    // log lines, alerts are the findings raised from them. Without the chip
    // there is no summary.
    function renderFindingsSummary() {
        var el = document.getElementById('email-findings-summary');
        if (!el) return;
        var parts = [];
        if (authOn()) {
            if (_overview) {
                var t = _overview.totals || {};
                parts.push('Failed login attempts in this range: ' + num((t.logins_smtp || 0) + (t.logins_mailbox || 0)) + '.');
            }
            if (_authAlerts !== null) parts.push('Alerts raised: ' + num(_authAlerts) + '.');
        }
        el.textContent = parts.join(' ');
        el.hidden = parts.length === 0;
    }

    function resetEmailFindingsTable() {
        if (!emailTable) return;
        emailTable.destroy();
        emailTable = null;
    }

    function clearEmailFindingsState() {
        _emailExportData = [];
        var label = document.getElementById('email-total-label');
        if (label) label.textContent = '';
        var note = document.getElementById('email-findings-note');
        if (note) note.replaceChildren();
    }

    function renderFindingsTable(findings, emptyTitle) {
        var tbody = document.getElementById('email-tbody');
        if (!tbody) {
            resetEmailFindingsTable();
            clearEmailFindingsState();
            return;
        }

        var sig = JSON.stringify([findings, emptyTitle]);
        if (sig === _findingsSig) return;
        _findingsSig = sig;
        var open = Object.create(null);
        tbody.querySelectorAll('.expand-btn[aria-expanded="true"]').forEach(function(btn) {
            open[btn.closest('tr').getAttribute('data-finding-key')] = true;
        });
        var active = document.activeElement;
        var focused = active && tbody.contains(active) && active.classList.contains('expand-btn') ? active.closest('tr').getAttribute('data-finding-key') : null;
        var state = tableState(emailTable);

        // Drop the previous instance first: it still holds listeners on the
        // shared search box and sort headers, and its allRows point at the
        // detached <tr>s this render replaces. Without destroy, a search would
        // re-insert those stale rows and every sort would fire once per leaked
        // instance.
        resetEmailFindingsTable();

        _emailExportData = findings.map(function(f) {
            return {
                check: f.check,
                severity: CSM.severity(f.severity).cls,
                message: f.message,
                account: f.account || '',
                timestamp: f.timestamp || ''
            };
        });

        if (findings.length === 0) {
            emptyRow(tbody, 6, 'mail-search', emptyTitle);
            return;
        }

        var html = '';
        for (var i = 0; i < findings.length; i++) {
            var f = findings[i];
            var cls = CSM.severityClass(f.severity);
            var account = f.account || '';
            var ip = f.ip || '';
            html += '<tr data-sev="' + cls + '" data-finding-key="' + CSM.attr(JSON.stringify([f.check, f.timestamp, account, ip, f.message])) + '">';
            html += '<td>' + CSM.severityBadge(f.severity) + '</td>';
            html += '<td><span class="small">' + CSM.esc(checkLabel(f.check)) + '</span></td>';
            html += '<td>' + CSM.esc(account || '') + '</td>';
            html += '<td><code>' + CSM.esc(ip || '') + '</code></td>';
            html += '<td class="text-wrap csm-tw-400">' + CSM.esc(f.message || '') +
                (f.details ? ' <button type="button" class="btn btn-ghost-secondary btn-sm expand-btn" aria-expanded="false" aria-label="Expand details" title="Expand details"><i class="ti ti-chevron-down"></i></button>' : '') + '</td>';
            html += '<td data-timestamp="' + CSM.attr(f.timestamp || '') + '">' + CSM.fmtDate(f.timestamp) + '</td>';
            html += '</tr>';
            if (f.details) {
                html += '<tr class="details-row"><td colspan="6"><div class="small text-muted csm-detail">' + CSM.esc(f.details) + '</div></td></tr>';
            }
        }
        tbody.innerHTML = html;

        // The table restores the search it saved last. A search in the box
        // is newer: from the address, or typed before the table saved it.
        var typed = searchEl ? searchEl.value : '';
        emailTable = new CSM.Table({
            tableId: 'email-table',
            perPage: 25,
            searchId: 'email-search',
            sortable: true,
            detailRows: true,
            mobileRowCard: true,
            stateKey: 'csm-email-table',
            countTargetId: 'email-total-label',
            emptyState: {
                icon: 'mail-search',
                title: 'No findings match',
                reason: 'Try clearing the search or filter selections.'
            }
        });
        if (typed || state || _findingsSearchEdited) {
            if (searchEl) searchEl.value = typed;
            emailTable.searchText = typed.toLowerCase();
            emailTable.applyFilters();
        }
        restoreTableState(emailTable, state);
        tbody.querySelectorAll('.expand-btn').forEach(function(btn) {
            var key = btn.closest('tr').getAttribute('data-finding-key');
            if (open[key]) CSM.toggleDetailRow(btn);
            if (key === focused) btn.focus();
        });
        if (CSM.initTimeAgo) CSM.initTimeAgo();
    }

    // ---------- Held mail tab ----------

    // Held mail is one list from two stores: messages the email AV
    // quarantined as malware, and forward copies the forward guard held
    // before they left for an outside address. Each store loads and fails
    // on its own, and the list shows what has arrived.
    var HELD_SOURCES = {
        malware: { url: '/api/v1/email/quarantine', title: 'Failed to load the mail quarantine' },
        forward: { url: '/api/v1/email/held', title: 'Failed to load held forward copies' }
    };
    var _held = {
        malware: { items: null, err: null, seq: 0 },
        forward: { items: null, err: null, seq: 0 }
    };
    var _heldTable = null;
    var _heldShown = []; // the items in the range, as the rows show them
    var _heldOutside = 0;
    var _heldOlder = 0;  // held items older than the range
    // What the rows on screen show, apart from the times; an answer that
    // shows the same leaves them, the focus and the selection alone.
    var _heldSig = '';
    // Items with an action in flight, by kind:id. Their actions stay
    // disabled, across a rebuild too.
    var _heldBusy = {};
    // What the held mail summary on screen says; an unchanged one is not
    // drawn again, so its link keeps the focus.
    var _heldSummaryKey = '';
    // Why the guard held a forward copy, from its reason codes.
    var HELD_REASONS = { bounce_backscatter: 'a bounce (backscatter)', bad_sender_ip: 'sent from a listed bad IP' };

    // Malware rows can be released or deleted together.
    var _emailQuarBulk = CSM.bulk({
        rowCheckboxSelector: '.email-quar-cb',
        selectAllEl: document.getElementById('email-quar-select-all'),
        selectAllSelector: '#email-quar-select-all',
        valueAttr: 'data-id',
        onChange: function(n, ids) {
            if (!ids.some(function(id) { return _heldBusy['malware:' + id]; })) return;
            ['email-quar-bulk-release', 'email-quar-bulk-delete'].forEach(function(id) {
                var btn = document.getElementById(id);
                if (btn) btn.disabled = true;
            });
        },
        buttons: [
            { el: document.getElementById('email-quar-bulk-release'), labelTemplate: 'Release {n} message(s)' },
            { el: document.getElementById('email-quar-bulk-delete'),  labelTemplate: 'Delete {n} message(s)' }
        ]
    });

    // The search and the kind filter are static, so the address binds to
    // them once.
    CSM.urlState.bind({
        inputs: {
            email_held_q: document.getElementById('email-held-search'),
            email_held_kind: document.getElementById('email-held-filter')
        },
        defaults: { email_held_kind: 'all' }
    });

    function loadHeldMail() {
        loadHeldSource('malware');
        loadHeldSource('forward');
    }

    // loadHeldSource reads one store. The list has its own error row, so
    // no toast repeats it.
    function loadHeldSource(kind) {
        var src = _held[kind];
        var seq = ++src.seq;
        CSM.get(HELD_SOURCES[kind].url, { silent: true })
            .then(function(resp) {
                if (seq !== src.seq) return;
                src.items = Array.isArray(resp.items) ? resp.items : [];
                src.err = null;
                renderHeld();
            })
            .catch(function(err) {
                if (seq !== src.seq) return;
                src.items = null;
                src.err = err;
                renderHeld();
            });
    }

    // heldEntries merges both stores, newest first.
    function heldEntries() {
        var out = [];
        function add(kind, id, raw, item) {
            out.push({ kind: kind, id: id, at: raw, time: CSM.parseTimestamp(raw), item: item });
        }
        (_held.malware.items || []).forEach(function(m) { add('malware', m.message_id, m.quarantined_at, m); });
        (_held.forward.items || []).forEach(function(m) { add('forward', m.id, m.held_at, m); });
        return out.sort(function(a, b) { return (b.time || 0) - (a.time || 0); });
    }

    function heldEntry(kind, id) {
        for (var i = 0; i < _heldShown.length; i++) {
            if (_heldShown[i].kind === kind && _heldShown[i].id === id) return _heldShown[i];
        }
        return null;
    }

    // renderHeld draws the merged list in the page range; items held
    // before it hide behind a note in the summary. A store that failed
    // shows its own error row above the other store's items. The 60 s
    // poll mostly brings the same list, and then only the times change.
    function renderHeld() {
        var tbody = document.getElementById('email-held-tbody');
        if (!tbody) return;
        var range = currentRange(), from = range.from.getTime(), to = range.to.getTime();
        var all = heldEntries();
        _heldShown = all.filter(function(e) { return e.time >= from && e.time < to; });
        _heldOlder = all.filter(function(e) { return e.time < from; }).length;
        _heldOutside = all.length - _heldShown.length - _heldOlder;
        var pending = ['malware', 'forward'].some(function(k) { return _held[k].items === null && !_held[k].err; });
        var failed = !!(_held.malware.err || _held.forward.err);
        var sig = JSON.stringify([_heldShown.map(function(e) { return [e.kind, e.id, e.at, e.item]; }), _heldOlder, _heldOutside, pending,
            !!_held.malware.err, !!_held.forward.err]);
        if (sig === _heldSig) {
            _heldShown.forEach(function(e) {
                var row = heldRowEl(e.kind, e.id);
                if (row) row.querySelector('[data-label="Held"]').textContent = CSM.timeAgo(e.at);
            });
        } else {
            _heldSig = sig;
            rebuildHeld(tbody, all.length, pending, failed);
        }
        // Retry takes its error away, so the error rows draw every time.
        tbody.querySelectorAll('[data-held-error]').forEach(function(tr) { tr.remove(); });
        // Inserted after the table took its rows, so filters and paging
        // leave the error rows in place, on top.
        ['forward', 'malware'].forEach(function(kind) {
            if (!_held[kind].err) return;
            var td = node('td');
            td.setAttribute('colspan', '9');
            var tr = node('tr');
            tr.setAttribute('data-held-error', kind);
            tr.appendChild(td);
            tbody.insertBefore(tr, tbody.firstChild);
            CSM.loadError(td, function() { loadHeldSource(kind); }, { title: HELD_SOURCES[kind].title, error: _held[kind].err });
        });
        _emailQuarBulk.refresh();
        renderHeldSummary();
    }

    // rebuildHeld draws the rows again. The selected malware stays
    // selected, the focused control gets the focus back, and the search
    // and filter keep what their boxes hold.
    function rebuildHeld(tbody, total, pending, failed) {
        var focus = heldFocus(tbody);
        var picked = {};
        tbody.querySelectorAll('.email-quar-cb').forEach(function(cb) {
            if (cb.checked) picked[cb.getAttribute('data-id')] = true;
        });
        var state = tableState(_heldTable);
        if (_heldTable) _heldTable.destroy();
        _heldTable = null;
        tbody.replaceChildren();
        _heldShown.forEach(function(e) {
            var row = heldRow(e);
            var cb = row.querySelector('.email-quar-cb');
            if (cb) cb.checked = !!picked[e.id];
            tbody.appendChild(row);
        });
        if (_heldShown.length > 0) {
            var search = document.getElementById('email-held-search');
            var kind = document.getElementById('email-held-filter');
            var typed = search ? search.value : '', shown = kind ? kind.value : 'all';
            _heldTable = new CSM.Table({
                tableId: 'email-held-table',
                perPage: 25,
                searchId: 'email-held-search',
                searchAttr: 'data-search',
                sortable: true,
                stateKey: 'csm-email-held',
                mobileRowCard: true,
                filters: [{ id: 'email-held-filter', attr: 'data-kind' }],
                emptyState: { icon: 'filter-off', title: 'No held mail matches', reason: 'Try another filter or search.' },
                onRender: function() { _emailQuarBulk.refresh(); }
            });
            // The table restores the search and filter it saved last. The
            // boxes can hold newer ones: from the address, or typed before
            // the table saved them.
            if (search) search.value = typed;
            if (kind) kind.value = shown;
            _heldTable.searchText = typed.toLowerCase();
            _heldTable.filterValues['email-held-filter'] = shown;
            _heldTable.applyFilters();
            restoreTableState(_heldTable, state);
        } else if (pending) {
            emptyRow(tbody, 9, 'loader-2', 'Loading held mail...', '');
        } else if (!failed) {
            emptyRow(tbody, 9, 'mail-check', total ? 'Nothing held in this range' : 'Nothing held', '');
        }
        if (focus) {
            var row = heldRowEl(focus.kind, focus.id);
            var target = row && row.querySelector(focus.sel);
            if (target) target.focus();
        }
    }

    // heldRowEl returns the row on screen for a held item, or null.
    function heldRowEl(kind, id) {
        var rows = document.querySelectorAll('#email-held-tbody tr[data-held-id]');
        for (var i = 0; i < rows.length; i++) {
            if (rows[i].getAttribute('data-kind') === kind && rows[i].getAttribute('data-held-id') === id) return rows[i];
        }
        return null;
    }

    // heldFocus names the row control that has the focus, to give it back
    // after a rebuild.
    function heldFocus(tbody) {
        var el = document.activeElement;
        var row = el && tbody.contains(el) ? el.closest('tr[data-held-id]') : null;
        if (!row) return null;
        var action = el.getAttribute('data-held-action');
        var sel = action ? '[data-held-action="' + action + '"]' : el.classList.contains('email-quar-cb') ? '.email-quar-cb' : '';
        return sel ? { kind: row.getAttribute('data-kind'), id: row.getAttribute('data-held-id'), sel: sel } : null;
    }

    // setHeldBusy marks an item's action as running, or done, and sets its
    // buttons on screen to match.
    function setHeldBusy(e, busy) {
        if (busy) _heldBusy[e.kind + ':' + e.id] = true;
        else delete _heldBusy[e.kind + ':' + e.id];
        var row = heldRowEl(e.kind, e.id);
        if (row) row.querySelectorAll('[data-held-action], .email-quar-cb').forEach(function(btn) { btn.disabled = busy; });
        _emailQuarBulk.refresh();
    }

    // virusNames names what the antivirus found in a message.
    function virusNames(m) {
        return uniqueValues((m.findings || []).map(function(f) { return f.signature; })).join(', ') || 'malware';
    }

    function uniqueValues(list) {
        return list.filter(function(v, i) { return v && list.indexOf(v) === i; });
    }

    // addressNode shows an address that may fold after its @, so a narrow
    // column breaks it there rather than mid-word.
    function addressNode(text) {
        var span = node('span');
        var at = text.indexOf('@') + 1;
        span.appendChild(document.createTextNode(at > 0 ? text.slice(0, at) : text));
        if (at > 0) {
            span.appendChild(document.createElement('wbr'));
            span.appendChild(document.createTextNode(text.slice(at)));
        }
        return span;
    }

    // addLine adds a second, muted line to a cell.
    function addLine(td, text) {
        td.appendChild(document.createTextNode(' '));
        td.appendChild(node('div', 'text-muted small', text));
    }

    // heldRow builds one held item's row. Senders, recipients, subjects and
    // virus names come from mail anyone can send, so all of it is text.
    function heldRow(e) {
        var m = e.item, malware = e.kind === 'malware';
        var from = malware ? m.from : m.sender;
        var to = malware ? (Array.isArray(m.to) ? m.to : []) : [m.recipient];
        var tr = node('tr');
        tr.setAttribute('data-kind', e.kind);
        tr.setAttribute('data-held-id', e.id);
        tr.setAttribute('data-search', [from, to.join(' '), m.forwarder, m.subject].join(' ').toLowerCase());

        var pick = node('td');
        if (malware) {
            var cb = node('input', 'form-check-input email-quar-cb');
            cb.type = 'checkbox';
            cb.disabled = !!_heldBusy[e.kind + ':' + e.id];
            cb.setAttribute('data-id', e.id);
            cb.setAttribute('aria-label', 'Select message from ' + (from || 'unknown sender') + ': ' + (m.subject || 'no subject'));
            pick.appendChild(cb);
        }
        tr.appendChild(pick);

        var held = queueCell('Held', 'text-nowrap');
        held.setAttribute('data-timestamp', e.at || '');
        held.textContent = CSM.timeAgo(e.at);
        if (e.at) held.title = CSM.fmtDate(e.at);
        tr.appendChild(held);

        var kind = queueCell('Kind', 'text-nowrap');
        kind.appendChild(node('span', 'badge ' + (malware ? 'bg-red-lt' : 'bg-secondary-lt'), malware ? 'Malware' : 'Forward copy'));
        if (malware && m.direction === 'outbound') addLine(kind, 'outgoing');
        tr.appendChild(kind);

        var sender = queueCell('From', 'csm-wrap-long');
        if (!malware && !from) sender.appendChild(node('span', 'badge bg-secondary-lt', 'bounce'));
        else sender.appendChild(from ? addressNode(from) : node('span', 'text-muted', '--'));
        tr.appendChild(sender);

        var rcpt = queueCell('To', 'csm-wrap-long');
        rcpt.appendChild(to[0] ? addressNode(to[0]) : node('span', 'text-muted', '--'));
        if (to.length > 1) rcpt.appendChild(node('span', 'text-muted small', ' +' + num(to.length - 1) + ' more'));
        if (!malware && m.forwarder) addLine(rcpt, 'via ' + m.forwarder);
        tr.appendChild(rcpt);

        tr.appendChild(rejectCell('Subject', m.subject, 'text-wrap csm-break-word csm-held-subject'));

        var why = queueCell('Why held', 'text-wrap csm-wrap-long');
        if (malware) {
            why.appendChild(node('span', null, virusNames(m)));
            var engines = uniqueValues((m.findings || []).map(function(f) { return f.engine; }));
            if (engines.length) addLine(why, 'found by ' + engines.join(', '));
        } else {
            why.appendChild(node('span', null, 'Held forward to external address'));
            var reasons = (Array.isArray(m.reasons) ? m.reasons : []).map(function(r) {
                return Object.prototype.hasOwnProperty.call(HELD_REASONS, r) ? HELD_REASONS[r] : r;
            });
            if (reasons.length) addLine(why, reasons.join(', '));
        }
        tr.appendChild(why);

        var size = queueCell('Size', 'text-nowrap');
        size.setAttribute('data-sort', String(m.size || 0));
        size.textContent = CSM.formatSize(m.size);
        tr.appendChild(size);

        var actions = queueCell('Actions', 'text-end');
        var buttons = node('div', 'btn-list justify-content-end flex-nowrap');
        var what = malware ? 'message from ' + (from || 'unknown sender') : 'held copy to ' + m.recipient;
        [['release', 'Release', 'btn-ghost-secondary'], ['delete', 'Delete', 'btn-ghost-danger']].forEach(function(a) {
            var btn = node('button', 'btn btn-sm ' + a[2], a[1]);
            btn.type = 'button';
            btn.setAttribute('data-held-action', a[0]);
            btn.setAttribute('aria-label', a[1] + ' ' + what);
            btn.disabled = !!_heldBusy[e.kind + ':' + e.id];
            buttons.appendChild(btn);
        });
        actions.appendChild(buttons);
        tr.appendChild(actions);
        return tr;
    }

    // renderHeldSummary repeats the Malware card's numbers for the range,
    // then says what is held now: what this tab lists and counts.
    function renderHeldSummary() {
        var malware = _held.malware.items, forward = _held.forward.items;
        var known = malware && forward;
        setTabCount('held', known ? malware.length + forward.length : _held.malware.err || _held.forward.err ? '?' : null);
        var el = document.getElementById('email-held-summary');
        if (!el) return;
        var line = node('div', 'fw-medium');
        if (_overview) {
            var stopped = malwareStopped(_overview.totals || {});
            line.appendChild(document.createTextNode('Malware stopped in this range: ' + num(stopped.smtp + stopped.quarantined) + ' ('));
            var link = node('a', null, num(stopped.smtp) + ' rejected at SMTP');
            link.href = '?tab=rejects';
            link.setAttribute('data-rejects-class', 'malware');
            bindTabLink(link);
            line.appendChild(link);
            line.appendChild(document.createTextNode(', ' + num(stopped.quarantined) + ' quarantined).'));
        }
        if (known) {
            var n = malware.length + forward.length;
            if (line.childNodes.length) line.appendChild(document.createTextNode(' '));
            line.appendChild(document.createTextNode(n === 0 ? 'Nothing is held now.' : 'Held now: ' + num(n) + ' (' + num(malware.length) + ' malware, ' +
                num(forward.length) + (forward.length === 1 ? ' forward copy' : ' forward copies') + ').'));
        }
        if (!line.childNodes.length) {
            // A spinner while the counts load; once they cannot, say so
            // rather than keep the spinner or numbers from before.
            var waiting = (!_overview && !_overviewErr) ||
                ['malware', 'forward'].some(function(k) { return _held[k].items === null && !_held[k].err; });
            if (waiting) return;
            line.textContent = 'Held mail counts unavailable.';
        }
        var parts = [line];
        if (_heldOutside > 0) {
            parts.push(node('div', 'mt-1', num(_heldOutside) + (_heldOutside === 1 ? ' held item outside this range' : ' held items outside this range') + '; widen the range.'));
        }
        if (_heldOlder > 0) {
            parts.push(node('div', 'mt-1', num(_heldOlder) + (_heldOlder === 1 ? ' older held item' : ' older held items') + '; widen the range.'));
        }
        var key = parts.map(function(p) { return p.textContent; }).join('|');
        if (key === _heldSummaryKey) return;
        _heldSummaryKey = key;
        el.replaceChildren.apply(el, parts);
    }

    var HELD_ROUTES = { malware: '/api/v1/email/quarantine/', forward: '/api/v1/email/held/' };

    // heldAction asks first, in words that differ by kind, then releases or
    // deletes the item through its own store's route.
    function heldAction(e, action) {
        if (_heldBusy[e.kind + ':' + e.id]) return;
        setHeldBusy(e, true);
        var asked;
        if (action === 'delete') asked = CSM.confirm('Delete permanently. This cannot be undone.', { danger: true, okLabel: 'Delete' });
        else if (e.kind === 'malware') asked = CSM.confirm('Deliver this message to its original recipients? It contained ' + virusNames(e.item) + '.', { danger: true, okLabel: 'Deliver' });
        else asked = CSM.confirm('Send this held copy to ' + e.item.recipient + '?', { okLabel: 'Send' });
        asked.then(function() {
            var url = HELD_ROUTES[e.kind] + encodeURIComponent(e.id);
            var req = action === 'delete' ? CSM.delete(url) : CSM.post(url + '/release', {});
            req.then(function() { CSM.toast(action === 'delete' ? 'Deleted' : 'Released', 'success'); })
                // A refused release leaves the item held; the error says why.
                .catch(function(err) { CSM.toast((action === 'delete' ? 'Delete' : 'Release') + ' failed: ' + CSM.errorText(err), 'error'); })
                .then(function() {
                    setHeldBusy(e, false);
                    loadHeldSource(e.kind);
                    if (e.kind === 'malware') loadAVStatus();
                });
        }).catch(function() { setHeldBusy(e, false); });
    }

    var heldBody = document.getElementById('email-held-tbody');
    if (heldBody) {
        heldBody.addEventListener('click', function(ev) {
            var btn = ev.target.closest('[data-held-action]');
            var row = btn && btn.closest('tr');
            var e = row && heldEntry(row.getAttribute('data-kind'), row.getAttribute('data-held-id'));
            if (e) heldAction(e, btn.getAttribute('data-held-action'));
        });
    }

    // Reserve every selected message before asking, including the ones
    // waiting behind another request in this batch.
    function heldBulkAction(action) {
        var ids = _emailQuarBulk.selectedValues();
        if (!ids.length || ids.some(function(id) { return _heldBusy['malware:' + id]; })) return;
        var entries = ids.map(function(id) { return { kind: 'malware', id: id }; });
        entries.forEach(function(e) { setHeldBusy(e, true); });
        var release = action === 'release';
        var ask = ids.length === 1 ? 'Deliver this message to its original recipients? It contained malware.'
            : 'Deliver these ' + ids.length + ' messages to their original recipients? They contained malware.';
        var asked = release ? CSM.confirm(ask, { danger: true, okLabel: 'Deliver' })
            : CSM.confirm('Permanently delete ' + ids.length + ' quarantined message(s)?', { danger: true, okLabel: 'Delete' });
        asked.then(function() {
            var succeeded = 0, failed = 0;
            var chain = Promise.resolve();
            ids.forEach(function(id) {
                chain = chain.then(function() {
                    var url = HELD_ROUTES.malware + encodeURIComponent(id);
                    return (release ? CSM.post(url + '/release', {}) : CSM.delete(url))
                        .then(function() { succeeded++; })
                        .catch(function() { failed++; });
                });
            });
            return chain.then(function() {
                CSM.toast((release ? 'Released ' : 'Deleted ') + succeeded + ' of ' + (succeeded + failed), failed > 0 ? 'warning' : 'success');
                loadHeldSource('malware');
                loadAVStatus();
            });
        }).catch(function(err) {
            if (err) CSM.toast(CSM.errorText(err), 'error');
        }).then(function() {
            entries.forEach(function(e) { setHeldBusy(e, false); });
        });
    }

    ['release', 'delete'].forEach(function(action) {
        var btn = document.getElementById('email-quar-bulk-' + action);
        if (btn) btn.addEventListener('click', function() { heldBulkAction(action); });
    });

    // ---------- Forwarders (inventory, collapsed under Sending accounts) ----------

    // Provider class -> badge colour. Free providers are the reputation-risk
    // case (forwarding spam to them tanks the outbound IP), so they read red.
    var FWD_PROVIDER_BADGE = Object.create(null);
    FWD_PROVIDER_BADGE.yahoo = 'bg-red';
    FWD_PROVIDER_BADGE.gmail = 'bg-red';
    FWD_PROVIDER_BADGE.outlook = 'bg-red';
    FWD_PROVIDER_BADGE.external = 'bg-yellow';
    FWD_PROVIDER_BADGE.local = 'bg-green';

    function providerBadge(provider) {
        provider = String(provider || '');
        var cls = Object.prototype.hasOwnProperty.call(FWD_PROVIDER_BADGE, provider)
            ? FWD_PROVIDER_BADGE[provider]
            : 'bg-secondary';
        return '<span class="badge ' + CSM.attr(cls) + ' me-1">' + CSM.esc(provider) + '</span>';
    }

    function loadForwarders() {
        if (forwardersLoaded) return;
        forwardersLoaded = true;
        CSM.get('/api/v1/email/forwarders')
            .then(function(data) {
                _forwarders = data.items;
                renderForwarders();
            })
            .catch(function(err) {
                forwardersLoaded = false;
                setForwardersCount('?');
                CSM.loadError(document.getElementById('email-fwd-tbody'), loadForwarders, { title: 'Failed to load forwarders', error: err });
            });
    }

    // setForwardersCount shows a count on the collapsed forwarders section.
    function setForwardersCount(text) {
        var badge = document.getElementById('email-fwd-section-count');
        if (!badge) return;
        badge.hidden = false;
        badge.textContent = text;
    }

    function forwarderMatchesFilter(f, mode) {
        if (mode === 'external') return f.has_external;
        if (mode === 'free') return f.has_free_provider;
        if (mode === 'forward_only') return f.forward_only;
        return true;
    }

    function forwarderMatchesSearch(f, q) {
        if (!q) return true;
        if (f.source.toLowerCase().indexOf(q) !== -1) return true;
        if (f.owner && f.owner.toLowerCase().indexOf(q) !== -1) return true;
        for (var i = 0; i < f.destinations.length; i++) {
            if (f.destinations[i].address.toLowerCase().indexOf(q) !== -1) return true;
        }
        return false;
    }

    function renderForwarders() {
        var tb = document.getElementById('email-fwd-tbody');
        if (!tb) return;
        var mode = (document.getElementById('email-fwd-filter') || {}).value || '';
        var q = ((document.getElementById('email-fwd-search') || {}).value || '').trim().toLowerCase();

        var rows = _forwarders.filter(function(f) {
            return forwarderMatchesFilter(f, mode) && forwarderMatchesSearch(f, q);
        });

        var countEl = document.getElementById('email-fwd-count');
        if (countEl) countEl.textContent = rows.length + ' of ' + _forwarders.length;
        setForwardersCount(num(_forwarders.filter(function(f) { return f.has_external; }).length));

        if (rows.length === 0) {
            if (_forwarders.length === 0) emptyRow(tb, 5, 'mail-forward', 'No forwarders found on this host', '');
            else emptyRow(tb, 5, 'filter-off', 'No forwarders match the current filter', '');
            return;
        }

        var html = '';
        for (var i = 0; i < rows.length; i++) {
            var f = rows[i];
            var dests = '';
            for (var d = 0; d < f.destinations.length; d++) {
                dests += '<div class="font-monospace small">' + CSM.esc(f.destinations[d].address) + '</div>';
            }
            var badges = '';
            for (var p = 0; p < f.providers.length; p++) {
                badges += providerBadge(f.providers[p]);
            }
            var copy = f.forward_only
                ? '<span class="badge bg-red-lt">Forward-only</span>'
                : '<span class="badge bg-green-lt">Keep local</span>';
            html += '<tr>';
            html += '<td class="font-monospace small">' + CSM.esc(f.source) + '</td>';
            html += '<td>' + (f.owner ? CSM.esc(f.owner) : '<span class="text-muted">--</span>') + '</td>';
            html += '<td>' + dests + '</td>';
            html += '<td>' + badges + '</td>';
            html += '<td>' + copy + '</td>';
            html += '</tr>';
        }
        tb.innerHTML = html;
    }

    // ---------- Queue tab: summary and messages ----------

    var QUEUE_PAGE_SIZE = 25;
    var queueFilterEl = document.getElementById('email-queue-filter');
    var queueSearchEl = document.getElementById('email-queue-search');
    var queueTable = null;
    var _queue = null; // the list page on screen; null while unread
    var _queuePage = 1;
    var _queueSeq = 0;
    // What the backscatter flush would remove, from the queue composition.
    var _queueFlushable = 0;
    var _queueFlushBusy = false;
    // Messages whose details are open. A reload opens them again.
    var _queueOpen = {};
    // What the rows on screen show, apart from the ages; a list page that
    // shows the same leaves them, with the focus and open details, alone.
    var _queueSig = '';
    // Messages with an action in flight. Their actions stay disabled,
    // across a rebuild too.
    var _queueBusy = {};
    // What the summary line on screen says, with the flush count; '' once
    // something else took its place.
    var _queueSummaryKey = '';

    // The per-message actions, in the order the row offers them. Each
    // confirm names the message and its recipients.
    var QUEUE_ACTIONS = {
        thaw: { label: 'Thaw', title: 'Thaw',
            ask: function(t) { return 'Thaw ' + t + '? Exim tries it again on its next queue run.'; } },
        retry: { label: 'Retry', title: 'Retry now',
            ask: function(t) { return 'Try delivering ' + t + ' now?'; } },
        bounce: { label: 'Return', title: 'Return to sender', danger: true,
            ask: function(t, m) {
                return 'Give up on ' + t + ' and return it to its sender? ' +
                    (m.bounce ? 'It is a bounce itself, so exim sends no new bounce.' : 'Exim stops trying and sends the sender a bounce.');
            } },
        'delete': { label: 'Delete', title: 'Delete', danger: true,
            ask: function(t) { return 'Delete ' + t + '? No bounce is sent and this cannot be undone.'; } }
    };

    // What the queue showed after an action, as the toast says it.
    var QUEUE_OUTCOMES = {
        removed: ['Deleted', 'success'],
        bounced: ['Returned to sender', 'success'],
        attempt_started: ['Delivery attempt started', 'success'],
        thawed: ['Thawed', 'success'],
        gone: ['No longer in the queue', 'info']
    };

    function loadQueue() {
        var seq = ++_queueSeq;
        var params = 'page=' + _queuePage + '&limit=' + QUEUE_PAGE_SIZE +
            '&filter=' + encodeURIComponent(queueFilterEl ? queueFilterEl.value : 'all') +
            '&q=' + encodeURIComponent(queueSearchEl ? queueSearchEl.value.trim() : '');
        // The list has its own error state, so no toast repeats it.
        CSM.get('/api/v1/email/queue?' + params, { silent: true })
            .then(function(data) {
                if (seq !== _queueSeq) return;
                if (data.unavailable) {
                    queueUnknown('CSM could not read the mail queue.');
                    return;
                }
                // An action can empty the last page; show the one before.
                var pages = Math.max(1, Math.ceil((data.total || 0) / QUEUE_PAGE_SIZE));
                if (_queuePage > pages) {
                    _queuePage = pages;
                    loadQueue();
                    return;
                }
                renderQueue(data);
            })
            .catch(function(err) {
                if (seq !== _queueSeq) return;
                queueUnknown(err);
            });
    }

    // reloadQueue reads the queue again after it changed: the list, the
    // flush count and the queue size on the card, the tab and the bar.
    function reloadQueue() {
        loadQueue();
        queueCompositionLoaded = false;
        loadQueueComposition();
        loadOverview();
    }

    // queueUnknown says the queue could not be read, with Retry. The list
    // hides: an unread queue has no count, and is not an empty one.
    function queueUnknown(err) {
        _queue = null;
        _queueSig = '';
        resetQueueTable();
        var list = document.getElementById('email-queue-list');
        if (list) list.hidden = true;
        var summary = document.getElementById('email-queue-summary');
        // Retry shows what the error covers; an old count must not return.
        if (summary) summary.replaceChildren();
        _queueSummaryKey = '';
        CSM.loadError(summary, loadQueue, { title: 'Queue size unknown', error: err });
    }

    // renderQueue shows a list page. The 60 s poll mostly brings the page
    // on screen again; rebuilding it would drop the focus and read every
    // open message again, so then only the summary and the ages change.
    function renderQueue(data) {
        var items = Array.isArray(data.items) ? data.items : [];
        var sig = JSON.stringify([data.total, items.map(function(m) {
            return [m.id, m.frozen, m.recipient_count, m.reason, m.sender, m.recipients, m.local_user, m.size, m.bounce, m.arrived];
        })]);
        _queue = data;
        renderQueueSummary();
        renderQueuePager(data.total || 0);
        if (sig === _queueSig) {
            items.forEach(function(m) {
                var row = queueRowEl(m.id);
                if (row) row.cells[0].textContent = CSM.formatDuration(m.age_seconds);
            });
            return;
        }
        _queueSig = sig;
        renderQueueRows(items);
    }

    // queueSize is the live queue size the card and the tab count show,
    // or null while it is not known.
    function queueSize() {
        var q = _overview && _overview.queue;
        return q && !q.unavailable ? q.size || 0 : null;
    }

    // renderQueueSummary says in one sentence how much is queued, frozen
    // and how old, and how much of it is backscatter, with the flush. The
    // count, the frozen and the oldest age are the card's, from the live
    // overview; the list's own come from a listing up to a minute old, and
    // the two must not disagree.
    function renderQueueSummary() {
        var el = document.getElementById('email-queue-summary');
        if (!el || !_queue) return;
        var q = _queue;
        var size = queueSize();
        var list = document.getElementById('email-queue-list');
        if (list) list.hidden = !((size === null ? q.queued : size) > 0);
        if (size === null) {
            // Wait for the overview; once it has failed, say so.
            if (_overview || _overviewErr) {
                el.replaceChildren();
                _queueSummaryKey = '';
                CSM.loadError(el, loadOverview, { title: 'Queue size unknown', error: _overviewErr || 'CSM could not read the mail queue.' });
            }
            return;
        }
        var text = 'The queue is empty.';
        if (size > 0) {
            var live = _overview.queue;
            text = num(size) + ' queued';
            if (live.detail_unavailable) text += ', oldest unknown';
            else {
                text += ', ' + num(live.frozen) + ' frozen';
                if (live.oldest_age_seconds != null) text += ', oldest ' + CSM.formatDuration(live.oldest_age_seconds);
            }
            text += '.';
            if (q.backscatter === 1) text += ' 1 is a bounce to a sender that does not exist (backscatter).';
            else if (q.backscatter > 1) text += ' ' + num(q.backscatter) + ' are bounces to senders that do not exist (backscatter).';
        }
        // The overview and list polls mostly answer with the same
        // numbers; a new line would take the focus off the flush button.
        var key = text + '|' + (size > 0 ? _queueFlushable : 0);
        if (key === _queueSummaryKey) return;
        _queueSummaryKey = key;
        if (size === 0) {
            el.replaceChildren(buildEmpty('mailbox', text, ''));
            return;
        }
        var focused = el.contains(document.activeElement) && document.activeElement.id === 'flush-backscatter-btn';
        var line = node('div', 'd-flex flex-wrap align-items-center gap-2');
        line.appendChild(node('span', 'fw-medium', text));
        // Flush is offered only for frozen null-sender messages: undeliverable
        // backscatter that cannot belong to a real sender or a live retry.
        if (_queueFlushable > 0) {
            var flush = node('button', 'btn btn-sm btn-outline-danger');
            flush.type = 'button';
            flush.id = 'flush-backscatter-btn';
            flush.disabled = _queueFlushBusy;
            flush.appendChild(node('i', 'ti ti-trash'));
            flush.appendChild(document.createTextNode('\u00a0Flush ' + num(_queueFlushable) + ' frozen backscatter message(s)'));
            line.appendChild(flush);
        }
        el.replaceChildren(line);
        if (focused && flush) flush.focus();
    }

    function resetQueueTable() {
        if (queueTable) queueTable.destroy();
        queueTable = null;
    }

    // queueRowEl returns the row on screen for a message, or null.
    function queueRowEl(id) {
        var rows = document.querySelectorAll('#email-queue-tbody tr[data-queue-id]');
        for (var i = 0; i < rows.length; i++) {
            if (rows[i].getAttribute('data-queue-id') === id) return rows[i];
        }
        return null;
    }

    // setQueueBusy marks a message's action as running, or done, and sets
    // its buttons on screen to match.
    function setQueueBusy(id, busy) {
        if (busy) _queueBusy[id] = true;
        else delete _queueBusy[id];
        var row = queueRowEl(id);
        if (!row) return;
        row.querySelectorAll('[data-queue-action]').forEach(function(btn) { btn.disabled = busy; });
    }

    function queueItem(id) {
        var list = _queue && Array.isArray(_queue.items) ? _queue.items : [];
        for (var i = 0; i < list.length; i++) {
            if (list[i].id === id) return list[i];
        }
        return null;
    }

    // queueTarget names a message and its undelivered recipients.
    function queueTarget(m) {
        var first = (m.recipients || [])[0];
        if (!first) return 'message ' + m.id;
        var more = (m.recipient_count || 1) - 1;
        return 'message ' + m.id + ' to ' + first + (more > 0 ? ' and ' + num(more) + ' more' : '');
    }

    function queueCell(label, cls) {
        var td = node('td', cls);
        td.setAttribute('data-label', label);
        return td;
    }

    // queueRow builds one message's row. Senders, recipients and the
    // reasons come from mail anyone can send, so all of it is text.
    function queueRow(m) {
        var tr = node('tr');
        tr.setAttribute('data-queue-id', m.id);

        var age = queueCell('Age', 'text-nowrap');
        age.textContent = CSM.formatDuration(m.age_seconds);
        if (m.arrived) age.title = 'Arrived ' + CSM.fmtDate(m.arrived);
        tr.appendChild(age);

        var from = queueCell('From', 'csm-break-word');
        if (m.bounce || !m.sender) from.appendChild(node('span', 'badge bg-secondary-lt', 'bounce'));
        else from.appendChild(node('span', null, m.sender));
        if (m.local_user) {
            var user = node('span', 'text-muted small', ' (' + m.local_user + ')');
            user.title = 'Sent by local user ' + m.local_user;
            from.appendChild(user);
        }
        tr.appendChild(from);

        var to = queueCell('To', 'csm-break-word');
        var first = (m.recipients || [])[0];
        var more = (m.recipient_count || 1) - 1;
        if (first) {
            to.appendChild(node('span', null, first));
            if (more > 0) to.appendChild(node('span', 'text-muted small', ' +' + num(more) + ' more'));
        } else {
            to.appendChild(node('span', 'text-muted', '--'));
        }
        tr.appendChild(to);

        var size = queueCell('Size', 'text-nowrap');
        size.textContent = CSM.formatSize(m.size);
        tr.appendChild(size);

        var why = queueCell('Why stuck', 'text-wrap');
        var reason = m.reason || {};
        why.appendChild(reason.text ? node('span', null, reason.text) : node('span', 'text-muted', '--'));
        var expand = node('button', 'btn btn-ghost-secondary btn-sm expand-btn');
        expand.type = 'button';
        expand.setAttribute('aria-expanded', 'false');
        expand.setAttribute('aria-label', 'Expand details');
        expand.title = 'Recipients, error and delivery log';
        expand.appendChild(node('i', 'ti ti-chevron-down'));
        why.appendChild(expand);
        tr.appendChild(why);

        var state = queueCell('State');
        state.appendChild(m.frozen ? node('span', 'badge bg-azure-lt', 'Frozen') : node('span', 'text-muted', 'Queued'));
        tr.appendChild(state);

        var actions = queueCell('Actions', 'text-end');
        var buttons = node('div', 'btn-list justify-content-end flex-nowrap');
        (m.frozen ? ['thaw'] : []).concat(['retry', 'bounce', 'delete']).forEach(function(name) {
            var a = QUEUE_ACTIONS[name];
            var btn = node('button', 'btn btn-sm ' + (a.danger ? 'btn-ghost-danger' : 'btn-ghost-secondary'), a.label);
            btn.type = 'button';
            btn.title = a.title;
            btn.setAttribute('data-queue-action', name);
            btn.setAttribute('aria-label', a.title + ', message ' + m.id);
            btn.disabled = !!_queueBusy[m.id];
            buttons.appendChild(btn);
        });
        actions.appendChild(buttons);
        tr.appendChild(actions);
        return tr;
    }

    // queueDetailsRow holds a message's details, read when it is expanded.
    function queueDetailsRow() {
        var tr = node('tr', 'details-row');
        var td = node('td');
        td.setAttribute('colspan', '7');
        var host = node('div', 'small');
        host.setAttribute('data-queue-detail', '');
        td.appendChild(host);
        tr.appendChild(td);
        return tr;
    }

    // renderQueueRows rebuilds the rows. The control that had the focus
    // gets it back, and open messages reopen with their details on screen
    // while they are read again.
    function renderQueueRows(items) {
        var tbody = document.getElementById('email-queue-tbody');
        if (!tbody) return;
        var focus = queueFocus(tbody);
        var shown = {};
        Object.keys(_queueOpen).forEach(function(id) {
            var row = queueRowEl(id);
            if (row && row.nextElementSibling) shown[id] = row.nextElementSibling.querySelector('[data-queue-detail]');
        });
        resetQueueTable();
        var count = document.getElementById('email-queue-count');
        var total = _queue.total || 0;
        if (count) count.textContent = num(total) + (total === 1 ? ' message' : ' messages');
        var open = _queueOpen;
        _queueOpen = {};
        if (items.length === 0) {
            emptyRow(tbody, 7, 'filter-off', 'No queued messages match', 'Try another filter or search.');
            return;
        }
        tbody.replaceChildren();
        var reopen = [];
        items.forEach(function(m) {
            var row = queueRow(m), details = queueDetailsRow();
            tbody.appendChild(row);
            tbody.appendChild(details);
            if (open[m.id]) reopen.push([m, row, details]);
        });
        queueTable = new CSM.Table({
            tableId: 'email-queue-table',
            perPage: 0,
            controls: false,
            search: false,
            sortable: false,
            detailRows: true,
            mobileRowCard: true
        });
        reopen.forEach(function(r) {
            var m = r[0], old = shown[m.id];
            _queueOpen[m.id] = true;
            CSM.toggleDetailRow(r[1].querySelector('.expand-btn'));
            if (old) {
                var host = r[2].querySelector('[data-queue-detail]');
                host.parentNode.replaceChild(old, host);
            }
            loadQueueDetail(m, r[2], !!old);
        });
        if (focus) {
            var row = queueRowEl(focus.id);
            var target = row && row.querySelector(focus.sel);
            if (target) target.focus();
        }
    }

    // queueFocus names the row control that has the focus, to give it back
    // after a rebuild.
    function queueFocus(tbody) {
        var el = document.activeElement;
        var row = el && tbody.contains(el) ? el.closest('tr[data-queue-id]') : null;
        if (!row) return null;
        var action = el.getAttribute('data-queue-action');
        var sel = action ? '[data-queue-action="' + action + '"]' : el.classList.contains('expand-btn') ? '.expand-btn' : '';
        return sel ? { id: row.getAttribute('data-queue-id'), sel: sel } : null;
    }

    function renderQueuePager(total) {
        var pager = document.getElementById('email-queue-pager');
        if (!pager) return;
        var pages = Math.max(1, Math.ceil(total / QUEUE_PAGE_SIZE));
        pager.hidden = pages <= 1;
        document.getElementById('email-queue-page').textContent = 'Page ' + _queuePage + ' of ' + pages;
        document.getElementById('email-queue-prev').disabled = _queuePage <= 1;
        document.getElementById('email-queue-next').disabled = _queuePage >= pages;
    }

    // loadQueueDetail reads an open message. quiet keeps what the details
    // show until the answer comes, for a message read again.
    function loadQueueDetail(m, details, quiet) {
        var host = details.querySelector('[data-queue-detail]');
        var seq = host._queueDetailSeq = (host._queueDetailSeq || 0) + 1;
        if (!quiet) host.replaceChildren(node('div', 'text-muted', 'Loading the message...'));
        CSM.get('/api/v1/email/queue/' + encodeURIComponent(m.id), { silent: true, refresh: false })
            .then(function(d) { if (seq === host._queueDetailSeq) renderQueueDetail(host, d); })
            .catch(function(err) {
                if (seq !== host._queueDetailSeq) return;
                host.replaceChildren();
                if (err && err.status === 404) {
                    host.appendChild(node('div', 'text-muted', 'No longer in the queue.'));
                    return;
                }
                CSM.loadError(host, function() { loadQueueDetail(m, details); }, { title: 'Failed to load the message', error: err });
            });
    }

    // renderQueueDetail shows every undelivered recipient, the full error
    // and the last lines exim logged for the message, all as text.
    function renderQueueDetail(host, d) {
        var parts = [];
        var head = node('div', 'mb-2');
        head.appendChild(node('span', 'font-monospace', d.id));
        if (d.arrived) head.appendChild(node('span', 'text-muted', ', arrived ' + CSM.fmtDate(d.arrived)));
        parts.push(head);

        var recipients = Array.isArray(d.recipients) ? d.recipients : [];
        parts.push(node('div', 'subheader mb-1', 'Undelivered recipients (' + num(d.recipient_count) + ')'));
        var list = node('div', 'csm-queue-recipients font-monospace mb-2');
        recipients.forEach(function(r) { list.appendChild(node('div', null, r)); });
        parts.push(list);
        if (recipients.length < d.recipient_count) {
            parts.push(node('div', 'text-muted mb-2', 'Showing the first ' + num(recipients.length) + '.'));
        }
        if (d.delivered > 0) parts.push(node('div', 'mb-2', 'Already delivered: ' + num(d.delivered)));

        var reason = d.reason || {};
        if (reason.raw) {
            parts.push(node('div', 'subheader mb-1', 'Last error'));
            parts.push(node('div', 'font-monospace csm-break-word mb-2', reason.raw));
        }

        var log = Array.isArray(d.msglog) ? d.msglog : [];
        if (log.length > 0) {
            parts.push(node('div', 'subheader mb-1', 'Delivery log, last ' + log.length + (log.length === 1 ? ' line' : ' lines')));
            parts.push(node('pre', 'csm-queue-log mb-0', log.join('\n')));
        } else {
            parts.push(node('div', 'text-muted', 'Exim has logged no delivery attempt for this message.'));
        }
        host.replaceChildren.apply(host, parts);
    }

    function queueAction(m, name) {
        if (_queueBusy[m.id]) return;
        setQueueBusy(m.id, true);
        var a = QUEUE_ACTIONS[name];
        CSM.confirm(a.ask(queueTarget(m), m), { danger: !!a.danger, okLabel: a.title }).then(function() {
            // exim can take most of a minute to act and to list the queue.
            CSM.post('/api/v1/email/queue/' + encodeURIComponent(m.id) + '/' + name, {}, { timeoutMs: 60000 })
                .then(function(res) {
                    var outcome = res && res.outcome;
                    if (Object.prototype.hasOwnProperty.call(QUEUE_OUTCOMES, outcome)) CSM.toast(QUEUE_OUTCOMES[outcome][0], QUEUE_OUTCOMES[outcome][1]);
                    else if (outcome === 'unchanged') CSM.toast('Nothing changed', 'warning');
                    else CSM.toast('Outcome unknown: no outcome returned. Refresh to check.', 'warning');
                })
                .catch(queueActionError)
                .then(function() {
                    setQueueBusy(m.id, false);
                    reloadQueue();
                });
        }).catch(function() { setQueueBusy(m.id, false); });
    }

    // Once an action may have run, an unreadable result is not proof that
    // nothing changed. A transport failure has no HTTP status either.
    function queueActionError(err) {
        if (err && err.status === 409) CSM.toast('No longer in the queue', 'info');
        else if (err && err.status === 503) CSM.toast('Queue actions need systemd-run on this server.', 'error');
        else if (err && err.status && !/could not be read back/.test(CSM.errorText(err))) CSM.toast('Nothing changed: ' + CSM.errorText(err), 'warning');
        else CSM.toast('Outcome unknown: ' + (err && err.name === 'AbortError' ? 'no answer within a minute' : CSM.errorText(err)) + '. Refresh to check.', 'warning');
    }

    var queueBody = document.getElementById('email-queue-tbody');
    if (queueBody) {
        queueBody.addEventListener('click', function(e) {
            var row = e.target.closest('tr');
            var m = row && row.hasAttribute('data-queue-id') ? queueItem(row.getAttribute('data-queue-id')) : null;
            if (!m) return;
            var expand = e.target.closest('.expand-btn');
            if (expand) {
                // The shared handler opens or closes the details after this.
                if (expand.getAttribute('aria-expanded') === 'true') {
                    delete _queueOpen[m.id];
                } else {
                    _queueOpen[m.id] = true;
                    loadQueueDetail(m, row.nextElementSibling);
                }
                return;
            }
            var btn = e.target.closest('[data-queue-action]');
            if (btn) queueAction(m, btn.getAttribute('data-queue-action'));
        });
    }

    var queueSummaryEl = document.getElementById('email-queue-summary');
    if (queueSummaryEl) {
        queueSummaryEl.addEventListener('click', function(e) {
            if (e.target.closest('#flush-backscatter-btn')) flushBackscatter();
        });
    }

    function firstQueuePage() {
        _queuePage = 1;
        loadQueue();
    }

    if (queueFilterEl) queueFilterEl.addEventListener('change', firstQueuePage);
    if (queueSearchEl) queueSearchEl.addEventListener('input', CSM.debounce(firstQueuePage, 300));
    [['email-queue-prev', -1], ['email-queue-next', 1]].forEach(function(p) {
        var btn = document.getElementById(p[0]);
        if (!btn) return;
        btn.addEventListener('click', function() {
            _queuePage = Math.max(1, _queuePage + p[1]);
            loadQueue();
        });
    });

    // ---------- Provider delays tab (outbound deferral intel) ----------

    // The deferrals come from the newest exim_mainlog lines. They are read
    // with the page for the tab count, again whenever the tab opens, and
    // every minute while it is open.
    var _delaysSeq = 0;
    // What the tables on screen show; an answer that shows the same leaves
    // them, the open samples and the focus alone.
    var _delaysSig = '';
    var _delaysTables = {};

    // Provider classes in plain words. The deferring MX host names the
    // provider first, so Google and Microsoft include the business domains
    // they host.
    var DELAY_PROVIDERS = { gmail: 'Google', outlook: 'Microsoft', yahoo: 'Yahoo', external: 'Other domains', local: 'This server' };

    // Reason codes in plain words, with the class that colors them: blocked
    // red, rate limited amber, greylisted grey, the rest neutral. Any other
    // code is a provider's own, such as Yahoo's TSS04, shown as it came.
    var DELAY_REASONS = {
        spamhaus: ['blocklisted (Spamhaus)', 'blocked'],
        blocked: ['blocked', 'blocked'],
        complaint: ['user complaints', 'blocked'],
        rate_limit: ['rate limited', 'rate_limited'],
        greylist: ['greylisted', 'greylisted'],
        mailbox_full: ['mailbox full', 'mailbox_full'],
        retry_wait: ['retry time not reached', 'retry_wait'],
        host_not_found: ['server not found or unreachable', 'host_not_found'],
        refused: ['refused', 'refused']
    };
    var DELAY_COLORS = { blocked: 'bg-red-lt', rate_limited: 'bg-yellow-lt', greylisted: 'bg-secondary-lt' };

    function deliverabilityArray(value) {
        return Array.isArray(value) ? value : [];
    }

    function formatIntegerString(digits) {
        return digits.replace(/^0+(?=\d)/, '').replace(/\B(?=(\d{3})+(?!\d))/g, ',');
    }

    function formatDeferralCount(value) {
        if (value == null || (typeof value === 'string' && value.trim() === '')) return '0';
        if (typeof value === 'string') {
            var trimmed = value.trim();
            if (/^\d+$/.test(trimmed)) return formatIntegerString(trimmed);
            value = Number(trimmed);
        }
        if (typeof value !== 'number' || !isFinite(value) || value <= 0) return '0';
        return CSM.formatNumber(Math.floor(value));
    }

    function providerName(provider) {
        provider = String(provider || '');
        return Object.prototype.hasOwnProperty.call(DELAY_PROVIDERS, provider) ? DELAY_PROVIDERS[provider] : provider;
    }

    // reasonBadge words one reason and how often it came, colored by its
    // class. No code stands for the deferrals no reason was read from.
    function reasonBadge(code, count) {
        var known = Object.prototype.hasOwnProperty.call(DELAY_REASONS, code) ? DELAY_REASONS[code] : null;
        var words = known ? known[0] : code ? 'code ' + code : 'other';
        var color = known && Object.prototype.hasOwnProperty.call(DELAY_COLORS, known[1]) ? DELAY_COLORS[known[1]] : 'badge-outline text-secondary';
        return node('span', 'badge me-1 ' + color, words + (queueCount(count) > 1 ? ' (' + formatDeferralCount(count) + ')' : ''));
    }

    // reasonsCell lists why some deferrals happened, most often first.
    function reasonsCell(reasons, deferrals) {
        var td = queueCell('Reason', 'text-wrap');
        var read = 0;
        deliverabilityArray(reasons).forEach(function(r) {
            r = r || {};
            read += queueCount(r.count);
            td.appendChild(reasonBadge(String(r.code || ''), r.count));
        });
        var rest = queueCount(deferrals) - read;
        if (rest > 0) td.appendChild(reasonBadge('', rest));
        return td;
    }

    function deferredCell(value) {
        var td = queueCell('Deferred', 'text-end text-nowrap');
        td.textContent = formatDeferralCount(value);
        return td;
    }

    // lastSeenCell keeps its distance from the right-aligned count before
    // it, apart from on phones, where the rows are cards.
    function lastSeenCell(at) {
        var td = queueCell('Last seen', 'text-nowrap ps-md-3');
        if (at) td.textContent = CSM.fmtDate(at);
        else td.appendChild(node('span', 'text-muted', '--'));
        return td;
    }

    // providerDelayRows builds a provider's row and, when the log gave a
    // sample error, the details row that shows it. Provider names, reason
    // codes and the sample come from log lines a remote server's reply
    // fills, so all of it is text.
    function providerDelayRows(p) {
        p = p || {};
        var tr = node('tr');
        tr.setAttribute('data-delay-key', 'provider:' + String(p.provider || ''));
        tr.appendChild(rejectCell('Provider', providerName(p.provider)));
        tr.appendChild(deferredCell(p.deferrals));
        tr.appendChild(lastSeenCell(p.last_seen));
        var why = reasonsCell(p.reasons, p.deferrals);
        tr.appendChild(why);
        if (!p.sample) return [tr];
        var expand = node('button', 'btn btn-ghost-secondary btn-sm expand-btn');
        expand.type = 'button';
        expand.setAttribute('aria-expanded', 'false');
        expand.setAttribute('aria-label', 'Expand details');
        expand.title = 'Sample error';
        expand.appendChild(node('i', 'ti ti-chevron-down'));
        why.appendChild(expand);
        var details = node('tr', 'details-row');
        var td = node('td');
        td.setAttribute('colspan', '4');
        td.appendChild(node('div', 'subheader mb-1', 'Sample error'));
        td.appendChild(node('div', 'font-monospace small csm-break-word', String(p.sample)));
        details.appendChild(td);
        return [tr, details];
    }

    // ipDelayRows builds one of this server's sending IPs: how often and
    // when it was last deferred, by which providers and why.
    function ipDelayRows(ip) {
        ip = ip || {};
        var tr = node('tr');
        tr.setAttribute('data-delay-key', 'ip:' + String(ip.ip || ''));
        var addr = queueCell('Sending IP', 'text-nowrap');
        addr.appendChild(node('span', 'font-monospace', String(ip.ip || '')));
        tr.appendChild(addr);
        tr.appendChild(deferredCell(ip.deferrals));
        tr.appendChild(lastSeenCell(ip.last_seen));
        // Each provider and its count wrap as one.
        var by = queueCell('Deferred by');
        deliverabilityArray(ip.providers).forEach(function(item, i) {
            item = item || {};
            if (i > 0) by.appendChild(document.createTextNode(', '));
            by.appendChild(node('span', 'text-nowrap', providerName(item.provider) + ' ' + formatDeferralCount(item.count)));
        });
        if (!by.firstChild) by.appendChild(node('span', 'text-muted', '--'));
        tr.appendChild(by);
        tr.appendChild(reasonsCell(ip.reasons, ip.deferrals));
        return [tr];
    }

    // loadDeliverability reads the deferrals. The tables have their own
    // error state, so no toast repeats it.
    function loadDeliverability() {
        var seq = ++_delaysSeq;
        CSM.get('/api/v1/email/deferrals', { silent: true })
            .then(function(data) {
                if (seq !== _delaysSeq) return;
                renderDeliverability(data || {});
            })
            .catch(function(err) {
                if (seq !== _delaysSeq) return;
                _delaysSig = '';
                setTabCount('delays', '?');
                var summary = document.getElementById('email-deliv-summary');
                if (summary) summary.textContent = 'Deferral activity unavailable.';
                var scope = document.getElementById('email-deliv-scope');
                if (scope) scope.textContent = '';
                ['email-deliv-providers', 'email-deliv-ips'].forEach(function(id) {
                    resetDelaysTable(id);
                    CSM.loadError(document.getElementById(id + '-body'), loadDeliverability, { title: 'Failed to load deferral activity', error: err });
                });
            });
    }

    function resetDelaysTable(id) {
        if (_delaysTables[id]) _delaysTables[id].destroy();
        _delaysTables[id] = null;
    }

    // renderDeliverability counts the providers deferring now on the tab,
    // says how much was deferred over which log lines, and lists the
    // providers and this server's sending IPs.
    function renderDeliverability(data) {
        var providers = deliverabilityArray(data.providers);
        var ips = deliverabilityArray(data.outbound_ips);
        setTabCount('delays', providers.length);
        var summary = document.getElementById('email-deliv-summary');
        if (summary) {
            var n = queueCount(data.deferrals);
            summary.textContent = n === 0 ? 'No outbound deferrals seen in the recent log window.'
                : formatDeferralCount(data.deferrals) + (n === 1 ? ' outbound deferral' : ' outbound deferrals') + ' across ' +
                    plural(providers.length, 'provider') + ' and ' + plural(ips.length, 'sending IP') + '.';
        }
        var scope = document.getElementById('email-deliv-scope');
        if (scope) {
            var lines = queueCount(data.lines);
            scope.textContent = lines === 0 ? 'No mail log lines read.'
                : 'From the last ' + formatDeferralCount(data.lines) + (lines === 1 ? ' log line' : ' log lines') +
                    (data.window_start ? ' (since ' + CSM.fmtDate(data.window_start) + ')' : '');
        }
        var sig = JSON.stringify([providers, ips]);
        if (sig === _delaysSig) return;
        _delaysSig = sig;
        fillDelays('email-deliv-providers', providers, 4, 'No providers are deferring mail from this server.', providerDelayRows);
        fillDelays('email-deliv-ips', ips, 5, 'No sending IP has been deferred.', ipDelayRows);
    }

    // fillDelays draws one table again. A sample open before stays open,
    // and its focused expand button gets the focus back.
    function fillDelays(id, list, cols, empty, rowsOf) {
        var tbody = document.getElementById(id + '-body');
        if (!tbody) return;
        var open = {};
        tbody.querySelectorAll('.expand-btn[aria-expanded="true"]').forEach(function(btn) {
            open[btn.closest('tr').getAttribute('data-delay-key')] = true;
        });
        var active = document.activeElement;
        var focused = active && tbody.contains(active) && active.classList.contains('expand-btn') ? active.closest('tr').getAttribute('data-delay-key') : null;
        resetDelaysTable(id);
        if (list.length === 0) {
            emptyRow(tbody, cols, 'circle-check', empty, '');
            return;
        }
        tbody.replaceChildren();
        list.forEach(function(item) {
            rowsOf(item).forEach(function(tr) { tbody.appendChild(tr); });
        });
        _delaysTables[id] = new CSM.Table({
            tableId: id,
            perPage: 0,
            controls: false,
            search: false,
            sortable: false,
            detailRows: true,
            mobileRowCard: true
        });
        tbody.querySelectorAll('tr[data-delay-key]').forEach(function(tr) {
            var btn = tr.querySelector('.expand-btn');
            if (!btn) return;
            var key = tr.getAttribute('data-delay-key');
            if (open[key]) CSM.toggleDetailRow(btn);
            if (key === focused) btn.focus();
        });
    }

    // ---------- Outbound abuse events (Sending accounts tab) ----------

    // loadOutboundAbuse lists the newest abuse events of the range.
    function loadOutboundAbuse() {
        var body = document.getElementById('email-abuse-events');
        if (!body) return;
        var seq = ++_outboundAbuseSeq;
        CSM.get('/api/v1/email/relay-abuse?' + emailDateQuery('limit=20'))
            .then(function(resp) {
                if (seq !== _outboundAbuseSeq) return;
                outboundAbuseLoaded = true;
                // A poll mostly brings the same events; drawing them again
                // would close their breakdowns.
                var sig = JSON.stringify([resp.items, resp.total, resp.truncated]);
                if (sig === _abuseSig) return;
                _abuseSig = sig;
                renderOutboundAbuse(resp);
                CSM.truncationNote(body, resp && resp.truncated, 'relay abuse findings');
            })
            .catch(function(err) {
                if (seq !== _outboundAbuseSeq) return;
                outboundAbuseLoaded = false;
                _abuseSig = '';
                document.getElementById('email-abuse-count').textContent = '';
                CSM.loadError(body, loadOutboundAbuse, { title: 'Failed to load outbound mail abuse', error: err });
            });
    }

    function renderOutboundAbuse(resp) {
        var body = document.getElementById('email-abuse-events');
        var open = Object.create(null), focused = null;
        body.querySelectorAll('tr[data-abuse-key]').forEach(function(row) {
            var toggle = row.querySelector('.oab-toggle');
            var details = toggle && document.getElementById(toggle.getAttribute('data-target'));
            var key = row.getAttribute('data-abuse-key');
            if (details && !details.classList.contains('d-none')) open[key] = true;
            if (row.contains(document.activeElement)) focused = { key: key, toggle: document.activeElement.classList.contains('oab-toggle') };
        });
        var entries = (resp && resp.items) || [];
        var total = resp && resp.total > 0 ? resp.total : 0;
        document.getElementById('email-abuse-count').textContent = total > 0 ? abuseCount(total) + (total === 1 ? ' event' : ' events') : '';
        if (entries.length === 0) {
            body.replaceChildren(buildEmpty('circle-check', 'No outbound mail abuse ' + rangeWords(currentRange()), ''));
            return;
        }
        var html = '<div class="table-responsive"><table class="table table-vcenter card-table table-sm">';
        html += '<thead><tr><th>Severity</th><th>Type</th><th>Source IP</th><th>Account</th><th>Count</th><th>Detected</th><th></th></tr></thead><tbody>';
        for (var i = 0; i < entries.length; i++) {
            var e = entries[i];
            var rid = 'oab-' + i;
            // Fanout trips on distinct scripts from one IP; the other paths trip
            // on message volume. Label the unit per path so the count is honest.
            var unit = e.path === 'fanout' ? 'scripts' : 'messages';
            html += '<tr data-abuse-key="' + CSM.attr(JSON.stringify([e.path, e.source_ip, e.cp_user, e.detected_at])) + '">';
            html += '<td>' + CSM.severityBadge(e.severity) + '</td>';
            html += '<td>' + CSM.esc(e.path_label) + '</td>';
            html += '<td>' + (e.source_ip ? '<code>' + CSM.esc(e.source_ip) + '</code>' : '<span class="text-muted">-</span>') + '</td>';
            html += '<td>' + CSM.esc(e.cp_user || '') + '</td>';
            html += '<td>' + CSM.esc(String(e.trigger_count) + ' ' + unit) + '</td>';
            html += '<td>' + (CSM.timeAgo ? CSM.timeAgo(e.detected_at) : CSM.esc(e.detected_at)) + '</td>';
            html += '<td class="text-end">';
            if (e.source_ip) {
                html += '<button class="btn btn-sm btn-outline-danger oab-block" data-ip="' + CSM.esc(e.source_ip) + '" data-reason="' + CSM.esc('PHP mail relay abuse: ' + e.path_label + ' (' + e.trigger_count + ' ' + unit + ')') + '">Block 24h</button>';
            }
            if (e.sites && e.sites.length > 0) {
                html += ' <button class="btn btn-sm btn-link oab-toggle" data-target="' + rid + '">Sites (' + e.sites.length + ')</button>';
            }
            html += '</td></tr>';
            if (e.sites && e.sites.length > 0) {
                html += '<tr id="' + rid + '" class="d-none"><td colspan="7"><div class="table-responsive"><table class="table table-sm mb-0"><thead><tr><th>Site</th><th>Script</th><th>Hits</th><th>Last seen</th><th>Sample subject</th></tr></thead><tbody>';
                for (var j = 0; j < e.sites.length; j++) {
                    var st = e.sites[j];
                    html += '<tr><td>' + CSM.esc(st.site) + '</td><td><code>' + CSM.esc(st.script) + '</code></td><td>' + CSM.esc(String(st.hits)) + '</td><td>' + (CSM.timeAgo ? CSM.timeAgo(st.last_seen) : CSM.esc(st.last_seen)) + '</td><td class="text-wrap csm-tw-400">' + CSM.esc(st.sample_subject || '') + '</td></tr>';
                }
                html += '</tbody></table></div></td></tr>';
            }
        }
        html += '</tbody></table></div>';
        body.innerHTML = html;

        body.querySelectorAll('.oab-toggle').forEach(function(btn) {
            btn.addEventListener('click', function() {
                var row = document.getElementById(btn.getAttribute('data-target'));
                if (row) row.classList.toggle('d-none');
            });
        });
        body.querySelectorAll('.oab-block').forEach(function(btn) {
            btn.addEventListener('click', function() {
                if (btn.disabled) return;
                var ip = btn.getAttribute('data-ip');
                if (_abuseBlocks[ip] === 'pending' || _abuseBlocks[ip] === 'blocked') return;
                var reason = btn.getAttribute('data-reason');
                _abuseBlocks[ip] = 'pending';
                renderAbuseBlocks();
                btn.disabled = true;
                CSM.confirm('Block ' + ip + ' in the firewall for 24 hours?\n\n' + reason, { danger: true, okLabel: 'Block' }).then(function() {
                    CSM.post('/api/v1/block-ip', { ip: ip, reason: reason, duration: '24h' })
                        .then(function() { _abuseBlocks[ip] = 'blocked'; renderAbuseBlocks(); })
                        .catch(function() { _abuseBlocks[ip] = 'failed'; renderAbuseBlocks(); });
                }).catch(function(err) {
                    delete _abuseBlocks[ip];
                    renderAbuseBlocks();
                    if (err) CSM.toast(CSM.errorText(err), 'error');
                });
            });
        });
        renderAbuseBlocks();
        body.querySelectorAll('tr[data-abuse-key]').forEach(function(row) {
            var key = row.getAttribute('data-abuse-key');
            var toggle = row.querySelector('.oab-toggle');
            if (toggle && open[key]) document.getElementById(toggle.getAttribute('data-target')).classList.remove('d-none');
            var target = focused && focused.key === key ? row.querySelector(focused.toggle ? '.oab-toggle' : '.oab-block') : null;
            if (target) target.focus();
        });
    }

    function renderAbuseBlocks() {
        document.querySelectorAll('#email-abuse-events .oab-block').forEach(function(btn) {
            var state = _abuseBlocks[btn.getAttribute('data-ip')];
            btn.disabled = state === 'pending' || state === 'blocked';
            btn.textContent = state === 'blocked' ? 'Blocked' : state === 'failed' ? 'Block failed' : 'Block 24h';
        });
    }

    // ---------- Queue composition (Queue tab) ----------

    function loadQueueComposition() {
        if (queueCompositionLoaded) return;
        queueCompositionLoaded = true;
        var seq = ++_queueCompositionSeq;
        CSM.get('/api/v1/email/queue-composition')
            .then(function(data) { if (seq === _queueCompositionSeq) renderQueueComposition(data || {}); })
            .catch(function(err) {
                if (seq !== _queueCompositionSeq) return;
                _queueCompositionSig = '';
                queueCompositionLoaded = false;
                _queueFlushable = 0;
                renderQueueSummary();
                var el = document.getElementById('queue-composition');
                if (el) el.parentElement.hidden = false;
                CSM.loadError(el, loadQueueComposition, { title: 'Failed to load queue composition', error: err });
            });
    }

    function queueCount(value) {
        var n = Number(value);
        if (!isFinite(n) || n < 0) return 0;
        return Math.floor(n);
    }

    function renderQueueComposition(data) {
        // The summary line offers the flush.
        _queueFlushable = queueCount(data.flushable_backscatter);
        renderQueueSummary();
        var el = document.getElementById('queue-composition');
        if (!el) return;
        var sig = JSON.stringify([data.total, data.bounce, data.real, data.frozen, data.top_recipients]);
        if (sig === _queueCompositionSig) return;
        _queueCompositionSig = sig;
        var total = queueCount(data.total);
        // The summary line says once that the queue is empty.
        el.parentElement.hidden = total === 0;
        if (total === 0) {
            el.replaceChildren();
            return;
        }
        var bounce = queueCount(data.bounce);
        var real = queueCount(data.real);
        var frozen = queueCount(data.frozen);
        var bouncePct = Math.round(bounce / total * 100);

        var html = '<div class="row g-3 mb-3">';
        html += metricCol('Real mail', CSM.formatNumber(real), 'text-success');
        html += metricCol('Backscatter', CSM.formatNumber(bounce) + ' (' + bouncePct + '%)', bounce > 0 ? 'text-danger' : 'text-muted');
        html += metricCol('Frozen', CSM.formatNumber(frozen), frozen > 0 ? 'text-warning' : 'text-muted');
        html += '</div>';

        // Count first, then the address, in a table as wide as its text.
        var recips = deliverabilityArray(data.top_recipients);
        if (recips.length > 0) {
            html += '<div class="subheader mb-1">Top stuck recipients</div>';
            html += '<table class="table table-sm w-auto mb-0"><tbody>';
            for (var i = 0; i < recips.length; i++) {
                var rc = recips[i] || {};
                html += '<tr><td class="text-end text-muted small">' + CSM.formatNumber(queueCount(rc.count)) + '</td>';
                html += '<td class="font-monospace small">' + CSM.esc(rc.address) + '</td></tr>';
            }
            html += '</tbody></table>';
        }
        el.innerHTML = html;
    }

    function metricCol(label, value, cls) {
        return '<div class="col-auto"><div class="small text-muted">' + CSM.esc(label) + '</div>' +
            '<div class="h3 mb-0 ' + CSM.attr(cls || '') + '">' + CSM.esc(String(value)) + '</div></div>';
    }

    function setFlushBusy(busy) {
        _queueFlushBusy = busy;
        var btn = document.getElementById('flush-backscatter-btn');
        if (btn) btn.disabled = busy;
    }

    function flushBackscatter() {
        if (_queueFlushBusy) return;
        setFlushBusy(true);
        CSM.confirm('Remove all frozen null-sender bounce messages from the mail queue? This deletes undeliverable backscatter only -- real mail and live retries are not touched.', { danger: true, okLabel: 'Remove' }).then(function() {
            return CSM.post('/api/v1/email/queue/flush-backscatter', {}, { timeoutMs: 60000 })
                .then(function(res) {
                    if (!res || typeof res.removed !== 'number') CSM.toast('Outcome unknown: no outcome returned. Refresh to check.', 'warning');
                    else CSM.toast(queueCount(res.removed) + ' backscatter message(s) no longer queued', 'success');
                })
                .catch(queueActionError)
                .then(reloadQueue);
        }).catch(function() { /* cancelled */ }).then(function() { setFlushBusy(false); });
    }

    // ---------- Tab activation ----------

    var tabsEl = document.getElementById('email-tabs');

    // Old tab names that links and bookmarks may still carry, and the job
    // tab that took each over. auth also turns the Auth failures chip on.
    var TAB_ALIASES = {
        quarantine: 'held', outbound: 'sending', senders: 'sending', 'outbound-abuse': 'sending',
        forwarders: 'sending', deliverability: 'delays', auth: 'findings'
    };

    // tabButton returns the button of a job tab, or null for any other name.
    function tabButton(name) {
        var btn = document.getElementById('email-tab-' + name);
        return btn && tabsEl && tabsEl.contains(btn) ? btn : null;
    }

    // activeTab returns the open tab of a tab bar, without its email-tab-
    // prefix.
    function activeTab(navId) {
        var btn = document.querySelector('#' + navId + ' .nav-link.active');
        return btn ? btn.id.replace('email-tab-', '') : '';
    }

    // tabFromURL returns the job tab a ?tab= value names (the address's
    // own by default), Overview for none or an unknown name, and whether
    // it asks for the Auth failures chip.
    function tabFromURL(value) {
        var raw = value === undefined ? CSM.urlState.get('tab') : value;
        var name = Object.prototype.hasOwnProperty.call(TAB_ALIASES, raw) ? TAB_ALIASES[raw] : raw;
        return { name: tabButton(name) ? name : 'overview', auth: raw === 'auth', forwarders: raw === 'forwarders' };
    }

    // selectTab opens a job tab through Bootstrap's tab plugin, which also
    // moves between tabs on the arrow keys. Its shown event loads the tab
    // and names it in the address.
    function selectTab(name) {
        var btn = tabButton(name);
        if (!btn) return;
        if (window.bootstrap && window.bootstrap.Tab) window.bootstrap.Tab.getOrCreateInstance(btn).show();
        revealTab(btn);
    }

    // revealTab scrolls the strip, never the page, until the tab shows
    // whole. On a phone the strip scrolls sideways, and counts that load
    // after a tab opened widen the tabs before it.
    function revealTab(btn) {
        if (!btn || !tabsEl) return;
        var strip = tabsEl.getBoundingClientRect(), tab = btn.getBoundingClientRect();
        if (tab.left < strip.left) tabsEl.scrollLeft -= strip.left - tab.left;
        else if (tab.right > strip.right) tabsEl.scrollLeft += tab.right - strip.right;
    }

    // openTab opens what an address or a headline card names. An old
    // forwarders link also opens the forwarders section.
    function openTab(t) {
        if (t.auth) applyAuthChip(true);
        if (t.forwarders) {
            var fwd = document.getElementById('email-forwarders-section');
            if (fwd) fwd.open = true;
        }
        selectTab(t.name);
    }

    // tabValue is the ?tab= value naming a job tab: none for Overview, and
    // auth for Findings while the Auth failures chip is on, so a reload
    // keeps the filter.
    function tabValue(name) {
        if (name === 'overview') return '';
        return name === 'findings' && authOn() ? 'auth' : name;
    }

    // syncTabURL names the open tab in the address. Opening a tab adds a
    // history entry, so Back returns to the tab before. An address that
    // already names the tab, maybe by an old name, is rewritten in place.
    function syncTabURL(name) {
        var value = tabValue(name);
        if (CSM.urlState.get('tab') === value) return;
        if (tabFromURL().name === name) CSM.urlState.set({ tab: value });
        else CSM.urlState.push({ tab: value });
    }

    // What each job tab counts, one and many, for screen readers.
    var TAB_COUNT_WORDS = {
        queue: ['queued', 'queued'], held: ['held', 'held'], rejects: ['rejected', 'rejected'],
        sending: ['abuse event', 'abuse events'], delays: ['provider deferring', 'providers deferring'],
        findings: ['finding', 'findings']
    };
    // Counts the server caps: at the cap there may be more.
    var TAB_COUNT_CAPS = { sending: ABUSE_EVENTS_CAP };
    // A count at a threshold: its badge color and what it adds in words.
    var TAB_COUNT_LEVELS = {
        warn: ['badge-warning', ', at or above warning level'],
        crit: ['badge-critical', ', at or above critical level']
    };

    // setTabCount shows a job tab's count: a number, or '?' for unknown.
    // null hides it, so a count that has not loaded shows nothing, never 0.
    // level ('warn' or 'crit') colors the badge. Screen readers get the
    // count in words, since the badge is a bare number and a color.
    function setTabCount(name, n, level) {
        var btn = tabButton(name);
        var badge = btn && btn.querySelector('[data-tab-count]');
        if (!badge) return;
        var lv = Object.prototype.hasOwnProperty.call(TAB_COUNT_LEVELS, level) ? TAB_COUNT_LEVELS[level] : ['bg-secondary-lt', ''];
        var capped = typeof n === 'number' && Object.prototype.hasOwnProperty.call(TAB_COUNT_CAPS, name) && n >= TAB_COUNT_CAPS[name];
        var text = n == null ? '' : typeof n === 'number' ? num(n) + (capped ? '+' : '') : n;
        // A new count can widen its tab and push the open tab out of the
        // strip. Bring it back only if it was in view: the polls must not
        // undo the operator scrolling the strip.
        var active = tabsEl.querySelector('.nav-link.active');
        var reveal = badge.textContent !== text && tabInView(active);
        badge.hidden = n == null;
        badge.textContent = text;
        badge.className = 'badge ms-1 ' + lv[0];
        var words = btn.querySelector('[data-tab-count-text]');
        if (words) {
            if (n == null) words.textContent = '';
            else if (typeof n !== 'number') words.textContent = 'count unknown';
            else words.textContent = num(n) + (capped ? ' or more ' : ' ') + TAB_COUNT_WORDS[name][n === 1 ? 0 : 1] + lv[1];
        }
        if (reveal) revealTab(active);
    }

    // tabInView reports whether a tab shows whole in the strip.
    function tabInView(btn) {
        if (!btn) return false;
        var strip = tabsEl.getBoundingClientRect(), tab = btn.getBoundingClientRect();
        return tab.left >= strip.left && tab.right <= strip.right;
    }

    // loadTab loads what a tab shows the first time it opens; force loads
    // it again. Queue, Held mail, Rejects, Provider delays and the sending
    // accounts read again whenever they open. Overview, Findings and the
    // Held mail, Sending accounts and Provider delays counts load with the
    // page.
    function loadTab(id, force) {
        if (id === 'findings') {
            if (!force && _emailFindingsLoadSeq > 0 && !_findingsPending) loadFindings();
        } else if (id === 'overview') {
            if (!force) {
                loadRspamd();
                loadAVStatus();
                loadActionGroups();
            }
        } else if (id === 'sending') {
            if (force || !statsLoaded) loadEmailStats();
            loadSenders();
            if (force || !outboundAbuseLoaded) loadOutboundAbuse();
            if (force) forwardersLoaded = false;
            loadForwarders();
        } else if (id === 'queue') {
            if (force) queueCompositionLoaded = false;
            loadQueueComposition();
            loadQueue();
        } else if (id === 'held') {
            loadHeldMail();
        } else if (id === 'rejects') {
            loadRejects();
        } else if (id === 'delays') {
            loadDeliverability();
        }
    }

    var tabButtons = document.querySelectorAll('[data-bs-toggle="tab"]');
    for (var t = 0; t < tabButtons.length; t++) {
        tabButtons[t].addEventListener('shown.bs.tab', function(ev) {
            var id = ev.target.id.replace('email-tab-', '');
            if (tabButton(id)) syncTabURL(id);
            loadTab(id, false);
        });
    }

    // Back and Forward reopen the tab the address names. The range and the
    // findings filters stay as the page shows them, and the address is
    // rewritten to say so.
    CSM.urlState.subscribe(function() {
        openTab(tabFromURL());
        CSM.urlState.set(Object.assign(rangeURL(), emailURLState()));
    });

    // bindTabLink makes a link to a tab open it in place, on the rejects
    // reason it names. A click meant for a new browser tab follows the
    // link's address instead.
    function bindTabLink(link) {
        link.addEventListener('click', function(e) {
            if (e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
            e.preventDefault();
            var cls = link.getAttribute('data-rejects-class');
            // A closed Rejects tab reads the new reason as it opens.
            if (cls && rejectsFilter && rejectsFilter.value !== cls) {
                rejectsFilter.value = cls;
                if (activeTab('email-tabs') === 'rejects') loadRejects();
            }
            openTab(tabFromURL(new URLSearchParams(link.getAttribute('href')).get('tab')));
        });
    }

    // A headline card opens the tab that explains its number.
    document.querySelectorAll('#email-kpis a.card').forEach(bindTabLink);

    // ---------- Forwarders filter/search (client-side, no refetch) ----------

    ['email-fwd-filter', 'email-fwd-search'].forEach(function(id) {
        var el = document.getElementById(id);
        if (!el) return;
        var evt = id === 'email-fwd-search' ? 'input' : 'change';
        el.addEventListener(evt, renderForwarders);
    });

    // ---------- Filter handlers (auto-apply on change) ----------

    // emailURLState is what the address carries for the findings filters,
    // with the tab while Findings is open, since the Auth failures chip
    // names it. The range select owns from and to.
    function emailURLState() {
        var state = {
            severity: sevEl ? sevEl.value : '',
            check: checkEl ? checkEl.value : '',
            search: searchEl ? searchEl.value : ''
        };
        if (activeTab('email-tabs') === 'findings') state.tab = tabValue('findings');
        return state;
    }

    function syncEmailURL() {
        CSM.urlState.set(emailURLState());
    }

    [sevEl, checkEl].forEach(function(el) {
        if (!el) return;
        el.addEventListener('change', function() {
            // A picked check replaces the Auth failures chip.
            if (el === checkEl && checkEl.value) setAuthChip(false);
            syncEmailURL();
            loadFindings();
        });
    });

    if (authChip) {
        authChip.addEventListener('click', function() { applyAuthChip(!authOn()); });
    }

    // ---------- Refresh button ----------

    var refreshBtn = document.getElementById('email-refresh');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            loadOverview();
            loadRspamd();
            loadAVStatus();
            loadActionGroups();
            loadFindings();
            statsLoaded = false;
            forwardersLoaded = false;
            outboundAbuseLoaded = false;
            ++_outboundAbuseSeq;
            queueCompositionLoaded = false;
            // Held mail, the sending accounts and the provider delays read
            // again on any tab, for their counts.
            if (activeTab('email-tabs') !== 'held') loadHeldMail();
            if (activeTab('email-tabs') !== 'sending') loadSenders();
            if (activeTab('email-tabs') !== 'delays') loadDeliverability();
            loadTab(activeTab('email-tabs'), true);
        });
    }

    // ---------- Export ----------

    var _emailExportCols = [
        {key:'check', label:'Check'},
        {key:'severity', label:'Severity'},
        {key:'message', label:'Message'},
        {key:'account', label:'Account'},
        {key:'timestamp', label:'Time'}
    ];
    document.querySelectorAll('[data-export]').forEach(function(el) {
        el.addEventListener('click', function(e) {
            e.preventDefault();
            CSM.exportTable(_emailExportData, _emailExportCols, this.getAttribute('data-export'), 'csm-email-findings');
        });
    });

    // ---------- Initialize ----------

    // Opening first lets an auth link turn the chip on before the address
    // names the tab.
    var startTab = tabFromURL();
    openTab(startTab);
    syncTabURL(startTab.name);
    loadOverview();
    loadRspamd();
    loadAVStatus();
    loadActionGroups();
    loadEmailChecks();
    loadFindings();
    // The Held mail, Sending accounts and Provider delays counts show on
    // every tab; an open tab has read its own already.
    if (startTab.name !== 'held') loadHeldMail();
    if (startTab.name !== 'sending') loadSenders();
    if (startTab.name !== 'delays') loadDeliverability();

    // Headline numbers poll every 30 s. Lists poll every 60 s while their
    // tab is open; Overview content also waits while that tab is hidden.
    var _emailIntervals = [];
    function _stopEmailIntervals() {
        for (var i = 0; i < _emailIntervals.length; i++) _emailIntervals[i].stop();
        _emailIntervals = [];
    }

    function _startEmailPolling() {
        _emailIntervals.push(CSM.refresh.interval(function() {
            try {
                loadOverview();
                if (activeTab('email-tabs') === 'sending') loadEmailStats();
            } catch(e) {}
        }, 30000));
        _emailIntervals.push(CSM.refresh.interval(function() {
            try {
                if (activeTab('email-tabs') === 'overview') {
                    loadRspamd();
                    loadAVStatus();
                }
                if (activeTab('email-tabs') === 'queue') {
                    loadQueue();
                    queueCompositionLoaded = false;
                    loadQueueComposition();
                }
                if (activeTab('email-tabs') === 'held') loadHeldMail();
                if (activeTab('email-tabs') === 'delays') loadDeliverability();
            } catch(e) {}
        }, 60000));
        _emailIntervals.push(CSM.refresh.interval(function() {
            try {
                if (activeTab('email-tabs') === 'overview') loadActionGroups();
                if (activeTab('email-tabs') === 'findings') loadFindings();
                if (activeTab('email-tabs') === 'rejects') loadRejects();
                if (activeTab('email-tabs') === 'sending') {
                    loadSenders();
                    loadOutboundAbuse();
                }
            } catch(e) {}
        }, 60000));
    }
    _startEmailPolling();
    window.addEventListener('beforeunload', function() {
        _stopEmailIntervals();
    });
})();
