// CSM Email Security page.
// Layout: range header, headline numbers, mail decisions chart and rspamd,
// recent rejects, needs attention and protection, tabs.
(function() {
    'use strict';

    var EMAIL_FINDINGS_LIMIT = 250; // first viewport row cap from the plan
    var EMAIL_CHECKS = [
        'mail_queue',
        'mail_queue_unavailable',
        'mail_per_account',
        'exim_frozen_realtime',
        'email_phishing_content',
        'email_malware',
        'email_av_degraded',
        'email_av_timeout',
        'email_av_parse_error',
        'email_av_quarantine_error',
        'email_compromised_account',
        'email_credential_leak',
        'email_weak_password',
        'email_spam_outbreak',
        'email_rate_critical',
        'email_rate_warning',
        'email_cloud_relay_abuse',
        'email_php_relay_abuse',
        'email_php_relay_action_failed',
        'email_php_relay_rate_limit_hit',
        'email_auth_failure_realtime',
        'email_suspicious_geo',
        'mail_bruteforce',
        'mail_subnet_spray',
        'mail_account_spray',
        'mail_account_compromised',
        'smtp_bruteforce',
        'smtp_subnet_spray',
        'smtp_account_spray',
        'smtp_probe_abuse',
        'email_dkim_failure',
        'email_spf_rejection',
        'email_pipe_forwarder',
        'email_suspicious_forwarder'
    ].join(',');
    var _emailExportData = [];
    var emailTable = null;
    var _emailFindingsLoadSeq = 0;
    var quarantineLoaded = false;
    var authGroupsLoaded = false;
    var forwardersLoaded = false;
    var _forwarders = [];
    var deliverabilityLoaded = false;
    var outboundAbuseLoaded = false;
    var queueCompositionLoaded = false;

    // ---------- Filter state from URL ----------
    var today = CSM.prefs.today();
    var fromEl = document.getElementById('filter-from');
    var toEl = document.getElementById('filter-to');
    var sevEl = document.getElementById('filter-severity');
    var checkEl = document.getElementById('filter-check');
    var searchEl = document.getElementById('email-search');
    if (fromEl) fromEl.value = CSM.urlState.get('from') || today;
    if (toEl) toEl.value = CSM.urlState.get('to') || today;
    if (sevEl && CSM.urlState.get('severity')) sevEl.value = CSM.urlState.get('severity');
    if (checkEl && CSM.urlState.get('check')) checkEl.value = CSM.urlState.get('check');
    if (searchEl && CSM.urlState.get('search')) searchEl.value = CSM.urlState.get('search');
    var initialTab = CSM.urlState.get('tab');

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
        var linked = CSM.prefs.dayRange(linkFrom || today, linkTo || today);
        if (linked.from && linked.to) {
            customRange = { from: Date.parse(linked.from), to: Date.parse(linked.to),
                label: (linkFrom || today) === (linkTo || today) ? (linkFrom || today) : (linkFrom || today) + ' to ' + (linkTo || today) };
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
        var wall = CSM.prefs.formatDateTime(new Date(ms));
        return Math.floor(ms / 1000) * 1000 - (+wall.slice(14, 16) * 60 + +wall.slice(17, 19)) * 1000;
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
        return { key: '24h', from: new Date(hourStart(now) - 23 * 3600000), to: new Date(now) };
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
        other: 'Other'
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
    var _overviewRange = null;
    var _overviewSeq = 0;
    var _rspamd = null;

    function loadOverview() {
        var range = currentRange();
        var seq = ++_overviewSeq;
        CSM.get('/api/v1/email/overview?' + rangeQuery(range))
            .then(function(ov) {
                if (seq !== _overviewSeq) return;
                _overview = ov;
                _overviewRange = range;
                CSM.clearLoadError(document.getElementById('email-kpis'));
                renderKPIs(ov);
                renderChart(ov, range);
                renderSubtitle();
                renderProtection();
            })
            .catch(function(err) {
                if (seq !== _overviewSeq) return;
                CSM.loadError(document.getElementById('email-kpis'), loadOverview, { title: 'Failed to load mail numbers', error: err });
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

    // otherRejects sums the permanent rejects outside spam and malware, the
    // same count the chart's Other rejects series shows: a temporary reject
    // defers the message, which comes back and is decided later.
    function otherRejects(t) {
        var rejects = t.rejects || {}, temporary = t.temporary || {};
        var out = { total: 0, top: '', topCount: 0 };
        Object.keys(rejects).forEach(function(cls) {
            if (cls === 'spam' || cls === 'malware') return;
            var n = (rejects[cls] || 0) - (temporary[cls] || 0);
            if (n <= 0) return;
            out.total += n;
            if (n > out.topCount) { out.top = cls; out.topCount = n; }
        });
        return out;
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

        var rejects = t.rejects || {}, temporary = t.temporary || {};
        var smtpMalware = (rejects.malware || 0) - (temporary.malware || 0);
        setKPI('kpi-malware', smtpMalware + (t.quarantined || 0),
            num(smtpMalware) + ' rejected at SMTP, ' + num(t.quarantined) + ' quarantined');

        var other = otherRejects(t);
        setKPI('kpi-other', other.total, other.top ? rejectClassLabel(other.top) + ' ' + num(other.topCount) : 'none');

        var blocks = ov.blocks || {};
        var blocked = blocks.in_range || 0;
        setKPI('kpi-logins', (t.logins_smtp || 0) + (t.logins_mailbox || 0),
            blocks.unavailable ? 'block count unavailable' : num(blocked) + (blocked === 1 ? ' IP blocked' : ' IPs blocked'));

        renderQueueKPI(ov.queue || {});
    }

    // The queue is colored from the thresholds the mail_queue check alerts
    // on, so the card and the alert agree.
    function renderQueueKPI(q) {
        if (q.unavailable) {
            setKPI('kpi-queue', '--', 'queue size unknown', 'text-warning');
            return;
        }
        var size = q.size || 0;
        var cls = '';
        if (q.crit > 0 && size >= q.crit) cls = 'text-danger';
        else if (q.warn > 0 && size >= q.warn) cls = 'text-warning';
        var sub;
        if (size === 0) sub = 'empty';
        else if (q.detail_unavailable) sub = 'oldest unknown';
        else {
            sub = q.oldest_age_seconds != null ? 'oldest ' + CSM.formatDuration(q.oldest_age_seconds) : 'no dated message';
            if (q.frozen > 0) sub += ', ' + num(q.frozen) + ' frozen';
        }
        setKPI('kpi-queue', size, sub, cls);
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
    // hours, operator-zone days otherwise. Hour bars are fixed 3600 s steps
    // from the first hour start, each labeled with the operator-zone time
    // at its start.
    function chartPeriods(range) {
        var from = range.from.getTime(), to = range.to.getTime();
        var periods = [];
        if (range.key === '24h') {
            for (var t = from; t < to; t += 3600000) {
                periods.push({ start: t, end: t + 3600000, label: CSM.prefs.formatDateTime(new Date(t)).slice(11, 16) });
            }
            return periods;
        }
        var day = CSM.prefs.formatDateTime(range.from).slice(0, 10);
        for (var start = from; start < to;) {
            var next = CSM.prefs.dayBoundary(day, true);
            if (next === null || next <= start) break;
            periods.push({ start: start, end: next, label: day.slice(5) });
            day = daysBefore(day, -1);
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
        return Math.round(ms / 60000);
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

    // sinceStart words rspamd's uptime so its numbers are not read as the
    // page range.
    function sinceStart(seconds) {
        if (!(seconds > 0)) return 'since rspamd started';
        var n, unit;
        if (seconds >= 86400) { n = Math.floor(seconds / 86400); unit = 'day'; }
        else if (seconds >= 3600) { n = Math.floor(seconds / 3600); unit = 'hour'; }
        else { n = Math.max(1, Math.floor(seconds / 60)); unit = 'minute'; }
        return 'since rspamd started ' + n + ' ' + unit + (n === 1 ? '' : 's') + ' ago';
    }

    function loadRspamd() {
        CSM.get('/api/v1/email/rspamd')
            .then(function(r) {
                _rspamd = r;
                renderRspamd(r);
                renderSubtitle();
                renderProtection();
            })
            .catch(function(err) {
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
        card.appendChild(node('div', 'text-muted small mb-2', 'Counts ' + sinceStart(s.uptime_seconds) + '.'));
        var nums = node('div', 'row g-2 mb-2');
        [['Scanned', s.scanned], ['Learned ham', s.ham_count], ['Learned spam', s.spam_count]].forEach(function(m) {
            var col = node('div', 'col-auto me-3');
            col.appendChild(node('div', 'small text-muted', m[0]));
            col.appendChild(node('div', 'h3 mb-0', num(m[1])));
            nums.appendChild(col);
        });
        card.appendChild(nums);

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

    if (rangeEl) {
        rangeEl.addEventListener('change', function() {
            if (rangeEl.value === 'custom') {
                CSM.urlState.set({ from: linkFrom, to: linkTo });
            } else {
                try { window.localStorage.setItem(RANGE_KEY, rangeEl.value); } catch (e) { /* storage unavailable */ }
                CSM.urlState.set({ from: '', to: '' });
            }
            loadOverview();
            loadRejects();
            loadActionGroups();
            authGroupsLoaded = false;
            outboundAbuseLoaded = false;
            var tab = activeEmailTab();
            if (tab === 'auth' || tab === 'outbound-abuse') loadActiveEmailTab(true);
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

    var queueCard = document.querySelector('#kpi-queue a');
    if (queueCard) queueCard.addEventListener('click', function() { activateTab('queue'); });

    // ---------- Recent rejects ----------

    var REJECT_BADGES = { spam: 'bg-orange-lt', malware: 'bg-red-lt' };
    var rejectsFilter = document.getElementById('email-rejects-filter');
    var rejectsTable = null;
    var _rejectsSeq = 0;

    if (rejectsFilter) {
        Object.keys(REJECT_CLASS_LABELS).forEach(function(cls) {
            var opt = node('option', null, REJECT_CLASS_LABELS[cls]);
            opt.value = cls;
            rejectsFilter.appendChild(opt);
        });
        rejectsFilter.addEventListener('change', loadRejects);
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
        var seq = ++_rejectsSeq;
        CSM.get('/api/v1/email/rejects?' + rangeQuery(range, 'class=' + encodeURIComponent(cls) + '&limit=50'))
            .then(function(data) {
                if (seq !== _rejectsSeq) return;
                var what = cls === 'content' ? 'spam or malware rejects' : cls === 'all' ? 'rejects' : 'rejects for ' + rejectClassLabel(cls);
                renderRejects(data.items, 'No ' + what + ' ' + rangeWords(range), data.kept_days);
            })
            .catch(function(err) {
                if (seq !== _rejectsSeq) return;
                resetRejectsTable();
                CSM.loadError(tbody, loadRejects, { title: 'Failed to load rejects', error: err });
            });
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

    function renderRejects(items, emptyTitle, keptDays) {
        var tbody = document.getElementById('email-rejects-tbody');
        if (!tbody) return;
        resetRejectsTable();
        tbody.replaceChildren();
        items = Array.isArray(items) ? items : [];
        if (items.length === 0) {
            var td = node('td');
            td.setAttribute('colspan', '6');
            td.appendChild(buildEmpty('mail-check', emptyTitle, keptDays > 0 ? 'Rejects are kept for ' + keptDays + ' days.' : ''));
            var tr = node('tr');
            tr.appendChild(td);
            tbody.appendChild(tr);
            return;
        }
        items.forEach(function(r) {
            var row = node('tr');
            row.appendChild(rejectCell('Time', CSM.fmtDate(r.at), 'text-nowrap'));
            var reason = rejectCell('Reason');
            reason.replaceChildren(node('span', 'badge ' + (Object.prototype.hasOwnProperty.call(REJECT_BADGES, r.class) ? REJECT_BADGES[r.class] : 'bg-secondary-lt'),
                rejectClassLabel(r.class) + (r.temporary && r.class !== 'rate_limited' ? ' (temporary)' : '')));
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
    }

    // ---------- Protection ----------

    var _av = null;
    var MODE_STATES = { 'enforce': 'ok', 'dry-run': 'warn', 'off': 'off' };
    var PROTECTION_DOTS = { ok: 'status-green', warn: 'status-yellow', bad: 'status-red', off: 'status-secondary' };

    function setProtection(id, state, text) {
        var line = document.getElementById(id);
        if (!line) return;
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

    // ---------- Mail stats: queue, SMTP firewall, senders ----------

    var _stats = null;

    function loadEmailStats() {
        CSM.get('/api/v1/email/stats')
            .then(function(data) {
                _stats = data;
                renderQueueHealth(data);
                renderSMTPFirewall(data);
                var sendersPane = document.getElementById('email-pane-senders');
                if (sendersPane && sendersPane.classList.contains('active')) {
                    renderTopSenders(data.top_senders || []);
                } else {
                    // Hold the data for first activation
                    _pendingSenders = data.top_senders || [];
                }
            })
            .catch(function(err) {
                CSM.loadError(document.getElementById('queue-health'), loadEmailStats, { title: 'Failed to load the mail queue', error: err });
                CSM.loadError(document.getElementById('smtp-firewall'), loadEmailStats, { title: 'Failed to load the SMTP firewall', error: err });
            });
    }

    var _pendingSenders = null;

    function emailDateQuery(base) {
        return rangeQuery(currentRange(), base);
    }

    function renderQueueHealth(data) {
        var el = document.getElementById('queue-health');
        if (!el) return;
        var pct = data.queue_unavailable ? 0 : Math.min(100, Math.round(data.queue_size / Math.max(1, data.queue_crit) * 100));
        var color = 'bg-green';
        if (data.queue_unavailable) color = 'bg-warning';
        else if (data.queue_size >= data.queue_crit) color = 'bg-danger';
        else if (data.queue_size >= data.queue_warn) color = 'bg-warning';
        el.replaceChildren();

        function row(label, value, cls) {
            var r = document.createElement('div');
            r.className = 'd-flex justify-content-between mb-1';
            var l = document.createElement('span');
            l.className = 'text-muted small';
            l.textContent = label;
            var v = document.createElement('span');
            v.className = 'small ' + (cls || '');
            v.textContent = value;
            r.appendChild(l);
            r.appendChild(v);
            return r;
        }

        var head = document.createElement('div');
        head.className = 'd-flex justify-content-between mb-1';
        var hl = document.createElement('span');
        hl.className = 'text-muted small';
        hl.textContent = 'Queue size';
        var hv = document.createElement('span');
        hv.className = 'fw-bold';
        if (data.queue_unavailable) {
            hv.className += ' text-warning';
            hv.textContent = 'unavailable';
        } else {
            hv.textContent = data.queue_size + ' / ' + data.queue_crit;
        }
        head.appendChild(hl); head.appendChild(hv);
        el.appendChild(head);

        var pwrap = document.createElement('div');
        pwrap.className = 'progress progress-sm mb-2';
        var pbar = document.createElement('div');
        pbar.className = 'progress-bar ' + color;
        CSM.setProgressBar(pbar, pct);
        pwrap.appendChild(pbar);
        el.appendChild(pwrap);

        el.appendChild(row('Frozen', data.frozen_count || 0, (data.frozen_count || 0) > 0 ? 'text-warning fw-bold' : ''));
        var oldest = CSM.formatDuration(data.oldest_age_seconds);
        el.appendChild(row('Oldest', oldest || 'none', data.oldest_age_seconds >= 86400 ? 'text-danger fw-bold' : ''));
        el.appendChild(row('Warn threshold', data.queue_warn, ''));
        el.appendChild(row('Crit threshold', data.queue_crit, ''));
    }

    function renderSMTPFirewall(data) {
        var el = document.getElementById('smtp-firewall');
        if (!el) return;
        el.replaceChildren();
        var head = document.createElement('div');
        head.className = 'd-flex align-items-center mb-1';
        var lbl = document.createElement('span');
        lbl.className = 'text-muted small';
        lbl.textContent = 'Outbound SMTP';
        var st = document.createElement('span');
        st.className = 'ms-auto fw-bold ' + (data.smtp_block ? 'text-danger' : 'text-green');
        st.textContent = data.smtp_block ? 'Restricted' : 'Open';
        head.appendChild(lbl); head.appendChild(st);
        el.appendChild(head);

        if (data.smtp_block && data.smtp_allow_users && data.smtp_allow_users.length > 0) {
            var allowed = document.createElement('div');
            allowed.className = 'text-muted small mb-1';
            allowed.textContent = 'Allowed: ' + data.smtp_allow_users.join(', ');
            el.appendChild(allowed);
        }
        if (data.port_flood && data.port_flood.length > 0) {
            for (var i = 0; i < data.port_flood.length; i++) {
                var pf = data.port_flood[i];
                var pfRow = document.createElement('div');
                pfRow.className = 'small text-muted';
                pfRow.textContent = 'Port ' + pf.port + ': ' + pf.hits + ' / ' + pf.window_seconds + 's';
                el.appendChild(pfRow);
            }
        }
    }

    // ---------- Top senders (Senders tab) ----------

    function renderTopSenders(senders) {
        var el = document.getElementById('top-senders');
        if (!el) return;
        // Suppress count=1 noise unless every sender has only 1 hit (plan rule).
        var meaningful = senders.filter(function(s) { return s.count > 1; });
        if (meaningful.length > 0) senders = meaningful;
        if (!senders || senders.length === 0) {
            el.replaceChildren();
            var empty = document.createElement('div');
            empty.className = 'text-muted text-center py-3';
            empty.textContent = 'No notable outbound activity';
            el.appendChild(empty);
            return;
        }
        var maxCount = senders[0].count || 1;
        var html = '<div class="list-group list-group-flush">';
        for (var i = 0; i < senders.length; i++) {
            var s = senders[i];
            var pct = Math.round(s.count / maxCount * 100);
            var countClass = s.count >= 100 ? 'text-danger fw-bold' : 'text-muted';
            html += '<div class="list-group-item feed-item" data-sender-domain="' + CSM.attr(s.domain) + '">';
            html += '<div class="d-flex align-items-center mb-1">';
            html += '<span class="font-monospace small">' + CSM.esc(s.domain) + '</span>';
            html += '<span class="ms-auto small ' + countClass + '">' + s.count + '</span></div>';
            html += '<div class="progress progress-sm"><div class="progress-bar bg-primary csm-progress-zero" role="progressbar" aria-valuemin="0" aria-valuemax="100" data-csm-progress="' + CSM.attr(pct) + '"></div></div>';
            html += '</div>';
        }
        html += '</div>';
        el.innerHTML = html;
        CSM.applyProgressBars(el);
        var items = el.querySelectorAll('[data-sender-domain]');
        for (var j = 0; j < items.length; j++) {
            CSM.makeClickable(items[j]);
            items[j].addEventListener('click', function() {
                var domain = this.getAttribute('data-sender-domain');
                var sb = document.getElementById('email-search');
                if (sb) {
                    sb.value = domain;
                    sb.dispatchEvent(new Event('input'));
                    activateTab('findings');
                }
            });
        }
    }

    // ---------- AV status (Protection card) ----------

    function loadAVStatus() {
        CSM.get('/api/v1/email/av/status', { silent: true })
            .then(function(data) {
                _av = data;
                renderProtection();
            })
            .catch(function() { /* non-fatal */ });
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
            toggle.textContent = (_showHandled ? 'Hide handled (' : 'Show handled (') + handled + ')';
            toggle.setAttribute('aria-pressed', String(_showHandled));
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

    // ---------- Auth failures tab (kind=auth_failure) ----------

    function loadAuthGroups() {
        if (authGroupsLoaded) return;
        authGroupsLoaded = true;
        CSM.get('/api/v1/email/groups?' + emailDateQuery('kind=auth_failure&limit=200'))
            .then(function(data) {
                var el = document.getElementById('email-auth-groups');
                if (!el) return;
                el.replaceChildren();
                var groups = data.items;
                if (groups.length === 0) {
                    el.appendChild(buildEmpty('lock-check', 'No auth-failure clusters', 'No mailbox or IP exceeded the auth-failure threshold in this window.'));
                    return;
                }
                for (var i = 0; i < groups.length; i++) {
                    var g = groups[i];
                    var item = CSM.summaryItem({
                        severity: g.severity,
                        title: g.title,
                        meta: g.summary,
                        count: g.count,
                        age: ageLabel(g.last_seen),
                        onClick: (function(group) { return function() { openGroupDetail(group); }; })(g),
                    });
                    el.appendChild(item);
                }
                CSM.truncationNote(el, data.truncated, 'auth-failure findings');
            })
            .catch(function(err) {
                authGroupsLoaded = false;
                CSM.loadError(document.getElementById('email-auth-groups'), loadAuthGroups, { title: 'Failed to load auth failure clusters', error: err });
            });
    }

    // ---------- Findings tab (table) ----------

    function loadFindings() {
        var range = CSM.prefs.dayRange(
            (document.getElementById('filter-from') || {}).value || '',
            (document.getElementById('filter-to') || {}).value || '');
        var sev = (document.getElementById('filter-severity') || {}).value || '';
        var check = (document.getElementById('filter-check') || {}).value || '';
        var params = 'checks=' + encodeURIComponent(check || EMAIL_CHECKS) + '&limit=' + EMAIL_FINDINGS_LIMIT;
        if (range.from) params += '&from=' + encodeURIComponent(range.from);
        if (range.to)   params += '&to=' + encodeURIComponent(range.to);
        if (sev)  params += '&severity=' + encodeURIComponent(sev);
        var seq = ++_emailFindingsLoadSeq;
        CSM.get('/api/v1/history?' + params)
            .then(function(data) {
                if (seq !== _emailFindingsLoadSeq) return;
                var findings = data.items;
                renderFindingsTable(findings);
                var label = document.getElementById('email-total-label');
                if (label) {
                    label.textContent = findings.length + ' / ' + data.total;
                }
            })
            .catch(function(err) {
                if (seq !== _emailFindingsLoadSeq) return;
                resetEmailFindingsTable();
                clearEmailFindingsState();
                CSM.loadError(document.getElementById('email-tbody'), loadFindings, { title: 'Failed to load email findings', error: err });
            });
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
    }

    function renderFindingsTable(findings) {
        var tbody = document.getElementById('email-tbody');
        if (!tbody) {
            resetEmailFindingsTable();
            clearEmailFindingsState();
            return;
        }

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
            tbody.innerHTML = CSM.emptyState('No email findings in this period', 6);
            return;
        }

        var html = '';
        for (var i = 0; i < findings.length; i++) {
            var f = findings[i];
            var cls = CSM.severityClass(f.severity);
            var account = f.account || '';
            var ip = f.ip || '';
            var checkLabel = f.check.replace(/_/g, ' ').replace(/realtime$/, '').replace(/^email /, '');
            html += '<tr data-sev="' + cls + '">';
            html += '<td>' + CSM.severityBadge(f.severity) + '</td>';
            html += '<td><span class="small">' + CSM.esc(checkLabel) + '</span></td>';
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
        if (CSM.initTimeAgo) CSM.initTimeAgo();
    }

    // ---------- Quarantine tab ----------

    var _emailQuarBulk = null;
    var _emailQuarTable = null;
    var _emailQuarURLUnbind = null;
    var _emailQuarDateListenersBound = false;

    function _emailQuarURLInputs(fromEl, toEl) {
        return {
            email_quar_q: document.getElementById('email-quar-search'),
            email_quar_dir: document.getElementById('email-quar-dir'),
            email_quar_from: fromEl,
            email_quar_to: toEl
        };
    }

    function _bindEmailQuarURLState(fromEl, toEl) {
        if (_emailQuarURLUnbind) _emailQuarURLUnbind();
        _emailQuarURLUnbind = CSM.urlState.bind({ inputs: _emailQuarURLInputs(fromEl, toEl) });
    }

    function _resetEmailQuarTable() {
        if (_emailQuarTable) {
            if (typeof _emailQuarTable.destroy === 'function') _emailQuarTable.destroy();
            _emailQuarTable = null;
        }
        var controls = document.getElementById('email-quar-table-controls');
        if (controls) controls.remove();
    }

    function _emailQuarUpdateBulk() {
        var releaseBtn = document.getElementById('email-quar-bulk-release');
        var deleteBtn = document.getElementById('email-quar-bulk-delete');
        var selectAll = document.getElementById('email-quar-select-all');
        if (!_emailQuarBulk && !selectAll && !document.querySelector('.email-quar-cb')) {
            [releaseBtn, deleteBtn].forEach(function(btn) {
                if (!btn) return;
                btn.disabled = true;
                btn.classList.add('d-none');
            });
            return;
        }
        if (_emailQuarBulk) { _emailQuarBulk.refresh(); return; }
        if (!releaseBtn && !deleteBtn) return;
        _emailQuarBulk = CSM.bulk({
            rowCheckboxSelector: '.email-quar-cb',
            selectAllEl: selectAll,
            selectAllSelector: '#email-quar-select-all',
            valueAttr: 'data-id',
            buttons: [
                { el: releaseBtn, labelTemplate: 'Release {n} message(s)' },
                { el: deleteBtn,  labelTemplate: 'Delete {n} message(s)' }
            ]
        });
    }

    function _bindEmailQuarDateFilters(fromEl, toEl) {
        if (_emailQuarDateListenersBound) return;
        function onDate() {
            if (_emailQuarTable) {
                _emailQuarTable.currentPage = 1;
                _emailQuarTable.applyFilters();
            }
        }
        if (fromEl) fromEl.addEventListener('change', onDate);
        if (toEl) toEl.addEventListener('change', onDate);
        _emailQuarDateListenersBound = true;
    }

    function loadQuarantine() {
        quarantineLoaded = true;
        CSM.get('/api/v1/email/quarantine')
            .then(function(resp) {
                var data = resp.items;
                var container = document.getElementById('quarantine-table');
                if (!container) return;
                var fromEl = document.getElementById('email-quar-from');
                var toEl = document.getElementById('email-quar-to');
                _resetEmailQuarTable();
                if (!data || data.length === 0) {
                    _bindEmailQuarURLState(fromEl, toEl);
                    container.innerHTML = '<p class="text-muted">No quarantined messages.</p>';
                    _emailQuarUpdateBulk();
                    return;
                }
                var html = '<div class="table-responsive"><table class="table table-vcenter card-table table-sm csm-table-rowcard" id="email-quar-table">';
                html += '<thead><tr><th><input type="checkbox" class="form-check-input" id="email-quar-select-all" aria-label="Select all visible quarantined messages"></th><th>Time</th><th>Dir</th><th>From</th><th>To</th><th>Subject</th><th>Threat</th><th>Actions</th></tr></thead><tbody>';
                for (var i = 0; i < data.length; i++) {
                    var msg = data[i];
                    var time = CSM.timeAgo ? CSM.timeAgo(msg.quarantined_at) : CSM.esc(msg.quarantined_at);
                    var dir = msg.direction === 'inbound'
                        ? '<span class="badge bg-blue">IN</span>'
                        : '<span class="badge bg-orange">OUT</span>';
                    var findings = msg.findings || [];
                    var threats = [];
                    for (var j = 0; j < findings.length; j++) {
                        threats.push(findings[j].signature + ' (' + findings[j].engine + ')');
                    }
                    var to = (msg.to || []).join(', ');
                    var msgID = CSM.attr(msg.message_id);
                    // Stash search-relevant fields on the row so the
                    // shared search input matches against just these
                    // (instead of the whole DOM text including badges).
                    var searchBlob = String(msg.from || '') + ' ' + String(to || '') + ' ' + String(msg.subject || '');
                    html += '<tr data-direction="' + CSM.attr(msg.direction || '') + '" data-quar-timestamp="' + CSM.attr(msg.quarantined_at || '') + '" data-search="' + CSM.attr(searchBlob.toLowerCase()) + '">';
                    html += '<td><input type="checkbox" class="form-check-input email-quar-cb" data-id="' + msgID + '" aria-label="Select message from ' + CSM.attr(msg.from || 'unknown sender') + ': ' + CSM.attr(msg.subject || 'no subject') + '"></td>';
                    html += '<td data-label="Time" data-timestamp="' + CSM.attr(msg.quarantined_at || '') + '">' + CSM.esc(time) + '</td>';
                    html += '<td data-label="Dir">' + dir + '</td>';
                    html += '<td data-label="From">' + CSM.esc(msg.from) + '</td>';
                    html += '<td data-label="To">' + CSM.esc(to) + '</td>';
                    html += '<td data-label="Subject">' + CSM.esc(msg.subject) + '</td>';
                    html += '<td data-label="Threat"><code>' + CSM.esc(threats.join(', ')) + '</code></td>';
                    html += '<td data-label="Actions">';
                    html += '<button class="btn btn-sm btn-warning" data-email-release="' + msgID + '">Release</button> ';
                    html += '<button class="btn btn-sm btn-danger" data-email-delete="' + msgID + '">Delete</button>';
                    html += '</td>';
                    html += '</tr>';
                }
                html += '</tbody></table></div>';
                container.innerHTML = html;
                function _inRange(row) {
                    var raw = row.getAttribute('data-quar-timestamp') || '';
                    if (!raw) return true;
                    var ts = CSM.parseTimestamp(raw);
                    if (isNaN(ts)) return true;
                    var from = fromEl ? CSM.prefs.dayBoundary(fromEl.value, false) : null;
                    var to = toEl ? CSM.prefs.dayBoundary(toEl.value, true) : null;
                    if (from !== null && ts < from) return false;
                    if (to !== null && ts >= to) return false;
                    return true;
                }
                _emailQuarTable = new CSM.Table({
                    tableId: 'email-quar-table',
                    perPage: 25,
                    searchId: 'email-quar-search',
                    searchAttr: 'data-search',
                    sortable: true,
                    stateKey: 'csm-email-quarantine',
                    mobileRowCard: true,
                    filters: [{ id: 'email-quar-dir', attr: 'data-direction' }],
                    rowFilter: _inRange,
                    onRender: function() {
                        if (_emailQuarBulk) _emailQuarBulk.refresh();
                    }
                });
                _bindEmailQuarDateFilters(fromEl, toEl);
                _bindEmailQuarURLState(fromEl, toEl);
                _emailQuarUpdateBulk();
            })
            .catch(function(err) {
                quarantineLoaded = false;
                CSM.loadError(document.getElementById('quarantine-table'), loadQuarantine, { title: 'Failed to load the mail quarantine', error: err });
            });
    }

    // Bulk release / delete wired through CSM.bulk's selectedValues.
    var _bulkReleaseBtn = document.getElementById('email-quar-bulk-release');
    if (_bulkReleaseBtn) {
        _bulkReleaseBtn.addEventListener('click', function() {
            if (!_emailQuarBulk) return;
            var ids = _emailQuarBulk.selectedValues();
            if (ids.length === 0) return;
            CSM.confirm('Release ' + ids.length + ' message(s) back to the mail queue?').then(function() {
                var succeeded = 0, failed = 0;
                var chain = Promise.resolve();
                ids.forEach(function(id) {
                    chain = chain.then(function() {
                        return CSM.post('/api/v1/email/quarantine/' + encodeURIComponent(id) + '/release', {})
                            .then(function() { succeeded++; })
                            .catch(function() { failed++; });
                    });
                });
                chain.then(function() {
                    CSM.toast('Released ' + succeeded + ' of ' + (succeeded + failed), failed > 0 ? 'warning' : 'success');
                    loadQuarantine();
                    loadAVStatus();
                });
            }).catch(function(err) { if (err) CSM.toast(err.message || 'Request failed', 'error'); });
        });
    }
    var _bulkDeleteBtn = document.getElementById('email-quar-bulk-delete');
    if (_bulkDeleteBtn) {
        _bulkDeleteBtn.addEventListener('click', function() {
            if (!_emailQuarBulk) return;
            var ids = _emailQuarBulk.selectedValues();
            if (ids.length === 0) return;
            CSM.confirm('Permanently delete ' + ids.length + ' quarantined message(s)?', { danger: true, okLabel: 'Delete' }).then(function() {
                var succeeded = 0, failed = 0;
                var chain = Promise.resolve();
                ids.forEach(function(id) {
                    chain = chain.then(function() {
                        return CSM.delete('/api/v1/email/quarantine/' + encodeURIComponent(id))
                            .then(function() { succeeded++; })
                            .catch(function() { failed++; });
                    });
                });
                chain.then(function() {
                    CSM.toast('Deleted ' + succeeded + ' of ' + (succeeded + failed), failed > 0 ? 'warning' : 'success');
                    loadQuarantine();
                    loadAVStatus();
                });
            }).catch(function() { /* cancelled */ });
        });
    }

    function releaseMessage(msgID) {
        CSM.confirm('Release this message back to the mail queue? Only do this for confirmed false positives.').then(function() {
            CSM.post('/api/v1/email/quarantine/' + encodeURIComponent(msgID) + '/release', {})
                .then(function() { loadQuarantine(); loadAVStatus(); })
                .catch(function(err) { CSM.toast('Release failed: ' + (err.message || ''), 'error'); });
        }).catch(function() { /* cancelled */ });
    }

    function deleteMessage(msgID) {
        CSM.confirm('Permanently delete this quarantined message?', { danger: true, okLabel: 'Delete' }).then(function() {
            CSM.delete('/api/v1/email/quarantine/' + encodeURIComponent(msgID))
                .then(function() { loadQuarantine(); loadAVStatus(); })
                .catch(function(err) { CSM.toast('Delete failed: ' + (err.message || ''), 'error'); });
        }).catch(function() { /* cancelled */ });
    }

    // ---------- Forwarders tab (inventory table) ----------

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
                CSM.loadError(document.getElementById('email-fwd-tbody'), loadForwarders, { title: 'Failed to load forwarders', error: err });
            });
    }

    var heldLoaded = false;

    function loadHeld() {
        if (heldLoaded) return;
        heldLoaded = true;
        CSM.get('/api/v1/email/held')
            .then(function(data) { renderHeld(data.items); })
            .catch(function(err) {
                heldLoaded = false;
                CSM.loadError(document.getElementById('email-held-tbody'), loadHeld, { title: 'Failed to load held forwards', error: err });
            });
    }

    function renderHeld(msgs) {
        var tb = document.getElementById('email-held-tbody');
        if (!tb) return;
        msgs = Array.isArray(msgs) ? msgs : [];
        var c = document.getElementById('email-held-count');
        if (c) c.textContent = msgs.length ? '(' + msgs.length + ')' : '';
        if (msgs.length === 0) {
            tb.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4">Nothing held.</td></tr>';
            return;
        }
        var html = '';
        for (var i = 0; i < msgs.length; i++) {
            var m = msgs[i] || {};
            var reasons = '';
            var rs = Array.isArray(m.reasons) ? m.reasons : [];
            for (var j = 0; j < rs.length; j++) {
                reasons += '<span class="badge bg-red-lt me-1">' + CSM.esc(rs[j]) + '</span>';
            }
            html += '<tr>';
            html += '<td class="small text-muted">' + CSM.esc(ageLabel(m.held_at)) + '</td>';
            html += '<td class="font-monospace small">' + CSM.esc(m.forwarder) + '</td>';
            html += '<td class="font-monospace small">' + CSM.esc(m.recipient) + '</td>';
            html += '<td>' + (reasons || '<span class="text-muted">--</span>') + '</td>';
            html += '<td class="text-end">' +
                '<button type="button" class="btn btn-sm btn-ghost-secondary" data-held-release="' + CSM.attr(m.id) + '"><i class="ti ti-mail-forward"></i>&nbsp;Release</button> ' +
                '<button type="button" class="btn btn-sm btn-ghost-danger" data-held-delete="' + CSM.attr(m.id) + '" aria-label="Delete held forward"><i class="ti ti-trash"></i></button>' +
                '</td>';
            html += '</tr>';
        }
        tb.innerHTML = html;
    }

    function releaseHeld(id) {
        CSM.confirm('Release this held forward copy to its external recipient? Only do this for confirmed false positives.').then(function() {
            CSM.post('/api/v1/email/held/' + encodeURIComponent(id) + '/release', {})
                .then(function() { CSM.toast('Released held forward', 'success'); heldLoaded = false; loadHeld(); })
                .catch(function(err) { CSM.toast('Release failed: ' + (err.message || ''), 'error'); });
        }).catch(function() { /* cancelled */ });
    }

    function deleteHeld(id) {
        CSM.confirm('Permanently delete this held forward copy?', { danger: true, okLabel: 'Delete' }).then(function() {
            CSM.delete('/api/v1/email/held/' + encodeURIComponent(id))
                .then(function() { CSM.toast('Deleted held forward', 'success'); heldLoaded = false; loadHeld(); })
                .catch(function(err) { CSM.toast('Delete failed: ' + (err.message || ''), 'error'); });
        }).catch(function() { /* cancelled */ });
    }

    var _heldBody = document.getElementById('email-held-tbody');
    if (_heldBody) {
        _heldBody.addEventListener('click', function(e) {
            var rel = e.target.closest('[data-held-release]');
            if (rel) { releaseHeld(rel.getAttribute('data-held-release')); return; }
            var del = e.target.closest('[data-held-delete]');
            if (del) { deleteHeld(del.getAttribute('data-held-delete')); }
        });
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

        if (rows.length === 0) {
            var msg = _forwarders.length === 0
                ? 'No forwarders found on this host.'
                : 'No forwarders match the current filter.';
            tb.innerHTML = '<tr><td colspan="5" class="text-center text-muted py-4">' + msg + '</td></tr>';
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

    // ---------- Deliverability tab (outbound deferral intel) ----------

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

    function reasonBadges(reasons) {
        reasons = deliverabilityArray(reasons);
        if (!reasons || reasons.length === 0) return '<span class="text-muted">--</span>';
        var out = '';
        for (var i = 0; i < reasons.length; i++) {
            var r = reasons[i] || {};
            out += '<span class="badge bg-secondary-lt me-1">' + CSM.esc(r.code) + ' &times;' + CSM.esc(formatDeferralCount(r.count)) + '</span>';
        }
        return out;
    }

    function loadDeliverability() {
        if (deliverabilityLoaded) return;
        deliverabilityLoaded = true;
        CSM.get('/api/v1/email/deferrals')
            .then(function(data) { renderDeliverability(data || {}); })
            .catch(function(err) {
                deliverabilityLoaded = false;
                ['email-deliv-providers-body', 'email-deliv-ips-body'].forEach(function(id) {
                    CSM.loadError(document.getElementById(id), loadDeliverability, { title: 'Failed to load deferral activity', error: err });
                });
            });
    }

    function setRowMessage(tbodyID, cols, msg) {
        var tb = document.getElementById(tbodyID);
        if (tb) tb.innerHTML = '<tr><td colspan="' + cols + '" class="text-center text-muted py-4">' + msg + '</td></tr>';
    }

    function renderDeliverability(data) {
        data = data || {};
        var providers = deliverabilityArray(data.providers);
        var ips = deliverabilityArray(data.outbound_ips);
        var total = formatDeferralCount(data.deferrals);

        var summary = document.getElementById('email-deliv-summary');
        if (summary) {
            summary.textContent = total === '0'
                ? 'No outbound deferrals seen in the recent log window.'
                : total + ' outbound deferral(s) across ' + providers.length + ' provider(s) and ' + ips.length + ' sending IP(s).';
        }

        if (providers.length === 0) {
            setRowMessage('email-deliv-providers-body', 3, 'No providers are deferring mail from this server.');
        } else {
            var ph = '';
            for (var i = 0; i < providers.length; i++) {
                var p = providers[i] || {};
                ph += '<tr>';
                ph += '<td>' + providerBadge(p.provider) + '</td>';
                ph += '<td class="text-end">' + CSM.esc(formatDeferralCount(p.deferrals)) + '</td>';
                ph += '<td>' + reasonBadges(p.reasons) + '</td>';
                ph += '</tr>';
            }
            var pb = document.getElementById('email-deliv-providers-body');
            if (pb) pb.innerHTML = ph;
        }

        if (ips.length === 0) {
            setRowMessage('email-deliv-ips-body', 3, 'No sending IP has been deferred.');
        } else {
            var ih = '';
            for (var j = 0; j < ips.length; j++) {
                var ip = ips[j] || {};
                var by = '';
                var byList = deliverabilityArray(ip.providers);
                for (var k = 0; k < byList.length; k++) {
                    var item = byList[k] || {};
                    by += providerBadge(item.provider) + '<span class="text-muted small me-2">&times;' + CSM.esc(formatDeferralCount(item.count)) + '</span>';
                }
                ih += '<tr>';
                ih += '<td class="font-monospace small">' + CSM.esc(ip.ip) + '</td>';
                ih += '<td class="text-end">' + CSM.esc(formatDeferralCount(ip.deferrals)) + '</td>';
                ih += '<td>' + (by || '<span class="text-muted">--</span>') + '</td>';
                ih += '</tr>';
            }
            var ib = document.getElementById('email-deliv-ips-body');
            if (ib) ib.innerHTML = ih;
        }
    }

    // ---------- Outbound mail abuse (Outbound abuse tab) ----------

    function loadOutboundAbuse() {
        var body = document.getElementById('outbound-abuse-body');
        if (!body) return;
        CSM.get('/api/v1/email/relay-abuse?' + emailDateQuery('limit=20'))
            .then(function(resp) {
                outboundAbuseLoaded = true;
                renderOutboundAbuse(resp);
                CSM.truncationNote(body, resp && resp.truncated, 'relay abuse findings');
            })
            .catch(function(err) {
                CSM.loadError(body, loadOutboundAbuse, { title: 'Failed to load outbound mail abuse', error: err });
            });
    }

    function renderOutboundAbuse(resp) {
        var body = document.getElementById('outbound-abuse-body');
        var entries = (resp && resp.items) || [];
        if (entries.length === 0) {
            body.innerHTML = '<div class="csm-empty"><div class="csm-empty__reason">No outbound mail abuse detected.</div></div>';
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
            html += '<tr>';
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
                var reason = btn.getAttribute('data-reason');
                btn.disabled = true;
                CSM.confirm('Block ' + ip + ' in the firewall for 24 hours?\n\n' + reason, { danger: true, okLabel: 'Block' }).then(function() {
                    CSM.post('/api/v1/block-ip', { ip: ip, reason: reason, duration: '24h' })
                        .then(function() { btn.textContent = 'Blocked'; })
                        .catch(function() { btn.disabled = false; btn.textContent = 'Block failed'; });
                }).catch(function(err) {
                    btn.disabled = false;
                    if (err) CSM.toast(err.message || 'Request failed', 'error');
                });
            });
        });
    }

    // ---------- Queue composition (Queue tab) ----------

    function loadQueueComposition() {
        if (queueCompositionLoaded) return;
        queueCompositionLoaded = true;
        CSM.get('/api/v1/email/queue-composition')
            .then(function(data) { renderQueueComposition(data || {}); })
            .catch(function(err) {
                queueCompositionLoaded = false;
                CSM.loadError(document.getElementById('queue-composition'), loadQueueComposition, { title: 'Failed to load queue composition', error: err });
            });
    }

    function queueCount(value) {
        var n = Number(value);
        if (!isFinite(n) || n < 0) return 0;
        return Math.floor(n);
    }

    function renderQueueComposition(data) {
        var el = document.getElementById('queue-composition');
        if (!el) return;
        var total = queueCount(data.total);
        if (total === 0) {
            el.innerHTML = '<div class="text-muted small">The mail queue is empty.</div>';
            return;
        }
        var bounce = queueCount(data.bounce);
        var real = queueCount(data.real);
        var frozen = queueCount(data.frozen);
        var flushable = queueCount(data.flushable_backscatter);
        var bouncePct = Math.round(bounce / total * 100);

        var html = '<div class="row g-2 mb-3">';
        html += metricCol('Total', CSM.formatNumber(total), '');
        html += metricCol('Real mail', CSM.formatNumber(real), 'text-success');
        html += metricCol('Backscatter', CSM.formatNumber(bounce) + ' (' + bouncePct + '%)', bounce > 0 ? 'text-danger' : 'text-muted');
        html += metricCol('Frozen', CSM.formatNumber(frozen), frozen > 0 ? 'text-warning' : 'text-muted');
        html += metricCol('Oldest', CSM.formatDuration(data.oldest_age_seconds) || '--', '');
        html += '</div>';

        // Flush is offered only for frozen null-sender messages: undeliverable
        // backscatter that cannot belong to a real sender or a live retry.
        if (flushable > 0) {
            html += '<button type="button" class="btn btn-sm btn-outline-danger mb-3" id="flush-backscatter-btn">' +
                '<i class="ti ti-trash"></i>&nbsp;Flush ' + CSM.formatNumber(flushable) + ' frozen backscatter message(s)</button>';
        }

        var recips = deliverabilityArray(data.top_recipients);
        if (recips.length > 0) {
            html += '<div class="subheader mb-1 small">Top stuck recipients</div>';
            html += '<div class="list-group list-group-flush">';
            for (var i = 0; i < recips.length; i++) {
                var rc = recips[i] || {};
                html += '<div class="list-group-item py-1 px-0 d-flex">';
                html += '<span class="font-monospace small">' + CSM.esc(rc.address) + '</span>';
                html += '<span class="ms-auto small text-muted">' + CSM.formatNumber(queueCount(rc.count)) + '</span>';
                html += '</div>';
            }
            html += '</div>';
        }
        el.innerHTML = html;
    }

    function metricCol(label, value, cls) {
        return '<div class="col-auto"><div class="small text-muted">' + CSM.esc(label) + '</div>' +
            '<div class="h3 mb-0 ' + CSM.attr(cls || '') + '">' + CSM.esc(String(value)) + '</div></div>';
    }

    function flushBackscatter() {
        CSM.confirm('Remove all frozen null-sender bounce messages from the mail queue? This deletes undeliverable backscatter only -- real mail and live retries are not touched.', { danger: true, okLabel: 'Remove' }).then(function() {
            CSM.post('/api/v1/email/queue/flush-backscatter', {})
                .then(function(res) {
                    CSM.toast(queueCount(res && res.removed) +
                        ' backscatter message(s) no longer queued', 'success');
                    queueCompositionLoaded = false;
                    loadQueueComposition();
                    loadEmailStats(); // refresh the queue size on the Queue tab
                })
                .catch(function(err) { CSM.toast('Flush failed: ' + (err.message || ''), 'error'); });
        }).catch(function() { /* cancelled */ });
    }

    var queueCompEl = document.getElementById('queue-composition');
    if (queueCompEl) {
        queueCompEl.addEventListener('click', function(e) {
            if (e.target.closest('#flush-backscatter-btn')) flushBackscatter();
        });
    }

    // ---------- Tab activation ----------

    function activateTab(name) {
        var btn = document.getElementById('email-tab-' + name);
        if (btn && window.bootstrap && window.bootstrap.Tab) {
            window.bootstrap.Tab.getOrCreateInstance(btn).show();
        }
    }

    function activeEmailTab() {
        var btn = document.querySelector('[id^="email-tab-"].active');
        if (!btn || !btn.id) return 'findings';
        return btn.id.replace('email-tab-', '');
    }

    function loadActiveEmailTab(force) {
        var id = activeEmailTab();
        if (id === 'auth') {
            if (force) authGroupsLoaded = false;
            loadAuthGroups();
        } else if (id === 'queue') {
            if (_stats) renderQueueHealth(_stats);
            if (force) queueCompositionLoaded = false;
            loadQueueComposition();
        } else if (id === 'quarantine') {
            if (force) quarantineLoaded = false;
            if (!quarantineLoaded) loadQuarantine();
        } else if (id === 'senders') {
            if (_pendingSenders) {
                renderTopSenders(_pendingSenders);
                _pendingSenders = null;
            } else if (force) {
                loadEmailStats();
            }
        } else if (id === 'forwarders') {
            if (force) { forwardersLoaded = false; heldLoaded = false; }
            loadForwarders();
            loadHeld();
        } else if (id === 'deliverability') {
            if (force) deliverabilityLoaded = false;
            loadDeliverability();
        } else if (id === 'outbound-abuse') {
            if (force) outboundAbuseLoaded = false;
            loadOutboundAbuse();
        }
    }

    var tabButtons = document.querySelectorAll('[data-bs-toggle="tab"]');
    for (var t = 0; t < tabButtons.length; t++) {
        tabButtons[t].addEventListener('shown.bs.tab', function(ev) {
            var id = ev.target.id.replace('email-tab-', '');
            CSM.urlState.set({ tab: id === 'findings' ? '' : id });
            if (id === 'auth')        loadAuthGroups();
            else if (id === 'queue')  { if (_stats) renderQueueHealth(_stats); loadQueueComposition(); }
            else if (id === 'quarantine' && !quarantineLoaded) loadQuarantine();
            else if (id === 'senders') {
                if (_pendingSenders) {
                    renderTopSenders(_pendingSenders);
                    _pendingSenders = null;
                } else {
                    loadEmailStats();
                }
            }
            else if (id === 'forwarders') { loadForwarders(); loadHeld(); }
            else if (id === 'deliverability') loadDeliverability();
            else if (id === 'outbound-abuse') { if (!outboundAbuseLoaded) loadOutboundAbuse(); }
        });
    }

    // ---------- Forwarders filter/search (client-side, no refetch) ----------

    ['email-fwd-filter', 'email-fwd-search'].forEach(function(id) {
        var el = document.getElementById(id);
        if (!el) return;
        var evt = id === 'email-fwd-search' ? 'input' : 'change';
        el.addEventListener(evt, renderForwarders);
    });

    // ---------- Filter handlers (auto-apply on change) ----------

    function syncEmailURL() {
        var fromVal = (document.getElementById('filter-from') || {}).value || '';
        var toVal = (document.getElementById('filter-to') || {}).value || '';
        var sevVal = (document.getElementById('filter-severity') || {}).value || '';
        var checkVal = (document.getElementById('filter-check') || {}).value || '';
        var searchVal = (document.getElementById('email-search') || {}).value || '';
        var todayStr = CSM.prefs.today();
        CSM.urlState.set({
            from: fromVal !== todayStr ? fromVal : '',
            to: toVal !== todayStr ? toVal : '',
            severity: sevVal,
            check: checkVal,
            search: searchVal
        });
    }

    ['filter-from', 'filter-to', 'filter-severity', 'filter-check'].forEach(function(id) {
        var el = document.getElementById(id);
        if (!el) return;
        el.addEventListener('change', function() {
            syncEmailURL();
            loadFindings();
            loadActionGroups();
            authGroupsLoaded = false; // re-fetch on next tab activation
            if (activeEmailTab() === 'auth') loadAuthGroups();
        });
    });

    // ---------- Quarantine action delegation ----------

    var quarantineTable = document.getElementById('quarantine-table');
    if (quarantineTable) {
        quarantineTable.addEventListener('click', function(e) {
            var releaseBtn = e.target.closest('[data-email-release]');
            if (releaseBtn) { releaseMessage(releaseBtn.getAttribute('data-email-release')); return; }
            var deleteBtn = e.target.closest('[data-email-delete]');
            if (deleteBtn) { deleteMessage(deleteBtn.getAttribute('data-email-delete')); }
        });
    }

    // ---------- Refresh button ----------

    var refreshBtn = document.getElementById('email-refresh');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', function() {
            loadOverview();
            loadRspamd();
            loadEmailStats();
            loadAVStatus();
            loadRejects();
            loadActionGroups();
            loadFindings();
            authGroupsLoaded = false;
            forwardersLoaded = false;
            heldLoaded = false;
            deliverabilityLoaded = false;
            outboundAbuseLoaded = false;
            queueCompositionLoaded = false;
            loadActiveEmailTab(true);
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

    if (initialTab) activateTab(initialTab);
    loadOverview();
    loadRspamd();
    loadEmailStats();
    loadAVStatus();
    loadRejects();
    loadActionGroups();
    loadFindings();
    loadActiveEmailTab(false);

    // Polling while the tab is visible: the numbers and the queue every 30 s,
    // rspamd and AV every 60 s (rspamd's own figures are cached that long),
    // and the rejects and groups every 60 s.
    var _emailIntervals = [];
    function _stopEmailIntervals() {
        for (var i = 0; i < _emailIntervals.length; i++) _emailIntervals[i].stop();
        _emailIntervals = [];
    }

    function _startEmailPolling() {
        _emailIntervals.push(CSM.refresh.interval(function() {
            try { loadOverview(); loadEmailStats(); } catch(e) {}
        }, 30000));
        _emailIntervals.push(CSM.refresh.interval(function() {
            try { loadRspamd(); loadAVStatus(); } catch(e) {}
        }, 60000));
        _emailIntervals.push(CSM.refresh.interval(function() {
            try { loadRejects(); loadActionGroups(); } catch(e) {}
        }, 60000));
    }
    _startEmailPolling();
    window.addEventListener('beforeunload', function() {
        _stopEmailIntervals();
    });
})();
