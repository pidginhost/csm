// Run with: node --test ui/timeago_test.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

// Loads the shared timestamp helpers with a document that returns the given
// elements for each selector the refresher may query.
function timeHelpers(bySelector = {}) {
    const source = fs.readFileSync(path.join(__dirname, 'static/js/csm-format.js'), 'utf8');
    const start = source.indexOf('// Parse an ISO 8601');
    const end = source.indexOf('// Auto-refresh relative timestamps');
    assert.ok(start >= 0 && end > start, 'timestamp helpers moved');
    const context = vm.createContext({
        Date,
        document: { querySelectorAll(sel) { return bySelector[sel] || []; } },
        CSM: {}
    });
    vm.runInContext(source.slice(start, end), context);
    return context.CSM;
}

function el(attrs, text) {
    return {
        textContent: text,
        title: '',
        getAttribute(name) { return Object.prototype.hasOwnProperty.call(attrs, name) ? attrs[name] : null; }
    };
}

const iso = offsetMs => new Date(Date.now() + offsetMs).toISOString();

test('future times read as "in", not "just now"', () => {
    const CSM = timeHelpers();
    assert.equal(CSM.timeAgo(iso(2 * 3600 * 1000 + 5000)), 'in 2h');
    assert.equal(CSM.timeAgo(iso(5 * 60 * 1000 + 5000)), 'in 5m');
    assert.equal(CSM.timeAgo(iso(-90 * 1000)), '1m ago');
});

test('the refresher only rewrites elements that opt in to relative time', () => {
    const absolute = el({ 'data-timestamp': iso(-3 * 3600 * 1000) }, '2026-09-23 08:00');
    const row = el({ 'data-timestamp': iso(-3600 * 1000) }, 'severity check message time');
    const relative = el({ 'data-time-ago': iso(-3 * 3600 * 1000) }, 'stale');
    const CSM = timeHelpers({
        '[data-timestamp]': [absolute, row, relative],
        '[data-time-ago]': [relative]
    });
    CSM.initTimeAgo();
    assert.equal(absolute.textContent, '2026-09-23 08:00', 'an absolute date must stay absolute');
    assert.equal(row.textContent, 'severity check message time', 'a row carrying a sort key must keep its cells');
    assert.equal(relative.textContent, '3h ago');
});

test('an empty relative stamp keeps its placeholder', () => {
    const permanent = el({ 'data-time-ago': '' }, 'Permanent');
    const CSM = timeHelpers({ '[data-time-ago]': [permanent] });
    CSM.initTimeAgo();
    assert.equal(permanent.textContent, 'Permanent');
});
