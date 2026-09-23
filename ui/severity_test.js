// Run with: node --test ui/severity_test.js
// One severity table serves every page: a numeric level or a label in any
// case maps to the same label, badge class and sort rank everywhere.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, SHARED } = require('./pagekit.js');

test('levels and labels map to the same severity', () => {
    const CSM = loadPage('', SHARED).window.CSM;
    for (const [input, want] of [
        [2, ['CRITICAL', 'critical', 2, 3]],
        ['critical', ['CRITICAL', 'critical', 2, 3]],
        [1, ['HIGH', 'high', 1, 2]],
        [' High ', ['HIGH', 'high', 1, 2]],
        [0, ['WARNING', 'warning', 0, 1]],
        ['WARNING', ['WARNING', 'warning', 0, 1]]
    ]) {
        const s = CSM.severity(input);
        assert.deepEqual([s.label, s.cls, s.level, s.rank], want, 'severity(' + JSON.stringify(input) + ')');
    }
});

test('anything else is an unknown severity, never a guess', () => {
    const CSM = loadPage('', SHARED).window.CSM;
    for (const input of [3, -1, 1.5, '', 'info', null, undefined, '2']) {
        const s = CSM.severity(input);
        assert.deepEqual([s.label, s.cls, s.level, s.rank], ['UNKNOWN', 'secondary', -1, 0], 'severity(' + JSON.stringify(input) + ')');
    }
});

test('the badge and class helpers use the same table', () => {
    const CSM = loadPage('', SHARED).window.CSM;
    assert.match(CSM.severityBadge(2), /badge-critical/);
    assert.match(CSM.severityBadge(2), />CRITICAL</);
    assert.match(CSM.severityBadge('high'), /badge-high/);
    assert.match(CSM.severityBadge(7), /badge-secondary/);
    assert.equal(CSM.severityClass(1), 'high');
    assert.equal(CSM.severityClass('warning'), 'warning');
    assert.equal(CSM.severityClass('nope'), 'secondary');
});
