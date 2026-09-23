// Run with: node --test ui/performance_test.js
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

const logFinding = { severity: 1, check: 'perf_error_logs', message: 'Bloated error_log: /home/a/public_html/error_log', key: 'k1' };
const perfData = findings => ({ metrics: { cpu_cores: 2, load_avg: [0.1, 0.1, 0.1] }, findings });

function perfPage() {
    const page = loadPage(templateBody('performance'), SHARED.concat(['performance.js']));
    page.window.CSM.confirm = () => Promise.resolve();
    page.window.CSM.toast = () => {};
    return page;
}

async function answerPerformance(page, findings) {
    page.respond('/api/v1/performance', 200, perfData(findings));
    await settle();
}

function refresh(page) {
    page.window.CSM.refresh.manual();
}

function fixButtons(page) {
    return page.document.querySelectorAll('#perf-findings button').filter(b => /Empty log file/.test(b.textContent));
}

test('a fix in progress stays locked across the periodic re-render', async () => {
    const page = perfPage();
    await answerPerformance(page, [logFinding]);
    fixButtons(page)[0].click();
    await settle();
    assert.equal(page.pending('/api/v1/perf/fix-error-log').length, 1);

    refresh(page);
    await answerPerformance(page, [logFinding]);
    const rebuilt = fixButtons(page)[0];
    assert.equal(rebuilt.disabled, true, 'the re-rendered button forgot the running fix');
    rebuilt.click();
    await settle();
    assert.equal(page.pending('/api/v1/perf/fix-error-log').length, 1, 'a second fix was sent for the same finding');

    page.respond('/api/v1/perf/fix-error-log', 200, { success: false, error: 'permission denied' });
    await settle();
    assert.equal(fixButtons(page)[0].disabled, false, 'a failed fix must allow a retry');
});

test('the bulk menu is not rebuilt under the operator while nothing changed', async () => {
    const page = perfPage();
    await answerPerformance(page, [logFinding]);
    const menu = page.document.querySelector('#perf-bulk-actions .dropdown-menu');
    assert.ok(menu, 'no bulk menu');
    menu.classList.add('show');
    refresh(page);
    await answerPerformance(page, [logFinding]);
    const after = page.document.querySelector('#perf-bulk-actions .dropdown-menu');
    assert.equal(after, menu, 'the open menu was replaced');
    assert.ok(after.classList.contains('show'));
});

test('the bulk menu follows a change in what can be fixed', async () => {
    const page = perfPage();
    await answerPerformance(page, [logFinding]);
    refresh(page);
    await answerPerformance(page, []);
    assert.equal(page.document.querySelector('#perf-bulk-actions .dropdown-menu'), null);
});

test('bulk fixes follow new targets even when their count stays the same', async () => {
    const page = perfPage();
    await answerPerformance(page, [logFinding]);
    refresh(page);
    const next = { ...logFinding, message: 'Bloated error_log: /home/b/public_html/error_log', key: 'k2' };
    await answerPerformance(page, [next]);
    page.document.querySelector('#perf-bulk-actions .dropdown-item').click();
    await settle();
    const requests = page.pending('/api/v1/perf/fix-error-log');
    assert.equal(requests.length, 1);
    assert.deepEqual(requests[0].body, { path: '/home/b/public_html/error_log', key: 'k2' });
});

test('bulk and individual fixes cannot submit the same target concurrently', async () => {
    for (const bulkFirst of [true, false]) {
        const page = perfPage();
        await answerPerformance(page, [logFinding]);
        const bulk = () => page.document.querySelector('#perf-bulk-actions .dropdown-item').click();
        const single = () => fixButtons(page)[0].click();
        (bulkFirst ? bulk : single)();
        await settle();
        refresh(page);
        await answerPerformance(page, [logFinding]);
        (bulkFirst ? single : bulk)();
        await settle();
        assert.equal(page.pending('/api/v1/perf/fix-error-log').length, 1, 'bulkFirst=' + bulkFirst);
        page.respond('/api/v1/perf/fix-error-log', 500, { error: 'failed' });
        await settle();
        assert.equal(fixButtons(page)[0].disabled, false, 'failure must release the target');
    }
});
