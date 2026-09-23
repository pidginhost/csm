// Run with: node --test ui/rules_test.js
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

// A suppression for a check name nothing uses is saved but matches nothing;
// the server says so and the page must pass that on, not report plain success.
test('a suppression for an unknown check shows the server warning', async () => {
    const page = loadPage(templateBody('rules'), SHARED.concat(['rules.js']));
    page.respond('/api/v1/suppressions', 200, []); // the page's initial list
    const toasts = [];
    page.window.CSM.toast = (message, kind) => toasts.push({ message, kind });
    page.document.getElementById('suppress-check').value = 'webshel';
    page.document.getElementById('suppress-all-paths').checked = true;
    page.document.getElementById('suppression-form').dispatchEvent(new page.window.Event('submit'));
    await settle();
    const warning = 'No known check is named webshel; the rule matches nothing until a finding with that check appears.';
    page.respond('/api/v1/suppressions', 200, { status: 'created', id: 'x', warning });
    await settle();
    assert.ok(toasts.some(t => t.kind === 'warning' && t.message.includes(warning)), JSON.stringify(toasts));
});
