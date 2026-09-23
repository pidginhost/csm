// Run with: node --test ui/escalation_test.js
// ModSecurity escalation exclusions live on the ModSec Rules page only. The
// daemon honours them whether or not rule management is configured, so the
// list and the add form work in both states.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, SHARED, settle } = require('./pagekit.js');

const RULES = {
    configured: true, total: 2, active: 2,
    rules: [
        { id: 900112, description: 'WP user enumeration', action: 'deny', status_code: 403, phase: 2, enabled: true, escalate: false },
        { id: 900200, description: 'Webshell upload', action: 'deny', status_code: 403, phase: 2, enabled: true, escalate: true }
    ]
};

async function modsecRules(rules, excluded) {
    const page = loadPage(templateBody('modsec-rules'), SHARED.concat(['modsec-rules.js']));
    page.window.CSM.confirm = () => Promise.resolve();
    await settle();
    page.respond('/api/v1/modsec/rules/escalation', 200, { rules: excluded });
    page.respond('/api/v1/modsec/rules', 200, rules);
    await settle();
    return page;
}

function listedIDs(page) {
    return Array.from(page.document.querySelectorAll('#escalation-list [data-escalation-id]'))
        .map(el => Number(el.getAttribute('data-escalation-id')));
}

async function submitExclusion(page, id) {
    page.document.getElementById('escalation-rule-id').value = String(id);
    page.document.getElementById('escalation-form').dispatchEvent(new page.window.Event('submit'));
    await settle();
}

test('exclusions are listed and editable without rule management configured', async () => {
    const page = await modsecRules({ configured: false, missing: ['rules_file'] }, [900112]);
    assert.ok(!page.document.getElementById('escalation-card').classList.contains('d-none'));
    assert.deepEqual(listedIDs(page), [900112]);
    await submitExclusion(page, 900300);
    const req = page.respond('/api/v1/modsec/rules/escalation', 200, { ok: true });
    assert.equal(req.method, 'POST');
    assert.deepEqual({ ...req.body }, { rule_id: 900300, escalate: false });
    await settle();
    assert.deepEqual(listedIDs(page), [900112, 900300]);
});

test('an exclusion outside the CSM range is refused before sending', async () => {
    const page = await modsecRules({ configured: false, missing: ['rules_file'] }, []);
    await submitExclusion(page, 123);
    assert.equal(page.pending('/api/v1/modsec/rules/escalation').length, 0);
});

test('removing an exclusion turns escalation back on for that rule only', async () => {
    const page = await modsecRules(RULES, [900112]);
    const remove = page.document.querySelector('#escalation-list [data-escalation-id="900112"] button');
    assert.ok(remove, 'no remove button for an excluded rule');
    assert.ok((remove.getAttribute('aria-label') || '').includes('900112'), 'remove button has no accessible name');
    remove.click();
    await settle();
    const req = page.respond('/api/v1/modsec/rules/escalation', 200, { ok: true });
    assert.deepEqual({ ...req.body }, { rule_id: 900112, escalate: true });
    await settle();
    assert.deepEqual(listedIDs(page), []);
    const toggle = page.document.querySelector('.escalate-toggle[data-id="900112"]');
    assert.equal(toggle.checked, true, 'rule table still shows the rule as excluded');
});

test('an exclusion added from the list updates the rule table', async () => {
    const page = await modsecRules(RULES, [900112]);
    await submitExclusion(page, 900200);
    page.respond('/api/v1/modsec/rules/escalation', 200, { ok: true });
    await settle();
    const toggle = page.document.querySelector('.escalate-toggle[data-id="900200"]');
    assert.equal(toggle.checked, false);
    assert.equal(page.document.getElementById('rule-row-900200').getAttribute('data-escalate'), 'no');
    assert.equal(page.document.getElementById('stat-no-escalate').textContent, '2');
});

test('turning escalation off in the rule table adds the rule to the list', async () => {
    const page = await modsecRules(RULES, [900112]);
    const toggle = page.document.querySelector('.escalate-toggle[data-id="900200"]');
    toggle.checked = false;
    toggle.dispatchEvent(new page.window.Event('change'));
    await settle();
    page.respond('/api/v1/modsec/rules/escalation', 200, { ok: true });
    await settle();
    assert.deepEqual(listedIDs(page), [900112, 900200]);
});

test('a failed exclusion leaves the list unchanged', async () => {
    const page = await modsecRules(RULES, [900112]);
    const toasts = [];
    page.window.CSM.toast = (message, kind) => toasts.push({ message, kind });
    await submitExclusion(page, 900200);
    page.respond('/api/v1/modsec/rules/escalation', 500, { error: 'Failed to update escalation setting' });
    await settle();
    assert.deepEqual(listedIDs(page), [900112]);
    assert.ok(toasts.some(t => t.kind === 'error'), JSON.stringify(toasts));
    assert.equal(page.document.getElementById('escalation-rule-id').value, '900200', 'the typed rule ID was lost');
});

test('the rule table cannot erase an exclusion-list load failure', async () => {
    const page = loadPage(templateBody('modsec-rules'), SHARED.concat(['modsec-rules.js']));
    page.respond('/api/v1/modsec/rules/escalation', 500, { error: 'store unavailable' });
    await settle();
    const error = page.document.getElementById('escalation-list').textContent;
    assert.match(error, /failed|retry/i);
    page.respond('/api/v1/modsec/rules', 200, RULES);
    await settle();
    assert.equal(page.document.getElementById('escalation-list').textContent, error);
});

test('a delayed rules snapshot cannot undo an exclusion just saved', async () => {
    const page = loadPage(templateBody('modsec-rules'), SHARED.concat(['modsec-rules.js']));
    page.respond('/api/v1/modsec/rules/escalation', 200, { rules: [900112] });
    await settle();
    await submitExclusion(page, 900200);
    page.respond('/api/v1/modsec/rules/escalation', 200, { ok: true });
    await settle();
    page.respond('/api/v1/modsec/rules', 200, RULES);
    await settle();
    assert.deepEqual(listedIDs(page), [900112, 900200]);
    assert.equal(page.document.querySelector('.escalate-toggle[data-id="900200"]').checked, false);
    assert.equal(page.document.getElementById('stat-no-escalate').textContent, '2');
});

test('Refresh cannot read an old exclusion set while a write is pending', async () => {
    const page = await modsecRules(RULES, [900112]);
    await submitExclusion(page, 900200);
    page.window.CSM.refresh.manual();
    await settle();
    assert.equal(page.pending('/api/v1/modsec/rules').filter(r => r.method === 'GET').length, 0);
    page.respond('/api/v1/modsec/rules/escalation', 200, { ok: true });
    await settle();
    assert.deepEqual(listedIDs(page), [900112, 900200]);
});

test('an escalation confirmation also holds Refresh until it is cancelled', async () => {
    const page = await modsecRules(RULES, [900112]);
    let reject;
    page.window.CSM.confirm = () => new Promise((_, no) => { reject = no; });
    const toggle = page.document.querySelector('.escalate-toggle[data-id="900200"]');
    toggle.checked = false;
    toggle.dispatchEvent(new page.window.Event('change'));
    page.window.CSM.refresh.manual();
    await settle();
    assert.equal(page.pending('/api/v1/modsec/rules').length, 0);
    reject(null);
    await settle();
    assert.equal(toggle.checked, true);
    assert.equal(toggle.disabled, false);
    page.window.CSM.refresh.manual();
    await settle();
    assert.equal(page.pending('/api/v1/modsec/rules').length, 2);
});

test('exclusion edits wait until the list finishes loading', async () => {
    const page = await modsecRules(RULES, [900112]);
    page.window.CSM.refresh.manual();
    await settle();
    await submitExclusion(page, 900200);
    assert.equal(page.pending('/api/v1/modsec/rules/escalation').filter(r => r.method === 'POST').length, 0);
    page.respond('/api/v1/modsec/rules/escalation', 200, { rules: [900112, 900200] });
    page.respond('/api/v1/modsec/rules', 200, RULES);
    await settle();
    assert.deepEqual(listedIDs(page), [900112, 900200]);
});

test('refreshing an unconfigured ruleset hides obsolete management controls', async () => {
    const page = await modsecRules(RULES, [900112]);
    page.window.CSM.refresh.manual();
    await settle();
    page.respond('/api/v1/modsec/rules/escalation', 200, { rules: [900112] });
    page.respond('/api/v1/modsec/rules', 200, { configured: false, missing: ['rules_file'] });
    await settle();
    assert.ok(page.document.getElementById('modsec-rules-content').classList.contains('d-none'));
    assert.deepEqual(listedIDs(page), [900112]);
});

test('staged rule controls stay locked while Refresh replaces their snapshot', async () => {
    const page = await modsecRules(RULES, [900112]);
    page.window.CSM.refresh.manual();
    await settle();
    assert.equal(page.document.querySelector('.enable-toggle').disabled, true);
    assert.equal(page.document.getElementById('btn-apply').disabled, true);
    page.respond('/api/v1/modsec/rules/escalation', 200, { rules: [900112] });
    page.respond('/api/v1/modsec/rules', 200, RULES);
    await settle();
    assert.equal(page.document.querySelector('.enable-toggle').disabled, false);
    assert.equal(page.document.getElementById('btn-apply').disabled, false);
});

function removeButton(page, id) {
    return page.document.querySelector('#escalation-list [data-escalation-remove="' + id + '"]');
}

test('a cancelled removal keeps the exclusion and frees the button', async () => {
    const page = await modsecRules(RULES, [900112]);
    page.window.CSM.confirm = () => Promise.reject(null);
    removeButton(page, 900112).click();
    await settle();
    assert.equal(page.pending('/api/v1/modsec/rules/escalation').length, 0);
    assert.deepEqual(listedIDs(page), [900112]);
    assert.equal(removeButton(page, 900112).disabled, false);
});

test('a second click while a removal is pending sends one request', async () => {
    const page = await modsecRules(RULES, [900112]);
    const btn = removeButton(page, 900112);
    btn.click();
    btn.click();
    await settle();
    assert.equal(page.pending('/api/v1/modsec/rules/escalation').length, 1);
});

test('a failed removal keeps the exclusion listed', async () => {
    const page = await modsecRules(RULES, [900112]);
    const toasts = [];
    page.window.CSM.toast = (message, kind) => toasts.push({ message, kind });
    removeButton(page, 900112).click();
    await settle();
    page.respond('/api/v1/modsec/rules/escalation', 500, { error: 'Failed to update escalation setting' });
    await settle();
    assert.deepEqual(listedIDs(page), [900112]);
    assert.equal(removeButton(page, 900112).disabled, false);
    assert.ok(toasts.some(t => t.kind === 'error'), JSON.stringify(toasts));
});

test('the Rules page no longer edits escalation exclusions', async () => {
    const page = loadPage(templateBody('rules'), SHARED.concat(['rules.js']));
    await settle();
    assert.equal(page.document.getElementById('modsec-escalation-form'), null);
    assert.equal(page.pending('modsec-escalation').length, 0);
    assert.ok(page.document.querySelector('a[href="/modsec/rules"]'), 'Rules page does not point to ModSec Rules');
});
