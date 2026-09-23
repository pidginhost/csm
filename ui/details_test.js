// Run with: node --test ui/details_test.js
// A finding's details sit in a hidden row under it, opened by the row's
// expand button. Email Security built those rows but gave them no button,
// and its table forced them hidden, so the details could never be read.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, templateBody, items, SHARED, settle, jsonResponse } = require('./pagekit.js');

async function answerAll(page, bodies) {
    for (let round = 0; round < 8; round++) {
        const pending = page.requests.filter(r => !r.settled);
        if (pending.length === 0) break;
        for (const req of pending) {
            req.settled = true;
            const hit = Object.keys(bodies).find(k => req.url.includes(k));
            req.resolve(jsonResponse(200, hit ? bodies[hit] : items([])));
        }
        await settle();
    }
}

function shown(el) {
    for (let n = el; n && n.nodeType === 1; n = n.parentNode) {
        if (n.style && n.style.display === 'none') return false;
        if (n.classList.contains('details-row') && !n.classList.contains('show')) return false;
    }
    return true;
}

async function emailPage() {
    const page = loadPage(templateBody('email'), SHARED.concat(['email.js']));
    await answerAll(page, { '/api/v1/history?': { items: [
        { severity: 2, check: 'email_phishing_content', account: 'alice', message: 'phish', details: 'Subject: urgent', timestamp: '2026-09-22T10:00:00Z' },
        { severity: 1, check: 'email_spam_outbreak', account: 'bob', message: 'spam', timestamp: '2026-09-22T09:00:00Z' }
    ], total: 2 } });
    return page;
}

test('Email findings open their details from the row', async () => {
    const page = await emailPage();
    const details = page.document.querySelector('#email-tbody .details-row');
    assert.ok(details, 'no details row');
    assert.equal(shown(details), false, 'details open before asked');
    const btn = details.previousElementSibling.querySelector('.expand-btn');
    assert.ok(btn, 'no expand button on a finding with details');
    assert.equal(btn.getAttribute('aria-expanded'), 'false');
    assert.equal(page.document.querySelectorAll('#email-tbody .expand-btn').length, 1, 'a finding without details has a button');
    btn.click();
    assert.equal(btn.getAttribute('aria-expanded'), 'true');
    assert.equal(shown(details), true, 'the details did not open');
    assert.match(details.textContent, /Subject: urgent/);
    btn.click();
    assert.equal(shown(details), false);
});

test('an open detail row hides with its filtered-out row and comes back with it', async () => {
    const page = await emailPage();
    const details = page.document.querySelector('#email-tbody .details-row');
    details.previousElementSibling.querySelector('.expand-btn').click();
    const search = page.document.getElementById('email-search');
    search.value = 'bob';
    search.dispatchEvent(new page.window.Event('input'));
    await new Promise(r => setTimeout(r, 400));
    assert.equal(shown(details), false, 'the details of a hidden row still show');
    search.value = '';
    search.dispatchEvent(new page.window.Event('input'));
    await new Promise(r => setTimeout(r, 400));
    assert.equal(shown(details), true, 'the open details did not come back with the row');
});
