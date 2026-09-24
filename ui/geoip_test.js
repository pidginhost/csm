// Run with: node --test ui/geoip_test.js
// Firewall and ModSecurity fill their Location cells through one helper:
// unique addresses, in chunks the batch endpoint accepts, painted into every
// cell that shows the address.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadPage, SHARED, settle } = require('./pagekit.js');

function cells(ips) {
    return '<table id="t">' + ips.map(ip => '<tr><td class="geo-cell" data-ip="' + ip + '">old</td></tr>').join('') + '</table>';
}

test('each address is looked up once and painted into every matching cell', async () => {
    const page = loadPage(cells(['192.0.2.1', '192.0.2.2', '192.0.2.1']), SHARED);
    page.window.CSM.enrichGeoIP(page.document.getElementById('t'), {
        format: g => g.country ? 'in ' + g.country : ''
    });
    const req = page.respond('/api/v1/geoip/batch', 200, { results: {
        '192.0.2.1': { country: 'RO' }, '192.0.2.2': {}
    } });
    assert.deepEqual(Array.from(req.body.ips).sort(), ['192.0.2.1', '192.0.2.2']);
    await settle();
    const text = Array.from(page.document.querySelectorAll('.geo-cell'), c => c.textContent);
    assert.deepEqual(text, ['in RO', 'old', 'in RO'], 'an empty format result must leave the cell as it is');
});

test('large lists are split into chunks the endpoint accepts', () => {
    const ips = [];
    for (let i = 0; i < 600; i++) ips.push('198.51.100.' + (i % 250) + '-' + i);
    const page = loadPage(cells(ips), SHARED);
    page.window.CSM.enrichGeoIP(page.document.getElementById('t'), { format: () => '' });
    const sizes = page.pending('/api/v1/geoip/batch').map(r => r.body.ips.length);
    assert.deepEqual(sizes, [250, 250, 100]);
});

test('a failed chunk shows the fail text only when asked', async () => {
    const page = loadPage(cells(['192.0.2.1']), SHARED);
    page.window.CSM.enrichGeoIP(page.document.getElementById('t'), { format: () => 'x', failText: '-' });
    page.fail('/api/v1/geoip/batch');
    await settle();
    assert.equal(page.document.querySelector('.geo-cell').textContent, '-');

    const quiet = loadPage(cells(['192.0.2.1']), SHARED);
    quiet.window.CSM.enrichGeoIP(quiet.document.getElementById('t'), { format: () => 'x' });
    quiet.fail('/api/v1/geoip/batch');
    await settle();
    assert.equal(quiet.document.querySelector('.geo-cell').textContent, 'old');
});
