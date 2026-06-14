// Verified-bots editor: operator-managed allowlist of crawlers / AI agents.
// Persists the whole reputation.verified_bots list via the admin API with
// optimistic locking (If-Match etag). All requests go through CSM.request.
(function () {
    var etag = '';
    var listEl = document.getElementById('vbots-list');
    var loadingEl = document.getElementById('vbots-loading');
    var emptyEl = document.getElementById('vbots-empty');

    function rowHTML(bot) {
        bot = bot || {};
        var ua = (bot.ua_substrings || []).join('\n');
        var rdns = (bot.rdns_suffixes || []).join('\n');
        var ips = (bot.ip_ranges || []).join('\n');
        return '' +
            '<div class="card mb-2 vbots-row">' +
            '<div class="card-body">' +
            '<div class="row g-2">' +
            '<div class="col-md-3">' +
            '<label class="form-label">Name</label>' +
            '<input type="text" class="form-control vb-name" placeholder="perplexitybot" value="' + CSM.attr(bot.name || '') + '">' +
            '</div>' +
            '<div class="col-md-3">' +
            '<label class="form-label">UA substrings <span class="text-muted">(one per line)</span></label>' +
            '<textarea class="form-control vb-ua" rows="3" placeholder="perplexitybot">' + CSM.esc(ua) + '</textarea>' +
            '</div>' +
            '<div class="col-md-3">' +
            '<label class="form-label">rDNS suffixes <span class="text-muted">(one per line)</span></label>' +
            '<textarea class="form-control vb-rdns" rows="3" placeholder="seranking.com">' + CSM.esc(rdns) + '</textarea>' +
            '</div>' +
            '<div class="col-md-3">' +
            '<label class="form-label">IP ranges <span class="text-muted">(one per line)</span></label>' +
            '<textarea class="form-control vb-ip" rows="3" placeholder="18.97.9.96/29">' + CSM.esc(ips) + '</textarea>' +
            '</div>' +
            '</div>' +
            '<div class="d-flex justify-content-between align-items-center mt-2">' +
            '<div class="vb-errors text-danger small"></div>' +
            '<button type="button" class="btn btn-ghost-danger btn-sm vb-remove"><i class="ti ti-trash"></i>&nbsp;Remove</button>' +
            '</div>' +
            '</div>' +
            '</div>';
    }

    function addRow(bot) {
        var wrap = document.createElement('div');
        wrap.innerHTML = rowHTML(bot);
        listEl.appendChild(wrap.firstChild);
        updateVisibility();
    }

    function updateVisibility() {
        loadingEl.classList.add('d-none');
        if (listEl.querySelectorAll('.vbots-row').length === 0) {
            emptyEl.classList.remove('d-none');
            listEl.classList.add('d-none');
        } else {
            emptyEl.classList.add('d-none');
            listEl.classList.remove('d-none');
        }
    }

    function lines(el) {
        return (el.value || '').split('\n').map(function (s) { return s.trim(); }).filter(Boolean);
    }

    function collect() {
        var rows = listEl.querySelectorAll('.vbots-row');
        var bots = [];
        for (var i = 0; i < rows.length; i++) {
            var r = rows[i];
            bots.push({
                name: r.querySelector('.vb-name').value.trim(),
                ua_substrings: lines(r.querySelector('.vb-ua')),
                rdns_suffixes: lines(r.querySelector('.vb-rdns')),
                ip_ranges: lines(r.querySelector('.vb-ip'))
            });
        }
        return bots;
    }

    function clearErrors() {
        var boxes = listEl.querySelectorAll('.vb-errors');
        for (var i = 0; i < boxes.length; i++) { boxes[i].textContent = ''; }
    }

    function showErrors(errors) {
        clearErrors();
        var rows = listEl.querySelectorAll('.vbots-row');
        (errors || []).forEach(function (e) {
            var m = /verified_bots\[(\d+)\]/.exec(e.field || '');
            var idx = m ? parseInt(m[1], 10) : -1;
            var label = (e.field || '').replace(/^reputation\.verified_bots(\[\d+\])?\.?/, '');
            var msg = (label ? label + ': ' : '') + e.message;
            if (idx >= 0 && rows[idx]) {
                var box = rows[idx].querySelector('.vb-errors');
                box.textContent += (box.textContent ? '  |  ' : '') + msg;
            } else {
                CSM.toast(e.message, 'error');
            }
        });
    }

    function renderRanges(br) {
        br = br || {};
        document.getElementById('vbots-ranges-auto').textContent = br.auto_update ? 'On' : 'Off';
        document.getElementById('vbots-ranges-interval').textContent = br.update_interval || '24h';
        document.getElementById('vbots-ranges-refresh').textContent = br.last_refresh || 'never';
        var prefixes = br.prefixes || {};
        var names = Object.keys(prefixes).sort();
        if (names.length === 0) {
            document.getElementById('vbots-ranges-prefixes').textContent = 'none loaded yet';
            return;
        }
        var parts = names.map(function (k) { return k + ': ' + prefixes[k]; });
        document.getElementById('vbots-ranges-prefixes').textContent = parts.join(', ');
    }

    function load() {
        CSM.get('/api/v1/verified-bots').then(function (data) {
            etag = data.etag || '';
            renderRanges(data.bot_ranges);
            listEl.innerHTML = '';
            (data.bots || []).forEach(addRow);
            updateVisibility();
        }).catch(function () {
            loadingEl.querySelector('.csm-empty__reason').textContent = 'Failed to load verified bots.';
        });
    }

    function save() {
        clearErrors();
        var bots = collect();
        CSM.request('/api/v1/verified-bots/apply', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': CSM.csrfToken,
                'If-Match': etag
            },
            body: JSON.stringify({ bots: bots }),
            allowNonOK: true,
            silent: true
        }).then(function (r) {
            return r.json().then(function (body) { return { status: r.status, body: body }; });
        }).then(function (res) {
            if (res.status === 200) {
                etag = res.body.new_etag || etag;
                CSM.toast('Saved ' + (res.body.count || 0) + ' verified bot(s)', 'success');
            } else if (res.status === 422) {
                showErrors(res.body.errors);
                CSM.toast('Validation failed — see highlighted entries', 'error');
            } else if (res.status === 412) {
                CSM.toast('Config changed on disk; reloading the current list', 'warning');
                load();
            } else {
                CSM.toast((res.body && res.body.error) || ('HTTP ' + res.status), 'error');
            }
        }).catch(function (err) {
            CSM.toast('Save failed: ' + err.message, 'error');
        });
    }

    document.getElementById('vbots-add').addEventListener('click', function () { addRow({}); });
    document.getElementById('vbots-save').addEventListener('click', save);
    listEl.addEventListener('click', function (e) {
        var btn = e.target.closest('.vb-remove');
        if (!btn) { return; }
        var row = btn.closest('.vbots-row');
        if (row) { row.remove(); }
        updateVisibility();
    });

    load();
})();
