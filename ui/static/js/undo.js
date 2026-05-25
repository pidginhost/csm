// CSM.undo - bulk-action undo banner (WEB_ROADMAP P5.3).
//
// After a bulk handler (firewall unblock, threat block, threat whitelist, ...)
// returns an `undo_token`, the calling page hands the token to CSM.undo.offer,
// which floats a small banner with a 30-second countdown. Clicking Undo POSTs
// to /api/v1/undo/run, which consumes the matching server-side entry and
// dispatches the inverse operation. The banner self-dismisses when the timer
// elapses or the operator clicks Dismiss.
var CSM = CSM || {};

CSM.undo = (function() {
    var BANNER_ID = 'csm-undo-banner';
    var TTL_MS = 30 * 1000;
    var current = null;

    function makeIcon(name) {
        var i = document.createElement('i');
        i.className = 'ti ti-' + name;
        i.setAttribute('aria-hidden', 'true');
        return i;
    }

    function ensureBanner() {
        var banner = document.getElementById(BANNER_ID);
        if (banner) return banner;
        banner = document.createElement('div');
        banner.id = BANNER_ID;
        banner.className = 'csm-undo-banner d-none';
        banner.setAttribute('role', 'status');
        banner.setAttribute('aria-live', 'polite');

        var icon = makeIcon('arrow-back-up');
        icon.classList.add('csm-undo-banner__icon');
        banner.appendChild(icon);

        var label = document.createElement('span');
        label.className = 'csm-undo-banner__label';
        banner.appendChild(label);

        var timer = document.createElement('span');
        timer.className = 'csm-undo-banner__timer text-muted ms-2';
        banner.appendChild(timer);

        var undoBtn = document.createElement('button');
        undoBtn.type = 'button';
        undoBtn.className = 'btn btn-sm btn-primary ms-3 csm-undo-banner__undo';
        undoBtn.textContent = 'Undo';
        banner.appendChild(undoBtn);

        var dismissBtn = document.createElement('button');
        dismissBtn.type = 'button';
        dismissBtn.className = 'btn btn-sm btn-ghost-secondary ms-1 csm-undo-banner__dismiss';
        dismissBtn.setAttribute('aria-label', 'Dismiss');
        dismissBtn.appendChild(makeIcon('x'));
        banner.appendChild(dismissBtn);

        document.body.appendChild(banner);
        return banner;
    }

    function hide() {
        if (!current) return;
        if (current.intervalId) clearInterval(current.intervalId);
        if (current.banner) current.banner.classList.add('d-none');
        current = null;
    }

    function tick(state) {
        var remainingMs = state.expiresAt - Date.now();
        if (remainingMs <= 0) {
            hide();
            return;
        }
        var s = Math.ceil(remainingMs / 1000);
        state.timerEl.textContent = '(' + s + 's)';
    }

    function offer(opts) {
        opts = opts || {};
        if (!opts.token) return;
        var label = opts.label || 'Action complete';
        hide();
        var banner = ensureBanner();
        var labelEl = banner.querySelector('.csm-undo-banner__label');
        var timerEl = banner.querySelector('.csm-undo-banner__timer');
        var undoBtn = banner.querySelector('.csm-undo-banner__undo');
        var dismissBtn = banner.querySelector('.csm-undo-banner__dismiss');
        labelEl.textContent = label + '. Undo within 30 seconds?';

        var ttl = (typeof opts.expiresInMs === 'number' && opts.expiresInMs > 0) ? opts.expiresInMs : TTL_MS;
        var state = {
            banner: banner,
            timerEl: timerEl,
            expiresAt: Date.now() + ttl,
            intervalId: null
        };
        current = state;
        tick(state);
        state.intervalId = setInterval(function() { tick(state); }, 1000);

        var newUndo = undoBtn.cloneNode(true);
        undoBtn.parentNode.replaceChild(newUndo, undoBtn);
        newUndo.addEventListener('click', function(ev) {
            ev.preventDefault();
            run(opts.token, label);
        });

        var newDismiss = dismissBtn.cloneNode(true);
        dismissBtn.parentNode.replaceChild(newDismiss, dismissBtn);
        newDismiss.addEventListener('click', function(ev) {
            ev.preventDefault();
            hide();
        });

        banner.classList.remove('d-none');
    }

    function run(token, label) {
        var banner = current && current.banner;
        var undoBtn = banner ? banner.querySelector('.csm-undo-banner__undo') : null;
        if (undoBtn) {
            undoBtn.disabled = true;
            undoBtn.textContent = 'Undoing...';
        }
        return CSM.request('/api/v1/undo/run', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                Accept: 'application/json',
                'X-CSRF-Token': CSM.csrfToken
            },
            body: JSON.stringify({ id: token || '' }),
            allowNonOK: true
        }).then(function(r) {
            if (!r) {
                throw new Error('undo failed');
            }
            if (r.status === 410) {
                throw new Error('expired');
            }
            if (!r.ok) {
                throw new Error('undo failed');
            }
            return r.json();
        }).then(function(resp) {
            hide();
            if (CSM && CSM.toast) {
                CSM.toast.success((label || 'Action') + ' undone (' + (resp.count || 0) + ' items)');
            }
            window.dispatchEvent(new CustomEvent('csm:undo-applied', { detail: resp }));
            // Reload so the page reflects the inverse state without
            // every per-page caller needing to register a refresh handler.
            setTimeout(function() { window.location.reload(); }, 600);
        }).catch(function(err) {
            hide();
            if (CSM && CSM.toast) {
                var msg = err && err.message === 'expired' ? 'Undo window expired' : 'Undo failed';
                CSM.toast.error(msg);
            }
        });
    }

    // On every page load, ask the server whether a recent undo entry is
    // still pending for this operator. Bulk actions that trigger a page
    // reload (firewall, threat) lose their in-memory banner, so the server
    // remains the source of truth for "is there anything left to undo".
    function pollPending() {
        if (typeof CSM === 'undefined' || !CSM.request) return;
        CSM.request('/api/v1/undo/pending', {
            headers: { Accept: 'application/json' },
            allowNonOK: true,
            silent: true
        }).then(function(r) {
            return r && r.ok ? r.json() : null;
        }).then(function(entry) {
            if (!entry || !entry.id || !entry.expires_at) return;
            var expires = Date.parse(entry.expires_at);
            if (!isFinite(expires) || expires <= Date.now()) return;
            var remaining = expires - Date.now();
            offer({ token: entry.id, label: entry.summary || 'Recent action', expiresInMs: remaining });
        }).catch(function() { /* poll is opportunistic */ });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', pollPending);
    } else {
        pollPending();
    }

    return {
        offer: offer,
        run: run,
        hide: hide,
        refresh: pollPending
    };
})();
