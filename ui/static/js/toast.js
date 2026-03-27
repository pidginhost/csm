/**
 * CSM Toast & Confirm — lightweight notification system.
 * No external dependencies. ES5 compatible.
 */
(function() {
    'use strict';

    window.CSM = window.CSM || {};

    // ---- Toast notifications ----

    /**
     * Show a toast notification.
     * @param {string} message - The message to display.
     * @param {string} type    - 'success' | 'error' | 'warning' | 'info'
     */
    CSM.toast = function(message, type) {
        type = type || 'info';
        var container = document.getElementById('csm-toasts');
        if (!container) return;

        var bgClass = {
            success: 'bg-success',
            error:   'bg-danger',
            warning: 'bg-warning',
            info:    'bg-info'
        }[type] || 'bg-info';

        var textClass = (type === 'warning') ? 'text-dark' : 'text-white';

        var toast = document.createElement('div');
        toast.className = 'alert ' + bgClass + ' ' + textClass + ' d-flex align-items-center mb-2';
        toast.setAttribute('role', 'alert');
        toast.style.cssText = 'min-width:280px;max-width:400px;box-shadow:0 4px 12px rgba(0,0,0,.25);opacity:0;transition:opacity .25s ease;word-break:break-word;padding:.75rem 1rem;margin:0 0 .5rem 0;border:0;border-radius:.375rem;';

        var msgSpan = document.createElement('span');
        msgSpan.style.cssText = 'flex:1;white-space:pre-line;';
        msgSpan.textContent = message;

        var closeBtn = document.createElement('button');
        closeBtn.type = 'button';
        closeBtn.className = 'btn-close' + (type !== 'warning' ? ' btn-close-white' : '');
        closeBtn.style.cssText = 'margin-left:.75rem;flex-shrink:0;';
        closeBtn.setAttribute('aria-label', 'Close');
        closeBtn.addEventListener('click', function() { removeToast(toast); });

        toast.appendChild(msgSpan);
        toast.appendChild(closeBtn);
        container.appendChild(toast);

        // Fade in
        requestAnimationFrame(function() {
            requestAnimationFrame(function() {
                toast.style.opacity = '1';
            });
        });

        // Auto-dismiss after 5 seconds
        var timer = setTimeout(function() { removeToast(toast); }, 5000);
        toast._csmTimer = timer;
    };

    function removeToast(el) {
        if (el._csmRemoved) return;
        el._csmRemoved = true;
        clearTimeout(el._csmTimer);
        el.style.opacity = '0';
        setTimeout(function() {
            if (el.parentNode) el.parentNode.removeChild(el);
        }, 300);
    }

    // ---- Confirm modal ----

    /**
     * Show a styled confirmation dialog.
     * @param  {string} message - The confirmation message (newlines preserved).
     * @return {Promise}        - Resolves on OK, rejects on Cancel.
     */
    CSM.confirm = function(message) {
        return new Promise(function(resolve, reject) {
            var modal = document.getElementById('csm-confirm-modal');
            var body  = document.getElementById('csm-confirm-body');
            var okBtn = document.getElementById('csm-confirm-ok');
            var noBtn = document.getElementById('csm-confirm-cancel');

            if (!modal || !body || !okBtn || !noBtn) {
                // Fallback to native confirm if DOM elements are missing
                if (confirm(message)) { resolve(); } else { reject(); }
                return;
            }

            body.textContent = '';
            // Preserve newlines by splitting into text nodes with <br>
            var lines = message.split('\n');
            for (var i = 0; i < lines.length; i++) {
                if (i > 0) body.appendChild(document.createElement('br'));
                body.appendChild(document.createTextNode(lines[i]));
            }

            // Show modal using Bootstrap modal API if available, otherwise manual
            var bsModal;
            if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
                bsModal = bootstrap.Modal.getOrCreateInstance(modal, { backdrop: 'static', keyboard: false });
                bsModal.show();
            } else {
                modal.style.display = 'block';
                modal.classList.add('show');
                document.body.classList.add('modal-open');
                // Add backdrop
                var backdrop = document.createElement('div');
                backdrop.className = 'modal-backdrop fade show';
                backdrop.id = 'csm-confirm-backdrop';
                document.body.appendChild(backdrop);
            }

            function cleanup() {
                okBtn.removeEventListener('click', onOk);
                noBtn.removeEventListener('click', onCancel);
                if (bsModal) {
                    bsModal.hide();
                } else {
                    modal.style.display = 'none';
                    modal.classList.remove('show');
                    document.body.classList.remove('modal-open');
                    var bd = document.getElementById('csm-confirm-backdrop');
                    if (bd && bd.parentNode) bd.parentNode.removeChild(bd);
                }
            }

            function onOk() { cleanup(); resolve(); }
            function onCancel() { cleanup(); reject(); }

            okBtn.addEventListener('click', onOk);
            noBtn.addEventListener('click', onCancel);
        });
    };

    /**
     * Show a styled prompt dialog.
     * @param  {string} message      - The prompt message.
     * @param  {string} defaultValue - Default input value.
     * @return {Promise}             - Resolves with entered value, rejects on Cancel.
     */
    CSM.prompt = function(message, defaultValue) {
        return new Promise(function(resolve, reject) {
            var modal  = document.getElementById('csm-confirm-modal');
            var body   = document.getElementById('csm-confirm-body');
            var okBtn  = document.getElementById('csm-confirm-ok');
            var noBtn  = document.getElementById('csm-confirm-cancel');

            if (!modal || !body || !okBtn || !noBtn) {
                // Fallback
                var val = prompt(message, defaultValue || '');
                if (val !== null) { resolve(val); } else { reject(); }
                return;
            }

            body.textContent = '';
            var lines = message.split('\n');
            for (var i = 0; i < lines.length; i++) {
                if (i > 0) body.appendChild(document.createElement('br'));
                body.appendChild(document.createTextNode(lines[i]));
            }
            var input = document.createElement('input');
            input.type = 'text';
            input.className = 'form-control form-control-sm mt-2';
            input.value = defaultValue || '';
            body.appendChild(input);

            var bsModal;
            if (typeof bootstrap !== 'undefined' && bootstrap.Modal) {
                bsModal = bootstrap.Modal.getOrCreateInstance(modal, { backdrop: 'static', keyboard: false });
                bsModal.show();
            } else {
                modal.style.display = 'block';
                modal.classList.add('show');
                document.body.classList.add('modal-open');
                var backdrop = document.createElement('div');
                backdrop.className = 'modal-backdrop fade show';
                backdrop.id = 'csm-confirm-backdrop';
                document.body.appendChild(backdrop);
            }

            setTimeout(function() { input.focus(); input.select(); }, 100);

            function cleanup() {
                okBtn.removeEventListener('click', onOk);
                noBtn.removeEventListener('click', onCancel);
                input.removeEventListener('keydown', onKey);
                if (bsModal) {
                    bsModal.hide();
                } else {
                    modal.style.display = 'none';
                    modal.classList.remove('show');
                    document.body.classList.remove('modal-open');
                    var bd = document.getElementById('csm-confirm-backdrop');
                    if (bd && bd.parentNode) bd.parentNode.removeChild(bd);
                }
            }

            function onOk() { cleanup(); resolve(input.value); }
            function onCancel() { cleanup(); reject(); }
            function onKey(e) { if (e.key === 'Enter') { onOk(); } }

            okBtn.addEventListener('click', onOk);
            noBtn.addEventListener('click', onCancel);
            input.addEventListener('keydown', onKey);
        });
    };

})();
