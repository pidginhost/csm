/**
 * CSM Toast & Confirm - lightweight notification system.
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
    // An error stays until closed; other toasts fade after five seconds. An
    // error already on screen is not shown twice.
    CSM.toast = function(message, type) {
        type = type || 'info';
        var container = document.getElementById('csm-toasts');
        if (!container) return;
        var key = type + '\u0000' + message;
        if (type === 'error') {
            var shown = container.children;
            for (var s = 0; s < shown.length; s++) {
                if (shown[s]._csmKey === key && !shown[s]._csmRemoved) return;
            }
        }

        var bgClass = {
            success: 'bg-success',
            error:   'bg-danger',
            warning: 'bg-warning',
            info:    'bg-info'
        }[type] || 'bg-info';

        var textClass = (type === 'warning') ? 'text-dark' : 'text-white';

        var toast = document.createElement('div');
        toast._csmKey = key;
        toast.className = 'alert ' + bgClass + ' ' + textClass + ' d-flex align-items-center mb-2';
        // WEB_ROADMAP P4.2: errors interrupt with assertive so screen
        // readers announce them immediately; success/warning/info use
        // polite so they don't preempt the user mid-utterance.
        toast.setAttribute('role', type === 'error' ? 'alert' : 'status');
        toast.setAttribute('aria-live', type === 'error' ? 'assertive' : 'polite');
        toast.setAttribute('aria-atomic', 'true');
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

        if (type !== 'error') {
            toast._csmTimer = setTimeout(function() { removeToast(toast); }, 5000);
        }
    };

    ['success', 'error', 'warning', 'info'].forEach(function(type) {
        CSM.toast[type] = function(message) {
            CSM.toast(message, type);
        };
    });

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

    var activeDialogCancel = null;

    function cancelActiveDialog() {
        if (!activeDialogCancel) return;
        var cancel = activeDialogCancel;
        activeDialogCancel = null;
        cancel();
    }

    function restoreAlertDialogRole(modal) {
        if (!modal) return;
        modal.setAttribute('role', 'alertdialog');
    }

    function restoreAlertDialogRoleAfterShow(modal) {
        if (!modal || !modal.addEventListener) return;
        var shownHandler = function() {
            modal.removeEventListener('shown.bs.modal', shownHandler);
            restoreAlertDialogRole(modal);
        };
        modal.addEventListener('shown.bs.modal', shownHandler);
    }

    /**
     * Show a styled confirmation dialog.
     * @param  {string} message - The confirmation message (newlines preserved).
     * @return {Promise}        - Resolves on OK, rejects on Cancel.
     */
    // opts.danger marks an action that deletes data, blocks traffic, turns
    // protection off or ends sessions: the confirm button turns red, reads
    // opts.okLabel (the action's verb) and focus starts on Cancel so a stray
    // Enter does not carry it out.
    CSM.confirm = function(message, opts) {
        opts = opts || {};
        var danger = !!opts.danger;
        return new Promise(function(resolve, reject) {
            cancelActiveDialog();
            var modal = document.getElementById('csm-confirm-modal');
            var body  = document.getElementById('csm-confirm-body');
            var okBtn = document.getElementById('csm-confirm-ok');
            var noBtn = document.getElementById('csm-confirm-cancel');

            if (!modal || !body || !okBtn || !noBtn) {
                // Fallback to native confirm if DOM elements are missing
                if (confirm(message)) { resolve(); } else { reject(); }
                return;
            }

            okBtn.textContent = opts.okLabel || 'OK';
            okBtn.classList.toggle('btn-danger', danger);
            okBtn.classList.toggle('btn-primary', !danger);

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
                restoreAlertDialogRoleAfterShow(modal);
                bsModal.show();
                restoreAlertDialogRole(modal);
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

            var settled = false;
            function focusConfirm() {
                if (!settled) (danger ? noBtn : okBtn).focus();
            }
            // Bootstrap focuses the modal when its transition finishes.
            modal.addEventListener('shown.bs.modal', focusConfirm);

            function cleanup() {
                modal.removeEventListener('shown.bs.modal', focusConfirm);
                if (activeDialogCancel === cancelSelf) activeDialogCancel = null;
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

            function settle(fn) {
                if (settled) return;
                settled = true;
                cleanup();
                fn();
            }

            function cancelSelf() {
                settle(function() { reject(); });
            }

            function onOk() { settle(resolve); }
            function onCancel() { cancelSelf(); }
            function onKeydown(e) {
                if (e.key === 'Tab') {
                    // Trap focus between noBtn and okBtn
                    if (e.shiftKey && document.activeElement === noBtn) {
                        e.preventDefault(); okBtn.focus();
                    } else if (!e.shiftKey && document.activeElement === okBtn) {
                        e.preventDefault(); noBtn.focus();
                    }
                }
                if (e.key === 'Escape') { onCancel(); }
            }

            okBtn.addEventListener('click', onOk);
            noBtn.addEventListener('click', onCancel);
            document.addEventListener('keydown', onKeydown);
            activeDialogCancel = cancelSelf;
            focusConfirm();

            var _origCleanup = cleanup;
            cleanup = function() {
                document.removeEventListener('keydown', onKeydown);
                _origCleanup();
            };
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
            cancelActiveDialog();
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

            okBtn.textContent = 'OK';
            okBtn.classList.remove('btn-danger');
            okBtn.classList.add('btn-primary');

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
                restoreAlertDialogRoleAfterShow(modal);
                bsModal.show();
                restoreAlertDialogRole(modal);
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

            var settled = false;

            function cleanup() {
                if (activeDialogCancel === cancelSelf) activeDialogCancel = null;
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

            function settle(fn) {
                if (settled) return;
                settled = true;
                cleanup();
                fn();
            }

            function cancelSelf() {
                settle(function() { reject(); });
            }

            function onOk() {
                var value = input.value;
                settle(function() { resolve(value); });
            }
            function onCancel() { cancelSelf(); }
            function onKey(e) { if (e.key === 'Enter') { onOk(); } }

            okBtn.addEventListener('click', onOk);
            noBtn.addEventListener('click', onCancel);
            input.addEventListener('keydown', onKey);
            activeDialogCancel = cancelSelf;
        });
    };

})();
