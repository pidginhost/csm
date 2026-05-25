// CSM.savedViews - per-page named filter views (WEB_ROADMAP P5.2).
//
// Each page that exposes filter state in its query string can opt into the
// "Saved views" dropdown by including:
//
//   <div data-csm-saved-views="findings" class="csm-saved-views"></div>
//
// in its toolbar. On boot, this module finds every element with
// data-csm-saved-views, mounts a dropdown, and wires "Save current view" and
// "Delete" actions through /api/v1/prefs/views.
//
// Restoring a view writes its captured params to CSM.urlState.replace, which
// resets every filter input via the existing bind() mechanism and triggers
// the page's data refresh.
var CSM = CSM || {};

CSM.savedViews = (function() {
    function makeIcon(name) {
        var i = document.createElement('i');
        i.className = 'ti ti-' + name;
        i.setAttribute('aria-hidden', 'true');
        return i;
    }

    function listViews(page) {
        return CSM.request('/api/v1/prefs/views?page=' + encodeURIComponent(page), {
            headers: { Accept: 'application/json' },
            allowNonOK: true,
            silent: true
        }).then(function(r) {
            return r && r.ok ? r.json() : [];
        }).catch(function() { return []; });
    }

    function saveView(page, name, params) {
        return CSM.request('/api/v1/prefs/views', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
                Accept: 'application/json',
                'X-CSRF-Token': CSM.csrfToken
            },
            body: JSON.stringify({ page: page, name: name, params: params })
        });
    }

    function deleteView(page, name) {
        return CSM.request('/api/v1/prefs/views', {
            method: 'DELETE',
            headers: {
                'Content-Type': 'application/json',
                Accept: 'application/json',
                'X-CSRF-Token': CSM.csrfToken
            },
            body: JSON.stringify({ page: page, name: name })
        });
    }

    function captureParams() {
        var url = new URL(window.location.href);
        var out = {};
        url.searchParams.forEach(function(value, key) {
            if (value === '') return;
            out[key] = value;
        });
        return out;
    }

    function applyParams(params) {
        if (typeof CSM === 'undefined' || !CSM.urlState) return;
        CSM.urlState.replace(params || {});
    }

    function buildDropdown(host, page, views) {
        host.replaceChildren();
        host.classList.add('csm-saved-views', 'dropdown');

        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-ghost-secondary btn-sm dropdown-toggle';
        btn.setAttribute('data-bs-toggle', 'dropdown');
        btn.setAttribute('aria-expanded', 'false');
        btn.setAttribute('aria-label', 'Saved views');
        btn.appendChild(makeIcon('bookmark'));
        var label = document.createElement('span');
        label.className = 'ms-1';
        label.textContent = views.length > 0 ? 'Views (' + views.length + ')' : 'Views';
        btn.appendChild(label);
        host.appendChild(btn);

        var menu = document.createElement('div');
        menu.className = 'dropdown-menu dropdown-menu-end csm-saved-views__menu';
        host.appendChild(menu);

        if (views.length === 0) {
            var empty = document.createElement('div');
            empty.className = 'dropdown-item-text text-muted small';
            empty.textContent = 'No saved views yet';
            menu.appendChild(empty);
            menu.appendChild(divider());
        } else {
            views.forEach(function(view) {
                menu.appendChild(buildViewRow(view, host, page));
            });
            menu.appendChild(divider());
        }

        var save = document.createElement('button');
        save.type = 'button';
        save.className = 'dropdown-item d-flex align-items-center gap-1';
        save.appendChild(makeIcon('bookmark-plus'));
        var saveLabel = document.createElement('span');
        saveLabel.textContent = 'Save current as...';
        save.appendChild(saveLabel);
        save.addEventListener('click', function(ev) {
            ev.preventDefault();
            promptSave(host, page);
        });
        menu.appendChild(save);
    }

    function buildViewRow(view, host, page) {
        var row = document.createElement('div');
        row.className = 'dropdown-item d-flex align-items-center justify-content-between gap-2';
        row.setAttribute('role', 'group');

        var apply = document.createElement('button');
        apply.type = 'button';
        apply.className = 'btn btn-link p-0 text-decoration-none text-start flex-grow-1';
        apply.textContent = view.name;
        apply.title = 'Apply view';
        apply.addEventListener('click', function(ev) {
            ev.preventDefault();
            applyParams(view.params);
            if (typeof CSM !== 'undefined' && CSM.toast) {
                CSM.toast.info('Applied view: ' + view.name);
            }
        });

        var trash = document.createElement('button');
        trash.type = 'button';
        trash.className = 'btn btn-link p-0 text-danger';
        trash.setAttribute('aria-label', 'Delete view');
        trash.appendChild(makeIcon('trash'));
        trash.addEventListener('click', function(ev) {
            ev.preventDefault();
            ev.stopPropagation();
            confirmDelete(view, host, page);
        });

        row.appendChild(apply);
        row.appendChild(trash);
        return row;
    }

    function divider() {
        var hr = document.createElement('div');
        hr.className = 'dropdown-divider';
        return hr;
    }

    function promptSave(host, page) {
        var nameInput = window.prompt('Save current filters as:', '');
        if (nameInput == null) return;
        var name = String(nameInput).trim();
        if (!name) return;
        if (name.length > 80) {
            if (CSM && CSM.toast) CSM.toast.error('Name must be 80 characters or fewer');
            return;
        }
        var params = captureParams();
        saveView(page, name, params).then(function(r) {
            if (!r || !r.ok) {
                throw new Error('save failed');
            }
            if (CSM && CSM.toast) CSM.toast.success('Saved view: ' + name);
            return refreshHost(host, page);
        }).catch(function() {
            if (CSM && CSM.toast) CSM.toast.error('Could not save view');
        });
    }

    function confirmDelete(view, host, page) {
        var go = function() {
            deleteView(page, view.name).then(function(r) {
                if (!r || !r.ok) throw new Error('delete failed');
                if (CSM && CSM.toast) CSM.toast.success('Deleted view: ' + view.name);
                return refreshHost(host, page);
            }).catch(function() {
                if (CSM && CSM.toast) CSM.toast.error('Could not delete view');
            });
        };
        if (CSM && CSM.confirm) {
            CSM.confirm('Delete saved view "' + view.name + '"?').then(function() {
                go();
            }).catch(function() {});
        } else if (window.confirm('Delete saved view "' + view.name + '"?')) {
            go();
        }
    }

    function refreshHost(host, page) {
        return listViews(page).then(function(views) {
            buildDropdown(host, page, views);
            return views;
        });
    }

    function mount(host, page) {
        if (!host || !page) return;
        host.dataset.csmSavedViewsMounted = '1';
        refreshHost(host, page);
    }

    // Pages whose query string carries operator-facing filter state. The
    // topbar dropdown auto-mounts on these pages; other pages can still opt
    // in by adding their own data-csm-saved-views element to a toolbar.
    var AUTO_MOUNT_PAGES = {
        audit: true,
        email: true,
        findings: true,
        firewall: true,
        incident: true,
        modsec: true,
        'modsec-rules': true,
        quarantine: true,
        threat: true
    };

    function init() {
        var hosts = document.querySelectorAll('[data-csm-saved-views]');
        hosts.forEach(function(host) {
            if (host.dataset.csmSavedViewsMounted === '1') return;
            var page = host.getAttribute('data-csm-saved-views') || '';
            mount(host, page);
        });

        // Auto-mount the topbar host when the current page is on the
        // filter-state allow-list above.
        var auto = document.querySelector('[data-csm-saved-views-auto]');
        if (auto && auto.dataset.csmSavedViewsMounted !== '1') {
            var page = document.body && document.body.getAttribute('data-csm-page');
            if (page && AUTO_MOUNT_PAGES[page]) {
                auto.setAttribute('data-csm-saved-views', page);
                auto.classList.remove('d-none');
                mount(auto, page);
            }
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    return {
        init: init,
        mount: mount,
        list: listViews,
        save: saveView,
        delete: deleteView
    };
})();
