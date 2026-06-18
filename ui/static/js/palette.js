// CSM Command Palette (WEB_ROADMAP P5.1).
//
// Ctrl/Cmd+K opens a modal palette listing every page in the sidebar
// and any registered command. Typing fuzzy-filters the list,
// ArrowUp/Down moves the selection, Enter activates it, Esc closes.
// The palette mounts itself on first open so layouts without nav (the
// login page) skip the overhead entirely.
var CSM = CSM || {};

CSM.palette = (function() {
    var entries = [];
    var overlay = null;
    var input = null;
    var listEl = null;
    var hintEl = null;
    var results = [];
    var selectedIndex = 0;
    var visible = false;
    var returnFocus = null;

    function isVisibleRoute(item) {
        return !item.hidden && !item.closest('[data-csm-admin-only][hidden]');
    }

    function collectEntries() {
        var items = document.querySelectorAll('#csm-nav [data-csm-route]');
        for (var i = 0; i < items.length; i++) {
            if (!isVisibleRoute(items[i])) continue;
            var link = items[i].querySelector('a.nav-link');
            if (!link) continue;
            var labelEl = link.querySelector('.nav-link-title');
            var iconEl = link.querySelector('.nav-link-icon i');
            entries.push({
                label: labelEl ? labelEl.textContent.trim() : link.textContent.trim(),
                href: link.getAttribute('href'),
                iconClass: iconEl ? iconEl.className : 'ti ti-arrow-right',
                group: items[i].closest('[data-csm-nav-group]') ? items[i].closest('[data-csm-nav-group]').getAttribute('data-csm-nav-group') : 'page'
            });
        }
    }

    function build() {
        if (overlay) return;
        overlay = document.createElement('div');
        overlay.id = 'csm-palette';
        overlay.className = 'csm-palette';
        overlay.setAttribute('role', 'dialog');
        overlay.setAttribute('aria-modal', 'true');
        overlay.setAttribute('aria-label', 'Command palette');
        overlay.style.display = 'none';

        var box = document.createElement('div');
        box.className = 'csm-palette__box';

        var inputWrap = document.createElement('div');
        inputWrap.className = 'csm-palette__inputwrap';
        var searchIcon = document.createElement('i');
        searchIcon.className = 'ti ti-search csm-palette__searchicon';
        searchIcon.setAttribute('aria-hidden', 'true');
        inputWrap.appendChild(searchIcon);

        input = document.createElement('input');
        input.type = 'text';
        input.className = 'csm-palette__input';
        input.setAttribute('placeholder', 'Jump to page');
        input.setAttribute('aria-label', 'Command palette search');
        input.setAttribute('aria-controls', 'csm-palette-list');
        input.setAttribute('aria-expanded', 'true');
        input.setAttribute('autocomplete', 'off');
        input.setAttribute('spellcheck', 'false');
        inputWrap.appendChild(input);
        box.appendChild(inputWrap);

        listEl = document.createElement('div');
        listEl.className = 'csm-palette__list';
        listEl.id = 'csm-palette-list';
        listEl.setAttribute('role', 'listbox');
        listEl.setAttribute('aria-label', 'Matching commands');
        box.appendChild(listEl);

        hintEl = document.createElement('div');
        hintEl.className = 'csm-palette__hint';
        hintEl.textContent = 'Up/Down Navigate | Enter Open | Esc Close';
        box.appendChild(hintEl);

        overlay.appendChild(box);
        overlay.addEventListener('click', function(ev) {
            if (ev.target === overlay) hide();
        });
        input.addEventListener('input', function() {
            render(input.value.trim());
        });

        document.body.appendChild(overlay);
    }

    function score(entry, query) {
        if (!query) return 0;
        var label = entry.label.toLowerCase();
        var q = query.toLowerCase();
        if (label === q) return 1000;
        if (label.indexOf(q) === 0) return 600 - label.length;
        if (label.indexOf(q) >= 0) return 300 - label.length;
        var li = 0;
        var qi = 0;
        while (li < label.length && qi < q.length) {
            if (label.charAt(li) === q.charAt(qi)) qi++;
            li++;
        }
        if (qi === q.length) return 60 - (label.length - q.length);
        return -1;
    }

    function render(query) {
        results = [];
        for (var i = 0; i < entries.length; i++) {
            var s = query ? score(entries[i], query) : 0;
            if (s < 0) continue;
            results.push({ entry: entries[i], score: s });
        }
        if (query) {
            results.sort(function(a, b) { return b.score - a.score; });
        }
        while (listEl.firstChild) listEl.removeChild(listEl.firstChild);

        if (results.length === 0) {
            var empty = document.createElement('div');
            empty.className = 'csm-palette__empty';
            empty.textContent = 'No matches';
            listEl.appendChild(empty);
            selectedIndex = -1;
            return;
        }

        for (var j = 0; j < results.length; j++) {
            var entry = results[j].entry;
            var row = document.createElement('button');
            row.type = 'button';
            row.className = 'csm-palette__row';
            row.setAttribute('role', 'option');
            row.dataset.idx = String(j);

            var rowIcon = document.createElement('i');
            rowIcon.className = entry.iconClass + ' csm-palette__rowicon';
            rowIcon.setAttribute('aria-hidden', 'true');
            row.appendChild(rowIcon);

            var rowLabel = document.createElement('span');
            rowLabel.className = 'csm-palette__rowlabel';
            rowLabel.textContent = entry.label;
            row.appendChild(rowLabel);

            var rowGroup = document.createElement('span');
            rowGroup.className = 'csm-palette__rowgroup';
            rowGroup.textContent = entry.group;
            row.appendChild(rowGroup);

            row.addEventListener('click', function(ev) {
                ev.preventDefault();
                go(Number(this.dataset.idx));
            });
            row.addEventListener('mousemove', function() {
                var idx = Number(this.dataset.idx);
                if (idx !== selectedIndex) select(idx);
            });
            listEl.appendChild(row);
        }
        select(0);
    }

    function select(idx) {
        var rows = listEl.querySelectorAll('.csm-palette__row');
        if (rows.length === 0) { selectedIndex = -1; return; }
        if (idx < 0) idx = rows.length - 1;
        if (idx >= rows.length) idx = 0;
        selectedIndex = idx;
        for (var i = 0; i < rows.length; i++) {
            rows[i].classList.toggle('is-selected', i === idx);
            rows[i].setAttribute('aria-selected', i === idx ? 'true' : 'false');
        }
        rows[idx].scrollIntoView({ block: 'nearest' });
    }

    function go(idx) {
        if (idx < 0 || idx >= results.length) return;
        var href = results[idx].entry.href;
        hide();
        if (href) window.location.href = href;
    }

    function show() {
        if (entries.length === 0) collectEntries();
        if (entries.length === 0) return;
        build();
        if (document.activeElement && document.activeElement !== document.body) {
            returnFocus = document.activeElement;
        }
        overlay.style.display = 'flex';
        visible = true;
        input.value = '';
        render('');
        setTimeout(function() { input.focus(); }, 0);
    }

    function hide() {
        if (!overlay) return;
        overlay.style.display = 'none';
        visible = false;
        if (returnFocus && document.contains(returnFocus) && typeof returnFocus.focus === 'function') {
            returnFocus.focus();
        }
        returnFocus = null;
    }

    function isVisible() { return visible; }

    document.addEventListener('keydown', function(ev) {
        if (ev.defaultPrevented && !visible) return;
        var mod = ev.metaKey || ev.ctrlKey;
        if (mod && (ev.key === 'k' || ev.key === 'K')) {
            ev.preventDefault();
            if (visible) { hide(); } else { show(); }
            return;
        }
        if (!visible) return;
        if (ev.key === 'Escape') { ev.preventDefault(); hide(); return; }
        if (ev.key === 'ArrowDown') { ev.preventDefault(); select(selectedIndex + 1); return; }
        if (ev.key === 'ArrowUp') { ev.preventDefault(); select(selectedIndex - 1); return; }
        if (ev.key === 'Enter') { ev.preventDefault(); go(selectedIndex); return; }
        if (ev.key === 'Tab') {
            CSM.focusTrap(overlay, ev);
            return;
        }
    });

    return { show: show, hide: hide, isVisible: isVisible };
})();
