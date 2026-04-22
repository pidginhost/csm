(function () {
    "use strict";

    // ---- Section group metadata ------------------------------------------
    // Keep in sync with SectionGroupOrder in settings_schema.go.
    const GROUP_ORDER = ["Alerting", "Detection", "Integrations", "Operations"];
    const GROUP_ICON = {
        "Alerting": "ti-bell-ringing",
        "Detection": "ti-radar",
        "Integrations": "ti-plug",
        "Operations": "ti-adjustments-horizontal"
    };

    // ---- State -----------------------------------------------------------
    let sections = [];
    let currentSection = null;
    let currentETag = null;
    let currentSchema = null;
    let initialValues = {};
    let dirty = false;
    const dirtySections = new Set();

    function csrfToken() {
        const meta = document.querySelector('meta[name="csrf-token"]');
        return meta ? meta.content : "";
    }

    function byId(id) { return document.getElementById(id); }
    function clearNode(el) { while (el && el.firstChild) el.removeChild(el.firstChild); }

    function iconEl(name, extraClass) {
        const i = document.createElement("i");
        i.className = "ti " + name + (extraClass ? " " + extraClass : "");
        return i;
    }
    function btnWithIcon(text, iconName, cls) {
        const b = document.createElement("button");
        b.type = "button";
        b.className = cls;
        b.appendChild(iconEl("ti-" + iconName, "me-1"));
        b.appendChild(document.createTextNode(text));
        return b;
    }

    function toast(msg, type) {
        if (window.CSM && CSM.toast) { CSM.toast(msg, type || "info"); }
    }

    // ---- Section list ----------------------------------------------------
    function loadSections() {
        // Keep in sync with settingsSections in internal/webui/settings_schema.go.
        sections = [
            {id: "alerts",           title: "Alerts",           group: "Alerting",     icon: "bell"},
            {id: "thresholds",       title: "Thresholds",       group: "Alerting",     icon: "adjustments"},
            {id: "suppressions",     title: "Suppressions",     group: "Alerting",     icon: "volume-off"},
            {id: "auto_response",    title: "Auto-Response",    group: "Detection",    icon: "bolt"},
            {id: "email_protection", title: "Email Protection", group: "Detection",    icon: "mail-shield"},
            {id: "challenge",        title: "Challenge",        group: "Detection",    icon: "user-question"},
            {id: "php_shield",       title: "PHP Shield",       group: "Detection",    icon: "brand-php"},
            {id: "signatures",       title: "Signatures",       group: "Detection",    icon: "scan"},
            {id: "email_av",         title: "Email AV",         group: "Detection",    icon: "virus"},
            {id: "modsec",           title: "ModSecurity",      group: "Detection",    icon: "shield-lock"},
            {id: "reputation",       title: "Reputation",       group: "Integrations", icon: "shield-check"},
            {id: "cloudflare",       title: "Cloudflare",       group: "Integrations", icon: "cloud"},
            {id: "geoip",            title: "GeoIP",            group: "Integrations", icon: "world"},
            {id: "sentry",           title: "Sentry",           group: "Integrations", icon: "bug"},
            {id: "performance",      title: "Performance",      group: "Operations",   icon: "activity"},
            {id: "infra_ips",        title: "Infra IPs",        group: "Operations",   icon: "server"}
        ];
    }

    // ---- Nav rendering ---------------------------------------------------
    function renderNav() {
        const nav = byId("settings-nav");
        clearNode(nav);
        GROUP_ORDER.forEach(function (group) {
            const inGroup = sections.filter(function (s) { return s.group === group; });
            if (inGroup.length === 0) return;

            const header = document.createElement("div");
            header.className = "settings-nav-group-header";
            header.appendChild(iconEl(GROUP_ICON[group] || "ti-circle", "me-2"));
            header.appendChild(document.createTextNode(group));
            nav.appendChild(header);

            inGroup.forEach(function (s) {
                const item = document.createElement("a");
                item.className = "settings-nav-link";
                item.href = "#" + s.id;
                item.dataset.section = s.id;
                item.appendChild(iconEl("ti-" + s.icon));
                const label = document.createElement("span");
                label.className = "settings-nav-label";
                label.textContent = s.title;
                item.appendChild(label);
                const dot = document.createElement("span");
                dot.className = "settings-nav-dirty-dot";
                dot.title = "Unsaved changes";
                item.appendChild(dot);
                item.addEventListener("click", function (ev) {
                    ev.preventDefault();
                    if (!confirmLeaveIfDirty()) return;
                    loadSection(s.id);
                });
                nav.appendChild(item);
            });
        });
    }

    function setActiveNav(id) {
        document.querySelectorAll(".settings-nav-link").forEach(function (el) {
            el.classList.toggle("active", el.dataset.section === id);
        });
    }

    function refreshDirtyMarkers() {
        document.querySelectorAll(".settings-nav-link").forEach(function (el) {
            el.classList.toggle("is-dirty", dirtySections.has(el.dataset.section));
        });
    }

    function confirmLeaveIfDirty() {
        if (!dirty) return true;
        return window.confirm("You have unsaved changes in this section. Discard them?");
    }

    // ---- Section loader --------------------------------------------------
    async function loadSection(id) {
        setActiveNav(id);
        window.location.hash = "#" + id;

        const panel = byId("settings-panel");
        clearNode(panel);
        const loading = document.createElement("div");
        loading.className = "settings-loading";
        const spinner = document.createElement("div");
        spinner.className = "spinner-border spinner-border-sm text-muted me-2";
        spinner.setAttribute("role", "status");
        loading.appendChild(spinner);
        loading.appendChild(document.createTextNode("Loading..."));
        panel.appendChild(loading);

        let resp;
        try {
            resp = await fetch("/api/v1/settings/" + encodeURIComponent(id), {headers: {Accept: "application/json"}});
        } catch (e) {
            renderError("Network error: " + (e && e.message ? e.message : "request failed"));
            return;
        }
        if (!resp.ok) { renderError("Failed to load: " + resp.status); return; }
        const data = await resp.json();
        currentSection = id;
        currentETag = data.etag;
        currentSchema = data.section;
        initialValues = JSON.parse(JSON.stringify(data.values || {}));
        dirty = false;
        dirtySections.delete(id);
        refreshDirtyMarkers();
        renderForm(data);
    }

    function renderError(msg) {
        const panel = byId("settings-panel");
        clearNode(panel);
        const alert = document.createElement("div");
        alert.className = "alert alert-danger m-3";
        alert.textContent = msg;
        panel.appendChild(alert);
    }

    // ---- Form rendering --------------------------------------------------
    function renderForm(data) {
        const panel = byId("settings-panel");
        clearNode(panel);

        // Header
        const header = document.createElement("div");
        header.className = "settings-panel-header";
        const h = document.createElement("h3");
        h.className = "settings-panel-title";
        h.appendChild(iconEl("ti-" + (sectionMeta(data.section.id).icon || "settings")));
        h.appendChild(document.createTextNode(" " + data.section.title));
        header.appendChild(h);

        const restartBadge = document.createElement("span");
        restartBadge.className = "badge " + (data.section.restart_hint ? "bg-orange-lt" : "bg-green-lt");
        restartBadge.textContent = data.section.restart_hint ? "Restart required" : "Applies live";
        header.appendChild(restartBadge);
        panel.appendChild(header);

        // Pending-restart notice
        if (data.pending_restart) {
            const b = document.createElement("div");
            b.className = "alert alert-warning mx-3 mt-3 mb-0";
            b.textContent = "Saved on disk. Running daemon still uses previous values until restart. Pending: " + ((data.pending_fields || []).join(", "));
            panel.appendChild(b);
        }

        // Form body: scalars in a two-column grid; wide types span full row
        const body = document.createElement("div");
        body.className = "settings-panel-body";
        const grid = document.createElement("div");
        grid.className = "settings-field-grid";
        data.section.fields.forEach(function (field) {
            const cell = fieldRow(field, lookupValue(data.values || {}, field.yaml_path));
            cell.classList.add(isWideField(field) ? "settings-field-wide" : "settings-field-half");
            grid.appendChild(cell);
        });
        body.appendChild(grid);
        panel.appendChild(body);

        // Footer actions
        const footer = document.createElement("div");
        footer.className = "settings-panel-footer";
        const btn = btnWithIcon("Save", "device-floppy", "btn btn-primary");
        btn.id = "settings-save";
        btn.addEventListener("click", save);
        const btnReset = btnWithIcon("Discard", "arrow-back", "btn btn-ghost-secondary ms-2");
        btnReset.id = "settings-reset";
        btnReset.addEventListener("click", function () {
            if (!dirty) return;
            if (!confirmLeaveIfDirty()) return;
            loadSection(currentSection);
        });
        footer.appendChild(btn);
        footer.appendChild(btnReset);
        panel.appendChild(footer);

        attachDirtyListeners();
    }

    function sectionMeta(id) {
        for (let i = 0; i < sections.length; i++) {
            if (sections[i].id === id) return sections[i];
        }
        return {};
    }

    function isWideField(field) {
        return field.type === "[]string" || field.type === "[]enum";
    }

    function lookupValue(values, path) {
        if (path === "") return values[currentSchema.yaml_path];
        const parts = path.split(".");
        let cur = values;
        for (let i = 0; i < parts.length; i++) {
            if (cur === null || cur === undefined) return undefined;
            cur = cur[parts[i]];
        }
        return cur;
    }

    function fieldId(field) {
        return "f_" + (field.yaml_path || "root").replace(/\./g, "_");
    }

    function fieldRow(field, value) {
        const wrapper = document.createElement("div");
        wrapper.className = "settings-field";
        const id = fieldId(field);

        if (field.type === "bool" && !field.nullable) {
            wrapper.classList.add("settings-field-toggle");
            const lbl = document.createElement("label");
            lbl.className = "form-check form-switch mb-0";
            const inp = document.createElement("input");
            inp.className = "form-check-input";
            inp.type = "checkbox";
            inp.id = id;
            inp.checked = !!value;
            const sp = document.createElement("span");
            sp.className = "form-check-label";
            sp.textContent = field.label;
            lbl.appendChild(inp);
            lbl.appendChild(sp);
            wrapper.appendChild(lbl);
            if (field.help) appendHint(wrapper, field.help);
            return wrapper;
        }

        const lbl = document.createElement("label");
        lbl.className = "form-label";
        lbl.setAttribute("for", id);
        lbl.textContent = field.label;
        if (field.secret) {
            const lock = iconEl("ti-lock", "ms-1 text-muted");
            lock.title = "Secret field";
            lbl.appendChild(lock);
        }
        wrapper.appendChild(lbl);

        let inp;
        if (field.type === "int") {
            inp = document.createElement("input");
            inp.className = "form-control";
            inp.type = "number";
            inp.id = id;
            inp.value = (value === undefined || value === null) ? "" : value;
            if (field.min !== undefined && field.min !== null) inp.min = field.min;
            if (field.max !== undefined && field.max !== null) inp.max = field.max;
        } else if (field.type === "float") {
            inp = document.createElement("input");
            inp.className = "form-control";
            inp.type = "number";
            inp.step = "any";
            inp.id = id;
            inp.value = (value === undefined || value === null) ? "" : value;
        } else if (field.type === "[]string") {
            inp = document.createElement("textarea");
            inp.className = "form-control";
            inp.id = id;
            inp.rows = 4;
            if (field.placeholder) inp.placeholder = field.placeholder;
            inp.value = Array.isArray(value) ? value.join("\n") : "";
        } else if (field.type === "[]enum") {
            inp = buildMultiSelect(id, field, Array.isArray(value) ? value : []);
        } else if (field.type === "enum") {
            inp = document.createElement("select");
            inp.className = "form-select";
            inp.id = id;
            (field.options || []).forEach(function (o) {
                const opt = document.createElement("option");
                opt.value = o;
                opt.textContent = o;
                if (o === value) opt.selected = true;
                inp.appendChild(opt);
            });
        } else if (field.type === "bool" && field.nullable) {
            inp = document.createElement("select");
            inp.className = "form-select";
            inp.id = id;
            const triOpts = [["", "Default"], ["true", "Enabled"], ["false", "Disabled"]];
            triOpts.forEach(function (pair) {
                const opt = document.createElement("option");
                opt.value = pair[0];
                opt.textContent = pair[1];
                const v = value === null || value === undefined ? "" : String(Boolean(value));
                if (pair[0] === v) opt.selected = true;
                inp.appendChild(opt);
            });
        } else {
            inp = document.createElement("input");
            inp.className = "form-control";
            inp.type = field.secret ? "password" : "text";
            inp.id = id;
            if (field.secret) {
                inp.placeholder = "(unchanged — type to replace)";
                inp.value = "";
            } else {
                if (field.placeholder) inp.placeholder = field.placeholder;
                inp.value = (value === undefined || value === null) ? "" : String(value);
            }
        }
        wrapper.appendChild(inp);
        if (field.help) appendHint(wrapper, field.help);
        return wrapper;
    }

    function appendHint(wrapper, text) {
        const hint = document.createElement("div");
        hint.className = "form-hint";
        hint.textContent = text;
        wrapper.appendChild(hint);
    }

    // ---- Multi-select (tag-pill + searchable menu) ----------------------
    function buildMultiSelect(id, field, initialSelected) {
        const root = document.createElement("div");
        root.className = "csm-multi";
        root.id = id;
        root.tabIndex = -1;
        root.dataset.type = "[]enum";

        const control = document.createElement("div");
        control.className = "csm-multi-control form-control";

        const chipsEl = document.createElement("div");
        chipsEl.className = "csm-multi-chips";
        control.appendChild(chipsEl);

        const search = document.createElement("input");
        search.type = "text";
        search.className = "csm-multi-search";
        search.placeholder = initialSelected.length ? "Add…" : "Search and add…";
        search.setAttribute("aria-label", field.label);
        control.appendChild(search);

        control.appendChild(iconEl("ti-chevron-down", "csm-multi-caret"));

        const menu = document.createElement("div");
        menu.className = "csm-multi-menu";
        menu.setAttribute("role", "listbox");

        root.appendChild(control);
        root.appendChild(menu);

        const selected = initialSelected.slice();
        const selectedSet = new Set(selected);
        let highlightIdx = -1;
        let filtered = [];

        function renderChips() {
            clearNode(chipsEl);
            selected.forEach(function (name, idx) {
                const chip = document.createElement("span");
                chip.className = "csm-multi-chip";
                const text = document.createElement("span");
                text.textContent = name;
                chip.appendChild(text);
                const rm = document.createElement("button");
                rm.type = "button";
                rm.className = "csm-multi-chip-remove";
                rm.setAttribute("aria-label", "Remove " + name);
                rm.textContent = "×";
                rm.addEventListener("click", function (ev) {
                    ev.stopPropagation();
                    removeAt(idx);
                });
                chip.appendChild(rm);
                chipsEl.appendChild(chip);
            });
            search.placeholder = selected.length ? "Add…" : "Search and add…";
        }

        function addValue(v) {
            if (selectedSet.has(v)) return;
            selected.push(v);
            selectedSet.add(v);
            renderChips();
            search.value = "";
            renderMenu();
            emitChange(root);
        }

        function removeAt(idx) {
            const v = selected[idx];
            selected.splice(idx, 1);
            selectedSet.delete(v);
            renderChips();
            renderMenu();
            emitChange(root);
        }

        function buildItems() {
            if (field.option_groups && field.option_groups.length > 0) {
                const out = [];
                field.option_groups.forEach(function (g) {
                    if (g.values && g.values.length > 0) {
                        out.push({isGroup: true, label: g.label});
                        g.values.forEach(function (v) { out.push({name: v, group: g.label}); });
                    }
                });
                return out;
            }
            return (field.options || []).map(function (v) { return {name: v}; });
        }

        function renderMenu() {
            clearNode(menu);
            const q = search.value.trim().toLowerCase();
            const items = buildItems();
            filtered = [];

            const output = [];
            let pendingGroup = null;
            let childrenInGroup = 0;
            items.forEach(function (it) {
                if (it.isGroup) {
                    pendingGroup = it;
                    childrenInGroup = 0;
                    return;
                }
                if (selectedSet.has(it.name)) return;
                if (q && it.name.toLowerCase().indexOf(q) === -1) return;
                if (pendingGroup && childrenInGroup === 0) {
                    output.push(pendingGroup);
                    pendingGroup = null;
                }
                output.push(it);
                childrenInGroup++;
            });

            const hasItems = output.some(function (x) { return !x.isGroup; });
            if (!hasItems) {
                const empty = document.createElement("div");
                empty.className = "csm-multi-empty";
                empty.textContent = q ? "No matches" : "All options selected";
                menu.appendChild(empty);
                return;
            }

            output.forEach(function (it) {
                if (it.isGroup) {
                    const hdr = document.createElement("div");
                    hdr.className = "csm-multi-menu-group";
                    hdr.textContent = it.label;
                    menu.appendChild(hdr);
                    return;
                }
                const row = document.createElement("div");
                row.className = "csm-multi-menu-item";
                row.setAttribute("role", "option");
                row.dataset.value = it.name;
                const nameEl = document.createElement("span");
                nameEl.textContent = it.name;
                row.appendChild(nameEl);
                row.addEventListener("mousedown", function (ev) {
                    ev.preventDefault();
                    addValue(it.name);
                    search.focus();
                });
                filtered.push(row);
                menu.appendChild(row);
            });
            highlightIdx = filtered.length > 0 ? 0 : -1;
            paintHighlight();
        }

        function paintHighlight() {
            filtered.forEach(function (el, i) {
                el.classList.toggle("is-highlighted", i === highlightIdx);
            });
            if (highlightIdx >= 0 && filtered[highlightIdx]) {
                const el = filtered[highlightIdx];
                const menuR = menu.getBoundingClientRect();
                const elR = el.getBoundingClientRect();
                if (elR.top < menuR.top) menu.scrollTop -= (menuR.top - elR.top);
                else if (elR.bottom > menuR.bottom) menu.scrollTop += (elR.bottom - menuR.bottom);
            }
        }

        function openMenu() {
            root.classList.add("is-open");
            renderMenu();
        }
        function closeMenu() { root.classList.remove("is-open"); }

        control.addEventListener("mousedown", function (ev) {
            if (ev.target.classList.contains("csm-multi-chip-remove")) return;
            ev.preventDefault();
            search.focus();
            openMenu();
        });
        search.addEventListener("focus", openMenu);
        search.addEventListener("input", openMenu);
        search.addEventListener("keydown", function (ev) {
            if (ev.key === "Backspace" && search.value === "" && selected.length > 0) {
                removeAt(selected.length - 1);
                return;
            }
            if (ev.key === "ArrowDown") {
                ev.preventDefault();
                if (!root.classList.contains("is-open")) openMenu();
                if (filtered.length > 0) {
                    highlightIdx = Math.min(filtered.length - 1, highlightIdx + 1);
                    paintHighlight();
                }
            } else if (ev.key === "ArrowUp") {
                ev.preventDefault();
                if (filtered.length > 0) {
                    highlightIdx = Math.max(0, highlightIdx - 1);
                    paintHighlight();
                }
            } else if (ev.key === "Enter") {
                ev.preventDefault();
                if (highlightIdx >= 0 && filtered[highlightIdx]) {
                    addValue(filtered[highlightIdx].dataset.value);
                }
            } else if (ev.key === "Escape") {
                closeMenu();
                search.blur();
            }
        });

        document.addEventListener("mousedown", function (ev) {
            if (!root.contains(ev.target)) closeMenu();
        });

        root.csmGetValues = function () { return selected.slice(); };
        renderChips();
        return root;
    }

    function emitChange(el) {
        const ev = document.createEvent("Event");
        ev.initEvent("change", true, true);
        el.dispatchEvent(ev);
    }

    // ---- Dirty tracking --------------------------------------------------
    function attachDirtyListeners() {
        const panel = byId("settings-panel");
        panel.addEventListener("input", markDirty);
        panel.addEventListener("change", markDirty);
    }

    function markDirty() {
        const changed = Object.keys(computeChanges()).length > 0;
        dirty = changed;
        if (changed) dirtySections.add(currentSection); else dirtySections.delete(currentSection);
        refreshDirtyMarkers();
    }

    // ---- Change computation + save --------------------------------------
    function readFieldValue(field) {
        const id = fieldId(field);
        const el = byId(id);
        if (!el) return undefined;
        if (field.type === "bool" && !field.nullable) return el.checked;
        if (field.type === "bool" && field.nullable) {
            if (el.value === "") return null;
            return el.value === "true";
        }
        if (field.type === "int") {
            if (el.value === "") return null;
            return parseInt(el.value, 10);
        }
        if (field.type === "float") {
            if (el.value === "") return null;
            const f = parseFloat(el.value);
            return isNaN(f) ? null : f;
        }
        if (field.type === "[]string") {
            return el.value.split("\n").map(function (s) { return s.trim(); }).filter(function (s) { return s !== ""; });
        }
        if (field.type === "[]enum") {
            return el.csmGetValues ? el.csmGetValues() : [];
        }
        return el.value;
    }

    function computeChanges() {
        const out = {};
        if (!currentSchema) return out;
        currentSchema.fields.forEach(function (field) {
            const nv = readFieldValue(field);
            const ov = lookupValue(initialValues, field.yaml_path);
            if (field.secret && nv === "") return;
            if (JSON.stringify(nv) !== JSON.stringify(ov)) {
                out[field.yaml_path] = nv;
            }
        });
        return out;
    }

    async function save() {
        const btn = byId("settings-save");
        btn.disabled = true;
        const changes = computeChanges();
        if (Object.keys(changes).length === 0) {
            toast("No changes to save.", "info");
            btn.disabled = false;
            return;
        }
        let resp;
        try {
            resp = await fetch("/api/v1/settings/" + encodeURIComponent(currentSection), {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "If-Match": currentETag,
                    "X-CSRF-Token": csrfToken()
                },
                body: JSON.stringify({changes: changes})
            });
        } catch (e) {
            toast("Network error: " + (e && e.message ? e.message : "request failed"), "error");
            btn.disabled = false;
            return;
        }
        btn.disabled = false;
        if (resp.status === 412) {
            toast("Config changed externally; reloading…", "warning");
            loadSection(currentSection);
            return;
        }
        if (resp.status === 422) {
            const data = await resp.json().catch(function () { return {}; });
            const lines = (data.errors || []).map(function (e) { return e.field + ": " + e.message; });
            toast("Validation errors:\n" + lines.join("\n"), "error");
            return;
        }
        if (!resp.ok) { toast("Save failed: " + resp.status, "error"); return; }
        const data = await resp.json();
        currentETag = data.new_etag;
        dirty = false;
        dirtySections.delete(currentSection);
        refreshDirtyMarkers();
        if (data.pending_restart) {
            showRestartBanner();
            toast("Saved on disk. Restart required.", "warning");
        } else {
            toast("Saved. Applied live.", "success");
        }
        loadSection(currentSection);
    }

    // ---- Restart banner --------------------------------------------------
    function showRestartBanner() {
        const banner = byId("settings-banner");
        clearNode(banner);
        banner.classList.remove("d-none");
        banner.appendChild(iconEl("ti-alert-triangle", "me-2"));
        banner.appendChild(document.createTextNode("Restart required to apply changes. "));
        const btn = btnWithIcon("Restart daemon", "refresh", "btn btn-sm btn-warning ms-2");
        btn.id = "settings-restart";
        btn.addEventListener("click", restartDaemon);
        banner.appendChild(btn);
    }

    async function restartDaemon() {
        const banner = byId("settings-banner");
        clearNode(banner);
        const sp = document.createElement("div");
        sp.className = "d-flex align-items-center";
        const spin = document.createElement("div");
        spin.className = "spinner-border spinner-border-sm me-2";
        sp.appendChild(spin);
        sp.appendChild(document.createTextNode("Restarting…"));
        banner.appendChild(sp);
        try {
            const resp = await fetch("/api/v1/settings/restart", {
                method: "POST",
                headers: {"X-CSRF-Token": csrfToken()}
            });
            if (resp.status === 202) {
                await pollHealth();
                window.location.reload();
                return;
            }
            const data = await resp.json().catch(function () { return {}; });
            clearNode(banner);
            const strong = document.createElement("strong");
            strong.textContent = "Restart failed. ";
            banner.appendChild(strong);
            banner.appendChild(document.createTextNode((data.error || "Unknown error") + ". Check journalctl -u csm -n 200 on the server."));
        } catch (e) {
            await pollHealth();
            window.location.reload();
        }
    }

    async function pollHealth() {
        const deadline = Date.now() + 60000;
        while (Date.now() < deadline) {
            try {
                const resp = await fetch("/api/v1/health", {cache: "no-store"});
                if (resp.ok) return;
            } catch (e) { /* keep polling */ }
            await new Promise(function (r) { setTimeout(r, 1000); });
        }
    }

    // ---- Boot ------------------------------------------------------------
    window.addEventListener("beforeunload", function (e) {
        if (dirty) { e.preventDefault(); e.returnValue = ""; }
    });

    document.addEventListener("DOMContentLoaded", function () {
        loadSections();
        renderNav();
        const hash = window.location.hash.replace(/^#/, "");
        loadSection(hash || "alerts");
    });
})();
