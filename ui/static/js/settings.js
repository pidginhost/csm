(function () {
    "use strict";

    // ---- Section group metadata ------------------------------------------
    let groupOrder = [];
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
    async function loadSections() {
        const data = await CSM.get("/api/v1/settings");
        sections = data.sections || [];
        groupOrder = data.groups || [];
    }

    // ---- Nav rendering ---------------------------------------------------
    function renderNav() {
        const nav = byId("settings-nav");
        clearNode(nav);
        groupOrder.forEach(function (group) {
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
                item.dataset.search = sectionSearchText(s);
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

    // Filter the sidebar by free-text. Matches section metadata and field
    // labels/keys so operators can search for the setting they need.
    function filterNav(query) {
        const q = (query || "").trim().toLowerCase();
        const links = document.querySelectorAll(".settings-nav-link");
        links.forEach(function (link) {
            if (!q) { link.hidden = false; return; }
            const haystack = link.dataset.search || "";
            const match = haystack.indexOf(q) >= 0;
            link.hidden = !match;
        });
        const headers = document.querySelectorAll(".settings-nav-group-header");
        headers.forEach(function (header) {
            let nextVisible = false;
            let n = header.nextElementSibling;
            while (n && !n.classList.contains("settings-nav-group-header")) {
                if (n.classList.contains("settings-nav-link") && !n.hidden) {
                    nextVisible = true;
                    break;
                }
                n = n.nextElementSibling;
            }
            header.hidden = !nextVisible;
        });
    }

    function sectionSearchText(section) {
        const parts = [
            section.id,
            section.title,
            section.yaml_path,
            section.group
        ];
        (section.fields || []).forEach(function (field) {
            parts.push(field.label, field.yaml_path, field.help, field.field_group);
        });
        return parts.filter(function (v) { return v !== undefined && v !== null && v !== ""; })
            .join(" ")
            .toLowerCase();
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

    function pendingSectionNames(sections) {
        return (sections || []).map(function (s) {
            return (s && (s.title || s.id)) ? (s.title || s.id) : "";
        }).filter(function (name) { return name !== ""; });
    }

    function currentSectionSummary() {
        const meta = sectionMeta(currentSection);
        return currentSection ? [{id: currentSection, title: meta.title || currentSection}] : [];
    }

    function pendingSectionsSentence(sections) {
        const names = pendingSectionNames(sections);
        return names.length ? "Changed sections: " + names.join(", ") + ". " : "";
    }

    function normaliseErrorField(fieldName) {
        let name = fieldName || "";
        if (!currentSchema) return name;
        const root = currentSchema.yaml_path || currentSchema.id || "";
        if (root && name.indexOf(root + ".") === 0) {
            name = name.slice(root.length + 1);
        } else if (name === root) {
            name = "";
        }
        return name;
    }

    function schemaFieldByKey(key) {
        if (!currentSchema || !currentSchema.fields) return null;
        for (let i = 0; i < currentSchema.fields.length; i++) {
            if (currentSchema.fields[i].yaml_path === key) return currentSchema.fields[i];
        }
        return null;
    }

    function clearValidationErrors() {
        const panel = byId("settings-panel");
        if (!panel) return;
        panel.querySelectorAll(".is-invalid").forEach(function (el) { el.classList.remove("is-invalid"); });
        panel.querySelectorAll(".settings-field-error").forEach(function (el) { el.remove(); });
        const summary = byId("settings-validation-summary");
        if (summary) summary.remove();
    }

    function showValidationErrors(errors) {
        clearValidationErrors();
        const unmatched = [];
        (errors || []).forEach(function (err) {
            const key = normaliseErrorField(err.field);
            const field = schemaFieldByKey(key);
            if (!field) {
                unmatched.push(err);
                return;
            }
            const input = byId(fieldId(field));
            const wrapper = input ? input.closest(".settings-field") : null;
            if (!input || !wrapper) {
                unmatched.push(err);
                return;
            }
            input.classList.add("is-invalid");
            const msg = document.createElement("div");
            msg.className = "invalid-feedback d-block settings-field-error";
            msg.textContent = err.message || "Invalid value";
            wrapper.appendChild(msg);
        });
        if (unmatched.length > 0) {
            const body = document.querySelector("#settings-panel .settings-panel-body");
            if (!body) return;
            const summary = document.createElement("div");
            summary.id = "settings-validation-summary";
            summary.className = "alert alert-danger mb-3";
            summary.textContent = "Validation errors: " + unmatched.map(function (err) {
                return (err.field ? err.field + ": " : "") + (err.message || "Invalid value");
            }).join("; ");
            body.insertBefore(summary, body.firstChild);
        }
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

        // CSM.request throws for both network failures and !ok HTTP responses,
        // so a single catch is enough — no separate resp.ok branch.
        let data;
        try {
            const resp = await CSM.request("/api/v1/settings/" + encodeURIComponent(id), {headers: {Accept: "application/json"}});
            data = await resp.json();
        } catch (e) {
            renderError("Failed to load: " + (e && e.message ? e.message : "request failed"));
            return;
        }
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

        const pendingSectionList = data.pending_sections || [];
        if (!activeRollbackStatus) {
            if (pendingSectionNames(pendingSectionList).length > 0) {
                showRestartBanner(pendingSectionList);
            } else {
                hideSettingsBanner();
            }
        }

        // Pending-restart notice
        if (data.pending_restart) {
            const b = document.createElement("div");
            b.className = "alert alert-warning mx-3 mt-3 mb-0";
            const pending = (data.pending_fields || []).join(", ");
            b.textContent = "Saved on disk. " + pendingSectionsSentence(data.pending_sections)
                + "Running daemon still uses previous values until restart."
                + (pending ? " Pending fields in this section: " + pending : "");
            panel.appendChild(b);
        }

        // Form body: scalars in a two-column grid; wide types span full row.
        // When any field carries a field_group, render one fieldset per group
        // so large sections (firewall, thresholds) read by topic instead of
        // as a flat wall of inputs. Sections without field_group fall back to
        // the original flat grid for back-compat.
        const body = document.createElement("div");
        body.className = "settings-panel-body";
        const fields = data.section.fields || [];
        const hasGroups = fields.some(function (f) { return f.field_group; });
        if (hasGroups) {
            const groupsOrder = [];
            const groupMap = Object.create(null);
            fields.forEach(function (f) {
                const key = f.field_group || "Other";
                if (!groupMap[key]) {
                    groupMap[key] = [];
                    groupsOrder.push(key);
                }
                groupMap[key].push(f);
            });
            groupsOrder.forEach(function (label) {
                const fset = document.createElement("fieldset");
                fset.className = "settings-field-group";
                const legend = document.createElement("legend");
                legend.className = "settings-field-group__legend";
                legend.textContent = label;
                fset.appendChild(legend);
                const grid = document.createElement("div");
                grid.className = "settings-field-grid";
                groupMap[label].forEach(function (field) {
                    const cell = fieldRow(field, lookupValue(data.values || {}, field.yaml_path));
                    cell.classList.add(isWideField(field) ? "settings-field-wide" : "settings-field-half");
                    grid.appendChild(cell);
                });
                fset.appendChild(grid);
                body.appendChild(fset);
            });
        } else {
            const grid = document.createElement("div");
            grid.className = "settings-field-grid";
            fields.forEach(function (field) {
                const cell = fieldRow(field, lookupValue(data.values || {}, field.yaml_path));
                cell.classList.add(isWideField(field) ? "settings-field-wide" : "settings-field-half");
                grid.appendChild(cell);
            });
            body.appendChild(grid);
        }
        panel.appendChild(body);

        // Footer actions
        const footer = document.createElement("div");
        footer.className = "settings-panel-footer";
        footer.id = "settings-panel-footer";
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
        if (currentSection === "firewall") {
            const btnTentative = btnWithIcon("Apply with rollback timer", "shield-half-filled", "btn btn-warning ms-2");
            btnTentative.id = "settings-tentative-apply";
            btnTentative.title = "Save and restart, but auto-revert in 5 minutes unless you confirm. Use this when changing port lists or other lockout-prone fields.";
            btnTentative.addEventListener("click", tentativeApplyFirewall);
            footer.appendChild(btnTentative);
        }
        footer.appendChild(btnReset);
        panel.appendChild(footer);
        renderRollbackFooter(activeRollbackStatus);

        attachDirtyListeners();
    }

    function sectionMeta(id) {
        for (let i = 0; i < sections.length; i++) {
            if (sections[i].id === id) return sections[i];
        }
        return {};
    }

    function isWideField(field) {
        return field.type === "[]string" || field.type === "[]enum" || field.type === "[]int";
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
        } else if (field.type === "[]int") {
            inp = document.createElement("textarea");
            inp.className = "form-control";
            inp.id = id;
            inp.rows = 4;
            inp.placeholder = field.placeholder || "one port per line, range 1-65535";
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
                inp.placeholder = "Secret unchanged";
                inp.value = "";
                inp.disabled = true;
            } else {
                if (field.placeholder) inp.placeholder = field.placeholder;
                inp.value = (value === undefined || value === null) ? "" : String(value);
            }
        }
        wrapper.appendChild(inp);
        if (field.secret) {
            const secretBtn = btnWithIcon("Set new value", "key", "btn btn-outline-secondary btn-sm mt-2 settings-secret-set");
            secretBtn.addEventListener("click", function () {
                inp.disabled = false;
                inp.placeholder = "New secret value";
                secretBtn.remove();
                inp.focus();
            });
            wrapper.appendChild(secretBtn);
        }
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
        clearValidationErrors();
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
        if (field.type === "[]int") {
            const tokens = el.value.split(/[\s,]+/).map(function (s) { return s.trim(); }).filter(function (s) { return s !== ""; });
            const out = [];
            const seen = {};
            let hasInvalid = false;
            for (let i = 0; i < tokens.length; i++) {
                const token = tokens[i];
                if (/^[+-]?\d+$/.test(token)) {
                    const n = Number(token);
                    if (Number.isSafeInteger(n) && !seen["n:" + n]) {
                        seen["n:" + n] = true;
                        out.push(n);
                        continue;
                    }
                }
                hasInvalid = true;
                if (!seen["s:" + token]) {
                    seen["s:" + token] = true;
                    out.push(token);
                }
            }
            if (!hasInvalid) out.sort(function (a, b) { return a - b; });
            return out;
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
        clearValidationErrors();
        if (Object.keys(changes).length === 0) {
            toast("No changes to save.", "info");
            btn.disabled = false;
            return;
        }
        let resp;
        try {
            resp = await fetch(CSM.apiUrl("/api/v1/settings/" + encodeURIComponent(currentSection)), {
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
            showValidationErrors(data.errors || []);
            toast("Validation errors. Review the highlighted fields.", "error");
            return;
        }
        if (!resp.ok) { toast("Save failed: " + resp.status, "error"); return; }
        const data = await resp.json();
        currentETag = data.new_etag;
        dirty = false;
        dirtySections.delete(currentSection);
        refreshDirtyMarkers();
        if (data.pending_restart) {
            const pendingSections = pendingSectionNames(data.pending_sections).length ? data.pending_sections : currentSectionSummary();
            showRestartBanner(pendingSections);
            toast("Saved on disk. Restart required.", "warning");
        } else {
            toast("Saved. Applied live.", "success");
        }
        loadSection(currentSection);
    }

    // ---- Restart banner --------------------------------------------------
    function showRestartBanner(sections) {
        const banner = byId("settings-banner");
        clearNode(banner);
        banner.classList.remove("d-none");
        banner.appendChild(iconEl("ti-alert-triangle", "me-2"));
        banner.appendChild(document.createTextNode("Restart required to apply changes. " + pendingSectionsSentence(sections)));
        const btn = btnWithIcon("Restart daemon", "refresh", "btn btn-sm btn-warning ms-2");
        btn.id = "settings-restart";
        btn.addEventListener("click", restartDaemon);
        banner.appendChild(btn);
    }

    function hideSettingsBanner() {
        const banner = byId("settings-banner");
        clearNode(banner);
        banner.classList.add("d-none");
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
            const resp = await fetch(CSM.apiUrl("/api/v1/settings/restart"), {
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

    // ---- Tentative apply (firewall section) -----------------------------
    let rollbackTimer = null;
    let activeRollbackStatus = null;

    async function tentativeApplyFirewall() {
        const btn = byId("settings-tentative-apply");
        const changes = computeChanges();
        if (Object.keys(changes).length === 0) {
            toast("No changes to apply.", "info");
            return;
        }
        const minutesStr = window.prompt("Auto-revert if unconfirmed within how many minutes? (1-30)", "5");
        if (minutesStr === null) return;
        const minutes = parseInt(minutesStr, 10);
        if (isNaN(minutes) || minutes < 1 || minutes > 30) {
            toast("Timeout must be 1-30 minutes.", "error");
            return;
        }
        const confirmMsg = "Apply firewall changes with a " + minutes + "-minute rollback timer?\n\n"
            + "The daemon will restart with the new config. If you do not click Confirm before "
            + "the timer expires, the previous config is restored automatically and the daemon "
            + "restarts again.";
        if (!window.confirm(confirmMsg)) return;
        btn.disabled = true;
        let resp;
        try {
            resp = await fetch(CSM.apiUrl("/api/v1/settings/firewall/tentative-apply"), {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "If-Match": currentETag,
                    "X-CSRF-Token": csrfToken()
                },
                body: JSON.stringify({changes: changes, timeout_min: minutes})
            });
        } catch (e) {
            toast("Network error: " + (e && e.message ? e.message : "request failed"), "error");
            btn.disabled = false;
            return;
        }
        btn.disabled = false;
        if (resp.status === 412) { toast("Config changed externally; reloading…", "warning"); loadSection(currentSection); return; }
        if (resp.status === 422) {
            const data = await resp.json().catch(function () { return {}; });
            showValidationErrors(data.errors || []);
            toast("Validation errors. Review the highlighted fields.", "error");
            return;
        }
        if (resp.status === 409) { toast("A rollback is already pending. Confirm or revert it first.", "warning"); return; }
        if (!resp.ok) { toast("Tentative apply failed: " + resp.status, "error"); return; }
        const data = await resp.json();
        currentETag = data.new_etag;
        dirty = false;
        dirtySections.delete(currentSection);
        refreshDirtyMarkers();
        await pollHealth();
        renderRollbackBanner(data.rollback);
    }

    function renderRollbackBanner(status) {
        activeRollbackStatus = status || null;
        const banner = byId("settings-banner");
        clearNode(banner);
        banner.classList.remove("d-none");
        banner.classList.remove("alert-warning");
        banner.classList.add("alert-warning");
        const iconWrap = iconEl("ti-shield-half-filled", "me-2");
        banner.appendChild(iconWrap);
        const textNode = document.createElement("strong");
        textNode.textContent = "Firewall changes pending confirmation. ";
        banner.appendChild(textNode);
        const remainingSpan = document.createElement("span");
        remainingSpan.id = "rollback-remaining";
        banner.appendChild(remainingSpan);
        banner.appendChild(document.createTextNode(" "));
        const confirmBtn = btnWithIcon("Confirm", "check", "btn btn-sm btn-success ms-2");
        confirmBtn.addEventListener("click", confirmRollback);
        banner.appendChild(confirmBtn);
        const revertBtn = btnWithIcon("Revert now", "rotate", "btn btn-sm btn-outline-warning ms-2");
        revertBtn.addEventListener("click", revertRollback);
        banner.appendChild(revertBtn);

        startRollbackTimer(status);
        renderRollbackFooter(status);
    }

    function renderRollbackFooter(status) {
        activeRollbackStatus = status || null;
        const old = byId("settings-rollback-footer");
        if (old) old.remove();
        if (!activeRollbackStatus || currentSection !== "firewall") return;
        const footer = byId("settings-panel-footer");
        if (!footer) return;
        const badge = document.createElement("span");
        badge.id = "settings-rollback-footer";
        badge.className = "badge bg-warning-lt ms-auto";
        badge.textContent = "Rollback pending";
        footer.appendChild(badge);
    }

    function startRollbackTimer(status) {
        if (rollbackTimer) { clearInterval(rollbackTimer); rollbackTimer = null; }
        const expiresAt = new Date(status.expires_at).getTime();
        function tick() {
            const remaining = Math.max(0, Math.floor((expiresAt - Date.now()) / 1000));
            const min = Math.floor(remaining / 60);
            const sec = remaining % 60;
            const span = byId("rollback-remaining");
            if (span) span.textContent = "Reverts in " + min + ":" + (sec < 10 ? "0" : "") + sec + ".";
            const footerSpan = byId("settings-rollback-footer");
            if (footerSpan) footerSpan.textContent = "Rollback: " + min + ":" + (sec < 10 ? "0" : "") + sec;
            if (remaining <= 0) {
                clearInterval(rollbackTimer);
                rollbackTimer = null;
                pollUntilRollbackGone();
            }
        }
        tick();
        rollbackTimer = setInterval(tick, 1000);
    }

    async function pollUntilRollbackGone() {
        const deadline = Date.now() + 60000;
        while (Date.now() < deadline) {
            try {
                const resp = await fetch(CSM.apiUrl("/api/v1/settings/firewall/rollback"), {cache: "no-store"});
                if (resp.ok) {
                    const data = await resp.json();
                    if (!data.pending) {
                        toast("Firewall rollback expired; previous config restored.", "warning");
                        window.location.reload();
                        return;
                    }
                }
            } catch (e) { /* keep polling */ }
            await new Promise(function (r) { setTimeout(r, 2000); });
        }
        window.location.reload();
    }

    async function confirmRollback() {
        const resp = await fetch(CSM.apiUrl("/api/v1/settings/firewall/confirm"), {
            method: "POST",
            headers: {"X-CSRF-Token": csrfToken()}
        });
        if (resp.ok) {
            if (rollbackTimer) { clearInterval(rollbackTimer); rollbackTimer = null; }
            activeRollbackStatus = null;
            renderRollbackFooter(null);
            const banner = byId("settings-banner");
            clearNode(banner);
            banner.classList.add("d-none");
            toast("Firewall changes confirmed.", "success");
            loadSection(currentSection);
        } else {
            toast("Confirm failed: " + resp.status, "error");
        }
    }

    async function revertRollback() {
        if (!window.confirm("Revert firewall changes now? The daemon will restart with the previous config.")) return;
        const resp = await fetch(CSM.apiUrl("/api/v1/settings/firewall/revert"), {
            method: "POST",
            headers: {"X-CSRF-Token": csrfToken()}
        });
        if (resp.ok) {
            if (rollbackTimer) { clearInterval(rollbackTimer); rollbackTimer = null; }
            activeRollbackStatus = null;
            renderRollbackFooter(null);
            await pollHealth();
            window.location.reload();
        } else {
            toast("Revert failed: " + resp.status, "error");
        }
    }

    async function checkPendingRollbackOnLoad() {
        try {
            const resp = await fetch(CSM.apiUrl("/api/v1/settings/firewall/rollback"), {cache: "no-store"});
            if (!resp.ok) return;
            const data = await resp.json();
            if (data && data.pending) renderRollbackBanner(data);
        } catch (e) { /* silent */ }
    }

    async function pollHealth() {
        const deadline = Date.now() + 60000;
        while (Date.now() < deadline) {
            try {
                const resp = await fetch(CSM.apiUrl("/api/v1/health"), {cache: "no-store"});
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
        const search = byId("settings-search");
        if (search) {
            search.addEventListener("input", function () { filterNav(this.value); });
        }
        loadSections().then(function () {
            renderNav();
            const search = byId("settings-search");
            if (search) filterNav(search.value);
            const hash = window.location.hash.replace(/^#/, "");
            const first = sections.length > 0 ? sections[0].id : "alerts";
            const target = sections.some(function (s) { return s.id === hash; }) ? hash : first;
            loadSection(target);
            checkPendingRollbackOnLoad();
        }).catch(function (e) {
            renderError("Failed to load settings metadata: " + (e && e.message ? e.message : "request failed"));
        });
    });
})();
