(function () {
    "use strict";
    const SECTIONS = [
        {id: "alerts", title: "Alerts"},
        {id: "thresholds", title: "Thresholds"},
        {id: "suppressions", title: "Suppressions"},
        {id: "auto_response", title: "Auto-Response"},
        {id: "reputation", title: "Reputation"},
        {id: "email_protection", title: "Email Protection"},
        {id: "challenge", title: "Challenge"},
        {id: "php_shield", title: "PHP Shield"},
        {id: "signatures", title: "Signatures"},
        {id: "email_av", title: "Email AV"},
        {id: "modsec", title: "ModSecurity"},
        {id: "performance", title: "Performance"},
        {id: "cloudflare", title: "Cloudflare"},
        {id: "geoip", title: "GeoIP"},
        {id: "infra_ips", title: "Infra IPs"},
        {id: "sentry", title: "Sentry"}
    ];

    let currentSection = null;
    let currentETag = null;
    let currentSchema = null;
    let initialValues = {};

    function csrfToken() {
        const meta = document.querySelector('meta[name="csrf-token"]');
        return meta ? meta.content : "";
    }

    function byId(id) { return document.getElementById(id); }

    function clearNode(el) {
        while (el.firstChild) el.removeChild(el.firstChild);
    }

    function renderNav() {
        const nav = byId("settings-nav");
        clearNode(nav);
        SECTIONS.forEach(function (s) {
            const li = document.createElement("li");
            li.className = "nav-item";
            const a = document.createElement("a");
            a.className = "nav-link";
            a.href = "#" + s.id;
            a.textContent = s.title;
            a.addEventListener("click", function (ev) {
                ev.preventDefault();
                loadSection(s.id);
            });
            li.appendChild(a);
            nav.appendChild(li);
        });
    }

    function setActiveNav(id) {
        document.querySelectorAll("#settings-nav .nav-link").forEach(function (el) {
            el.classList.toggle("active", el.getAttribute("href") === "#" + id);
        });
    }

    async function loadSection(id) {
        setActiveNav(id);
        const panel = byId("settings-panel");
        clearNode(panel);
        const loading = document.createElement("div");
        loading.className = "card-body";
        const muted = document.createElement("div");
        muted.className = "text-muted";
        muted.textContent = "Loading...";
        loading.appendChild(muted);
        panel.appendChild(loading);

        const resp = await fetch("/api/v1/settings/" + encodeURIComponent(id), {headers: {Accept: "application/json"}});
        if (!resp.ok) {
            renderError("Failed to load: " + resp.status);
            return;
        }
        const data = await resp.json();
        currentSection = id;
        currentETag = data.etag;
        currentSchema = data.section;
        initialValues = JSON.parse(JSON.stringify(data.values || {}));
        renderForm(data);
    }

    function renderError(msg) {
        const panel = byId("settings-panel");
        clearNode(panel);
        const body = document.createElement("div");
        body.className = "card-body";
        const alert = document.createElement("div");
        alert.className = "alert alert-danger";
        alert.textContent = msg;
        body.appendChild(alert);
        panel.appendChild(body);
    }

    function renderForm(data) {
        const panel = byId("settings-panel");
        clearNode(panel);

        const header = document.createElement("div");
        header.className = "card-header";
        const title = document.createElement("h3");
        title.className = "card-title";
        title.textContent = data.section.title;
        header.appendChild(title);
        panel.appendChild(header);

        const cardBody = document.createElement("div");
        cardBody.className = "card-body";
        if (data.pending_restart) {
            const b = document.createElement("div");
            b.className = "alert alert-warning";
            b.textContent = "Saved on disk. Running daemon still uses previous values until restart. Pending: " + ((data.pending_fields || []).join(", "));
            cardBody.appendChild(b);
        }
        data.section.fields.forEach(function (field) {
            cardBody.appendChild(fieldRow(field, lookupValue(data.values || {}, field.yaml_path)));
        });
        panel.appendChild(cardBody);

        const footer = document.createElement("div");
        footer.className = "card-footer";
        const btn = document.createElement("button");
        btn.id = "settings-save";
        btn.className = "btn btn-primary";
        btn.textContent = "Save";
        btn.addEventListener("click", save);
        footer.appendChild(btn);
        const status = document.createElement("span");
        status.id = "settings-status";
        status.className = "ms-3 text-muted";
        footer.appendChild(status);
        panel.appendChild(footer);
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

    function fieldRow(field, value) {
        const wrapper = document.createElement("div");
        wrapper.className = "mb-3";
        const id = "f_" + (field.yaml_path || "root").replace(/\./g, "_");

        if (field.type === "bool" && !field.nullable) {
            const lbl = document.createElement("label");
            lbl.className = "form-check form-switch";
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
        } else {
            const lbl = document.createElement("label");
            lbl.className = "form-label";
            lbl.setAttribute("for", id);
            lbl.textContent = field.label;
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
            } else if (field.type === "[]string") {
                inp = document.createElement("textarea");
                inp.className = "form-control";
                inp.id = id;
                inp.rows = 4;
                if (field.placeholder) inp.placeholder = field.placeholder;
                inp.value = Array.isArray(value) ? value.join("\n") : "";
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
                    inp.placeholder = "(unchanged -- type to replace)";
                    inp.value = "";
                } else {
                    if (field.placeholder) inp.placeholder = field.placeholder;
                    inp.value = (value === undefined || value === null) ? "" : String(value);
                }
            }
            wrapper.appendChild(inp);
        }

        if (field.help) {
            const hint = document.createElement("div");
            hint.className = "form-hint";
            hint.textContent = field.help;
            wrapper.appendChild(hint);
        }
        return wrapper;
    }

    function readFieldValue(field) {
        const id = "f_" + (field.yaml_path || "root").replace(/\./g, "_");
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
        if (field.type === "[]string") {
            return el.value.split("\n").map(function (s) { return s.trim(); }).filter(function (s) { return s !== ""; });
        }
        return el.value;
    }

    function computeChanges() {
        const out = {};
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
        const status = byId("settings-status");
        status.textContent = "Saving...";
        const changes = computeChanges();
        if (Object.keys(changes).length === 0) {
            status.textContent = "No changes.";
            return;
        }
        const resp = await fetch("/api/v1/settings/" + encodeURIComponent(currentSection), {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "If-Match": currentETag,
                "X-CSRF-Token": csrfToken()
            },
            body: JSON.stringify({changes: changes})
        });
        if (resp.status === 412) {
            status.textContent = "Config changed externally; reloading...";
            loadSection(currentSection);
            return;
        }
        if (resp.status === 422) {
            const data = await resp.json().catch(function () { return {}; });
            clearNode(status);
            (data.errors || []).forEach(function (e) {
                const line = document.createElement("div");
                line.className = "text-danger";
                line.textContent = e.field + ": " + e.message;
                status.appendChild(line);
            });
            return;
        }
        if (!resp.ok) {
            status.textContent = "Save failed: " + resp.status;
            return;
        }
        const data = await resp.json();
        currentETag = data.new_etag;
        if (data.pending_restart) {
            showRestartBanner();
            status.textContent = "Saved on disk. Restart required.";
        } else {
            status.textContent = "Applied live.";
        }
        loadSection(currentSection);
    }

    function showRestartBanner() {
        const banner = byId("settings-banner");
        clearNode(banner);
        banner.classList.remove("d-none");
        banner.appendChild(document.createTextNode("Restart required to apply changes. "));
        const btn = document.createElement("button");
        btn.id = "settings-restart";
        btn.className = "btn btn-sm btn-warning ms-2";
        btn.textContent = "Restart daemon";
        btn.addEventListener("click", restartDaemon);
        banner.appendChild(btn);
    }

    async function restartDaemon() {
        const banner = byId("settings-banner");
        clearNode(banner);
        banner.appendChild(document.createTextNode("Restarting..."));
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
            // Connection reset is the expected outcome of a successful restart.
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

    document.addEventListener("DOMContentLoaded", function () {
        renderNav();
        const hash = window.location.hash.replace(/^#/, "");
        loadSection(hash || "alerts");
    });
})();
