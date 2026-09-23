// CSM runtime: page helpers. Loading and load-error states, click to
// copy, debounce, table export and URL state.
var CSM = CSM || {};

(function() {

// Render a loading skeleton placeholder
CSM.loading = function(el) {
    if (el) el.innerHTML = '<div class="card-body text-center text-muted py-4"><span class="spinner-border spinner-border-sm me-2"></span>Loading...</div>';
};

// loadError shows that a load failed inside el: what failed, why, and a
// Retry button. It hides el's content instead of replacing it, so a loader
// that fills elements inside el still finds them. A loader that rebuilds el
// wipes the error with it; one that only fills elements inside el calls
// CSM.clearLoadError(el) when it succeeds. Inside a table body the error is
// one row across the table.
//   opts.title  what failed (default "Failed to load data")
//   opts.error  the caught failure, shown as the reason
CSM.loadError = function(el, retryFn, opts) {
    if (!el) return;
    opts = opts || {};
    CSM.clearLoadError(el);
    var inTable = el.tagName === 'TBODY';
    var body = document.createElement(inTable ? 'td' : 'div');
    // Card padding, unless el already is a padded card body.
    var padded = !inTable && !el.classList.contains('card-body');
    body.className = (padded ? 'card-body ' : '') + 'text-center py-4';
    var title = document.createElement('div');
    title.className = 'text-danger mb-2';
    title.textContent = opts.title || 'Failed to load data';
    body.appendChild(title);
    if (opts.error) {
        var reason = document.createElement('div');
        reason.className = 'text-muted small mb-2';
        reason.textContent = CSM.errorText(opts.error);
        body.appendChild(reason);
    }
    if (retryFn) {
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-sm btn-outline-secondary csm-retry-btn';
        btn.textContent = 'Retry';
        btn.addEventListener('click', function() {
            CSM.clearLoadError(el);
            retryFn();
        });
        body.appendChild(btn);
    }
    Array.prototype.slice.call(el.childNodes).forEach(function(node) {
        if (node.nodeType === 3) {
            if (!/\S/.test(node.nodeValue)) return;
            var span = document.createElement('span');
            el.replaceChild(span, node);
            span.appendChild(node);
            node = span;
        }
        if (node.nodeType !== 1 || node.hidden) return;
        node.hidden = true;
        node.setAttribute('data-csm-load-error-hidden', '');
    });
    var block = body;
    if (inTable) {
        block = document.createElement('tr');
        body.setAttribute('colspan', String(tableColumns(el)));
        block.appendChild(body);
    }
    block.classList.add('csm-load-error');
    el.appendChild(block);

    function tableColumns(tbody) {
        var table = tbody.parentNode;
        var head = table && table.querySelector('thead tr');
        var row = head || tbody.querySelector('tr');
        return row && row.children.length ? row.children.length : 1;
    }
};

// clearLoadError removes the error CSM.loadError put in el and shows the
// content it hid.
CSM.clearLoadError = function(el) {
    if (!el) return;
    Array.prototype.slice.call(el.children).forEach(function(child) {
        if (child.classList.contains('csm-load-error')) {
            el.removeChild(child);
        } else if (child.hasAttribute('data-csm-load-error-hidden')) {
            child.removeAttribute('data-csm-load-error-hidden');
            child.hidden = false;
        }
    });
};

// Click-to-copy: delegated handler for .csm-copy elements
document.addEventListener('click', function(e) {
    var el = e.target.closest('.csm-copy');
    if (el) {
        e.stopPropagation();
        CSM.copyText(el.textContent.trim(), el);
    }
});

// Copy text to clipboard with visual feedback
CSM.copyText = function(text, el) {
    navigator.clipboard.writeText(text).then(function() {
        if (el) {
            var orig = el.textContent;
            el.textContent = 'Copied!';
            setTimeout(function() { el.textContent = orig; }, 1000);
        } else {
            CSM.toast('Copied to clipboard', 'success');
        }
    }).catch(function() { /* clipboard API unavailable — intentionally silent */ });
};

// Debounce utility
CSM.debounce = function(fn, delay) {
    var timer = null;
    var debounced = function() {
        var ctx = this, args = arguments;
        if (timer) clearTimeout(timer);
        timer = setTimeout(function() {
            timer = null;
            fn.apply(ctx, args);
        }, delay);
    };
    debounced.cancel = function() {
        if (timer) {
            clearTimeout(timer);
            timer = null;
        }
    };
    return debounced;
};

function csmCSVCell(value) {
    var val = value != null ? String(value) : '';
    if (/^[\t\r\n=+\-@]/.test(val) || /^\s+[=+\-@]/.test(val)) {
        val = "'" + val;
    }
    return '"' + val.replace(/"/g, '""') + '"';
}

// Client-side table export (CSV / JSON)
CSM.exportTable = function(data, columns, format, filename) {
    var content, mime;
    if (format === 'json') {
        var filtered = data.map(function(row) {
            var obj = {};
            columns.forEach(function(col) { obj[col.key] = row[col.key] != null ? row[col.key] : ''; });
            return obj;
        });
        content = JSON.stringify(filtered, null, 2);
        mime = 'application/json';
    } else {
        var lines = [columns.map(function(c) { return csmCSVCell(c.label || c.key); }).join(',')];
        data.forEach(function(row) {
            lines.push(columns.map(function(c) {
                return csmCSVCell(row[c.key]);
            }).join(','));
        });
        content = lines.join('\n');
        mime = 'text/csv';
    }
    if (!data.length) { CSM.toast('No data to export.', 'warning'); return; }
    var blob = new Blob([content], { type: mime });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename + '.' + format;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
};

// URL state helpers. Convention:
//   - Query string carries filter / search / paging state so the
//     browser back/forward stack and bookmarks survive reloads.
//   - Hash fragment carries legacy in-page anchors only (incident id,
//     expanded row id).
//
// Pages that need to persist filter state call CSM.urlState.bind to
// wire one or more inputs declaratively; ad-hoc callers use get / set
// / push / replace / clear / subscribe.
CSM.urlState = (function() {
    function hasURLValue(value) {
        return value !== undefined && value !== null && String(value) !== '';
    }
    function setParam(url, key, value) {
        if (hasURLValue(value)) url.searchParams.set(key, String(value));
        else url.searchParams.delete(key);
    }
    function own(obj, key) {
        return Object.prototype.hasOwnProperty.call(obj, key);
    }
    function eventName(el) {
        if (String(el.tagName || '').toUpperCase() === 'SELECT') return 'change';
        var type = String(el.type || '').toLowerCase();
        if (type === 'date' || type === 'time' || type === 'datetime-local' || type === 'month' || type === 'week') return 'change';
        return 'input';
    }
    function stateValue(state, defaults, name) {
        if (own(state, name)) return state[name] == null ? '' : String(state[name]);
        if (own(defaults, name)) return defaults[name] == null ? '' : String(defaults[name]);
        return '';
    }
    function clearHashIfRequested(url, opts) {
        if (opts && opts.clearHash) url.hash = '';
    }
    function writeParams(params, push, opts) {
        var url = new URL(window.location);
        Object.keys(params || {}).forEach(function(k) {
            setParam(url, k, params[k]);
        });
        clearHashIfRequested(url, opts);
        if (push) history.pushState(null, '', url);
        else history.replaceState(null, '', url);
    }

    return {
        get: function(key) {
            return new URLSearchParams(window.location.search).get(key) || '';
        },
        getAll: function() {
            var out = {};
            new URLSearchParams(window.location.search).forEach(function(value, key) {
                out[key] = value;
            });
            return out;
        },
        set: function(params, opts) {
            writeParams(params, false, opts);
        },
        push: function(params, opts) {
            writeParams(params, true, opts);
        },
        clear: function(keys, opts) {
            var url = new URL(window.location);
            (keys || []).forEach(function(k) { url.searchParams.delete(k); });
            clearHashIfRequested(url, opts);
            history.replaceState(null, '', url);
        },
        replace: function(params, opts) {
            var url = new URL(window.location);
            Array.from(url.searchParams.keys()).forEach(function(k) {
                url.searchParams.delete(k);
            });
            Object.keys(params || {}).forEach(function(k) {
                setParam(url, k, params[k]);
            });
            clearHashIfRequested(url, opts);
            history.replaceState(null, '', url);
        },
        // subscribe(fn) calls fn(getAll()) on popstate (back/forward) so the
        // page can re-apply state after the browser walks history. Returns an
        // unsubscribe function.
        subscribe: function(fn) {
            function handler() { fn(CSM.urlState.getAll()); }
            window.addEventListener('popstate', handler);
            return function() { window.removeEventListener('popstate', handler); };
        },
        // bind({ inputs: { paramName: el, ... }, defaults: { paramName: 'x' } })
        // wires each input two-way to URL state:
        //   - on load, sets input.value from the URL (or defaults if absent);
        //   - on input/change, writes the input value back to the URL,
        //     omitting the param when the value matches its default.
        // Returns an unsubscribe function that removes the listeners.
        bind: function(opts) {
            opts = opts || {};
            var inputs = opts.inputs || {};
            var defaults = opts.defaults || {};
            var debounceMs = (opts.debounceMs == null) ? 200 : opts.debounceMs;
            var listeners = [];
            var applying = false;

            function applyState(state) {
                applying = true;
                try {
                    Object.keys(inputs).forEach(function(name) {
                        var el = inputs[name];
                        if (!el) return;
                        var desired = stateValue(state || {}, defaults, name);
                        if (el.value !== desired) {
                            el.value = desired;
                            // Dispatch so dependent table / chart listeners pick up
                            // restored values during page-load and history navigation.
                            el.dispatchEvent(new Event(eventName(el), { bubbles: true }));
                        }
                    });
                } finally {
                    applying = false;
                }
            }

            applyState(CSM.urlState.getAll());

            Object.keys(inputs).forEach(function(name) {
                var el = inputs[name];
                if (!el) return;
                var sync = CSM.debounce(function() {
                    var v = el.value || '';
                    var patch = {};
                    patch[name] = (v && v !== stateValue({}, defaults, name)) ? v : '';
                    CSM.urlState.set(patch);
                }, debounceMs);
                var inputHandler = function() {
                    if (applying) return;
                    sync();
                };
                var evt = eventName(el);
                el.addEventListener(evt, inputHandler);
                listeners.push({ el: el, evt: evt, fn: inputHandler, cancel: sync.cancel });
            });

            var unsubscribePopstate = CSM.urlState.subscribe(function(state) { applyState(state); });

            return function() {
                unsubscribePopstate();
                listeners.forEach(function(l) {
                    l.el.removeEventListener(l.evt, l.fn);
                    if (l.cancel) l.cancel();
                });
            };
        }
    };
})();

})();
