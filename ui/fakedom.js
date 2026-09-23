'use strict';
// Minimal DOM for the Web UI's node tests. The page scripts run unchanged in
// a vm context built from createWindow(): an element tree, the CSS selectors
// the pages use, innerHTML for the markup they generate, bubbling events,
// reflected form properties, and offsetParent following display:none the way
// the shared bulk-selection helper relies on. It is a test harness, not a
// browser: anything a page needs beyond this belongs here, with a test in
// fakedom_test.js.

const VOID = new Set(['area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'source', 'track', 'wbr']);
const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0' };

function decodeEntities(s) {
    return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
        if (e[0] === '#') {
            const code = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
            return String.fromCodePoint(code);
        }
        const k = e.toLowerCase();
        return Object.prototype.hasOwnProperty.call(ENTITIES, k) ? ENTITIES[k] : m;
    });
}
const escapeText = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/\u00a0/g, '&nbsp;');
const escapeAttr = s => escapeText(s).replace(/"/g, '&quot;');

class Event {
    constructor(type, init = {}) {
        this.type = type;
        this.bubbles = !!init.bubbles;
        this.cancelable = !!init.cancelable;
        this.key = init.key;
        this.detail = init.detail;
        this.shiftKey = !!init.shiftKey;
        this.ctrlKey = !!init.ctrlKey;
        this.metaKey = !!init.metaKey;
        this.altKey = !!init.altKey;
        this.defaultPrevented = false;
        this.target = null;
        this.currentTarget = null;
        this._stop = false;
        this._stopNow = false;
    }
    initEvent(type, bubbles, cancelable) { this.type = type; this.bubbles = !!bubbles; this.cancelable = !!cancelable; }
    preventDefault() { this.defaultPrevented = true; }
    stopPropagation() { this._stop = true; }
    stopImmediatePropagation() { this._stop = true; this._stopNow = true; }
}
class CustomEvent extends Event {}

const INSPECT = Symbol.for('nodejs.util.inspect.custom');

class Node {
    constructor(doc) {
        // The upward links are not enumerable, so printing or diffing a node
        // (a failing assert.equal does both) walks its subtree only. Walking
        // up reaches the document, the window and every page global, which
        // exhausts memory.
        Object.defineProperty(this, 'ownerDocument', { value: doc, writable: true, enumerable: false });
        Object.defineProperty(this, 'parentNode', { value: null, writable: true, enumerable: false });
        this.childNodes = [];
        this._listeners = {};
    }
    [INSPECT]() {
        if (this.nodeType !== 1) return '[' + this.nodeName + ']';
        const id = this.getAttribute('id');
        const cls = this.getAttribute('class');
        return '<' + this.tagName.toLowerCase() + (id ? '#' + id : '') + (cls ? '.' + cls.trim().split(/\s+/).join('.') : '') + '>';
    }
    get parentElement() { return this.parentNode && this.parentNode.nodeType === 1 ? this.parentNode : null; }
    get firstChild() { return this.childNodes[0] || null; }
    get lastChild() { return this.childNodes[this.childNodes.length - 1] || null; }
    get children() { return this.childNodes.filter(n => n.nodeType === 1); }
    get firstElementChild() { return this.children[0] || null; }
    get lastElementChild() { const c = this.children; return c[c.length - 1] || null; }
    get childElementCount() { return this.children.length; }
    _sibling(step, elementsOnly) {
        const p = this.parentNode;
        if (!p) return null;
        const list = elementsOnly ? p.children : p.childNodes;
        return list[list.indexOf(this) + step] || null;
    }
    get nextSibling() { return this._sibling(1, false); }
    get previousSibling() { return this._sibling(-1, false); }
    get nextElementSibling() { return this._sibling(1, true); }
    get previousElementSibling() { return this._sibling(-1, true); }
    appendChild(n) { return this.insertBefore(n, null); }
    append(...nodes) { nodes.forEach(n => this.appendChild(typeof n === 'string' ? this.ownerDocument.createTextNode(n) : n)); }
    insertBefore(n, ref) {
        if (n.nodeType === 11) {
            n.childNodes.slice().forEach(c => this.insertBefore(c, ref));
            return n;
        }
        if (n.parentNode) n.parentNode.removeChild(n);
        n.parentNode = this;
        const i = ref ? this.childNodes.indexOf(ref) : -1;
        if (i < 0) this.childNodes.push(n);
        else this.childNodes.splice(i, 0, n);
        return n;
    }
    removeChild(n) {
        const i = this.childNodes.indexOf(n);
        if (i < 0) throw new Error('fakedom: removeChild of a node that is not a child');
        this.childNodes.splice(i, 1);
        n.parentNode = null;
        return n;
    }
    replaceChild(n, old) { this.insertBefore(n, old); return this.removeChild(old); }
    replaceChildren(...nodes) { this.childNodes.slice().forEach(c => this.removeChild(c)); this.append(...nodes); }
    remove() { if (this.parentNode) this.parentNode.removeChild(this); }
    contains(n) { for (let c = n; c; c = c.parentNode) if (c === this) return true; return false; }
    get textContent() { return this.childNodes.map(c => c.textContent).join(''); }
    set textContent(v) {
        this.childNodes.slice().forEach(c => this.removeChild(c));
        if (v !== '' && v != null) this.appendChild(this.ownerDocument.createTextNode(String(v)));
    }
    get isConnected() { return this.ownerDocument.contains(this); }
    addEventListener(type, fn) {
        if (typeof fn !== 'function') return;
        const list = this._listeners[type] || (this._listeners[type] = []);
        if (!list.includes(fn)) list.push(fn);
    }
    removeEventListener(type, fn) {
        const list = this._listeners[type];
        if (!list) return;
        const i = list.indexOf(fn);
        if (i >= 0) list.splice(i, 1);
    }
    listenerCount(type) { return (this._listeners[type] || []).length; }
    dispatchEvent(ev) {
        if (!ev.target) ev.target = this;
        let node = this;
        while (node) {
            ev.currentTarget = node;
            for (const fn of (node._listeners[ev.type] || []).slice()) {
                fn.call(node, ev);
                if (ev._stopNow) break;
            }
            if (!ev.bubbles || ev._stop) break;
            node = node.parentNode || (node.nodeType === 9 ? node.defaultView : null);
        }
        return !ev.defaultPrevented;
    }
    querySelectorAll(sel) {
        const groups = parseSelector(sel);
        const out = [];
        walk(this, el => { if (groups.some(g => matchComplex(el, g, this))) out.push(el); });
        return out;
    }
    querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
}

class Text extends Node {
    constructor(doc, data) { super(doc); this.nodeType = 3; this.nodeName = '#text'; this.data = String(data); }
    get textContent() { return this.data; }
    set textContent(v) { this.data = String(v); }
    get nodeValue() { return this.data; }
    cloneNode() { return new Text(this.ownerDocument, this.data); }
}

class Comment extends Node {
    constructor(doc, data) { super(doc); this.nodeType = 8; this.nodeName = '#comment'; this.data = String(data); }
    get textContent() { return ''; }
    set textContent(v) { this.data = String(v); }
    cloneNode() { return new Comment(this.ownerDocument, this.data); }
}

class Fragment extends Node {
    constructor(doc) { super(doc); this.nodeType = 11; this.nodeName = '#document-fragment'; }
    cloneNode(deep) { const f = new Fragment(this.ownerDocument); if (deep) this.childNodes.forEach(c => f.appendChild(c.cloneNode(true))); return f; }
}

function camelToData(name) { return 'data-' + name.replace(/[A-Z]/g, c => '-' + c.toLowerCase()); }
function dataToCamel(attr) { return attr.slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase()); }

function styleFor() {
    const style = {};
    Object.defineProperties(style, {
        setProperty: { value(k, v) { this[k.replace(/-([a-z])/g, (_, c) => c.toUpperCase())] = String(v); } },
        removeProperty: { value(k) { delete this[k.replace(/-([a-z])/g, (_, c) => c.toUpperCase())]; } },
        getPropertyValue: { value(k) { return this[k.replace(/-([a-z])/g, (_, c) => c.toUpperCase())] || ''; } }
    });
    return style;
}

class Element extends Node {
    constructor(doc, tag) {
        super(doc);
        this.nodeType = 1;
        this.tagName = tag.toUpperCase();
        this.nodeName = this.tagName;
        this._attrs = new Map();
        this._props = {};
        this.style = styleFor();
        const el = this;
        this.dataset = new Proxy({}, {
            get(_, k) { return typeof k === 'string' ? (el.getAttribute(camelToData(k)) ?? undefined) : undefined; },
            set(_, k, v) { el.setAttribute(camelToData(k), v); return true; },
            deleteProperty(_, k) { el.removeAttribute(camelToData(k)); return true; },
            has(_, k) { return el.hasAttribute(camelToData(k)); },
            ownKeys() { return [...el._attrs.keys()].filter(a => a.startsWith('data-')).map(dataToCamel); },
            getOwnPropertyDescriptor(_, k) {
                return el.hasAttribute(camelToData(k)) ? { enumerable: true, configurable: true, value: el.getAttribute(camelToData(k)) } : undefined;
            }
        });
        this.classList = {
            _list() { return (el.getAttribute('class') || '').split(/\s+/).filter(Boolean); },
            _set(list) { el.setAttribute('class', list.join(' ')); },
            contains(c) { return this._list().includes(c); },
            add(...cs) { const l = this._list(); cs.forEach(c => { if (!l.includes(c)) l.push(c); }); this._set(l); },
            remove(...cs) { this._set(this._list().filter(c => !cs.includes(c))); },
            toggle(c, force) {
                const has = this.contains(c);
                const want = force === undefined ? !has : !!force;
                if (want && !has) this.add(c);
                if (!want && has) this.remove(c);
                return want;
            },
            get length() { return this._list().length; }
        };
    }
    getAttribute(n) { n = n.toLowerCase(); return this._attrs.has(n) ? this._attrs.get(n) : null; }
    setAttribute(n, v) { this._attrs.set(n.toLowerCase(), String(v)); }
    removeAttribute(n) { this._attrs.delete(n.toLowerCase()); }
    hasAttribute(n) { return this._attrs.has(n.toLowerCase()); }
    toggleAttribute(n, force) {
        const want = force === undefined ? !this.hasAttribute(n) : !!force;
        if (want) this.setAttribute(n, ''); else this.removeAttribute(n);
        return want;
    }
    get attributes() { return [...this._attrs].map(([name, value]) => ({ name, value })); }
    get id() { return this.getAttribute('id') || ''; }
    set id(v) { this.setAttribute('id', v); }
    get className() { return this.getAttribute('class') || ''; }
    set className(v) { this.setAttribute('class', v); }

    // Reflected attributes.
    _reflect(name) { return this.getAttribute(name) || ''; }
    get title() { return this._reflect('title'); }
    set title(v) { this.setAttribute('title', v); }
    get href() { return this._reflect('href'); }
    set href(v) { this.setAttribute('href', v); }
    get name() { return this._reflect('name'); }
    set name(v) { this.setAttribute('name', v); }
    get placeholder() { return this._reflect('placeholder'); }
    set placeholder(v) { this.setAttribute('placeholder', v); }
    get type() { return (this.getAttribute('type') || (this.tagName === 'BUTTON' ? 'submit' : 'text')).toLowerCase(); }
    set type(v) { this.setAttribute('type', v); }
    get disabled() { return this.hasAttribute('disabled'); }
    set disabled(v) { this.toggleAttribute('disabled', !!v); }
    get hidden() { return this.hasAttribute('hidden'); }
    set hidden(v) { this.toggleAttribute('hidden', !!v); }
    get readOnly() { return this.hasAttribute('readonly'); }
    set readOnly(v) { this.toggleAttribute('readonly', !!v); }
    get tabIndex() { const v = this.getAttribute('tabindex'); return v === null ? -1 : parseInt(v, 10); }
    set tabIndex(v) { this.setAttribute('tabindex', v); }

    // Form state lives in properties once a script sets it, as in a browser.
    get checked() { return 'checked' in this._props ? this._props.checked : this.hasAttribute('checked'); }
    set checked(v) { this._props.checked = !!v; }
    get indeterminate() { return !!this._props.indeterminate; }
    set indeterminate(v) { this._props.indeterminate = !!v; }
    get selected() { return 'selected' in this._props ? this._props.selected : this.hasAttribute('selected'); }
    set selected(v) {
        if (v && this.parentNode) {
            const select = this.closest('select');
            if (select && !select.hasAttribute('multiple')) select.querySelectorAll('option').forEach(o => { o._props.selected = false; });
        }
        this._props.selected = !!v;
    }
    get options() { return this.querySelectorAll('option'); }
    get selectedIndex() {
        const opts = this.options;
        const i = opts.findIndex(o => o.selected);
        return i >= 0 ? i : (opts.length ? 0 : -1);
    }
    set selectedIndex(i) { this.options.forEach((o, j) => { o._props.selected = j === i; }); }
    get value() {
        if ('value' in this._props) return this._props.value;
        if (this.tagName === 'SELECT') {
            const opt = this.options[this.selectedIndex];
            return opt ? opt.value : '';
        }
        if (this.tagName === 'OPTION') return this.hasAttribute('value') ? this.getAttribute('value') : this.textContent;
        if (this.tagName === 'TEXTAREA') return this.textContent;
        const v = this.getAttribute('value');
        if (v === null && (this.type === 'checkbox' || this.type === 'radio')) return 'on';
        return v === null ? '' : v;
    }
    set value(v) {
        if (this.tagName === 'SELECT') {
            const s = String(v);
            this.options.forEach(o => { o._props.selected = o.value === s; });
            return;
        }
        this._props.value = String(v);
    }

    get offsetParent() {
        if (!this.isConnected) return null;
        for (let n = this; n && n.nodeType === 1; n = n.parentNode) {
            if (n.style.display === 'none' || n.hidden || n.classList.contains('d-none')) return null;
        }
        return this.ownerDocument.body;
    }
    getBoundingClientRect() { return { top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0 }; }
    scrollIntoView() {}
    focus() {
        const doc = this.ownerDocument;
        if (doc.activeElement === this) return;
        const prev = doc.activeElement;
        doc.activeElement = this;
        if (prev && prev !== this) prev.dispatchEvent(new Event('blur'));
        this.dispatchEvent(new Event('focus'));
        this.dispatchEvent(new Event('focusin', { bubbles: true }));
    }
    blur() {
        if (this.ownerDocument.activeElement === this) this.ownerDocument.activeElement = this.ownerDocument.body;
        this.dispatchEvent(new Event('blur'));
    }
    click() {
        if (this.disabled) return;
        const toggles = this.tagName === 'INPUT' && (this.type === 'checkbox' || this.type === 'radio');
        if (toggles) {
            if (this.type === 'radio') {
                const name = this.getAttribute('name');
                if (name) this.ownerDocument.querySelectorAll('input[type="radio"][name="' + name + '"]').forEach(r => { r._props.checked = false; });
                this.checked = true;
            } else {
                this.checked = !this.checked;
            }
        }
        const ev = new Event('click', { bubbles: true, cancelable: true });
        this.dispatchEvent(ev);
        if (toggles) {
            this.dispatchEvent(new Event('input', { bubbles: true }));
            this.dispatchEvent(new Event('change', { bubbles: true }));
        } else if (!ev.defaultPrevented && (this.tagName === 'BUTTON' && this.type === 'submit')) {
            const form = this.closest('form');
            if (form) form.dispatchEvent(new Event('submit', { bubbles: true, cancelable: true }));
        }
    }
    matches(sel) { return parseSelector(sel).some(g => matchComplex(this, g, null)); }
    closest(sel) {
        for (let n = this; n && n.nodeType === 1; n = n.parentNode) if (n.matches(sel)) return n;
        return null;
    }
    get innerHTML() { return this.childNodes.map(serialize).join(''); }
    set innerHTML(html) {
        this.childNodes.slice().forEach(c => this.removeChild(c));
        parseHTML(this.ownerDocument, String(html), this);
    }
    get outerHTML() { return serialize(this); }
    insertAdjacentHTML(pos, html) {
        const frag = new Fragment(this.ownerDocument);
        parseHTML(this.ownerDocument, String(html), frag);
        switch (pos.toLowerCase()) {
            case 'beforebegin': this.parentNode.insertBefore(frag, this); break;
            case 'afterbegin': this.insertBefore(frag, this.firstChild); break;
            case 'beforeend': this.appendChild(frag); break;
            case 'afterend': this.parentNode.insertBefore(frag, this.nextSibling); break;
            default: throw new Error('fakedom: insertAdjacentHTML position ' + pos);
        }
    }
    cloneNode(deep) {
        const c = new Element(this.ownerDocument, this.tagName.toLowerCase());
        this._attrs.forEach((v, k) => c._attrs.set(k, v));
        Object.assign(c.style, this.style);
        if (deep) this.childNodes.forEach(n => c.appendChild(n.cloneNode(true)));
        return c;
    }
}

class Document extends Node {
    constructor() {
        super(null);
        this.ownerDocument = this;
        this.nodeType = 9;
        this.nodeName = '#document';
        this.readyState = 'complete';
        this.hidden = false;
        this.visibilityState = 'visible';
        this.cookie = '';
        this.documentElement = this.createElement('html');
        this.head = this.createElement('head');
        this.body = this.createElement('body');
        this.documentElement.appendChild(this.head);
        this.documentElement.appendChild(this.body);
        this.appendChild(this.documentElement);
        this.activeElement = this.body;
    }
    createElement(tag) { return new Element(this, tag); }
    createTextNode(data) { return new Text(this, data); }
    createComment(data) { return new Comment(this, data); }
    createDocumentFragment() { return new Fragment(this); }
    createEvent() { return new Event(''); }
    getElementById(id) {
        let found = null;
        walk(this, el => { if (!found && el.getAttribute('id') === id) found = el; });
        return found;
    }
    get textContent() { return null; }
}

function walk(root, fn) {
    for (const c of root.childNodes) {
        if (c.nodeType === 1) {
            fn(c);
            walk(c, fn);
        } else if (c.nodeType === 11) {
            walk(c, fn);
        }
    }
}

function serialize(n) {
    if (n.nodeType === 3) return escapeText(n.data);
    if (n.nodeType === 8) return '<!--' + n.data + '-->';
    if (n.nodeType === 11) return n.childNodes.map(serialize).join('');
    const tag = n.tagName.toLowerCase();
    let s = '<' + tag;
    n._attrs.forEach((v, k) => { s += ' ' + k + '="' + escapeAttr(v) + '"'; });
    s += '>';
    if (VOID.has(tag)) return s;
    return s + n.childNodes.map(serialize).join('') + '</' + tag + '>';
}

// parseHTML handles the markup the pages build: elements, quoted and bare
// attributes, text, comments and character references. It does not repair
// malformed markup beyond closing an unclosed element at its parent's end.
function parseHTML(doc, html, parent) {
    const stack = [parent];
    const top = () => stack[stack.length - 1];
    let i = 0;
    while (i < html.length) {
        if (html.startsWith('<!--', i)) {
            const end = html.indexOf('-->', i + 4);
            const stop = end < 0 ? html.length : end;
            top().appendChild(doc.createComment(html.slice(i + 4, stop)));
            i = stop + 3;
            continue;
        }
        if (html[i] === '<' && html[i + 1] === '/') {
            const end = html.indexOf('>', i);
            const name = html.slice(i + 2, end).trim().toUpperCase();
            for (let j = stack.length - 1; j > 0; j--) {
                if (stack[j].tagName === name) { stack.length = j; break; }
            }
            i = end + 1;
            continue;
        }
        if (html[i] === '<' && /[a-zA-Z]/.test(html[i + 1] || '')) {
            const m = /^<([a-zA-Z][a-zA-Z0-9-]*)/.exec(html.slice(i));
            const el = doc.createElement(m[1].toLowerCase());
            i += m[0].length;
            const attrRe = /^\s*([^\s"'>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>`]+)))?/;
            for (;;) {
                const rest = html.slice(i);
                const close = /^\s*(\/?)>/.exec(rest);
                if (close) { i += close[0].length; break; }
                const a = attrRe.exec(rest);
                if (!a) throw new Error('fakedom: cannot parse attributes at ' + JSON.stringify(rest.slice(0, 40)));
                const value = a[2] !== undefined ? a[2] : a[3] !== undefined ? a[3] : a[4] !== undefined ? a[4] : '';
                el.setAttribute(a[1], decodeEntities(value));
                i += a[0].length;
            }
            top().appendChild(el);
            const tag = el.tagName.toLowerCase();
            if (!VOID.has(tag)) stack.push(el);
            continue;
        }
        const next = html.indexOf('<', i + 1);
        const stop = next < 0 ? html.length : next;
        top().appendChild(doc.createTextNode(decodeEntities(html.slice(i, stop))));
        i = stop;
    }
}

// --- Selectors: compound selectors joined by descendant or child combinators,
// comma lists, tag, #id, .class, [attr], [attr=v], [attr^=v], [attr*=v],
// :checked, :disabled, :not(simple), :first-child and :last-child.
function parseSelector(sel) {
    const groups = [];
    let depth = 0, quote = null, start = 0;
    for (let i = 0; i < sel.length; i++) {
        const ch = sel[i];
        if (quote) { if (ch === quote) quote = null; continue; }
        if (ch === '"' || ch === "'") quote = ch;
        else if (ch === '(' || ch === '[') depth++;
        else if (ch === ')' || ch === ']') depth--;
        else if (ch === ',' && depth === 0) { groups.push(sel.slice(start, i)); start = i + 1; }
    }
    groups.push(sel.slice(start));
    return groups.map(g => parseComplex(g.trim()));
}

function parseComplex(s) {
    const parts = [];
    let i = 0, combinator = ' ';
    while (i < s.length) {
        while (s[i] === ' ') i++;
        if (s[i] === '>') { combinator = '>'; i++; continue; }
        const [compound, next] = parseCompound(s, i);
        parts.push({ combinator: parts.length ? combinator : null, compound });
        combinator = ' ';
        i = next;
    }
    return parts;
}

function parseCompound(s, i) {
    const c = { tag: null, id: null, classes: [], attrs: [], pseudos: [] };
    const tag = /^[a-zA-Z*][a-zA-Z0-9-]*/.exec(s.slice(i));
    if (tag) { if (tag[0] !== '*') c.tag = tag[0].toUpperCase(); i += tag[0].length; }
    while (i < s.length && s[i] !== ' ' && s[i] !== '>') {
        const rest = s.slice(i);
        let m;
        if ((m = /^#([\w-]+)/.exec(rest))) { c.id = m[1]; }
        else if ((m = /^\.([\w-]+)/.exec(rest))) { c.classes.push(m[1]); }
        else if ((m = /^\[\s*([\w-]+)\s*(?:([\^*$|~]?=)\s*(?:"([^"]*)"|'([^']*)'|([^\]\s]+)))?\s*\]/.exec(rest))) {
            c.attrs.push({ name: m[1], op: m[2] || null, value: m[3] !== undefined ? m[3] : m[4] !== undefined ? m[4] : m[5] });
        } else if ((m = /^:not\(([^)]*)\)/.exec(rest))) { c.pseudos.push({ not: parseSelector(m[1]) }); }
        else if ((m = /^:([\w-]+)/.exec(rest))) { c.pseudos.push({ name: m[1] }); }
        else throw new Error('fakedom: unsupported selector ' + JSON.stringify(s));
        i += m[0].length;
    }
    return [c, i];
}

function matchCompound(el, c) {
    if (el.nodeType !== 1) return false;
    if (c.tag && el.tagName !== c.tag) return false;
    if (c.id && el.getAttribute('id') !== c.id) return false;
    for (const cls of c.classes) if (!el.classList.contains(cls)) return false;
    for (const a of c.attrs) {
        const v = el.getAttribute(a.name);
        if (v === null) return false;
        if (a.op === '=' && v !== a.value) return false;
        if (a.op === '^=' && !v.startsWith(a.value)) return false;
        if (a.op === '$=' && !v.endsWith(a.value)) return false;
        if (a.op === '*=' && !v.includes(a.value)) return false;
        if (a.op === '~=' && !v.split(/\s+/).includes(a.value)) return false;
    }
    for (const p of c.pseudos) {
        if (p.not) { if (p.not.some(g => matchComplex(el, g, null))) return false; continue; }
        if (p.name === 'checked' && !(el.checked || (el.tagName === 'OPTION' && el.selected))) return false;
        if (p.name === 'disabled' && !el.disabled) return false;
        if (p.name === 'first-child' && el.previousElementSibling) return false;
        if (p.name === 'last-child' && el.nextElementSibling) return false;
        if (!['checked', 'disabled', 'first-child', 'last-child'].includes(p.name)) throw new Error('fakedom: unsupported pseudo-class :' + p.name);
    }
    return true;
}

// Right-to-left match; ancestors stop at scope so querySelectorAll on an
// element does not match through its own ancestors for the leftmost part.
function matchComplex(el, parts, scope) {
    function matchAt(node, idx) {
        if (!matchCompound(node, parts[idx].compound)) return false;
        if (idx === 0) return true;
        const comb = parts[idx].combinator;
        let p = node.parentNode;
        if (comb === '>') return !!p && p !== scope && p.nodeType === 1 && matchAt(p, idx - 1);
        for (; p && p !== scope && p.nodeType === 1; p = p.parentNode) if (matchAt(p, idx - 1)) return true;
        return false;
    }
    return matchAt(el, parts.length - 1);
}

function memoryStorage() {
    const data = new Map();
    return {
        getItem(k) { return data.has(k) ? data.get(k) : null; },
        setItem(k, v) { data.set(k, String(v)); },
        removeItem(k) { data.delete(k); },
        clear() { data.clear(); },
        key(i) { return [...data.keys()][i] ?? null; },
        get length() { return data.size; }
    };
}

// createWindow returns a global object for vm.createContext. bodyHTML is
// parsed into document.body; options.url sets location.
function createWindow(bodyHTML = '', options = {}) {
    const document = new Document();
    if (bodyHTML) document.body.innerHTML = bodyHTML;
    const url = new URL(options.url || 'https://csm.example.test/');
    const window = {
        document,
        Event, CustomEvent,
        KeyboardEvent: Event, MouseEvent: Event, FocusEvent: Event,
        URL, URLSearchParams, Blob, JSON, Math, Date, Promise, Number, String, Array, Object, Error, Map, Set, RegExp,
        console,
        setTimeout, clearTimeout, setInterval, clearInterval, setImmediate,
        requestAnimationFrame: fn => setTimeout(() => fn(Date.now()), 0),
        cancelAnimationFrame: id => clearTimeout(id),
        localStorage: memoryStorage(),
        sessionStorage: memoryStorage(),
        location: {
            href: url.href, origin: url.origin, protocol: url.protocol, host: url.host, hostname: url.hostname,
            pathname: url.pathname, search: url.search, hash: url.hash,
            reloads: 0, assigned: [],
            reload() { this.reloads++; },
            assign(u) { this.assigned.push(String(u)); },
            replace(u) { this.assigned.push(String(u)); }
        },
        history: {
            entries: [],
            replaceState(_, __, u) { this.entries.push(['replace', String(u)]); if (u != null) window.location._set(u); },
            pushState(_, __, u) { this.entries.push(['push', String(u)]); if (u != null) window.location._set(u); }
        },
        navigator: { userAgent: 'fakedom', clipboard: { writeText() { return Promise.resolve(); } } },
        matchMedia: () => ({ matches: false, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} }),
        getComputedStyle: el => el.style,
        MutationObserver: class { observe() {} disconnect() {} },
        _listeners: {},
        addEventListener(type, fn) { (this._listeners[type] = this._listeners[type] || []).push(fn); },
        removeEventListener(type, fn) { const l = this._listeners[type]; if (l && l.includes(fn)) l.splice(l.indexOf(fn), 1); },
        dispatchEvent(ev) {
            if (!ev.target) ev.target = window;
            (this._listeners[ev.type] || []).slice().forEach(fn => fn.call(window, ev));
            return !ev.defaultPrevented;
        }
    };
    Object.defineProperty(window.location, '_set', {
        value(u) {
            const next = new URL(String(u), url.href);
            Object.assign(this, { href: next.href, pathname: next.pathname, search: next.search, hash: next.hash });
        }
    });
    Object.defineProperty(document, 'defaultView', { value: window, enumerable: false });
    window.window = window;
    window.self = window;
    window.globalThis = window;
    return window;
}

module.exports = { createWindow, Event, CustomEvent };
