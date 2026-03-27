// CSRF helper — reads token from <meta name="csrf-token"> and provides fetch wrapper
var CSM = CSM || {};
CSM.csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';

// Wrapper for POST requests with CSRF token
CSM.post = function(url, body) {
    return fetch(url, {
        method: 'POST',
        credentials: 'same-origin',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': CSM.csrfToken
        },
        body: JSON.stringify(body)
    }).then(function(r) { return r.json(); });
};

// Shared HTML-escape helper used across all pages
CSM.esc = function(s) {
    var d = document.createElement('div');
    d.appendChild(document.createTextNode(s || ''));
    return d.innerHTML;
};
