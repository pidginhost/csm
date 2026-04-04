// CSM Incident Timeline
(function() {
    'use strict';

    var sevLabels = {}; for (var sk in CSM.sevMap) sevLabels[sk] = CSM.sevMap[sk].label;
    var sevClasses = {}; for (var sk2 in CSM.sevMap) sevClasses[sk2] = CSM.sevMap[sk2].cls;

    function loadIncident() {
        var query = document.getElementById('incident-query').value.trim();
        if (!query) return;
        var hours = document.getElementById('incident-hours').value;

        // Detect if query is an IP or account
        var isIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(query) || query.indexOf(':') >= 0;
        var url = '/api/v1/incident?hours=' + hours;
        if (isIP) { url += '&ip=' + encodeURIComponent(query); }
        else { url += '&account=' + encodeURIComponent(query); }

        var container = document.getElementById('incident-content');
        container.innerHTML = '<div class="card-body text-center text-muted py-4"><span class="spinner-border spinner-border-sm"></span> Searching...</div>';

        fetch(CSM.apiUrl(url), { credentials: 'same-origin' })
            .then(function(r) { return r.json(); })
            .then(function(data) { renderTimeline(data); })
            .catch(function() { CSM.loadError(container, loadIncident); });
    }

    function renderTimeline(data) {
        var container = document.getElementById('incident-content');
        var events = data.events || [];
        if (events.length === 0) {
            container.innerHTML = '<div class="card-body text-center text-muted py-4">No events found for this query.</div>';
            return;
        }

        var html = '<div class="card-body">';
        html += '<div class="text-muted small mb-3">' + events.length + ' events found</div>';
        html += '<div class="timeline-list">';

        for (var i = 0; i < events.length; i++) {
            var e = events[i];
            var sevClass = sevClasses[e.severity] || 'info';
            var sevLabel = sevLabels[e.severity] || 'INFO';
            var typeLabel = e.type === 'finding' ? 'Finding' : e.type === 'action' ? 'Action' : 'Event';
            var ago = CSM.timeAgo(e.timestamp);

            html += '<div class="d-flex mb-2 align-items-start">';
            html += '<div class="text-nowrap me-3 text-muted small" style="min-width:80px" data-timestamp="' + CSM.esc(e.timestamp) + '">' + CSM.esc(ago) + '</div>';
            html += '<div class="me-2"><span class="badge badge-' + sevClass + '">' + sevLabel + '</span></div>';
            html += '<div class="me-2"><span class="badge bg-azure-lt">' + CSM.esc(typeLabel) + '</span></div>';
            html += '<div style="word-break:break-all">' + CSM.esc(e.summary);
            if (e.details) {
                html += '<div class="text-muted small mt-1" style="white-space:pre-wrap">' + CSM.esc(e.details) + '</div>';
            }
            html += '</div></div>';
        }

        html += '</div></div>';
        container.innerHTML = html;
    }

    document.getElementById('incident-search-btn').addEventListener('click', loadIncident);
    document.getElementById('incident-query').addEventListener('keydown', function(e) {
        if (e.key === 'Enter') loadIncident();
    });

    // Check URL params for pre-populated search
    var params = new URLSearchParams(window.location.search);
    var preIP = params.get('ip');
    var preAccount = params.get('account');
    if (preIP || preAccount) {
        document.getElementById('incident-query').value = preIP || preAccount;
        loadIncident();
    }
})();
