// CSM.shortcuts — Global keyboard shortcuts
var CSM = CSM || {};

CSM.shortcuts = (function() {
    var _helpVisible = false;
    var _helpOverlay = null;
    var _pendingChord = null;
    var _chordTimer = null;
    var _selectedRowIndex = -1;

    // Route map for g+key chords
    var _chords = {
        d: '/dashboard',
        f: '/findings',
        h: '/history',
        t: '/threat',
        r: '/rules',
        b: '/firewall'
    };

    // All shortcut descriptions for help modal
    var _descriptions = [
        { keys: '?', desc: 'Show this help' },
        { keys: '/', desc: 'Focus search input' },
        { keys: 'g d', desc: 'Go to Dashboard' },
        { keys: 'g f', desc: 'Go to Findings' },
        { keys: 'g h', desc: 'Go to History' },
        { keys: 'g t', desc: 'Go to Threat Intel' },
        { keys: 'g r', desc: 'Go to Rules' },
        { keys: 'g b', desc: 'Go to Blocked IPs (Firewall)' },
        { keys: 'j / k', desc: 'Move selection down / up (Findings)' },
        { keys: 'd', desc: 'Dismiss selected finding (Findings)' },
        { keys: 'f', desc: 'Fix selected finding (Findings)' }
    ];

    function _isInputFocused() {
        var el = document.activeElement;
        if (!el) return false;
        var tag = el.tagName.toLowerCase();
        return tag === 'input' || tag === 'textarea' || tag === 'select' || el.isContentEditable;
    }

    function _isFindingsPage() {
        return !!document.getElementById('findings-table');
    }

    function _getVisibleFindingRows() {
        return Array.from(document.querySelectorAll('.finding-row')).filter(function(r) {
            return r.style.display !== 'none';
        });
    }

    function _clearSelection() {
        var prev = document.querySelector('.finding-row.csm-kbd-selected');
        if (prev) prev.classList.remove('csm-kbd-selected');
        _selectedRowIndex = -1;
    }

    function _selectRow(index) {
        var rows = _getVisibleFindingRows();
        if (rows.length === 0) return;
        _clearSelection();
        if (index < 0) index = 0;
        if (index >= rows.length) index = rows.length - 1;
        _selectedRowIndex = index;
        rows[index].classList.add('csm-kbd-selected');
        // Scroll into view if needed
        rows[index].scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }

    function _buildHelpOverlay() {
        if (_helpOverlay) return _helpOverlay;

        _helpOverlay = document.createElement('div');
        _helpOverlay.id = 'csm-shortcuts-help';
        _helpOverlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.6);z-index:10000;display:flex;align-items:center;justify-content:center;';

        var box = document.createElement('div');
        box.style.cssText = 'background:#1e293b;color:#c8d3e0;border-radius:8px;padding:24px 32px;max-width:420px;width:90%;max-height:80vh;overflow-y:auto;box-shadow:0 8px 32px rgba(0,0,0,0.4);';

        var title = document.createElement('h3');
        title.style.cssText = 'margin:0 0 16px 0;font-size:16px;font-weight:600;';
        title.textContent = 'Keyboard Shortcuts';
        box.appendChild(title);

        var table = document.createElement('table');
        table.style.cssText = 'width:100%;border-collapse:collapse;';

        for (var i = 0; i < _descriptions.length; i++) {
            var tr = document.createElement('tr');
            tr.style.cssText = 'border-bottom:1px solid #2d3a4e;';
            var tdKey = document.createElement('td');
            tdKey.style.cssText = 'padding:6px 12px 6px 0;white-space:nowrap;';
            var parts = _descriptions[i].keys.split(' / ');
            for (var p = 0; p < parts.length; p++) {
                if (p > 0) tdKey.appendChild(document.createTextNode(' / '));
                var kbd = document.createElement('kbd');
                kbd.style.cssText = 'background:#334155;border:1px solid #475569;border-radius:3px;padding:2px 6px;font-size:12px;font-family:monospace;';
                kbd.textContent = parts[p].trim();
                tdKey.appendChild(kbd);
            }
            var tdDesc = document.createElement('td');
            tdDesc.style.cssText = 'padding:6px 0;color:#94a3b8;font-size:13px;';
            tdDesc.textContent = _descriptions[i].desc;
            tr.appendChild(tdKey);
            tr.appendChild(tdDesc);
            table.appendChild(tr);
        }
        box.appendChild(table);

        var hint = document.createElement('div');
        hint.style.cssText = 'margin-top:16px;text-align:center;color:#64748b;font-size:12px;';
        hint.textContent = 'Press ? or Escape to close';
        box.appendChild(hint);

        _helpOverlay.appendChild(box);

        _helpOverlay.addEventListener('click', function(e) {
            if (e.target === _helpOverlay) _hideHelp();
        });

        document.body.appendChild(_helpOverlay);
        return _helpOverlay;
    }

    function _showHelp() {
        _buildHelpOverlay();
        _helpOverlay.style.display = 'flex';
        _helpVisible = true;
    }

    function _hideHelp() {
        if (_helpOverlay) _helpOverlay.style.display = 'none';
        _helpVisible = false;
    }

    function _cancelChord() {
        _pendingChord = null;
        if (_chordTimer) {
            clearTimeout(_chordTimer);
            _chordTimer = null;
        }
    }

    // Inject CSS for selected row highlight
    var style = document.createElement('style');
    style.textContent = '.csm-kbd-selected { outline: 2px solid #206bc4; outline-offset: -2px; background-color: rgba(32,107,196,0.08) !important; }';
    document.head.appendChild(style);

    document.addEventListener('keydown', function(e) {
        // Close help on Escape
        if (e.key === 'Escape') {
            if (_helpVisible) { _hideHelp(); e.preventDefault(); return; }
            _cancelChord();
            return;
        }

        // Don't activate shortcuts when typing in form elements
        if (_isInputFocused()) {
            return;
        }

        // If help is visible, only ? or Escape closes it
        if (_helpVisible) {
            if (e.key === '?') { _hideHelp(); e.preventDefault(); }
            return;
        }

        // Handle pending chord (g was pressed)
        if (_pendingChord === 'g') {
            _cancelChord();
            var target = _chords[e.key];
            if (target) {
                e.preventDefault();
                window.location.href = target;
            }
            return;
        }

        // Single-key shortcuts
        if (e.key === '?') {
            e.preventDefault();
            _showHelp();
            return;
        }

        if (e.key === '/') {
            // Focus search input
            var searchInput = document.querySelector('input[id*="search"]');
            if (searchInput) {
                e.preventDefault();
                searchInput.focus();
            }
            return;
        }

        if (e.key === 'g') {
            // Start chord sequence
            _pendingChord = 'g';
            _chordTimer = setTimeout(function() {
                _pendingChord = null;
            }, 1000);
            return;
        }

        // Findings-page shortcuts
        if (_isFindingsPage()) {
            if (e.key === 'j') {
                e.preventDefault();
                _selectRow(_selectedRowIndex + 1);
                return;
            }
            if (e.key === 'k') {
                e.preventDefault();
                _selectRow(_selectedRowIndex - 1);
                return;
            }
            if (e.key === 'd' && _selectedRowIndex >= 0) {
                e.preventDefault();
                var rows = _getVisibleFindingRows();
                var row = rows[_selectedRowIndex];
                if (row) {
                    var dismissBtn = row.querySelector('.dismiss-btn');
                    if (dismissBtn) dismissBtn.click();
                }
                return;
            }
            if (e.key === 'f' && _selectedRowIndex >= 0) {
                e.preventDefault();
                var rows2 = _getVisibleFindingRows();
                var row2 = rows2[_selectedRowIndex];
                if (row2) {
                    var fixBtn = row2.querySelector('.fix-btn');
                    if (fixBtn) fixBtn.click();
                }
                return;
            }
        }
    });

    return {
        showHelp: _showHelp,
        hideHelp: _hideHelp,
        clearSelection: _clearSelection
    };
})();
