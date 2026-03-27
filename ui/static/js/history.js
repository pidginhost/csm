// CSM History page
var historyTable;
if (document.getElementById('history-table')) {
    historyTable = new CSM.Table({
        tableId: 'history-table',
        perPage: 25,
        search: true,
        searchId: 'history-search',
        sortable: true,
        detailRows: true,
        filters: [
            { id: 'sev-filter', attr: 'data-sev' }
        ]
    });
}

// Bind click-to-expand on history rows
document.querySelectorAll('.history-row').forEach(function(row) {
    row.addEventListener('click', function() {
        if (historyTable) historyTable.toggleDetail(this);
    });
});
