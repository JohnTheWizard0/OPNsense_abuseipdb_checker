<style>
    .country-flag-icon {
        display: inline-block;
        width: 1.33em;
        height: 1em;
        margin-right: 0.5em;
        vertical-align: text-bottom;
    }

    .country-flag-local {
        width: 20px;
        height: 15px;
        margin-right: 0.5em;
        vertical-align: middle;
        border: 1px solid #ccc;
        border-radius: 2px;
    }
    
    .table .country-flag-icon {
        width: 1.2em;
        height: 0.9em;
    }
    
    .fi {
        border-radius: 2px;
        box-shadow: 0 1px 2px rgba(0,0,0,0.1);
    }
    
    /* Enhanced styling for marked safe rows */
    .table tbody tr.info {
        background-color: #d9edf7;
    }
    
    .pagination {
        margin: 10px 0;
    }
    
    .search-container {
        margin-bottom: 15px;
    }
    
    .search-container input {
        width: 100%;
        max-width: 300px;
    }

    /* Connection details styling */
    .connection-info-btn {
        margin-left: 5px;
        padding: 2px 6px;
        font-size: 11px;
    }

    .connection-details-popup {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
}

    .connection-details-popup h5 {
        margin-bottom: 15px;
        color: #2c3e50;
        border-bottom: 2px solid #3498db;
        padding-bottom: 8px;
        font-weight: 600;
    }

    .connection-detail {
        background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
        border: 1px solid #dee2e6;
        border-left: 4px solid #007bff;
        border-radius: 6px;
        padding: 12px 15px;
        margin-bottom: 10px;
        font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
        font-size: 13px;
        color: #2c3e50;
        transition: all 0.2s ease;
    }

    .connection-detail:hover {
        border-left-color: #0056b3;
        box-shadow: 0 2px 8px rgba(0, 123, 255, 0.15);
        transform: translateX(2px);
    }

    .connection-detail strong {
        color: #495057;
        font-weight: 600;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    .connection-detail:last-child {
        margin-bottom: 0;
    }

    .modal-dialog .modal-content {
        border-radius: 8px;
        box-shadow: 0 10px 25px rgba(0, 0, 0, 0.2);
    }

    .connection-detail:last-child {
        margin-bottom: 0;
    }

    /* Enhanced table styling */
    .table th .fa-info-circle {
        margin-left: 5px;
        cursor: help;
    }

    .btn-secondary {
        background-color: #6c757d;
        border-color: #6c757d;
        color: #fff;
    }

    .btn-secondary:hover {
        background-color: #5a6268;
        border-color: #545b62;
    }

    .alert-warning i {
        margin-right: 8px;
    }
</style>