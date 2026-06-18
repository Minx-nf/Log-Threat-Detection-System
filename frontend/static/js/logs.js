let allLogs = [];
let currentSearch = "";
let currentEvent = "";
let currentHost = ""; // Tracks the selected PC

// Helper to make event names look clean (e.g., "failed_login" -> "FAILED LOGIN")
function formatEventName(value) {
    return (value || "unknown").replaceAll("_", " ").toUpperCase();
}

// Helper to convert timestamps safely without double-shifting timezones
function formatTime(isoString) {
    if (!isoString) return "Unknown time";
    
    // Let the browser natively parse the string without forcing a 'Z'
    const date = new Date(isoString);
    
    // Fallback just in case a truly broken string sneaks through
    return isNaN(date) ? "Invalid Date" : date.toLocaleString(); 
}

function addCell(row, value) {
    const cell = document.createElement("td");
    cell.textContent = value || "";
    row.appendChild(cell);
}

async function loadLogs() {
    const response = await fetch("/api/logs");
    let rawLogs = await response.json();

    // FOOLPROOF SORTING: Forces JS to guarantee the newest timestamp is at index 0
    rawLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    allLogs = rawLogs;
    
    // Auto-populate the dropdown with whatever PCs are currently reporting
    populateHostDropdown(allLogs);
    applyFilter();
}

function populateHostDropdown(logs) {
    const hostFilter = document.getElementById("hostFilter");
    const selectedHost = hostFilter.value; // Remember what the user currently has selected

    // Extract a list of unique hostnames from the logs
    const uniqueHosts = [...new Set(logs.map(log => log.hostname))].filter(Boolean);

    // Reset the dropdown
    hostFilter.innerHTML = '<option value="">All Hosts (PCs)</option>';

    // Add an option for each unique PC
    uniqueHosts.forEach(host => {
        const option = document.createElement("option");
        option.value = host;
        option.textContent = host;
        if (host === selectedHost) {
            option.selected = true; // Keep it selected if it refreshes
        }
        hostFilter.appendChild(option);
    });
}

function renderLogs(logs) {
    const tbody = document.getElementById("logsBody");
    tbody.innerHTML = "";

    logs.forEach(log => {
        const row = document.createElement("tr");
        row.style.cursor = "pointer";
        row.addEventListener("click", () => showLogDetails(log));

        // Use our new formatters for the table UI
        addCell(row, formatTime(log.timestamp));
        addCell(row, formatEventName(log.event_type));
        addCell(row, log.hostname);
        addCell(row, log.source_ip);
        addCell(row, log.username);
        addCell(row, log.collector_ip);

        tbody.appendChild(row);
    });
}

function applyFilter() {
    let filtered = [...allLogs];

    // 1. Filter by Search Text
    if (currentSearch !== "") {
        filtered = filtered.filter(log =>
            JSON.stringify(log).toLowerCase().includes(currentSearch)
        );
    }

    // 2. Filter by Event Type
    if (currentEvent !== "") {
        filtered = filtered.filter(log => log.event_type === currentEvent);
    }

    // 3. Filter by Host PC
    if (currentHost !== "") {
        filtered = filtered.filter(log => log.hostname === currentHost);
    }

    renderLogs(filtered);
}

// Event Listeners for the UI controls
document.getElementById("searchBox").addEventListener("keyup", event => {
    currentSearch = event.target.value.toLowerCase();
    applyFilter();
});

document.getElementById("eventFilter").addEventListener("change", event => {
    currentEvent = event.target.value;
    applyFilter();
});

// NEW: Event Listener for the Host dropdown
document.getElementById("hostFilter").addEventListener("change", event => {
    currentHost = event.target.value;
    applyFilter();
});

function showLogDetails(log) {
    const content = document.getElementById("modalContent");
    content.innerHTML = "";

    const detailGrid = document.createElement("div");
    detailGrid.className = "detail-grid";

    const fields = [
        ["Timestamp", formatTime(log.timestamp)],
        ["Event Type", formatEventName(log.event_type)],
        ["Host", log.hostname],
        ["Collector IP", log.collector_ip],
        ["Source IP", log.source_ip],
        ["Username", log.username],
        ["Event ID", log.event_id],
        ["Record Number", log.record_number],
    ];

    fields.forEach(([label, value]) => {
        const item = document.createElement("div");
        item.className = "detail-item";

        const strong = document.createElement("strong");
        strong.textContent = label;

        const span = document.createElement("span");
        span.textContent = value || "";

        item.appendChild(strong);
        item.appendChild(span);
        detailGrid.appendChild(item);
    });

    content.appendChild(detailGrid);

    if (log.message) {
        const message = document.createElement("div");
        message.className = "detail-item mt-3";

        const strong = document.createElement("strong");
        strong.textContent = "Message";

        const span = document.createElement("span");
        span.textContent = log.message;

        message.appendChild(strong);
        message.appendChild(span);
        content.appendChild(message);
    }

    document.getElementById("logModal").style.display = "block";
}

function closeModal() {
    document.getElementById("logModal").style.display = "none";
}

loadLogs();
setInterval(loadLogs, 5000);