const sidebar = document.getElementById("sidebar");
const toggleBtn = document.getElementById("sidebarToggle");
const statusCard = document.getElementById("globalStatusCard");
const statusLabel = document.getElementById("globalStatusLabel");

if (toggleBtn && sidebar) {
    toggleBtn.addEventListener("click", () => {
        sidebar.classList.toggle("collapsed");
    });
}

async function updateGlobalStatus() {
    if (!statusCard || !statusLabel) {
        return;
    }

    try {
        const response = await fetch("/api/system-status");
        const data = await response.json();
        const healthy = data.elasticsearch && data.flask;

        statusCard.classList.toggle("is-offline", !healthy);
        statusLabel.innerText = healthy ? "Services online" : "Service issue";
    } catch (error) {
        statusCard.classList.add("is-offline");
        statusLabel.innerText = "Status unavailable";
    }
}

updateGlobalStatus();
setInterval(updateGlobalStatus, 10000);
