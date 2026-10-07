const API_BASE_URL = "http://127.0.0.1:8000";


// ==========================================
// HELPERS
// ==========================================

function formatTime(timestamp) {

    if (!timestamp) {
        return "-";
    }

    const date = new Date(timestamp);

    if (isNaN(date.getTime())) {
        return timestamp;
    }

    return date.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
    });
}


function getRiskClass(score) {

    if (score >= 70) {
        return "risk-high";
    }

    if (score >= 40) {
        return "risk-medium";
    }

    return "risk-low";
}


function getStatusClass(status) {

    if (status === "malicious") {
        return "badge-danger";
    }

    if (status === "suspicious") {
        return "badge-warning";
    }

    return "badge-success";
}


function getActionClass(action) {

    if (action === "blocked") {
        return "badge-danger";
    }

    if (action === "alerted") {
        return "badge-warning";
    }

    return "badge-success";
}


// ==========================================
// LOAD STATISTICS
// ==========================================

async function loadStatistics() {

    try {

        const response = await fetch(
            `${API_BASE_URL}/api/statistics`
        );

        if (!response.ok) {
            throw new Error("Statistics request failed");
        }

        const data = await response.json();


        // Main cards

        document.getElementById("totalRequests").textContent =
            data.total_requests;

        document.getElementById("attacksDetected").textContent =
            data.attacks_detected;

        document.getElementById("blockedRequests").textContent =
            data.blocked_requests;

        document.getElementById("allowedRequests").textContent =
            data.allowed_requests;


        // Detection rate

        const total = data.total_requests || 0;

        const detectionRate =
            total > 0
                ? (data.attacks_detected / total) * 100
                : 0;


        // Block rate

        const blockRate =
            total > 0
                ? (data.blocked_requests / total) * 100
                : 0;


        document.getElementById("detectionRate").textContent =
            `${detectionRate.toFixed(1)}%`;

        document.getElementById("blockRate").textContent =
            `${blockRate.toFixed(1)}%`;


        document.getElementById("detectionProgress").style.width =
            `${Math.min(detectionRate, 100)}%`;

        document.getElementById("blockProgress").style.width =
            `${Math.min(blockRate, 100)}%`;


    } catch (error) {

        console.error(
            "Statistics error:",
            error
        );

    }
}


// ==========================================
// LOAD LOGS
// ==========================================

async function loadLogs() {

    try {

        const response = await fetch(
            `${API_BASE_URL}/api/logs`
        );

        if (!response.ok) {
            throw new Error("Logs request failed");
        }

        const logs = await response.json();


        const tableBody =
            document.getElementById("logsTableBody");


        tableBody.innerHTML = "";


        document.getElementById("eventCount").textContent =
            `${logs.length} EVENTS`;


        if (logs.length === 0) {

            tableBody.innerHTML = `
                <tr>
                    <td colspan="8"
                        style="text-align:center; padding:40px; color:#52657e;">
                        No security events detected
                    </td>
                </tr>
            `;

            renderAttackChart([]);

            return;
        }


        // Average risk

        let totalRisk = 0;

        logs.forEach(log => {

            totalRisk +=
                Number(log.risk_score) || 0;

        });


        const averageRisk =
            logs.length > 0
                ? totalRisk / logs.length
                : 0;


        document.getElementById("averageRisk").textContent =
            averageRisk.toFixed(1);


        document.getElementById("riskProgress").style.width =
            `${Math.min(averageRisk, 100)}%`;


        // Build table

        logs.forEach(log => {

            const row =
                document.createElement("tr");


            const timeCell =
                document.createElement("td");

            timeCell.textContent =
                formatTime(log.timestamp);


            const requestCell =
                document.createElement("td");

            requestCell.className =
                "request-id";

            requestCell.textContent =
                log.request_id || "-";


            const sourceCell =
                document.createElement("td");

            sourceCell.textContent =
                log.ip_address || "-";


            const endpointCell =
                document.createElement("td");

            endpointCell.className =
                "endpoint";

            endpointCell.textContent =
                log.endpoint || "-";


            const threatCell =
                document.createElement("td");

            threatCell.className =
                "threat-name";

            threatCell.textContent =
                log.attack_type || "Normal";


            const riskCell =
                document.createElement("td");

            const risk =
                Number(log.risk_score) || 0;

            riskCell.className =
                getRiskClass(risk);

            riskCell.textContent =
                `${risk}`;


            const statusCell =
                document.createElement("td");

            const statusBadge =
                document.createElement("span");

            statusBadge.className =
                `badge ${getStatusClass(log.status)}`;

            statusBadge.textContent =
                (log.status || "normal").toUpperCase();

            statusCell.appendChild(statusBadge);


            const actionCell =
                document.createElement("td");

            const actionBadge =
                document.createElement("span");

            actionBadge.className =
                `badge ${getActionClass(log.action)}`;

            actionBadge.textContent =
                (log.action || "allowed").toUpperCase();

            actionCell.appendChild(actionBadge);


            row.appendChild(timeCell);

            row.appendChild(requestCell);

            row.appendChild(sourceCell);

            row.appendChild(endpointCell);

            row.appendChild(threatCell);

            row.appendChild(riskCell);

            row.appendChild(statusCell);

            row.appendChild(actionCell);


            tableBody.appendChild(row);

        });


        renderAttackChart(logs);


    } catch (error) {

        console.error(
            "Logs error:",
            error
        );

    }
}


// ==========================================
// ATTACK DISTRIBUTION
// ==========================================

function renderAttackChart(logs) {

    const chart =
        document.getElementById("attackChart");


    chart.innerHTML = "";


    const attacks = {};


    logs.forEach(log => {

        const attack =
            log.attack_type || "Normal";

        attacks[attack] =
            (attacks[attack] || 0) + 1;

    });


    const entries =
        Object.entries(attacks)
            .sort((a, b) => b[1] - a[1]);


    if (entries.length === 0) {

        chart.innerHTML = `
            <div class="empty-chart">
                Waiting for security events...
            </div>
        `;

        return;
    }


    const maximum =
        entries[0][1];


    entries.forEach(([attack, count]) => {

        const row =
            document.createElement("div");

        row.className =
            "attack-row";


        const info =
            document.createElement("div");

        info.className =
            "attack-info";


        const name =
            document.createElement("span");

        name.className =
            "attack-name";

        name.textContent =
            attack;


        const countElement =
            document.createElement("span");

        countElement.className =
            "attack-count";

        countElement.textContent =
            `${count} event${count !== 1 ? "s" : ""}`;


        info.appendChild(name);

        info.appendChild(countElement);


        const bar =
            document.createElement("div");

        bar.className =
            "attack-bar";


        const fill =
            document.createElement("div");

        fill.className =
            "attack-fill";


        const percentage =
            (count / maximum) * 100;


        fill.style.width =
            `${percentage}%`;


        bar.appendChild(fill);


        row.appendChild(info);

        row.appendChild(bar);


        chart.appendChild(row);

    });

}


// ==========================================
// UPDATE TIME
// ==========================================

function updateTime() {

    const now =
        new Date();


    document.getElementById("lastUpdated")
        .textContent =
        now.toLocaleTimeString();

}


// ==========================================
// LOAD EVERYTHING
// ==========================================

async function loadDashboard() {

    await Promise.all([
        loadStatistics(),
        loadLogs()
    ]);

    updateTime();

}


// ==========================================
// INITIAL LOAD
// ==========================================

loadDashboard();


// ==========================================
// AUTO REFRESH
// ==========================================

setInterval(() => {

    loadDashboard();

}, 5000);