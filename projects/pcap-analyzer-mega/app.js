/**
 * Charger l'exemple
 */
document.getElementById('load-sample-btn').addEventListener('click', () => {
    console.log('📦 Chargement de l\'exemple...');
    
    if (!SAMPLE_PCAP_DATA || SAMPLE_PCAP_DATA.length === 0) {
        showError('Données d\'exemple non disponibles');
        return;
    }

    // Afficher loading
    document.getElementById('loading').style.display = 'block';

    // Simuler un délai d'analyse
    setTimeout(() => {
        try {
            processPackets(SAMPLE_PCAP_DATA);
            displayDashboard();
            showNotification('✅ Exemple chargé: ' + SAMPLE_PCAP_DATA.length + ' packets', 'success');
        } catch (error) {
            showError(error.message);
        } finally {
            document.getElementById('loading').style.display = 'none';
        }
    }, 1000);
});

/**
 * Traiter les packets
 */
function processPackets(packets) {
    console.log('🔍 Traitement de', packets.length, 'packets...');
    
    // Analyser les packets
    const stats = analyzePackets(packets);
    const threats = detectThreats(packets);
    
    // Stocker globalement
    window.pcapData = {
        packets: packets,
        stats: stats,
        threats: threats,
        loadedAt: new Date()
    };
    
    console.log('✅ Analyse complète');
    console.log(stats);
    console.log(threats);
    
    return window.pcapData;
}

/**
 * Analyser les packets
 */
function analyzePackets(packets) {
    const stats = {
        total: packets.length,
        byProtocol: {},
        byIP: { src: {}, dst: {} },
        bySeverity: { low: 0, high: 0, critical: 0 },
        totalSize: 0,
        timeRange: {}
    };

    packets.forEach(p => {
        // Protocol stats
        stats.byProtocol[p.protocol] = (stats.byProtocol[p.protocol] || 0) + 1;

        // IP stats
        stats.byIP.src[p.srcIP] = (stats.byIP.src[p.srcIP] || 0) + 1;
        stats.byIP.dst[p.dstIP] = (stats.byIP.dst[p.dstIP] || 0) + 1;

        // Severity
        const sev = p.severity || 'low';
        stats.bySeverity[sev]++;

        // Size
        stats.totalSize += p.size;
    });

    stats.avgSize = Math.round(stats.totalSize / stats.total);

    return stats;
}

/**
 * Détecter les menaces
 */
function detectThreats(packets) {
    const threats = [];

    packets.forEach((p, idx) => {
        if (p.severity === 'critical' || p.severity === 'high') {
            threats.push({
                packetNum: p.number,
                type: detectThreatType(p),
                severity: p.severity,
                src: p.srcIP,
                dst: p.dstIP,
                protocol: p.protocol,
                description: generateThreatDesc(p)
            });
        }
    });

    return threats;
}

/**
 * Détecter le type de menace
 */
function detectThreatType(packet) {
    const payload = packet.payload.toLowerCase();
    
    if (packet.dstPort === 3389) return 'RDP Brute Force';
    if (payload.includes('cmd') || payload.includes('powershell')) return 'C2 Communication';
    if (packet.protocol === 'ICMP' && packet.flags === 'ECHO') return 'ICMP Flood';
    if (payload.includes('or 1=1') || payload.includes('sql')) return 'SQL Injection';
    if (payload.includes('attacker')) return 'DNS Exfiltration';
    if (payload.includes('malware')) return 'Malware Download';
    if (packet.dstPort === 445) return 'SMB Lateral Movement';
    
    return 'Suspicious Activity';
}

/**
 * Générer description menace
 */
function generateThreatDesc(packet) {
    return `${packet.srcIP}:${packet.srcPort} → ${packet.dstIP}:${packet.dstPort} (${packet.protocol})`;
}

/**
 * Afficher le dashboard
 */
function displayDashboard() {
    const data = window.pcapData;
    const dashboard = document.getElementById('dashboard');
    
    let html = `
        <div class="dashboard-grid">
            <div class="card stats">
                <h3>📊 Statistiques</h3>
                <div class="stat">
                    <span>Packets Total</span>
                    <strong>${data.stats.total}</strong>
                </div>
                <div class="stat">
                    <span>Taille Moyenne</span>
                    <strong>${data.stats.avgSize} bytes</strong>
                </div>
                <div class="stat">
                    <span>Menaces Détectées</span>
                    <strong style="color: #ff4444;">${data.threats.length}</strong>
                </div>
            </div>

            <div class="card protocols">
                <h3>🔌 Protocoles</h3>
                ${Object.entries(data.stats.byProtocol)
                    .map(([proto, count]) => `
                        <div class="protocol-item">
                            <span>${proto}</span>
                            <strong>${count}</strong>
                        </div>
                    `)
                    .join('')}
            </div>

            <div class="card severity">
                <h3>🚨 Sévérité</h3>
                <div class="severity-item">
                    <span>🟢 Low</span>
                    <strong>${data.stats.bySeverity.low}</strong>
                </div>
                <div class="severity-item">
                    <span>🟡 High</span>
                    <strong>${data.stats.bySeverity.high}</strong>
                </div>
                <div class="severity-item">
                    <span>🔴 Critical</span>
                    <strong>${data.stats.bySeverity.critical}</strong>
                </div>
            </div>
        </div>

        <div class="card threats-list">
            <h3>🔴 Menaces Détectées (${data.threats.length})</h3>
            <table class="threats-table">
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Sévérité</th>
                    </tr>
                </thead>
                <tbody>
                    ${data.threats.map(t => `
                        <tr class="severity-${t.severity}">
                            <td>${t.type}</td>
                            <td>${t.src}</td>
                            <td>${t.dst}</td>
                            <td><strong>${t.severity.toUpperCase()}</strong></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;

    dashboard.innerHTML = html;
    dashboard.style.display = 'block';
}

/**
 * Notifications
 */
function showNotification(msg, type) {
    const div = document.createElement('div');
    div.className = 'notification ' + type;
    div.textContent = msg;
    document.body.appendChild(div);
    setTimeout(() => div.remove(), 3000);
}

function showError(msg) {
    document.getElementById('error').textContent = '❌ ' + msg;
    document.getElementById('error').style.display = 'block';
}