/**
 * Visualization - Charts et Graphs Avancés
 */

const chartInstances = {};

/**
 * Protocol Chart - Doughnut
 */
function createProtocolChart(protocolStats) {
    const ctx = document.getElementById('protocolChart');
    if (!ctx) return;

    if (chartInstances.protocolChart) {
        chartInstances.protocolChart.destroy();
    }

    const top10 = protocolStats.slice(0, 10);
    const colors = [
        '#00d4ff', '#ff006e', '#00ff41', '#ffa500',
        '#ff0000', '#9d00ff', '#00ffff', '#ff69b4',
        '#1e90ff', '#32cd32'
    ];

    chartInstances.protocolChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: top10.map(p => p.name),
            datasets: [{
                data: top10.map(p => p.count),
                backgroundColor: colors.slice(0, top10.length),
                borderColor: '#0a0e27',
                borderWidth: 3,
                hoverBorderWidth: 5
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#ffffff',
                        font: { size: 12, weight: 'bold' },
                        padding: 15,
                        usePointStyle: true
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    titleColor: '#00d4ff',
                    bodyColor: '#ffffff',
                    borderColor: '#00d4ff',
                    borderWidth: 2,
                    padding: 12,
                    displayColors: true
                }
            }
        }
    });
}

/**
 * Packet Size Distribution Chart - Bar
 */
function createSizeChart(sizeDistribution) {
    const ctx = document.getElementById('sizeChart');
    if (!ctx) return;

    if (chartInstances.sizeChart) {
        chartInstances.sizeChart.destroy();
    }

    chartInstances.sizeChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: Object.keys(sizeDistribution),
            datasets: [{
                label: 'Nombre de Packets',
                data: Object.values(sizeDistribution),
                backgroundColor: [
                    'rgba(0, 212, 255, 0.7)',
                    'rgba(0, 212, 255, 0.75)',
                    'rgba(0, 212, 255, 0.8)',
                    'rgba(0, 212, 255, 0.85)',
                    'rgba(0, 212, 255, 0.9)',
                    'rgba(0, 212, 255, 0.95)'
                ],
                borderColor: '#00d4ff',
                borderWidth: 2,
                borderRadius: 5,
                hoverBackgroundColor: '#ff006e'
            }]
        },
        options: {
            responsive: true,
            indexAxis: 'x',
            plugins: {
                legend: {
                    labels: {
                        color: '#ffffff',
                        font: { size: 12, weight: 'bold' }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    titleColor: '#00d4ff',
                    bodyColor: '#ffffff',
                    borderColor: '#00d4ff',
                    borderWidth: 2,
                    padding: 12,
                    callbacks: {
                        label: (context) => `Packets: ${context.parsed.y}`
                    }
                }
            },
            scales: {
                y: {
                    ticks: { color: '#ffffff', font: { size: 11 } },
                    grid: { color: 'rgba(42, 63, 95, 0.3)' },
                    beginAtZero: true
                },
                x: {
                    ticks: { color: '#ffffff', font: { size: 11 } },
                    grid: { color: 'rgba(42, 63, 95, 0.3)' }
                }
            }
        }
    });
}

/**
 * Traffic Direction Chart - Pie
 */
function createDirectionChart(trafficStats) {
    const ctx = document.getElementById('directionChart');
    if (!ctx) return;

    if (chartInstances.directionChart) {
        chartInstances.directionChart.destroy();
    }

    const inboundMB = (trafficStats.inbound / (1024 * 1024)).toFixed(2);
    const outboundMB = (trafficStats.outbound / (1024 * 1024)).toFixed(2);

    chartInstances.directionChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: [`Inbound (${inboundMB} MB)`, `Outbound (${outboundMB} MB)`],
            datasets: [{
                data: [trafficStats.inbound, trafficStats.outbound],
                backgroundColor: ['#00d4ff', '#ff006e'],
                borderColor: '#0a0e27',
                borderWidth: 3,
                hoverBorderWidth: 5
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#ffffff',
                        font: { size: 12, weight: 'bold' },
                        padding: 15
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    titleColor: '#00d4ff',
                    bodyColor: '#ffffff',
                    borderColor: '#00d4ff',
                    borderWidth: 2,
                    padding: 12,
                    callbacks: {
                        label: (context) => {
                            const bytes = context.parsed;
                            const mb = (bytes / (1024 * 1024)).toFixed(2);
                            const percent = context.label.match(/\d+\.\d+/)[0];
                            return `${mb} MB`;
                        }
                    }
                }
            }
        }
    });
}

/**
 * Timeline Chart - Line
 */
function createTimelineChart(timeline) {
    const ctx = document.getElementById('timelineChart');
    if (!ctx) return;

    if (chartInstances.timelineChart) {
        chartInstances.timelineChart.destroy();
    }

    chartInstances.timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array.from({length: timeline.length}, (_, i) => `${i}`),
            datasets: [{
                label: 'Packets per Time Bucket',
                data: timeline,
                borderColor: '#00d4ff',
                backgroundColor: 'rgba(0, 212, 255, 0.1)',
                borderWidth: 3,
                fill: true,
                tension: 0.4,
                pointRadius: 3,
                pointBackgroundColor: '#ff006e',
                pointBorderColor: '#ffffff',
                pointBorderWidth: 2,
                pointHoverRadius: 5,
                pointHoverBackgroundColor: '#00d4ff'
            }]
        },
        options: {
            responsive: true,
            interaction: {
                mode: 'index',
                intersect: false
            },
            plugins: {
                legend: {
                    labels: {
                        color: '#ffffff',
                        font: { size: 12, weight: 'bold' }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    titleColor: '#00d4ff',
                    bodyColor: '#ffffff',
                    borderColor: '#00d4ff',
                    borderWidth: 2,
                    padding: 12
                }
            },
            scales: {
                y: {
                    ticks: { color: '#ffffff', font: { size: 11 } },
                    grid: { color: 'rgba(42, 63, 95, 0.3)' },
                    beginAtZero: true
                },
                x: {
                    ticks: { color: '#ffffff', font: { size: 10 } },
                    grid: { color: 'rgba(42, 63, 95, 0.3)' }
                }
            }
        }
    });
}

/**
 * Protocol Distribution Chart - Horizontal Bar
 */
function createProtocolDistChart(protocolStats) {
    const ctx = document.getElementById('protocolDistChart');
    if (!ctx) return;

    if (chartInstances.protocolDistChart) {
        chartInstances.protocolDistChart.destroy();
    }

    const top8 = protocolStats.slice(0, 8);

    chartInstances.protocolDistChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: top8.map(p => p.name),
            datasets: [{
                label: 'Nombre de Packets',
                data: top8.map(p => p.count),
                backgroundColor: [
                    '#00d4ff', '#ff006e', '#00ff41', '#ffa500',
                    '#ff0000', '#9d00ff', '#00ffff', '#ff69b4'
                ],
                borderColor: '#ffffff',
                borderWidth: 2,
                borderRadius: 5,
                hoverBackgroundColor: '#00ffff'
            }]
        },
        options: {
            responsive: true,
            indexAxis: 'y',
            plugins: {
                legend: {
                    labels: {
                        color: '#ffffff',
                        font: { size: 12, weight: 'bold' }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    titleColor: '#00d4ff',
                    bodyColor: '#ffffff',
                    borderColor: '#00d4ff',
                    borderWidth: 2,
                    padding: 12
                }
            },
            scales: {
                y: {
                    ticks: { color: '#ffffff', font: { size: 11 } },
                    grid: { color: 'rgba(42, 63, 95, 0.3)' }
                },
                x: {
                    ticks: { color: '#ffffff', font: { size: 11 } },
                    grid: { color: 'rgba(42, 63, 95, 0.3)' },
                    beginAtZero: true
                }
            }
        }
    });
}

/**
 * Port Activity Chart - Bubble
 */
function createPortChart(portStats) {
    const ctx = document.getElementById('portChart');
    if (!ctx) return;

    if (chartInstances.portChart) {
        chartInstances.portChart.destroy();
    }

    const srcTop = portStats.source.slice(0, 10);
    const dstTop = portStats.destination.slice(0, 10);

    const bubbleData = [
        ...srcTop.map((p, i) => ({ x: parseInt(p.port), y: p.count, r: 8, label: 'Source' })),
        ...dstTop.map((p, i) => ({ x: parseInt(p.port), y: p.count, r: 8, label: 'Destination' }))
    ];

    chartInstances.portChart = new Chart(ctx, {
        type: 'bubble',
        data: {
            datasets: [
                {
                    label: 'Source Ports',
                    data: srcTop.map(p => ({ x: parseInt(p.port), y: p.count, r: 6 })),
                    backgroundColor: 'rgba(0, 212, 255, 0.6)',
                    borderColor: '#00d4ff',
                    borderWidth: 2
                },
                {
                    label: 'Destination Ports',
                    data: dstTop.map(p => ({ x: parseInt(p.port), y: p.count, r: 6 })),
                    backgroundColor: 'rgba(255, 0, 110, 0.6)',
                    borderColor: '#ff006e',
                    borderWidth: 2
                }
            ]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    labels: {
                        color: '#ffffff',
                        font: { size: 12, weight: 'bold' }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    titleColor: '#00d4ff',
                    bodyColor: '#ffffff',
                    borderColor: '#00d4ff',
                    borderWidth: 2,
                    padding: 12,
                    callbacks: {
                        label: (context) => `Count: ${context.parsed.y}`
                    }
                }
            },
            scales: {
                y: {
                    ticks: { color: '#ffffff', font: { size: 11 } },
                    grid: { color: 'rgba(42, 63, 95, 0.3)' },
                    beginAtZero: true
                },
                x: {
                    ticks: { color: '#ffffff', font: { size: 11 } },
                    grid: { color: 'rgba(42, 63, 95, 0.3)' },
                    type: 'linear'
                }
            }
        }
    });
}

/**
 * IP Communication Map - Scatter
 */
function createIPMapChart(communications) {
    const ctx = document.getElementById('ipMapChart');
    if (!ctx) return;

    if (chartInstances.ipMapChart) {
        chartInstances.ipMapChart.destroy();
    }

    const data = communications.slice(0, 15).map((comm, i) => ({
        x: i,
        y: (comm.size / (1024 * 1024)).toFixed(2),
        r: Math.log(comm.size) / 10
    }));

    const labels = communications.slice(0, 15).map(c => `${c.src} → ${c.dst}`);

    chartInstances.ipMapChart = new Chart(ctx, {
        type: 'scatter',
        data: {
            labels: labels,
            datasets: [{
                label: 'Communication Size (MB)',
                data: data,
                backgroundColor: 'rgba(0, 212, 255, 0.6)',
                borderColor: '#00d4ff',
                borderWidth: 2,
                pointRadius: (ctx) => ctx.raw.r || 5,
                pointHoverRadius: 8
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    labels: {
                        color: '#ffffff',
                        font: { size: 12, weight: 'bold' }
                    }
                },
                tooltip: {
                    backgroundColor: 'rgba(0, 0, 0, 0.8)',
                    titleColor: '#00d4ff',
                    bodyColor: '#ffffff',
                    borderColor: '#00d4ff',
                    borderWidth: 2,
                    padding: 12,
                    callbacks: {
                        title: (context) => labels[context[0].dataIndex],
                        label: (context) => `Data: ${context.parsed.y} MB`
                    }
                }
            },
            scales: {
                y: {
                    ticks: { color: '#ffffff', font: { size: 11 } },
                    grid: { color: 'rgba(42, 63, 95, 0.3)' },
                    beginAtZero: true
                },
                x: {
                    ticks: { color: '#ffffff', font: { size: 11 } },
                    grid: { color: 'rgba(42, 63, 95, 0.3)' }
                }
            }
        }
    });
}

/**
 * Render Flows List
 */
function renderFlowsList(flows) {
    const container = document.getElementById('flowsList');
    if (!container) return;

    container.innerHTML = flows.map((flow, idx) => `
        <div class="flow-item">
            <div class="flow-header">
                <span class="flow-number">#${idx + 1}</span>
                <span class="flow-info">
                    <strong>${flow.srcIP}:${flow.srcPort}</strong> → <strong>${flow.dstIP}:${flow.dstPort}</strong>
                </span>
            </div>
            <div class="flow-details">
                <span class="flow-protocol">${flow.protocol}</span>
                <span class="flow-stat">📦 ${flow.packets} packets</span>
                <span class="flow-stat">📊 ${formatBytes(flow.bytes)}</span>
                <span class="flow-stat">⏱️ ${flow.duration.toFixed(2)}s</span>
            </div>
        </div>
    `).join('');
}

/**
 * Render Threats List
 */
function renderThreatsList(threats) {
    const container = document.getElementById('threatsList');
    if (!container) return;

    if (!threats.length) {
        container.innerHTML = '<p class="no-threats">✅ Aucune menace détectée</p>';
        return;
    }

    container.innerHTML = threats.map(threat => `
        <div class="threat-card severity-${threat.severity}">
            <div class="threat-header">
                <h4>${threat.type}</h4>
                <span class="threat-badge ${threat.severity}">${threat.severity.toUpperCase()}</span>
            </div>
            <p class="threat-desc">${threat.description}</p>
            <div class="threat-meta">
                <span class="confidence">🎯 Confidence: ${threat.confidence}%</span>
                ${threat.source ? `<span class="source">📍 Source: ${threat.source}</span>` : ''}
            </div>
            <div class="threat-evidence">
                <strong>Evidence:</strong>
                <ul>
                    ${threat.evidence.map(e => `<li>${e}</li>`).join('')}
                </ul>
            </div>
        </div>
    `).join('');
}

/**
 * Render IPs List
 */
function renderIPsList(ips, type) {
    const container = document.getElementById(type === 'source' ? 'sourceIPsList' : 'destIPsList');
    if (!container) return;

    container.innerHTML = ips.map((ip, idx) => `
        <div class="ip-item">
            <div class="ip-rank">#${idx + 1}</div>
            <div class="ip-info">
                <strong>${ip.ip}</strong>
                <span class="ip-count">${ip.count} packets (${ip.percent}%)</span>
            </div>
            <div class="ip-bar">
                <div class="ip-bar-fill" style="width: ${ip.percent}%"></div>
            </div>
        </div>
    `).join('');
}

/**
 * Render Ports List
 */
function renderPortsList(ports, type) {
    const container = document.getElementById(type === 'src' ? 'srcPortsList' : 'dstPortsList');
    if (!container) return;

    container.innerHTML = ports.map((port, idx) => `
        <div class="port-item">
            <div class="port-rank">#${idx + 1}</div>
            <div class="port-info">
                <strong>Port ${port.port}</strong>
                <span class="port-count">${port.count} packets</span>
            </div>
        </div>
    `).join('');
}

/**
 * Render Protocol Table
 */
function renderProtocolTable(protocols) {
    const tbody = document.getElementById('protocolBody');
    if (!tbody) return;

    tbody.innerHTML = protocols.map(proto => `
        <tr>
            <td>${proto.name}</td>
            <td>${proto.count}</td>
            <td>${formatBytes(proto.bytes)}</td>
            <td>${proto.percent}%</td>
        </tr>
    `).join('');
}

/**
 * Format Bytes
 */
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

/**
 * Format Duration
 */
function formatDuration(seconds) {
    if (seconds < 60) return Math.round(seconds) + 's';
    if (seconds < 3600) return (seconds / 60).toFixed(2) + 'm';
    return (seconds / 3600).toFixed(2) + 'h';
}

/**
 * Update All UI Stats
 */
function updateUIStats(stats, threats) {
    // Overview
    document.getElementById('totalPackets').textContent = stats.overview.totalPackets.toLocaleString();
    document.getElementById('totalData').textContent = formatBytes(stats.overview.totalBytes);
    document.getElementById('duration').textContent = formatDuration(stats.overview.duration);
    document.getElementById('anomalyCount').textContent = threats.threats.length;

    // Statistics
    document.getElementById('inboundTraffic').textContent = formatBytes(stats.traffic.inbound);
    document.getElementById('inboundPercent').textContent = stats.traffic.inboundPercent + '%';
    document.getElementById('outboundTraffic').textContent = formatBytes(stats.traffic.outbound);
    document.getElementById('outboundPercent').textContent = stats.traffic.outboundPercent + '%';
    document.getElementById('totalFlows').textContent = stats.flows?.length || 0;
    document.getElementById('avgPacketSize').textContent = formatBytes(stats.overview.avgPacketSize);
    document.getElementById('maxPacketSize').textContent = `Max: ${formatBytes(stats.overview.maxPacketSize)}`;

    // Render lists
    renderFlowsList(stats.flows || []);
    renderThreatsList(threats.threats);
    renderIPsList(stats.ipStats.source, 'source');
    renderIPsList(stats.ipStats.destination, 'destination');
    renderPortsList(stats.portStats.source, 'src');
    renderPortsList(stats.portStats.destination, 'dst');
    renderProtocolTable(stats.protocols);

    // Create charts
    createProtocolChart(stats.protocols);
    createSizeChart(stats.sizeDistribution);
    createDirectionChart(stats.traffic);
    createTimelineChart(stats.timeline);
    createProtocolDistChart(stats.protocols);
    createPortChart(stats.portStats);
    createIPMapChart(stats.topCommunications);
}

/**
 * Export Report as PDF
 */
function exportReportPDF(stats, threats) {
    const html = `
        <html>
            <head>
                <title>PCAP Analysis Report</title>
                <style>
                    body { font-family: Arial; background: #0a0e27; color: #fff; }
                    .header { text-align: center; padding: 20px; border-bottom: 2px solid #00d4ff; }
                    .section { margin: 20px 0; padding: 20px; border: 1px solid #2a3f5f; }
                    table { width: 100%; border-collapse: collapse; }
                    th, td { padding: 10px; text-align: left; border: 1px solid #2a3f5f; }
                    th { background: #1a1f3a; color: #00d4ff; }
                    .threat { background: rgba(255, 0, 0, 0.1); }
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>🔍 PCAP ANALYSIS REPORT</h1>
                    <p>${new Date().toLocaleString()}</p>
                </div>
                
                <div class="section">
                    <h2>📊 Overview</h2>
                    <p><strong>Total Packets:</strong> ${stats.overview.totalPackets}</p>
                    <p><strong>Total Data:</strong> ${formatBytes(stats.overview.totalBytes)}</p>
                    <p><strong>Duration:</strong> ${formatDuration(stats.overview.duration)}</p>
                    <p><strong>Threats Detected:</strong> ${threats.threats.length}</p>
                </div>

                <div class="section">
                    <h2>⚠️ Detected Threats</h2>
                    ${threats.threats.length ? threats.threats.map(t => `
                        <div class="threat">
                            <h4>${t.type} (${t.severity.toUpperCase()})</h4>
                            <p>${t.description}</p>
                        </div>
                    `).join('') : '<p>✅ No threats detected</p>'}
                </div>

                <div class="section">
                    <h2>🔌 Protocols</h2>
                    <table>
                        <tr><th>Protocol</th><th>Packets</th><th>Data</th><th>%</th></tr>
                        ${stats.protocols.map(p => `<tr><td>${p.name}</td><td>${p.count}</td><td>${formatBytes(p.bytes)}</td><td>${p.percent}%</td></tr>`).join('')}
                    </table>
                </div>
            </body>
        </html>
    `;

    const newWindow = window.open('', '', 'height=400,width=800');
    newWindow.document.write(html);
    newWindow.document.close();
    newWindow.print();
}