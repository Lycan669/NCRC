/* ============================================
   NCRC VISUALIZATION ENGINE
   Advanced Charts, Graphs & Data Visualization
   ============================================ */

class VisualizationEngine {
    constructor() {
        this.charts = new Map();
        this.canvases = new Map();
    }

    /* ============================================
       INITIALIZE VISUALIZATION SYSTEM
       ============================================ */

    init(containerId) {
        this.container = document.getElementById(containerId);
        if (!this.container) {
            console.error(`Container ${containerId} not found`);
            return;
        }
        return this;
    }

    /* ============================================
       PROTOCOL DISTRIBUTION PIE CHART
       ============================================ */

    createProtocolChart(data) {
        const ctx = this._getOrCreateCanvas('protocol-chart', 'pie');

        const labels = data.sorted.map(p => p.name);
        const values = data.sorted.map(p => p.packets);
        const colors = data.sorted.map(p => p.colors);

        if (this.charts.has('protocol-chart')) {
            this.charts.get('protocol-chart').destroy();
        }

        const chart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: values,
                    backgroundColor: colors,
                    borderColor: '#1a1f3a',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#e0e0e0',
                            font: { size: 12 }
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(10, 14, 39, 0.9)',
                        titleColor: '#00d4ff',
                        bodyColor: '#e0e0e0',
                        borderColor: '#00d4ff',
                        borderWidth: 1,
                        callbacks: {
                            label: function(context) {
                                const value = context.parsed;
                                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                const percentage = ((value / total) * 100).toFixed(2);
                                return `${context.label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });

        this.charts.set('protocol-chart', chart);
        return chart;
    }

    /* ============================================
       PACKET TIME SERIES CHART
       ============================================ */

    createTimeSeriesChart(timeSeries) {
        const ctx = this._getOrCreateCanvas('timeseries-chart', 'line');

        const labels = timeSeries.map(ts => {
            const date = new Date(ts.timestamp);
            return date.toLocaleTimeString();
        });

        const packetData = timeSeries.map(ts => ts.packetCount);
        const byteData = timeSeries.map(ts => (ts.bytes / 1000).toFixed(2)); // KB

        if (this.charts.has('timeseries-chart')) {
            this.charts.get('timeseries-chart').destroy();
        }

        const chart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Packets/sec',
                        data: packetData,
                        borderColor: '#00d4ff',
                        backgroundColor: 'rgba(0, 212, 255, 0.1)',
                        fill: true,
                        tension: 0.3,
                        pointRadius: 3,
                        pointBackgroundColor: '#00d4ff',
                        yAxisID: 'y'
                    },
                    {
                        label: 'Throughput (KB/s)',
                        data: byteData,
                        borderColor: '#ffd700',
                        backgroundColor: 'rgba(255, 215, 0, 0.1)',
                        fill: true,
                        tension: 0.3,
                        pointRadius: 3,
                        pointBackgroundColor: '#ffd700',
                        yAxisID: 'y1'
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                interaction: {
                    mode: 'index',
                    intersect: false
                },
                plugins: {
                    legend: {
                        labels: {
                            color: '#e0e0e0',
                            font: { size: 12 }
                        }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(10, 14, 39, 0.9)',
                        titleColor: '#00d4ff',
                        bodyColor: '#e0e0e0',
                        borderColor: '#00d4ff',
                        borderWidth: 1
                    }
                },
                scales: {
                    y: {
                        type: 'linear',
                        display: true,
                        position: 'left',
                        title: {
                            display: true,
                            text: 'Packets/sec',
                            color: '#00d4ff'
                        },
                        ticks: { color: '#00d4ff' },
                        grid: { color: 'rgba(0, 212, 255, 0.1)' }
                    },
                    y1: {
                        type: 'linear',
                        display: true,
                        position: 'right',
                        title: {
                            display: true,
                            text: 'Throughput (KB/s)',
                            color: '#ffd700'
                        },
                        ticks: { color: '#ffd700' },
                        grid: { drawOnChartArea: false },
                        border: { display: false }
                    },
                    x: {
                        ticks: { color: '#a0a0a0' },
                        grid: { color: 'rgba(160, 160, 160, 0.1)' }
                    }
                }
            }
        });

        this.charts.set('timeseries-chart', chart);
        return chart;
    }

    /* ============================================
       TOP TALKERS CHART
       ============================================ */

    createTopTalkersChart(talkers) {
        const ctx = this._getOrCreateCanvas('talkers-chart', 'bar');

        const labels = talkers.slice(0, 10).map(t => t.ip);
        const bytes = talkers.slice(0, 10).map(t => (t.bytes / 1000000).toFixed(2)); // MB

        if (this.charts.has('talkers-chart')) {
            this.charts.get('talkers-chart').destroy();
        }

        const chart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Data Transferred (MB)',
                    data: bytes,
                    backgroundColor: [
                        '#00d4ff', '#ffd700', '#ff1744', '#00e676', '#9c27b0',
                        '#673ab7', '#3f51b5', '#2196f3', '#00bcd4', '#009688'
                    ],
                    borderColor: '#1a1f3a',
                    borderWidth: 1
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        labels: { color: '#e0e0e0' }
                    },
                    tooltip: {
                        backgroundColor: 'rgba(10, 14, 39, 0.9)',
                        titleColor: '#00d4ff',
                        bodyColor: '#e0e0e0',
                        borderColor: '#00d4ff',
                        borderWidth: 1,
                        callbacks: {
                            label: function(context) {
                                return `${context.parsed.x} MB`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#a0a0a0' },
                        grid: { color: 'rgba(160, 160, 160, 0.1)' },
                        title: { display: true, text: 'MB', color: '#e0e0e0' }
                    },
                    y: {
                        ticks: { color: '#a0a0a0' },
                        grid: { display: false }
                    }
                }
            }
        });

        this.charts.set('talkers-chart', chart);
        return chart;
    }

    /* ============================================
       PACKET SIZE DISTRIBUTION
       ============================================ */

    createPacketSizeChart(distribution) {
        const ctx = this._getOrCreateCanvas('size-chart', 'bar');

        const labels = Object.keys(distribution);
        const counts = Object.values(distribution).map(r => r.count);

        if (this.charts.has('size-chart')) {
            this.charts.get('size-chart').destroy();
        }

        const chart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Packet Count',
                    data: counts,
                    backgroundColor: [
                        'rgba(0, 212, 255, 0.7)',
                        'rgba(255, 215, 0, 0.7)',
                        'rgba(255, 23, 68, 0.7)',
                        'rgba(0, 230, 118, 0.7)',
                        'rgba(156, 39, 176, 0.7)'
                    ],
                    borderColor: [
                        '#00d4ff', '#ffd700', '#ff1744', '#00e676', '#9c27b0'
                    ],
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: { labels: { color: '#e0e0e0' } },
                    tooltip: {
                        backgroundColor: 'rgba(10, 14, 39, 0.9)',
                        titleColor: '#00d4ff',
                        bodyColor: '#e0e0e0',
                        borderColor: '#00d4ff',
                        borderWidth: 1
                    }
                },
                scales: {
                    y: {
                        ticks: { color: '#a0a0a0' },
                        grid: { color: 'rgba(160, 160, 160, 0.1)' },
                        title: { display: true, text: 'Count', color: '#e0e0e0' }
                    },
                    x: {
                        ticks: { color: '#a0a0a0' },
                        grid: { display: false }
                    }
                }
            }
        });

        this.charts.set('size-chart', chart);
        return chart;
    }

    /* ============================================
       PORT ANALYSIS CHART
       ============================================ */

    createPortChart(portData) {
        const ctx = this._getOrCreateCanvas('port-chart', 'bar');

        const labels = portData.tcp.slice(0, 15).map(p => `${p.port} (${p.service})`);
        const packets = portData.tcp.slice(0, 15).map(p => p.packets);

        if (this.charts.has('port-chart')) {
            this.charts.get('port-chart').destroy();
        }

        const chart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'TCP Packets',
                    data: packets,
                    backgroundColor: 'rgba(0, 212, 255, 0.7)',
                    borderColor: '#00d4ff',
                    borderWidth: 2
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: { labels: { color: '#e0e0e0' } },
                    tooltip: {
                        backgroundColor: 'rgba(10, 14, 39, 0.9)',
                        titleColor: '#00d4ff',
                        bodyColor: '#e0e0e0',
                        borderColor: '#00d4ff',
                        borderWidth: 1
                    }
                },
                scales: {
                    x: {
                        ticks: { color: '#a0a0a0' },
                        grid: { color: 'rgba(160, 160, 160, 0.1)' }
                    },
                    y: {
                        ticks: { color: '#a0a0a0' },
                        grid: { display: false }
                    }
                }
            }
        });

        this.charts.set('port-chart', chart);
        return chart;
    }

    /* ============================================
       THREAT LEVEL RADAR CHART
       ============================================ */

    createThreatRadarChart(threatData) {
        const ctx = this._getOrCreateCanvas('threat-chart', 'radar');

        const threatScores = {
            'SYN Flood': threatData.critical.length > 0 ? 100 : 0,
            'Port Scan': threatData.high.length > 0 ? 75 : 0,
            'DNS Anomaly': threatData.medium.filter(t => t.type === 'DNS_ANOMALY').length > 0 ? 50 : 0,
            'Large Packets': threatData.low.filter(t => t.type === 'LARGE_PACKETS').length > 0 ? 25 : 0
        };

        if (this.charts.has('threat-chart')) {
            this.charts.get('threat-chart').destroy();
        }

        const chart = new Chart(ctx, {
            type: 'radar',
            data: {
                labels: Object.keys(threatScores),
                datasets: [{
                    label: 'Threat Level',
                    data: Object.values(threatScores),
                    borderColor: '#ff1744',
                    backgroundColor: 'rgba(255, 23, 68, 0.2)',
                    pointBackgroundColor: '#ff1744',
                    pointBorderColor: '#fff',
                    pointHoverBackgroundColor: '#fff',
                    pointHoverBorderColor: '#ff1744'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        labels: { color: '#e0e0e0' }
                    }
                },
                scales: {
                    r: {
                        beginAtZero: true,
                        max: 100,
                        ticks: { color: '#a0a0a0' },
                        grid: { color: 'rgba(160, 160, 160, 0.2)' }
                    }
                }
            }
        });

        this.charts.set('threat-chart', chart);
        return chart;
    }

    /* ============================================
       NETWORK FLOW SANKEY DIAGRAM (TEXT REPRESENTATION)
       ============================================ */

    createNetworkFlowHTML(flows) {
        const html = `
            <div class="flow-diagram">
                <h3>Top Network Flows</h3>
                <div class="flow-list">
                    ${flows.slice(0, 10).map((flow, idx) => `
                        <div class="flow-item">
                            <div class="flow-arrow">
                                <span class="flow-src">${flow.src}</span>
                                <span class="flow-icon">→</span>
                                <span class="flow-dst">${flow.dst}</span>
                            </div>
                            <div class="flow-stats">
                                <span>${flow.packets} pkts</span>
                                <span>${(flow.bytes / 1000000).toFixed(2)} MB</span>
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
        return html;
    }

    /* ============================================
       HELPER FUNCTIONS
       ============================================ */

    _getOrCreateCanvas(id, type) {
        if (this.canvases.has(id)) {
            return this.canvases.get(id);
        }

        const canvas = document.createElement('canvas');
        canvas.id = id;
        canvas.className = 'chart-canvas';
        this.container.appendChild(canvas);

        this.canvases.set(id, canvas.getContext('2d'));
        return canvas.getContext('2d');
    }

    destroyAllCharts() {
        this.charts.forEach(chart => {
            if (chart) chart.destroy();
        });
        this.charts.clear();
    }

    exportChartAsImage(chartName, format = 'png') {
        const chart = this.charts.get(chartName);
        if (!chart) return null;

        const canvas = chart.canvas;
        if (format === 'png') {
            return canvas.toDataURL('image/png');
        } else if (format === 'jpg') {
            return canvas.toDataURL('image/jpeg');
        }
        return null;
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = VisualizationEngine;
}