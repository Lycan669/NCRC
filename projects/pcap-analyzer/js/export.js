/* ============================================
   NCRC EXPORT & REPORTING ENGINE
   Multi-format Export System
   ============================================ */

class ExportEngine {
    constructor() {
        this.exportFormats = ['JSON', 'CSV', 'PCAP', 'HTML', 'PDF', 'XML', 'XLSX'];
        this.reportTemplates = {};
        this.exportHistory = [];
    }

    /* ============================================
       JSON EXPORT
       ============================================ */

    exportJSON(packets, options = {}) {
        const config = {
            includePayload: options.includePayload !== false,
            prettify: options.prettify !== false,
            compressed: options.compressed || false,
            ...options
        };

        let data = {
            metadata: {
                exportTime: new Date().toISOString(),
                totalPackets: packets.length,
                exportFormat: 'JSON',
                ncrcVersion: '2.0.0'
            },
            packets: packets.map(packet => ({
                number: packet.number,
                timestamp: packet.timestampDate,
                timestampEpoch: packet.timestamp,
                size: packet.size,
                protocol: packet.protocol,
                layers: {
                    frame: packet.layers.frame,
                    ethernet: packet.layers.ethernet,
                    ip: packet.layers.ip ? {
                        srcIP: packet.layers.ip.srcIP,
                        dstIP: packet.layers.ip.dstIP,
                        TTL: packet.layers.ip.TTL,
                        version: packet.layers.ip.version,
                        totalLength: packet.layers.ip.totalLength,
                        protocol: packet.layers.ip.protocol,
                        flags: packet.layers.ip.flags,
                        fragmentOffset: packet.layers.ip.fragmentOffset,
                        moreFragments: packet.layers.ip.moreFragments,
                        dontFragment: packet.layers.ip.dontFragment
                    } : null,
                    tcp: packet.layers.tcp ? {
                        srcPort: packet.layers.tcp.srcPort,
                        dstPort: packet.layers.tcp.dstPort,
                        sequence: packet.layers.tcp.sequence,
                        acknowledgment: packet.layers.tcp.acknowledgment,
                        windowSize: packet.layers.tcp.windowSize,
                        flags: packet.layers.tcp.flags,
                        checksum: packet.layers.tcp.checksum
                    } : null,
                    udp: packet.layers.udp ? {
                        srcPort: packet.layers.udp.srcPort,
                        dstPort: packet.layers.udp.dstPort,
                        length: packet.layers.udp.length,
                        checksum: packet.layers.udp.checksum
                    } : null,
                    dns: packet.layers.dns ? {
                        transactionID: packet.layers.dns.transactionID,
                        isResponse: packet.layers.dns.isResponse,
                        queries: packet.layers.dns.queries,
                        answers: packet.layers.dns.answers
                    } : null,
                    http: packet.layers.http ? {
                        method: packet.layers.http.request?.method,
                        uri: packet.layers.http.request?.uri,
                        version: packet.layers.http.request?.version,
                        statusCode: packet.layers.http.response?.statusCode,
                        statusMessage: packet.layers.http.response?.statusMessage,
                        contentType: packet.layers.http.contentType,
                        contentLength: packet.layers.http.contentLength,
                        userAgent: packet.layers.http.request?.userAgent,
                        referrer: packet.layers.http.request?.referrer
                    } : null,
                    ssl: packet.layers.ssl ? {
                        version: packet.layers.ssl.version,
                        contentType: packet.layers.ssl.contentType,
                        length: packet.layers.ssl.length
                    } : null
                },
                payload: config.includePayload ? packet.payload : undefined
            }))
        };

        const jsonStr = config.prettify 
            ? JSON.stringify(data, null, 2)
            : JSON.stringify(data);

        if (config.compressed) {
            return this._compressString(jsonStr);
        }

        return jsonStr;
    }

    /* ============================================
       CSV EXPORT
       ============================================ */

    exportCSV(packets, options = {}) {
        const config = {
            delimiter: options.delimiter || ',',
            includeHeaders: options.includeHeaders !== false,
            ...options
        };

        const headers = [
            'Packet #',
            'Timestamp',
            'Source IP',
            'Destination IP',
            'Protocol',
            'Source Port',
            'Destination Port',
            'Size (bytes)',
            'TTL',
            'Flags',
            'Info'
        ];

        let csv = '';

        if (config.includeHeaders) {
            csv += headers.map(h => this._escapeCsvField(h)).join(config.delimiter) + '\n';
        }

        packets.forEach((packet, idx) => {
            const row = [
                packet.number,
                packet.timestampDate,
                packet.layers.ip?.srcIP || '-',
                packet.layers.ip?.dstIP || '-',
                packet.protocol,
                packet.layers.tcp?.srcPort || packet.layers.udp?.srcPort || '-',
                packet.layers.tcp?.dstPort || packet.layers.udp?.dstPort || '-',
                packet.size,
                packet.layers.ip?.TTL || '-',
                this._getPacketFlags(packet),
                this._getPacketInfo(packet)
            ];

            csv += row.map(field => this._escapeCsvField(field)).join(config.delimiter) + '\n';
        });

        return csv;
    }

    /* ============================================
       PCAP EXPORT
       ============================================ */

    exportPCAP(packets, options = {}) {
        const config = {
            format: options.format || 'PCAP',
            byteOrder: options.byteOrder || 'little-endian',
            ...options
        };

        const isLittleEndian = config.byteOrder === 'little-endian';
        
        // PCAP file header (24 bytes)
        const magicNumber = isLittleEndian ? 0xa1b2c3d4 : 0xd4c3b2a1;
        const buffer = new ArrayBuffer(24 + packets.reduce((sum, p) => sum + 16 + p.size, 0));
        const view = new DataView(buffer);

        let offset = 0;

        // Write global header
        view.setUint32(offset, magicNumber, isLittleEndian); offset += 4;
        view.setUint16(offset, 2, isLittleEndian); offset += 2; // Major version
        view.setUint16(offset, 4, isLittleEndian); offset += 2; // Minor version
        view.setInt32(offset, 0, isLittleEndian); offset += 4;  // Timezone
        view.setUint32(offset, 0, isLittleEndian); offset += 4; // Timestamp accuracy
        view.setUint32(offset, 65535, isLittleEndian); offset += 4; // Snapshot length
        view.setUint32(offset, 1, isLittleEndian); offset += 4; // Data link type (Ethernet)

        // Write packet headers and data
        packets.forEach(packet => {
            const timestamp = Math.floor(new Date(packet.timestampDate).getTime() / 1000);
            const microseconds = Math.floor((new Date(packet.timestampDate).getTime() % 1000) * 1000);

            // Packet header
            view.setUint32(offset, timestamp, isLittleEndian); offset += 4;
            view.setUint32(offset, microseconds, isLittleEndian); offset += 4;
            view.setUint32(offset, packet.size, isLittleEndian); offset += 4;
            view.setUint32(offset, packet.size, isLittleEndian); offset += 4;

            // Packet data
            const packetData = this._hexToBytes(packet.hexData);
            for (let i = 0; i < packetData.length; i++) {
                view.setUint8(offset + i, packetData[i]);
            }
            offset += packet.size;
        });

        return buffer;
    }

    /* ============================================
       HTML EXPORT
       ============================================ */

    exportHTML(packets, analysis, options = {}) {
        const config = {
            includeCharts: options.includeCharts !== false,
            includeAnalysis: options.includeAnalysis !== false,
            theme: options.theme || 'dark',
            ...options
        };

        const html = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NCRC Report - ${new Date().toLocaleDateString()}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: ${config.theme === 'dark' ? '#0a0e27' : '#ffffff'};
            color: ${config.theme === 'dark' ? '#e0e0e0' : '#333333'};
            line-height: 1.6;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
        }

        .header {
            text-align: center;
            border-bottom: 3px solid #00ff88;
            padding-bottom: 20px;
            margin-bottom: 40px;
        }

        .header h1 {
            color: #00ff88;
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 0 0 10px rgba(0, 255, 136, 0.5);
        }

        .header p {
            font-size: 0.9em;
            opacity: 0.8;
        }

        .section {
            margin-bottom: 40px;
            padding: 20px;
            background: ${config.theme === 'dark' ? '#1a1f3a' : '#f9f9f9'};
            border-left: 4px solid #00ff88;
            border-radius: 4px;
        }

        .section h2 {
            color: #00ff88;
            margin-bottom: 15px;
            font-size: 1.8em;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }

        .stat-box {
            background: ${config.theme === 'dark' ? '#0a0e27' : '#f0f0f0'};
            padding: 20px;
            border-radius: 4px;
            border: 1px solid #00ff88;
        }

        .stat-label {
            font-size: 0.9em;
            opacity: 0.7;
            text-transform: uppercase;
            margin-bottom: 10px;
        }

        .stat-value {
            font-size: 2em;
            color: #00ff88;
            font-weight: bold;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            font-size: 0.9em;
        }

        th {
            background: ${config.theme === 'dark' ? '#0a0e27' : '#e0e0e0'};
            color: #00ff88;
            padding: 12px;
            text-align: left;
            border-bottom: 2px solid #00ff88;
        }

        td {
            padding: 10px 12px;
            border-bottom: 1px solid ${config.theme === 'dark' ? '#1a1f3a' : '#ddd'};
        }

        tr:hover {
            background: ${config.theme === 'dark' ? '#0a0e27' : '#f9f9f9'};
        }

        .threat-critical {
            color: #ff4444;
            font-weight: bold;
        }

        .threat-high {
            color: #ff8844;
        }

        .threat-medium {
            color: #ffcc44;
        }

        .threat-low {
            color: #88ff44;
        }

        .footer {
            text-align: center;
            padding-top: 40px;
            border-top: 1px solid #00ff88;
            opacity: 0.6;
            font-size: 0.9em;
        }

        @media print {
            body {
                background: white;
                color: black;
            }

            .section {
                page-break-inside: avoid;
                border-left: none;
                box-shadow: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 NCRC Security Analysis Report</h1>
            <p>Generated: ${new Date().toLocaleString()}</p>
            <p>Total Packets Analyzed: ${packets.length}</p>
        </div>

        ${this._generateHTMLSummary(analysis, config)}
        ${config.includeAnalysis ? this._generateHTMLAnalysis(analysis, config) : ''}
        ${this._generateHTMLPacketTable(packets.slice(0, 100), config)}

        <div class="footer">
            <p>Network Capture & Real-time Analysis Center (NCRC) v2.0.0</p>
            <p>© 2026 - Confidential</p>
        </div>
    </div>
</body>
</html>
        `;

        return html;
    }

    /* ============================================
       PDF EXPORT
       ============================================ */

    exportPDF(packets, analysis, options = {}) {
        // Using jsPDF + html2canvas (external libraries)
        const config = {
            orientation: options.orientation || 'portrait',
            format: options.format || 'a4',
            margin: options.margin || 10,
            ...options
        };

        // Generate HTML first
        const html = this.exportHTML(packets, analysis, { 
            includeCharts: false,
            theme: 'light'
        });

        // This would require jsPDF library
        // In production, use: new jsPDF().html(html, {...})
        return {
            format: 'PDF',
            config: config,
            htmlContent: html,
            note: 'PDF export requires jsPDF library'
        };
    }

    /* ============================================
       XML EXPORT
       ============================================ */

    exportXML(packets, options = {}) {
        const config = {
            includePayload: options.includePayload !== false,
            prettify: options.prettify !== false,
            ...options
        };

        let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
        xml += '<ncrc_report>\n';
        xml += '  <metadata>\n';
        xml += `    <export_time>${new Date().toISOString()}</export_time>\n`;
        xml += `    <total_packets>${packets.length}</total_packets>\n`;
        xml += `    <format>XML</format>\n`;
        xml += `    <version>2.0.0</version>\n`;
        xml += '  </metadata>\n';
        xml += '  <packets>\n';

        packets.forEach((packet, idx) => {
            xml += '    <packet>\n';
            xml += `      <number>${packet.number}</number>\n`;
            xml += `      <timestamp>${this._escapeXML(packet.timestampDate)}</timestamp>\n`;
            xml += `      <size>${packet.size}</size>\n`;
            xml += `      <protocol>${packet.protocol}</protocol>\n`;

            if (packet.layers.ip) {
                xml += '      <ip_layer>\n';
                xml += `        <src_ip>${packet.layers.ip.srcIP}</src_ip>\n`;
                xml += `        <dst_ip>${packet.layers.ip.dstIP}</dst_ip>\n`;
                xml += `        <ttl>${packet.layers.ip.TTL}</ttl>\n`;
                xml += `        <version>${packet.layers.ip.version}</version>\n`;
                xml += '      </ip_layer>\n';
            }

            if (packet.layers.tcp) {
                xml += '      <tcp_layer>\n';
                xml += `        <src_port>${packet.layers.tcp.srcPort}</src_port>\n`;
                xml += `        <dst_port>${packet.layers.tcp.dstPort}</dst_port>\n`;
                xml += `        <seq>${packet.layers.tcp.sequence}</seq>\n`;
                xml += `        <ack>${packet.layers.tcp.acknowledgment}</ack>\n`;
                xml += '      </tcp_layer>\n';
            }

            if (config.includePayload && packet.payload) {
                xml += `      <payload>${this._escapeXML(packet.payload.substring(0, 200))}</payload>\n`;
            }

            xml += '    </packet>\n';
        });

        xml += '  </packets>\n';
        xml += '</ncrc_report>';

        return xml;
    }

    /* ============================================
       XLSX EXPORT (EXCEL)
       ============================================ */

    exportXLSX(packets, analysis, options = {}) {
        // Using SheetJS/xlsx library format
        const config = {
            sheets: {
                packets: true,
                analysis: true,
                threats: true,
                conversations: true
            },
            ...options
        };

        const workbook = {
            SheetNames: [],
            Sheets: {}
        };

        // Packets sheet
        if (config.sheets.packets) {
            const packetData = packets.map((p, idx) => ({
                'Packet #': p.number,
                'Timestamp': p.timestampDate,
                'Src IP': p.layers.ip?.srcIP || '-',
                'Dst IP': p.layers.ip?.dstIP || '-',
                'Protocol': p.protocol,
                'Src Port': p.layers.tcp?.srcPort || p.layers.udp?.srcPort || '-',
                'Dst Port': p.layers.tcp?.dstPort || p.layers.udp?.dstPort || '-',
                'Size (B)': p.size,
                'TTL': p.layers.ip?.TTL || '-'
            }));

            workbook.Sheets['Packets'] = this._createSheet(packetData);
            workbook.SheetNames.push('Packets');
        }

        // Analysis sheet
        if (config.sheets.analysis && analysis) {
            const analysisData = [
                { Metric: 'Total Packets', Value: analysis.summary?.totalPackets || 0 },
                { Metric: 'Total Bytes', Value: analysis.summary?.totalBytes || 0 },
                { Metric: 'Avg Packet Size', Value: analysis.summary?.averagePacketSize || 0 },
                { Metric: 'Duration (s)', Value: analysis.summary?.captureDuration || 0 },
                { Metric: 'Packets/sec', Value: analysis.summary?.packetsPerSecond || 0 },
                { Metric: 'Unique Source IPs', Value: analysis.summary?.uniqueSourceIPs || 0 }
            ];

            workbook.Sheets['Analysis'] = this._createSheet(analysisData);
            workbook.SheetNames.push('Analysis');
        }

        return workbook;
    }

    /* ============================================
       REPORT GENERATION
       ============================================ */

    generateReport(packets, analysis, options = {}) {
        const config = {
            title: options.title || 'Network Analysis Report',
            includeExecutiveSummary: options.includeExecutiveSummary !== false,
            includeFindings: options.includeFindings !== false,
            includeRecommendations: options.includeRecommendations !== false,
            format: options.format || 'HTML',
            ...options
        };

        const report = {
            metadata: {
                title: config.title,
                generatedAt: new Date().toISOString(),
                format: config.format
            },
            sections: {}
        };

        if (config.includeExecutiveSummary) {
            report.sections.executiveSummary = this._generateExecutiveSummary(packets, analysis);
        }

        if (config.includeFindings) {
            report.sections.findings = this._generateFindings(analysis);
        }

        if (config.includeRecommendations) {
            report.sections.recommendations = this._generateRecommendations(analysis);
        }

        return report;
    }

    /* ============================================
       HELPER FUNCTIONS
       ============================================ */

    _escapeCsvField(field) {
        if (!field) return '';
        const str = field.toString();
        if (str.includes(',') || str.includes('"') || str.includes('\n')) {
            return `"${str.replace(/"/g, '""')}"`;
        }
        return str;
    }

    _escapeXML(str) {
        if (!str) return '';
        return str
            .replace(/&/g, '&')
            .replace(/</g, '<')
            .replace(/>/g, '>')
            .replace(/"/g, '"')
            .replace(/'/g, ''');
    }

    _getPacketFlags(packet) {
        if (!packet.layers.tcp) return '-';
        const flags = packet.layers.tcp.flags;
        const flagStr = [];
        if (flags.SYN) flagStr.push('SYN');
        if (flags.ACK) flagStr.push('ACK');
        if (flags.FIN) flagStr.push('FIN');
        if (flags.RST) flagStr.push('RST');
        if (flags.PSH) flagStr.push('PSH');
        if (flags.URG) flagStr.push('URG');
        return flagStr.length > 0 ? flagStr.join(',') : '-';
    }

    _getPacketInfo(packet) {
        if (packet.layers.http) {
            return `HTTP ${packet.layers.http.request?.method || 'Response'}`;
        }
        if (packet.layers.dns) {
            return `DNS Query`;
        }
        if (packet.layers.ssh) {
            return `SSH Data`;
        }
        return `${packet.protocol} Data`;
    }

    _generateHTMLSummary(analysis, config) {
        return `
        <div class="section">
            <h2>📊 Summary Statistics</h2>
            <div class="stats-grid">
                <div class="stat-box">
                    <div class="stat-label">Total Packets</div>
                    <div class="stat-value">${analysis.summary?.totalPackets || 0}</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Total Data</div>
                    <div class="stat-value">${((analysis.summary?.totalBytes || 0) / 1000000).toFixed(2)} MB</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Avg Packet Size</div>
                    <div class="stat-value">${(analysis.summary?.averagePacketSize || 0).toFixed(0)} B</div>
                </div>
                <div class="stat-box">
                    <div class="stat-label">Protocols Found</div>
                    <div class="stat-value">${Object.keys(analysis.protocolBreakdown || {}).length}</div>
                </div>
            </div>
        </div>
        `;
    }

    _generateHTMLAnalysis(analysis, config) {
        return `
        <div class="section">
            <h2>🔍 Detailed Analysis</h2>
            <h3>Protocol Breakdown</h3>
            <table>
                <tr>
                    <th>Protocol</th>
                    <th>Packets</th>
                    <th>Percentage</th>
                </tr>
                ${Object.entries(analysis.protocolBreakdown || {})
                    .slice(0, 10)
                    .map(([protocol, count]) => `
                    <tr>
                        <td>${protocol}</td>
                        <td>${count}</td>
                        <td>${((count / (analysis.summary?.totalPackets || 1)) * 100).toFixed(2)}%</td>
                    </tr>
                    `).join('')}
            </table>
        </div>
        `;
    }

    _generateHTMLPacketTable(packets, config) {
        return `
        <div class="section">
            <h2>📋 Packet Details (First 100)</h2>
            <table>
                <tr>
                    <th>#</th>
                    <th>Time</th>
                    <th>Source</th>
                    <th>Destination</th>
                    <th>Protocol</th>
                    <th>Size</th>
                    <th>Info</th>
                </tr>
                ${packets.map((p, idx) => `
                <tr>
                    <td>${p.number}</td>
                    <td>${p.timestampDate}</td>
                    <td>${p.layers.ip?.srcIP || '-'}</td>
                    <td>${p.layers.ip?.dstIP || '-'}</td>
                    <td>${p.protocol}</td>
                    <td>${p.size}</td>
                    <td>${this._getPacketInfo(p)}</td>
                </tr>
                `).join('')}
            </table>
        </div>
        `;
    }

    _generateExecutiveSummary(packets, analysis) {
        return {
            overview: `Analyzed ${packets.length} network packets captured during the specified time period.`,
            keyFindings: [
                `Identified ${Object.keys(analysis.protocolBreakdown || {}).length} different protocols`,
                `Total data volume: ${((analysis.summary?.totalBytes || 0) / 1000000).toFixed(2)} MB`,
                `Average packet size: ${(analysis.summary?.averagePacketSize || 0).toFixed(0)} bytes`
            ],
            riskLevel: analysis.threatAnalysis?.riskLevel || 'LOW'
        };
    }

    _generateFindings(analysis) {
        return {
            threats: analysis.threatAnalysis?.threats || [],
            anomalies: analysis.threatAnalysis?.anomalies || [],
            topConcerns: [
                'Review identified security anomalies',
                'Monitor flagged IP addresses',
                'Validate suspicious protocols'
            ]
        };
    }

    _generateRecommendations(analysis) {
        return [
            'Implement network-based IDS/IPS',
            'Review and update firewall rules',
            'Conduct regular packet analysis',
            'Monitor DNS queries for C2 activity',
            'Track unusual outbound connections'
        ];
    }

    _createSheet(data) {
        // Simplified sheet creation
        return {
            data: data,
            range: `A1:Z${data.length}`
        };
    }

    _compressString(str) {
        // Would use pako or similar compression library
        return str;
    }

    _hexToBytes(hex) {
        const bytes = [];
        for (let i = 0; i < hex.length; i += 2) {
            bytes.push(parseInt(hex.substr(i, 2), 16));
        }
        return bytes;
    }

    downloadFile(content, filename, mimeType) {
        const blob = new Blob([content], { type: mimeType });
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    }

    // Export tracking
    recordExport(filename, format, size, duration) {
        this.exportHistory.push({
            timestamp: Date.now(),
            filename: filename,
            format: format,
            size: size,
            duration: duration
        });
    }

    getExportHistory() {
        return this.exportHistory;
    }

    clearExportHistory() {
        this.exportHistory = [];
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = ExportEngine;
}