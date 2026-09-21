/**
 * Threat Analyzer - Détecte les menaces
 */

class ThreatAnalyzer {
    constructor(packets, stats) {
        this.packets = packets;
        this.stats = stats;
        this.threats = [];
    }

    /**
     * Analyse et détecte les menaces
     */
    analyze() {
        this.detectPortSweeps();
        this.detectBruteForceSuspicion();
        this.detectDOSPatterns();
        this.detectUnusualTraffic();
        this.detectSuspiciousProtos();
        this.detectDNSAnomalies();
        this.detectWeakConnections();
        this.detectDataExfiltration();
        
        return {
            threats: this.threats.sort((a, b) => {
                const severityMap = { critical: 4, high: 3, medium: 2, low: 1 };
                return severityMap[b.severity] - severityMap[a.severity];
            }),
            summary: this.generateSummary()
        };
    }

    /**
     * Port Sweeps - Scans de ports
     */
    detectPortSweeps() {
        const portsByIP = {};

        this.packets.forEach(p => {
            if (!p.srcIP || !p.dstPort) return;

            if (!portsByIP[p.srcIP]) {
                portsByIP[p.srcIP] = new Set();
            }
            portsByIP[p.srcIP].add(p.dstPort);
        });

        Object.entries(portsByIP).forEach(([ip, ports]) => {
            const portCount = ports.size;
            
            if (portCount > 50) {
                this.threats.push({
                    type: 'Port Sweep Detected',
                    description: `${ip} scanned ${portCount} different ports - Possible port scanning activity`,
                    severity: 'high',
                    confidence: 85,
                    source: ip,
                    evidence: [
                        `Unique destination ports: ${portCount}`,
                        `Ports scanned: ${Array.from(ports).slice(0, 10).join(', ')}...`
                    ]
                });
            } else if (portCount > 20) {
                this.threats.push({
                    type: 'Port Scanning Activity',
                    description: `${ip} accessed ${portCount} different ports`,
                    severity: 'medium',
                    confidence: 70,
                    source: ip,
                    evidence: [`Unique ports: ${portCount}`]
                });
            }
        });
    }

    /**
     * Brute Force Suspicion
     */
    detectBruteForceSuspicion() {
        const flowCounts = {};

        this.stats.flows.forEach(flow => {
            const key = `${flow.srcIP}:${flow.dstIP}:${flow.dstPort}`;
            flowCounts[key] = (flowCounts[key] || 0) + flow.packets;
        });

        Object.entries(flowCounts).forEach(([key, count]) => {
            if (count > 1000) {
                const [srcIP, dstIP, dstPort] = key.split(':');
                const portName = this.getPortName(parseInt(dstPort));
                
                this.threats.push({
                    type: 'Brute Force Attempt',
                    description: `High connection count to ${portName} (${dstPort}) - Possible brute force attack`,
                    severity: 'high',
                    confidence: 80,
                    source: srcIP,
                    target: `${dstIP}:${dstPort}`,
                    evidence: [
                        `${count} packets exchanged`,
                        `Target port: ${portName} (${dstPort})`,
                        `Source: ${srcIP}`,
                        'High packet count suggests credential attempts'
                    ]
                });
            }
        });
    }

    /**
     * DOS Patterns
     */
    detectDOSPatterns() {
        // High packet count from single source
        const topSrc = this.stats.ipStats.source[0];
        if (topSrc && topSrc.count > 10000) {
            this.threats.push({
                type: 'Potential DDoS Source',
                description: `${topSrc.ip} generated ${topSrc.count} packets (${topSrc.percent}% of traffic)`,
                severity: 'high',
                confidence: 75,
                source: topSrc.ip,
                evidence: [
                    `Total packets: ${topSrc.count}`,
                    `Percentage of traffic: ${topSrc.percent}%`,
                    'Abnormally high packet count from single source'
                ]
            });
        }

        // Lots of packets to single destination
        const topDst = this.stats.ipStats.destination[0];
        if (topDst && topDst.count > 10000) {
            this.threats.push({
                type: 'Potential DDoS Target',
                description: `${topDst.ip} received ${topDst.count} packets - Possible attack target`,
                severity: 'high',
                confidence: 70,
                source: 'Multiple',
                target: topDst.ip,
                evidence: [
                    `Packets received: ${topDst.count}`,
                    `Percentage of traffic: ${topDst.percent}%`
                ]
            });
        }
    }

    /**
     * Unusual Traffic Patterns
     */
    detectUnusualTraffic() {
        // Bidir imbalance
        const inbound = this.stats.traffic.inbound;
        const outbound = this.stats.traffic.outbound;
        const total = inbound + outbound || 1;

        if (inbound > 0 && outbound > 0) {
            const ratio = Math.max(inbound, outbound) / Math.min(inbound, outbound);
            
            if (ratio > 10) {
                this.threats.push({
                    type: 'Unusual Traffic Direction Imbalance',
                    description: 'Traffic is heavily skewed in one direction - Possible data exfiltration or one-way attack',
                    severity: 'medium',
                    confidence: 65,
                    evidence: [
                        `Inbound: ${(inbound / total * 100).toFixed(1)}%`,
                        `Outbound: ${(outbound / total * 100).toFixed(1)}%`,
                        `Ratio: ${ratio.toFixed(1)}:1`
                    ]
                });
            }
        }
    }

    /**
     * Suspicious Protocols
     */
    detectSuspiciousProtos() {
        const protocols = this.stats.protocols;

        // Check for suspicious protocol combinations
        const suspiciousProtos = {
            'ICMP': { threshold: 1000, msg: 'Potential ICMP flood' },
            'UDP': { threshold: 5000, msg: 'Excessive UDP traffic' }
        };

        protocols.forEach(proto => {
            if (suspiciousProtos[proto.name]) {
                const config = suspiciousProtos[proto.name];
                if (proto.count > config.threshold) {
                    this.threats.push({
                        type: `Suspicious ${proto.name} Activity`,
                        description: config.msg,
                        severity: 'medium',
                        confidence: 70,
                        evidence: [
                            `${proto.name} packets: ${proto.count}`,
                            `Data transferred: ${this.formatBytes(proto.bytes)}`,
                            `Percentage: ${proto.percent}%`
                        ]
                    });
                }
            }
        });
    }

    /**
     * DNS Anomalies
     */
    detectDNSAnomalies() {
        const dnsTraffic = this.packets.filter(p => p.dstPort === 53 || p.srcPort === 53);

        if (dnsTraffic.length > 0) {
            const dnsCount = dnsTraffic.length;
            const totalCount = this.packets.length;
            const dnsPercent = (dnsCount / totalCount) * 100;

            if (dnsPercent > 20) {
                this.threats.push({
                    type: 'Excessive DNS Traffic',
                    description: 'Unusual amount of DNS queries detected',
                    severity: 'medium',
                    confidence: 60,
                    evidence: [
                        `DNS packets: ${dnsCount}`,
                        `Percentage of total traffic: ${dnsPercent.toFixed(1)}%`,
                        'Possible DNS tunneling or DGA activity'
                    ]
                });
            }
        }
    }

    /**
     * Weak Connections
     */
    detectWeakConnections() {
        const weakProtos = ['telnet', 'ftp', 'http'];
        const flows = this.stats.flows;

        flows.forEach(flow => {
            if (weakProtos.includes(flow.protocol?.toLowerCase())) {
                this.threats.push({
                    type: 'Insecure Protocol Usage',
                    description: `${flow.protocol} used - Credentials may be sent in cleartext`,
                    severity: 'medium',
                    confidence: 95,
                    source: flow.srcIP,
                    target: `${flow.dstIP}:${flow.dstPort}`,
                    evidence: [
                        `Protocol: ${flow.protocol}`,
                        `Not encrypted - sensitive data at risk`,
                        `Destination: ${flow.dstIP}:${flow.dstPort}`
                    ]
                });
            }
        });
    }

    /**
     * Data Exfiltration Detection
     */
    detectDataExfiltration() {
        const flows = this.stats.flows;

        flows.forEach(flow => {
            if (flow.srcIP && this.isPrivateIP(flow.srcIP) && 
                flow.dstIP && !this.isPrivateIP(flow.dstIP)) {
                
                if (flow.bytes > 100 * 1024 * 1024) { // >100MB
                    this.threats.push({
                        type: 'Possible Data Exfiltration',
                        description: `Large data transfer from internal IP to external network detected`,
                        severity: 'high',
                        confidence: 65,
                        source: flow.srcIP,
                        target: flow.dstIP,
                        evidence: [
                            `Internal IP: ${flow.srcIP}`,
                            `External IP: ${flow.dstIP}`,
                            `Data transferred: ${this.formatBytes(flow.bytes)}`,
                            `Port: ${flow.dstPort}`,
                            'Potential unauthorized data transfer'
                        ]
                    });
                }
            }
        });
    }

    /**
     * Generate Summary
     */
    generateSummary() {
        const bySeverity = {
            critical: this.threats.filter(t => t.severity === 'critical').length,
            high: this.threats.filter(t => t.severity === 'high').length,
            medium: this.threats.filter(t => t.severity === 'medium').length,
            low: this.threats.filter(t => t.severity === 'low').length
        };

        return {
            totalThreats: this.threats.length,
            bySeverity,
            riskLevel: this.calculateRiskLevel(bySeverity)
        };
    }

    /**
     * Calculate Risk Level
     */
    calculateRiskLevel(bySeverity) {
        if (bySeverity.critical > 0) return 'CRITICAL';
        if (bySeverity.high > 2) return 'HIGH';
        if (bySeverity.high > 0 || bySeverity.medium > 3) return 'MEDIUM';
        if (bySeverity.medium > 0) return 'LOW';
        return 'SAFE';
    }

    /**
     * Helpers
     */
    isPrivateIP(ip) {
        if (!ip) return false;
        const parts = ip.split('.').map(Number);
        return (parts[0] === 10) ||
               (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
               (parts[0] === 192 && parts[1] === 168) ||
               (parts[0] === 127);
    }

    getPortName(port) {
        const names = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            443: 'HTTPS', 445: 'SMB', 3389: 'RDP', 3306: 'MySQL'
        };
        return names[port] || `Port ${port}`;
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
    }
}