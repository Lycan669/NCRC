/* ============================================
   NCRC STATISTICS ENGINE
   Advanced Network Analysis & Metrics
   ============================================ */

class StatisticsEngine {
    constructor() {
        this.packets = [];
        this.analysis = {
            summary: {},
            timeSeries: {},
            protocolBreakdown: {},
            topTalkers: {},
            conversations: [],
            flows: [],
            geoLocation: {},
            threatLevel: 'LOW'
        };
    }

    /* ============================================
       COMPREHENSIVE ANALYSIS
       ============================================ */

    analyze(packets) {
        this.packets = packets;
        this.analysis = {
            summary: this._generateSummary(),
            timeSeries: this._generateTimeSeries(),
            protocolBreakdown: this._generateProtocolBreakdown(),
            topTalkers: this._generateTopTalkers(),
            conversations: this._generateConversations(),
            flows: this._generateFlows(),
            throughput: this._calculateThroughput(),
            latency: this._calculateLatency(),
            packetSizeDistribution: this._generatePacketSizeDistribution(),
            portAnalysis: this._generatePortAnalysis(),
            protocolSequence: this._generateProtocolSequence(),
            threatAnalysis: this._generateThreatAnalysis(),
            qualityMetrics: this._generateQualityMetrics()
        };

        return this.analysis;
    }

    /* ============================================
       SUMMARY STATISTICS
       ============================================ */

    _generateSummary() {
        if (this.packets.length === 0) {
            return {
                totalPackets: 0,
                totalBytes: 0,
                averagePacketSize: 0,
                minPacketSize: 0,
                maxPacketSize: 0,
                captureStartTime: null,
                captureEndTime: null,
                captureDuration: 0,
                packetsPerSecond: 0,
                bytesPerSecond: 0,
                uniqueSourceIPs: 0,
                uniqueDestIPs: 0,
                uniqueConversations: 0,
                protocolCount: 0
            };
        }

        const totalBytes = this.packets.reduce((sum, p) => sum + p.size, 0);
        const packetSizes = this.packets.map(p => p.size);
        const startTime = this.packets[0].timestamp;
        const endTime = this.packets[this.packets.length - 1].timestamp;
        const duration = (endTime - startTime) / 1000; // seconds

        const sourceIPs = new Set();
        const destIPs = new Set();
        const protocols = new Set();

        this.packets.forEach(packet => {
            if (packet.layers.ip) {
                sourceIPs.add(packet.layers.ip.srcIP);
                destIPs.add(packet.layers.ip.dstIP);
            }
            if (packet.protocol) {
                protocols.add(packet.protocol);
            }
        });

        return {
            totalPackets: this.packets.length,
            totalBytes: totalBytes,
            averagePacketSize: Math.round(totalBytes / this.packets.length),
            minPacketSize: Math.min(...packetSizes),
            maxPacketSize: Math.max(...packetSizes),
            captureStartTime: this.packets[0].timestampDate,
            captureEndTime: this.packets[this.packets.length - 1].timestampDate,
            captureDuration: duration,
            packetsPerSecond: duration > 0 ? Math.round(this.packets.length / duration) : 0,
            bytesPerSecond: duration > 0 ? Math.round(totalBytes / duration) : 0,
            uniqueSourceIPs: sourceIPs.size,
            uniqueDestIPs: destIPs.size,
            uniqueConversations: this._countConversations(),
            protocolCount: protocols.size,
            protocols: Array.from(protocols)
        };
    }

    /* ============================================
       TIME SERIES ANALYSIS
       ============================================ */

    _generateTimeSeries() {
        const timeSeries = {};
        const bucketSize = 1000; // 1 second buckets

        this.packets.forEach(packet => {
            const bucket = Math.floor(packet.timestamp / bucketSize);
            if (!timeSeries[bucket]) {
                timeSeries[bucket] = {
                    timestamp: bucket * bucketSize,
                    packetCount: 0,
                    bytes: 0,
                    protocols: {}
                };
            }
            timeSeries[bucket].packetCount++;
            timeSeries[bucket].bytes += packet.size;

            if (packet.protocol) {
                if (!timeSeries[bucket].protocols[packet.protocol]) {
                    timeSeries[bucket].protocols[packet.protocol] = 0;
                }
                timeSeries[bucket].protocols[packet.protocol]++;
            }
        });

        return Object.values(timeSeries).sort((a, b) => a.timestamp - b.timestamp);
    }

    /* ============================================
       PROTOCOL BREAKDOWN
       ============================================ */

    _generateProtocolBreakdown() {
        const breakdown = {};

        this.packets.forEach(packet => {
            if (packet.protocol) {
                if (!breakdown[packet.protocol]) {
                    breakdown[packet.protocol] = {
                        name: packet.protocol,
                        packets: 0,
                        bytes: 0,
                        percentage: 0,
                        averageSize: 0,
                        colors: this._getProtocolColor(packet.protocol)
                    };
                }
                breakdown[packet.protocol].packets++;
                breakdown[packet.protocol].bytes += packet.size;
            }
        });

        // Calculate percentages and averages
        Object.values(breakdown).forEach(proto => {
            proto.percentage = (proto.packets / this.packets.length) * 100;
            proto.averageSize = Math.round(proto.bytes / proto.packets);
        });

        // Sort by packet count
        const sorted = Object.values(breakdown).sort((a, b) => b.packets - a.packets);

        return {
            byName: breakdown,
            sorted: sorted,
            totalProtocols: Object.keys(breakdown).length
        };
    }

    /* ============================================
       TOP TALKERS ANALYSIS
       ============================================ */

    _generateTopTalkers() {
        const srcTalkers = {};
        const dstTalkers = {};

        this.packets.forEach(packet => {
            if (packet.layers.ip) {
                const src = packet.layers.ip.srcIP;
                const dst = packet.layers.ip.dstIP;

                if (!srcTalkers[src]) {
                    srcTalkers[src] = { ip: src, packets: 0, bytes: 0, connections: new Set() };
                }
                srcTalkers[src].packets++;
                srcTalkers[src].bytes += packet.size;
                srcTalkers[src].connections.add(dst);

                if (!dstTalkers[dst]) {
                    dstTalkers[dst] = { ip: dst, packets: 0, bytes: 0, connections: new Set() };
                }
                dstTalkers[dst].packets++;
                dstTalkers[dst].bytes += packet.size;
                dstTalkers[dst].connections.add(src);
            }
        });

        // Convert to arrays and sort
        const topSources = Object.values(srcTalkers)
            .map(t => ({
                ip: t.ip,
                packets: t.packets,
                bytes: t.bytes,
                uniqueDestinations: t.connections.size
            }))
            .sort((a, b) => b.bytes - a.bytes)
            .slice(0, 20);

        const topDestinations = Object.values(dstTalkers)
            .map(t => ({
                ip: t.ip,
                packets: t.packets,
                bytes: t.bytes,
                uniqueSources: t.connections.size
            }))
            .sort((a, b) => b.bytes - a.bytes)
            .slice(0, 20);

        return {
            topSources: topSources,
            topDestinations: topDestinations
        };
    }

    /* ============================================
       CONVERSATION ANALYSIS
       ============================================ */

    _generateConversations() {
        const conversations = {};

        this.packets.forEach(packet => {
            if (packet.layers.ip && (packet.layers.tcp || packet.layers.udp)) {
                const srcIP = packet.layers.ip.srcIP;
                const dstIP = packet.layers.ip.dstIP;
                const srcPort = packet.layers.tcp ? packet.layers.tcp.srcPort : packet.layers.udp.srcPort;
                const dstPort = packet.layers.tcp ? packet.layers.tcp.dstPort : packet.layers.udp.dstPort;
                const protocol = packet.protocol;

                // Create bidirectional key
                const key1 = `${srcIP}:${srcPort}<->${dstIP}:${dstPort}`;
                const key2 = `${dstIP}:${dstPort}<->${srcIP}:${srcPort}`;
                const key = conversations[key1] ? key1 : key2;

                if (!conversations[key]) {
                    conversations[key] = {
                        src: srcIP,
                        srcPort: srcPort,
                        dst: dstIP,
                        dstPort: dstPort,
                        protocol: protocol,
                        packets: 0,
                        bytes: 0,
                        startTime: packet.timestamp,
                        endTime: packet.timestamp,
                        service: this._getService(dstPort),
                        state: 'ACTIVE'
                    };
                }

                conversations[key].packets++;
                conversations[key].bytes += packet.size;
                conversations[key].endTime = packet.timestamp;

                // Detect conversation state
                if (packet.layers.tcp) {
                    if (packet.layers.tcp.flags.FIN || packet.layers.tcp.flags.RST) {
                        conversations[key].state = 'CLOSED';
                    }
                }
            }
        });

        const convArray = Object.values(conversations)
            .sort((a, b) => b.bytes - a.bytes)
            .slice(0, 100);

        return convArray;
    }

    /* ============================================
       FLOW ANALYSIS
       ============================================ */

    _generateFlows() {
        const flows = {};

        this.packets.forEach(packet => {
            if (packet.layers.ip) {
                const srcIP = packet.layers.ip.srcIP;
                const dstIP = packet.layers.ip.dstIP;

                const key = `${srcIP}-${dstIP}`;

                if (!flows[key]) {
                    flows[key] = {
                        src: srcIP,
                        dst: dstIP,
                        packets: 0,
                        bytes: 0,
                        startTime: packet.timestamp,
                        endTime: packet.timestamp,
                        protocols: {},
                        ports: new Set()
                    };
                }

                flows[key].packets++;
                flows[key].bytes += packet.size;
                flows[key].endTime = packet.timestamp;

                if (packet.protocol) {
                    if (!flows[key].protocols[packet.protocol]) {
                        flows[key].protocols[packet.protocol] = 0;
                    }
                    flows[key].protocols[packet.protocol]++;
                }

                if (packet.layers.tcp || packet.layers.udp) {
                    const port = packet.layers.tcp ? packet.layers.tcp.dstPort : packet.layers.udp.dstPort;
                    flows[key].ports.add(port);
                }
            }
        });

        const flowArray = Object.values(flows)
            .map(f => ({
                src: f.src,
                dst: f.dst,
                packets: f.packets,
                bytes: f.bytes,
                duration: (f.endTime - f.startTime) / 1000,
                protocols: f.protocols,
                uniquePorts: f.ports.size
            }))
            .sort((a, b) => b.bytes - a.bytes)
            .slice(0, 100);

        return flowArray;
    }

    /* ============================================
       THROUGHPUT CALCULATION
       ============================================ */

    _calculateThroughput() {
        if (this.packets.length < 2) {
            return { average: 0, peak: 0, min: 0 };
        }

        const buckets = {};
        const bucketSize = 100; // 100ms buckets

        this.packets.forEach(packet => {
            const bucket = Math.floor(packet.timestamp / bucketSize);
            if (!buckets[bucket]) {
                buckets[bucket] = 0;
            }
            buckets[bucket] += packet.size;
        });

        const throughputs = Object.values(buckets).map(bytes => bytes * 8 / 0.1); // bits per second

        return {
            average: throughputs.length > 0 ? Math.round(throughputs.reduce((a, b) => a + b, 0) / throughputs.length) : 0,
            peak: throughputs.length > 0 ? Math.max(...throughputs) : 0,
            min: throughputs.length > 0 ? Math.min(...throughputs) : 0,
            unit: 'bps'
        };
    }

    /* ============================================
       LATENCY CALCULATION
       ============================================ */

    _calculateLatency() {
        const rtts = [];

        // Simple RTT detection for TCP
        const tcpFlows = {};

        this.packets.forEach(packet => {
            if (packet.layers.tcp) {
                const src = packet.layers.ip.srcIP;
                const dst = packet.layers.ip.dstIP;
                const srcPort = packet.layers.tcp.srcPort;
                const dstPort = packet.layers.tcp.dstPort;

                const key = `${src}:${srcPort}-${dst}:${dstPort}`;

                if (!tcpFlows[key]) {
                    tcpFlows[key] = [];
                }
                tcpFlows[key].push(packet);
            }
        });

        // Calculate RTT from ACK packets
        Object.values(tcpFlows).forEach(flow => {
            for (let i = 1; i < flow.length; i++) {
                if (flow[i].layers.tcp.flags.ACK && flow[i - 1].timestamp < flow[i].timestamp) {
                    const rtt = flow[i].timestamp - flow[i - 1].timestamp;
                    if (rtt > 0 && rtt < 60000) { // 0-60 seconds
                        rtts.push(rtt);
                    }
                }
            }
        });

        if (rtts.length === 0) {
            return { average: 0, min: 0, max: 0, unit: 'ms' };
        }

        rtts.sort((a, b) => a - b);

        return {
            average: Math.round(rtts.reduce((a, b) => a + b, 0) / rtts.length),
            min: rtts[0],
            max: rtts[rtts.length - 1],
            median: rtts[Math.floor(rtts.length / 2)],
            p95: rtts[Math.floor(rtts.length * 0.95)],
            unit: 'ms'
        };
    }

    /* ============================================
       PACKET SIZE DISTRIBUTION
       ============================================ */

    _generatePacketSizeDistribution() {
        const ranges = {
            'Tiny (< 50B)': { min: 0, max: 50, count: 0 },
            'Small (50-300B)': { min: 50, max: 300, count: 0 },
            'Medium (300-1000B)': { min: 300, max: 1000, count: 0 },
            'Large (1000-5000B)': { min: 1000, max: 5000, count: 0 },
            'Jumbo (> 5000B)': { min: 5000, max: Infinity, count: 0 }
        };

        this.packets.forEach(packet => {
            Object.values(ranges).forEach(range => {
                if (packet.size >= range.min && packet.size < range.max) {
                    range.count++;
                }
            });
        });

        return ranges;
    }

    /* ============================================
       PORT ANALYSIS
       ============================================ */

    _generatePortAnalysis() {
        const ports = {
            tcp: {},
            udp: {}
        };

        this.packets.forEach(packet => {
            if (packet.layers.tcp) {
                const port = packet.layers.tcp.dstPort;
                if (!ports.tcp[port]) {
                    ports.tcp[port] = { port: port, packets: 0, bytes: 0, service: this._getService(port) };
                }
                ports.tcp[port].packets++;
                ports.tcp[port].bytes += packet.size;
            }

            if (packet.layers.udp) {
                const port = packet.layers.udp.dstPort;
                if (!ports.udp[port]) {
                    ports.udp[port] = { port: port, packets: 0, bytes: 0, service: this._getService(port) };
                }
                ports.udp[port].packets++;
                ports.udp[port].bytes += packet.size;
            }
        });

        const topTcpPorts = Object.values(ports.tcp)
            .sort((a, b) => b.packets - a.packets)
            .slice(0, 20);

        const topUdpPorts = Object.values(ports.udp)
            .sort((a, b) => b.packets - a.packets)
            .slice(0, 20);

        return {
            tcp: topTcpPorts,
            udp: topUdpPorts
        };
    }

    /* ============================================
       PROTOCOL SEQUENCE ANALYSIS
       ============================================ */

    _generateProtocolSequence() {
        const sequences = [];
        let currentSequence = [];
        let lastProtocol = null;

        this.packets.forEach(packet => {
            if (packet.protocol !== lastProtocol) {
                if (currentSequence.length > 0) {
                    sequences.push({
                        protocol: lastProtocol,
                        count: currentSequence.length,
                        packets: currentSequence
                    });
                }
                currentSequence = [packet];
                lastProtocol = packet.protocol;
            } else {
                currentSequence.push(packet);
            }
        });

        if (currentSequence.length > 0) {
            sequences.push({
                protocol: lastProtocol,
                count: currentSequence.length,
                packets: currentSequence
            });
        }

        return sequences.slice(0, 50);
    }

    /* ============================================
       THREAT ANALYSIS
       ============================================ */

    _generateThreatAnalysis() {
        const threats = {
            critical: [],
            high: [],
            medium: [],
            low: []
        };

        // Detect SYN flood
        const synFlood = this._detectSynFlood();
        if (synFlood) threats.critical.push(synFlood);

        // Detect port scanning
        const portScanning = this._detectPortScanning();
        if (portScanning) threats.high.push(portScanning);

        // Detect DNS anomalies
        const dnsAnomaly = this._detectDNSAnomaly();
        if (dnsAnomaly) threats.medium.push(dnsAnomaly);

        // Detect unusual behavior
        const unusual = this._detectUnusualBehavior();
        if (unusual.length > 0) threats.low.push(...unusual);

        // Calculate overall threat level
        let threatLevel = 'LOW';
        if (threats.critical.length > 0) threatLevel = 'CRITICAL';
        else if (threats.high.length > 0) threatLevel = 'HIGH';
        else if (threats.medium.length > 0) threatLevel = 'MEDIUM';

        return {
            level: threatLevel,
            critical: threats.critical,
            high: threats.high,
            medium: threats.medium,
            low: threats.low,
            totalThreats: threats.critical.length + threats.high.length + threats.medium.length + threats.low.length
        };
    }

    _detectSynFlood() {
        const synPackets = {};

        this.packets.forEach(packet => {
            if (packet.layers.tcp && packet.layers.tcp.flags.SYN && !packet.layers.tcp.flags.ACK) {
                const dst = packet.layers.ip.dstIP;
                synPackets[dst] = (synPackets[dst] || 0) + 1;
            }
        });

        for (const [ip, count] of Object.entries(synPackets)) {
            if (count > 20) {
                return {
                    type: 'SYN_FLOOD',
                    severity: 'CRITICAL',
                    target: ip,
                    packets: count,
                    description: `Detected ${count} SYN packets to ${ip}`
                };
            }
        }

        return null;
    }

    _detectPortScanning() {
        const portScans = {};

        this.packets.forEach(packet => {
            if (packet.layers.tcp && packet.layers.tcp.flags.SYN && !packet.layers.tcp.flags.ACK) {
                const src = packet.layers.ip.srcIP;
                if (!portScans[src]) portScans[src] = new Set();
                portScans[src].add(packet.layers.tcp.dstPort);
            }
        });

        for (const [ip, ports] of Object.entries(portScans)) {
            if (ports.size > 10) {
                return {
                    type: 'PORT_SCANNING',
                    severity: 'HIGH',
                    source: ip,
                    ports: ports.size,
                    description: `Detected ${ports.size} port scan attempts from ${ip}`
                };
            }
        }

        return null;
    }

    _detectDNSAnomaly() {
        let dnsCount = 0;
        let dnsData = 0;

        this.packets.forEach(packet => {
            if (packet.layers.dns) {
                dnsCount++;
                dnsData += packet.size;
            }
        });

        if (dnsCount > 50) {
            return {
                type: 'DNS_ANOMALY',
                severity: 'MEDIUM',
                count: dnsCount,
                bytes: dnsData,
                description: `Unusual DNS activity: ${dnsCount} queries, ${dnsData} bytes`
            };
        }

        return null;
    }

    _detectUnusualBehavior() {
        const unusual = [];

        // Check for large packet sizes
        const largePackets = this.packets.filter(p => p.size > 10000);
        if (largePackets.length > 5) {
            unusual.push({
                type: 'LARGE_PACKETS',
                severity: 'LOW',
                count: largePackets.length,
                description: `Detected ${largePackets.length} unusually large packets`
            });
        }

        return unusual;
    }

    /* ============================================
       QUALITY METRICS
       ============================================ */

    _generateQualityMetrics() {
        const metrics = {
            retransmissions: 0,
            duplicates: 0,
            outOfOrder: 0,
            checksumErrors: 0,
            fragmentedPackets: 0
        };

        // Detect retransmissions and duplicates
        const seen = new Set();
        this.packets.forEach(packet => {
            const key = `${packet.layers.ip?.srcIP}:${packet.layers.tcp?.srcPort || 'N/A'}-${packet.layers.ip?.dstIP}:${packet.layers.tcp?.dstPort || 'N/A'}:${packet.layers.tcp?.seqNum || 'N/A'}`;
            if (seen.has(key)) {
                metrics.retransmissions++;
            }
            seen.add(key);
        });

        // Detect fragmented packets
        this.packets.forEach(packet => {
            if (packet.layers.ip && packet.layers.ip.fragmentOffset > 0) {
                metrics.fragmentedPackets++;
            }
        });

        return metrics;
    }

    /* ============================================
       HELPER FUNCTIONS
       ============================================ */

    _countConversations() {
        const conversations = new Set();
        this.packets.forEach(packet => {
            if (packet.layers.ip && (packet.layers.tcp || packet.layers.udp)) {
                const src = packet.layers.ip.srcIP;
                const dst = packet.layers.ip.dstIP;
                const srcPort = packet.layers.tcp ? packet.layers.tcp.srcPort : packet.layers.udp?.srcPort;
                const dstPort = packet.layers.tcp ? packet.layers.tcp.dstPort : packet.layers.udp?.dstPort;
                const key = `${src}:${srcPort}<->${dst}:${dstPort}`;
                conversations.add(key);
            }
        });
        return conversations.size;
    }

    _getService(port) {
        const services = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP',
            53: 'DNS', 67: 'DHCP', 68: 'DHCP', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 161: 'SNMP', 162: 'SNMP-TRAP', 389: 'LDAP', 443: 'HTTPS',
            445: 'SMB', 465: 'SMTPS', 514: 'SYSLOG', 587: 'SMTP', 636: 'LDAPS',
            993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-ALT', 8443: 'HTTPS-ALT'
        };
        return services[port] || `Port${port}`;
    }

    _getProtocolColor(protocol) {
        const colors = {
            'TCP': '#00d4ff',
            'UDP': '#ffd700',
            'ICMP': '#ff1744',
            'DNS': '#00e676',
            'HTTP': '#9c27b0',
            'HTTPS': '#673ab7'
        };
        return colors[protocol] || '#a0a0a0';
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = StatisticsEngine;
}