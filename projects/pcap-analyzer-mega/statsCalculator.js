/**
 * Stats Calculator - Calcule toutes les statistiques
 */

class StatsCalculator {
    constructor(packets) {
        this.packets = packets;
        this.stats = {
            overview: {},
            traffic: {},
            protocols: [],
            ipStats: { source: [], destination: [] },
            portStats: { source: [], destination: [] },
            sizeDistribution: {},
            flows: [],
            timeline: [],
            topCommunications: [],
            geoData: {},
            anomalies: []
        };
    }

    /**
     * Calcule TOUTES les stats
     */
    calculateAll() {
        this.calculateOverview();
        this.calculateTraffic();
        this.calculateProtocols();
        this.calculateIPs();
        this.calculatePorts();
        this.calculateSizeDistribution();
        this.calculateFlows();
        this.calculateTimeline();
        this.calculateTopCommunications();
        this.detectAnomalies();
        
        return this.stats;
    }

    /**
     * Overview - Stats globales
     */
    calculateOverview() {
        const totalPackets = this.packets.length;
        const totalBytes = this.packets.reduce((sum, p) => sum + p.size, 0);
        const sizes = this.packets.map(p => p.size).sort((a, b) => a - b);
        
        const startTime = Math.min(...this.packets.map(p => p.timestamp));
        const endTime = Math.max(...this.packets.map(p => p.timestamp));
        const duration = endTime - startTime;

        this.stats.overview = {
            totalPackets,
            totalBytes,
            duration: duration || 1,
            avgPacketSize: Math.round(totalBytes / totalPackets),
            minPacketSize: Math.min(...this.packets.map(p => p.size)),
            maxPacketSize: Math.max(...this.packets.map(p => p.size)),
            medianPacketSize: sizes[Math.floor(sizes.length / 2)],
            packetsPerSecond: Math.round(totalPackets / (duration || 1)),
            bytesPerSecond: Math.round(totalBytes / (duration || 1)),
            startTime: new Date(startTime * 1000),
            endTime: new Date(endTime * 1000)
        };
    }

    /**
     * Traffic - Inbound/Outbound
     */
    calculateTraffic() {
        let inbound = 0;
        let outbound = 0;
        const privateIPs = new Set();

        // Identifier les IPs privées
        this.packets.forEach(p => {
            if (this.isPrivateIP(p.srcIP)) privateIPs.add(p.srcIP);
            if (this.isPrivateIP(p.dstIP)) privateIPs.add(p.dstIP);
        });

        // Calculer inbound/outbound
        this.packets.forEach(p => {
            const srcIsPrivate = this.isPrivateIP(p.srcIP);
            const dstIsPrivate = this.isPrivateIP(p.dstIP);

            if (!srcIsPrivate && dstIsPrivate) {
                inbound += p.size;
            } else if (srcIsPrivate && !dstIsPrivate) {
                outbound += p.size;
            }
        });

        const total = inbound + outbound || 1;

        this.stats.traffic = {
            inbound,
            outbound,
            internalTraffic: total - inbound - outbound,
            inboundPercent: Math.round((inbound / total) * 100),
            outboundPercent: Math.round((outbound / total) * 100),
            privateIPs: Array.from(privateIPs)
        };
    }

    /**
     * Protocols - Distribution des protocoles
     */
    calculateProtocols() {
        const protocolMap = {};

        this.packets.forEach(p => {
            const proto = p.protocol || 'UNKNOWN';
            if (!protocolMap[proto]) {
                protocolMap[proto] = { name: proto, count: 0, bytes: 0, percent: 0 };
            }
            protocolMap[proto].count++;
            protocolMap[proto].bytes += p.size;
        });

        const totalBytes = this.packets.reduce((sum, p) => sum + p.size, 0);
        const protocols = Object.values(protocolMap);

        protocols.forEach(p => {
            p.percent = Math.round((p.bytes / totalBytes) * 100);
        });

        this.stats.protocols = protocols.sort((a, b) => b.count - a.count);
    }

    /**
     * IPs - Source et Destination
     */
    calculateIPs() {
        const sourceIPs = {};
        const destIPs = {};

        this.packets.forEach(p => {
            if (p.srcIP) {
                sourceIPs[p.srcIP] = (sourceIPs[p.srcIP] || 0) + 1;
            }
            if (p.dstIP) {
                destIPs[p.dstIP] = (destIPs[p.dstIP] || 0) + 1;
            }
        });

        const totalPkts = this.packets.length;

        const srcArray = Object.entries(sourceIPs)
            .map(([ip, count]) => ({
                ip,
                count,
                percent: Math.round((count / totalPkts) * 100),
                isPrivate: this.isPrivateIP(ip),
                isLocal: this.isLocalIP(ip)
            }))
            .sort((a, b) => b.count - a.count);

        const destArray = Object.entries(destIPs)
            .map(([ip, count]) => ({
                ip,
                count,
                percent: Math.round((count / totalPkts) * 100),
                isPrivate: this.isPrivateIP(ip),
                isLocal: this.isLocalIP(ip)
            }))
            .sort((a, b) => b.count - a.count);

        this.stats.ipStats = {
            source: srcArray.slice(0, 50),
            destination: destArray.slice(0, 50),
            totalSourceIPs: Object.keys(sourceIPs).length,
            totalDestIPs: Object.keys(destIPs).length
        };
    }

    /**
     * Ports - Source et Destination
     */
    calculatePorts() {
        const sourcePorts = {};
        const destPorts = {};

        this.packets.forEach(p => {
            if (p.srcPort) {
                const port = String(p.srcPort);
                sourcePorts[port] = (sourcePorts[port] || 0) + 1;
            }
            if (p.dstPort) {
                const port = String(p.dstPort);
                destPorts[port] = (destPorts[port] || 0) + 1;
            }
        });

        const srcArray = Object.entries(sourcePorts)
            .map(([port, count]) => ({
                port,
                count,
                name: this.getPortName(parseInt(port)),
                isWellKnown: parseInt(port) < 1024
            }))
            .sort((a, b) => b.count - a.count);

        const destArray = Object.entries(destPorts)
            .map(([port, count]) => ({
                port,
                count,
                name: this.getPortName(parseInt(port)),
                isWellKnown: parseInt(port) < 1024
            }))
            .sort((a, b) => b.count - a.count);

        this.stats.portStats = {
            source: srcArray.slice(0, 20),
            destination: destArray.slice(0, 20),
            totalSourcePorts: Object.keys(sourcePorts).length,
            totalDestPorts: Object.keys(destPorts).length,
            suspiciousPorts: destArray.filter(p => this.isSuspiciousPort(parseInt(p.port)))
        };
    }

    /**
     * Size Distribution - Répartition des tailles
     */
    calculateSizeDistribution() {
        const ranges = {
            '<64 Bytes': 0,
            '64-128 Bytes': 0,
            '128-256 Bytes': 0,
            '256-512 Bytes': 0,
            '512-1024 Bytes': 0,
            '1024+ Bytes': 0
        };

        this.packets.forEach(p => {
            if (p.size < 64) ranges['<64 Bytes']++;
            else if (p.size < 128) ranges['64-128 Bytes']++;
            else if (p.size < 256) ranges['128-256 Bytes']++;
            else if (p.size < 512) ranges['256-512 Bytes']++;
            else if (p.size < 1024) ranges['512-1024 Bytes']++;
            else ranges['1024+ Bytes']++;
        });

        this.stats.sizeDistribution = ranges;
    }

    /**
     * Flows - Conversations réseau
     */
    calculateFlows() {
        const flowMap = {};

        this.packets.forEach(p => {
            if (!p.srcIP || !p.dstIP) return;

            const flowKey = [p.srcIP, p.srcPort, p.dstIP, p.dstPort, p.protocol].join('|');
            
            if (!flowMap[flowKey]) {
                flowMap[flowKey] = {
                    srcIP: p.srcIP,
                    srcPort: p.srcPort || 0,
                    dstIP: p.dstIP,
                    dstPort: p.dstPort || 0,
                    protocol: p.protocol,
                    packets: 0,
                    bytes: 0,
                    startTime: p.timestamp,
                    endTime: p.timestamp,
                    flags: {}
                };
            }

            flowMap[flowKey].packets++;
            flowMap[flowKey].bytes += p.size;
            flowMap[flowKey].endTime = p.timestamp;
            
            if (p.flags) {
                Object.assign(flowMap[flowKey].flags, p.flags);
            }
        });

        const flows = Object.values(flowMap).map(f => ({
            ...f,
            duration: f.endTime - f.startTime,
            avgPacketSize: Math.round(f.bytes / f.packets),
            throughput: Math.round(f.bytes / ((f.endTime - f.startTime) || 1))
        })).sort((a, b) => b.bytes - a.bytes);

        this.stats.flows = flows.slice(0, 1000);
    }

    /**
     * Timeline - Packets par intervalle de temps
     */
    calculateTimeline() {
        if (this.packets.length === 0) {
            this.stats.timeline = [];
            return;
        }

        const startTime = Math.min(...this.packets.map(p => p.timestamp));
        const endTime = Math.max(...this.packets.map(p => p.timestamp));
        const duration = endTime - startTime || 1;
        const bucketCount = Math.min(Math.ceil(duration), 100);
        const bucketSize = duration / bucketCount;

        const timeline = new Array(bucketCount).fill(0);

        this.packets.forEach(p => {
            const bucketIndex = Math.floor((p.timestamp - startTime) / bucketSize);
            if (bucketIndex >= 0 && bucketIndex < bucketCount) {
                timeline[bucketIndex]++;
            }
        });

        this.stats.timeline = timeline;
    }

    /**
     * Top Communications - IPs qui communiquent le plus
     */
    calculateTopCommunications() {
        const commMap = {};

        this.packets.forEach(p => {
            if (!p.srcIP || !p.dstIP) return;

            const key = [p.srcIP, p.dstIP].sort().join('-');
            
            if (!commMap[key]) {
                commMap[key] = {
                    src: p.srcIP,
                    dst: p.dstIP,
                    packets: 0,
                    size: 0
                };
            }
            commMap[key].packets++;
            commMap[key].size += p.size;
        });

        this.stats.topCommunications = Object.values(commMap)
            .sort((a, b) => b.size - a.size)
            .slice(0, 20);
    }

    /**
     * Detect Anomalies
     */
    detectAnomalies() {
        const anomalies = [];
        const avgSize = this.stats.overview.avgPacketSize;
        const avgSize2X = avgSize * 2;

        // Packets beaucoup plus gros
        const jumboPackets = this.packets.filter(p => p.size > avgSize2X);
        if (jumboPackets.length > 0) {
            anomalies.push({
                type: 'Jumbo Packets',
                count: jumboPackets.length,
                percent: Math.round((jumboPackets.length / this.packets.length) * 100),
                severity: 'low'
            });
        }

        // Packets minuscules (possibles floods)
        const tinyPackets = this.packets.filter(p => p.size < 60);
        if (tinyPackets.length > this.packets.length * 0.1) {
            anomalies.push({
                type: 'Tiny Packets (Potential Flood)',
                count: tinyPackets.length,
                percent: Math.round((tinyPackets.length / this.packets.length) * 100),
                severity: 'medium'
            });
        }

        // Ports suspects
        this.stats.portStats.suspiciousPorts.forEach(port => {
            if (port.count > 100) {
                anomalies.push({
                    type: `Suspicious Port Activity - ${port.name}`,
                    count: port.count,
                    port: port.port,
                    severity: 'medium'
                });
            }
        });

        // IPs communicant beaucoup
        const topSrcIP = this.stats.ipStats.source[0];
        if (topSrcIP && topSrcIP.percent > 30) {
            anomalies.push({
                type: `Heavy Traffic from Single IP - ${topSrcIP.ip}`,
                percent: topSrcIP.percent,
                severity: 'medium'
            });
        }

        this.stats.anomalies = anomalies;
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

    isLocalIP(ip) {
        return ip?.startsWith('127.') || ip === 'localhost';
    }

    getPortName(port) {
        const names = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
            25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
            587: 'SMTP', 993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt', 27017: 'MongoDB', 6379: 'Redis',
            1433: 'MSSQL', 3389: 'RDP', 5555: 'Android ADB'
        };
        return names[port] || `Port ${port}`;
    }

    isSuspiciousPort(port) {
        const suspicious = [
            135, 139, 445,      // SMB
            3389,                // RDP
            22,                  // SSH
            23,                  // Telnet
            21,                  // FTP
            1433, 3306, 5432,   // Databases
            27017, 6379,        // NoSQL
            5555                // ADB
        ];
        return suspicious.includes(port);
    }
}