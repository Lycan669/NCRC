/* ============================================
   NCRC PACKET DISSECTOR
   Advanced Layer Analysis & Conversation Tracking
   ============================================ */

class PacketDissector {
    constructor() {
        this.conversations = new Map();
        this.flows = new Map();
        this.stats = {
            protocolStats: {},
            ipStats: {
                sources: {},
                destinations: {}
            },
            portStats: {
                tcp: {},
                udp: {}
            },
            domainStats: {},
            anomalies: []
        };
    }

    /* ============================================
       ANALYZE COMPLETE PACKET SET
       ============================================ */

    analyzePackets(packets) {
        this.conversations.clear();
        this.flows.clear();
        this.stats = {
            protocolStats: {},
            ipStats: {
                sources: {},
                destinations: {}
            },
            portStats: {
                tcp: {},
                udp: {}
            },
            domainStats: {},
            anomalies: []
        };

        packets.forEach((packet, index) => {
            this._analyzePacket(packet, index);
        });

        this._buildConversations(packets);
        this._buildFlows(packets);
        this._detectAnomalies(packets);

        return {
            conversations: Array.from(this.conversations.values()),
            flows: Array.from(this.flows.values()),
            statistics: this.stats
        };
    }

    /* ============================================
       ANALYZE INDIVIDUAL PACKET
       ============================================ */

    _analyzePacket(packet, index) {
        // Protocol statistics
        if (packet.protocol) {
            if (!this.stats.protocolStats[packet.protocol]) {
                this.stats.protocolStats[packet.protocol] = {
                    count: 0,
                    bytes: 0,
                    packets: []
                };
            }
            this.stats.protocolStats[packet.protocol].count++;
            this.stats.protocolStats[packet.protocol].bytes += packet.size;
            this.stats.protocolStats[packet.protocol].packets.push(index);
        }

        // IP statistics
        if (packet.layers.ip) {
            const srcIP = packet.layers.ip.srcIP;
            const dstIP = packet.layers.ip.dstIP;

            if (!this.stats.ipStats.sources[srcIP]) {
                this.stats.ipStats.sources[srcIP] = { count: 0, bytes: 0 };
            }
            this.stats.ipStats.sources[srcIP].count++;
            this.stats.ipStats.sources[srcIP].bytes += packet.size;

            if (!this.stats.ipStats.destinations[dstIP]) {
                this.stats.ipStats.destinations[dstIP] = { count: 0, bytes: 0 };
            }
            this.stats.ipStats.destinations[dstIP].count++;
            this.stats.ipStats.destinations[dstIP].bytes += packet.size;
        }

        // Port statistics
        if (packet.layers.tcp) {
            const srcPort = packet.layers.tcp.srcPort;
            const dstPort = packet.layers.tcp.dstPort;

            if (!this.stats.portStats.tcp[dstPort]) {
                this.stats.portStats.tcp[dstPort] = { count: 0, bytes: 0 };
            }
            this.stats.portStats.tcp[dstPort].count++;
            this.stats.portStats.tcp[dstPort].bytes += packet.size;
        }

        if (packet.layers.udp) {
            const dstPort = packet.layers.udp.dstPort;

            if (!this.stats.portStats.udp[dstPort]) {
                this.stats.portStats.udp[dstPort] = { count: 0, bytes: 0 };
            }
            this.stats.portStats.udp[dstPort].count++;
            this.stats.portStats.udp[dstPort].bytes += packet.size;
        }

        // DNS statistics
        if (packet.layers.dns) {
            packet.layers.dns.queries.forEach(query => {
                if (!this.stats.domainStats[query.name]) {
                    this.stats.domainStats[query.name] = { count: 0 };
                }
                this.stats.domainStats[query.name].count++;
            });
        }
    }

    /* ============================================
       BUILD CONVERSATION PAIRS
       ============================================ */

    _buildConversations(packets) {
        packets.forEach(packet => {
            if (packet.layers.ip && (packet.layers.tcp || packet.layers.udp)) {
                const srcIP = packet.layers.ip.srcIP;
                const dstIP = packet.layers.ip.dstIP;
                const srcPort = packet.layers.tcp ? packet.layers.tcp.srcPort : packet.layers.udp.srcPort;
                const dstPort = packet.layers.tcp ? packet.layers.tcp.dstPort : packet.layers.udp.dstPort;
                const protocol = packet.protocol;

                const convKey = this._getConversationKey(srcIP, dstIP, srcPort, dstPort, protocol);
                const reverseKey = this._getConversationKey(dstIP, srcIP, dstPort, srcPort, protocol);

                let conv = this.conversations.get(convKey) || this.conversations.get(reverseKey);

                if (!conv) {
                    conv = {
                        key: convKey,
                        srcIP: srcIP,
                        dstIP: dstIP,
                        srcPort: srcPort,
                        dstPort: dstPort,
                        protocol: protocol,
                        packets: [],
                        bytes: 0,
                        startTime: packet.timestamp,
                        endTime: packet.timestamp,
                        service: this._getServiceName(dstPort, protocol)
                    };
                    this.conversations.set(convKey, conv);
                }

                conv.packets.push(packet);
                conv.bytes += packet.size;
                conv.endTime = packet.timestamp;
            }
        });
    }

    /* ============================================
       BUILD TRAFFIC FLOWS
       ============================================ */

    _buildFlows(packets) {
        packets.forEach(packet => {
            if (packet.layers.ip) {
                const srcIP = packet.layers.ip.srcIP;
                const dstIP = packet.layers.ip.dstIP;

                const flowKey = `${srcIP}-${dstIP}`;
                const reverseKey = `${dstIP}-${srcIP}`;

                let flow = this.flows.get(flowKey) || this.flows.get(reverseKey);

                if (!flow) {
                    flow = {
                        key: flowKey,
                        srcIP: srcIP,
                        dstIP: dstIP,
                        packets: [],
                        bytes: 0,
                        protocols: {},
                        startTime: packet.timestamp,
                        endTime: packet.timestamp
                    };
                    this.flows.set(flowKey, flow);
                }

                flow.packets.push(packet);
                flow.bytes += packet.size;
                flow.endTime = packet.timestamp;

                if (packet.protocol) {
                    if (!flow.protocols[packet.protocol]) {
                        flow.protocols[packet.protocol] = { count: 0, bytes: 0 };
                    }
                    flow.protocols[packet.protocol].count++;
                    flow.protocols[packet.protocol].bytes += packet.size;
                }
            }
        });
    }

    /* ============================================
       ANOMALY DETECTION
       ============================================ */

    _detectAnomalies(packets) {
        const anomalies = [];

        // Port scanning detection
        const dstPorts = {};
        packets.forEach(packet => {
            if (packet.layers.tcp) {
                const srcIP = packet.layers.ip.srcIP;
                const dstPort = packet.layers.tcp.dstPort;
                const key = `${srcIP}`;

                if (!dstPorts[key]) dstPorts[key] = new Set();
                dstPorts[key].add(dstPort);
            }
        });

        Object.entries(dstPorts).forEach(([ip, ports]) => {
            if (ports.size > 10) {
                anomalies.push({
                    type: 'PORT_SCANNING',
                    severity: 'HIGH',
                    description: `Possible port scanning from ${ip} targeting ${ports.size} different ports`,
                    affectedIP: ip,
                    data: {
                        sourceIP: ip,
                        uniquePorts: ports.size,
                        ports: Array.from(ports)
                    }
                });
            }
        });

        // SYN flood detection
        const synCount = {};
        packets.forEach(packet => {
            if (packet.layers.tcp && packet.layers.tcp.flags.SYN && !packet.layers.tcp.flags.ACK) {
                const key = `${packet.layers.ip.dstIP}`;
                synCount[key] = (synCount[key] || 0) + 1;
            }
        });

        Object.entries(synCount).forEach(([ip, count]) => {
            if (count > 20) {
                anomalies.push({
                    type: 'SYN_FLOOD',
                    severity: 'CRITICAL',
                    description: `Possible SYN flood attack on ${ip} with ${count} SYN packets`,
                    affectedIP: ip,
                    data: {
                        targetIP: ip,
                        synPackets: count
                    }
                });
            }
        });

        // DNS anomalies
        const dnsStats = {};
        packets.forEach(packet => {
            if (packet.layers.dns && packet.layers.dns.isQuery) {
                const srcIP = packet.layers.ip.srcIP;
                if (!dnsStats[srcIP]) dnsStats[srcIP] = 0;
                dnsStats[srcIP]++;
            }
        });

        Object.entries(dnsStats).forEach(([ip, count]) => {
            if (count > 50) {
                anomalies.push({
                    type: 'DNS_EXFILTRATION',
                    severity: 'HIGH',
                    description: `Excessive DNS queries from ${ip} (${count} queries)`,
                    affectedIP: ip,
                    data: {
                        sourceIP: ip,
                        dnsQueries: count
                    }
                });
            }
        });

        this.stats.anomalies = anomalies;
    }

    /* ============================================
       HELPER FUNCTIONS
       ============================================ */

    _getConversationKey(srcIP, dstIP, srcPort, dstPort, protocol) {
        return `${srcIP}:${srcPort}-${dstIP}:${dstPort}-${protocol}`;
    }

    _getServiceName(port, protocol) {
        const services = {
            20: 'FTP-DATA',
            21: 'FTP',
            22: 'SSH',
            23: 'TELNET',
            25: 'SMTP',
            53: 'DNS',
            67: 'DHCP',
            68: 'DHCP',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            161: 'SNMP',
            162: 'SNMP-TRAP',
            389: 'LDAP',
            443: 'HTTPS',
            445: 'SMB',
            465: 'SMTPS',
            514: 'SYSLOG',
            587: 'SMTP',
            636: 'LDAPS',
            993: 'IMAPS',
            995: 'POP3S',
            1433: 'MSSQL',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP-ALT',
            8443: 'HTTPS-ALT'
        };
        return services[port] || `Unknown(${port})`;
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = PacketDissector;
}