/* ============================================
   NCRC SECURITY THREAT DETECTOR
   Advanced Anomaly & Attack Detection
   ============================================ */

class SecurityDetector {
    constructor() {
        this.threats = [];
        this.anomalies = [];
        this.whitelistIPs = new Set();
        this.blacklistIPs = new Set();
        this.knownAttackSignatures = this._loadAttackSignatures();
    }

    /* ============================================
       COMPREHENSIVE THREAT ANALYSIS
       ============================================ */

    detectThreats(packets) {
        this.threats = [];
        this.anomalies = [];

        this._detectSYNFlood(packets);
        this._detectPortScanning(packets);
        this._detectDNSExfiltration(packets);
        this._detectDNSTunneling(packets);
        this._detectSSLAnomalies(packets);
        this._detectHTTPAnomalies(packets);
        this._detectFragmentationAttacks(packets);
        this._detectReconnaissanceActivity(packets);
        this._detectMalwareSignatures(packets);
        this._detectBruteForceAttacks(packets);
        this._detectDataExfiltration(packets);
        this._detectRansomwarePatterns(packets);
        this._detectIPSpoofing(packets);
        this._detectDDoSPatterns(packets);
        this._detectUnusualBehavior(packets);

        return {
            threats: this.threats,
            anomalies: this.anomalies,
            riskLevel: this._calculateRiskLevel(),
            summary: this._generateThreatSummary()
        };
    }

    /* ============================================
       SYN FLOOD DETECTION
       ============================================ */

    _detectSYNFlood(packets) {
        const synPackets = packets.filter(p => 
            p.layers.tcp?.flags.SYN && !p.layers.tcp?.flags.ACK
        );

        if (synPackets.length === 0) return;

        const sourceCounts = {};
        const targetCounts = {};

        synPackets.forEach(packet => {
            const src = packet.layers.ip.srcIP;
            const dst = packet.layers.ip.dstIP;

            sourceCounts[src] = (sourceCounts[src] || 0) + 1;
            targetCounts[dst] = (targetCounts[dst] || 0) + 1;
        });

        // Detect SYN floods
        Object.entries(sourceCounts).forEach(([ip, count]) => {
            if (count > 100) {
                this.threats.push({
                    type: 'SYN_FLOOD',
                    severity: 'CRITICAL',
                    confidence: Math.min(100, (count / 50) * 100),
                    sourceIP: ip,
                    packetCount: count,
                    description: `SYN flood detected from ${ip} (${count} SYN packets)`,
                    timestamp: Date.now(),
                    affectedService: this._identifyAffectedService(packets, ip)
                });
            }
        });

        // Detect SYN-to-ACK ratio anomalies
        const ackPackets = packets.filter(p => 
            p.layers.tcp?.flags.ACK && !p.layers.tcp?.flags.SYN
        );

        const synAckRatio = synPackets.length / (ackPackets.length || 1);

        if (synAckRatio > 5) {
            this.anomalies.push({
                type: 'ABNORMAL_SYN_ACK_RATIO',
                severity: 'HIGH',
                ratio: synAckRatio.toFixed(2),
                description: `Abnormal SYN/ACK ratio: ${synAckRatio.toFixed(2)}:1`
            });
        }
    }

    /* ============================================
       PORT SCANNING DETECTION
       ============================================ */

    _detectPortScanning(packets) {
        const scanPatterns = {};

        packets.forEach(packet => {
            if (packet.layers.tcp?.flags.SYN && !packet.layers.tcp?.flags.ACK) {
                const src = packet.layers.ip.srcIP;
                const dst = packet.layers.ip.dstIP;
                const port = packet.layers.tcp.dstPort;

                const key = `${src}-${dst}`;
                if (!scanPatterns[key]) {
                    scanPatterns[key] = {
                        srcIP: src,
                        dstIP: dst,
                        ports: new Set(),
                        timestamps: []
                    };
                }

                scanPatterns[key].ports.add(port);
                scanPatterns[key].timestamps.push(packet.timestamp);
            }
        });

        Object.values(scanPatterns).forEach(pattern => {
            // Sequential port scan detection
            if (pattern.ports.size > 20) {
                const sortedPorts = Array.from(pattern.ports).sort((a, b) => a - b);
                const isSequential = this._isSequentialScan(sortedPorts);

                if (isSequential || pattern.ports.size > 50) {
                    this.threats.push({
                        type: 'PORT_SCANNING',
                        severity: 'HIGH',
                        confidence: Math.min(100, (pattern.ports.size / 20) * 100),
                        sourceIP: pattern.srcIP,
                        targetIP: pattern.dstIP,
                        portsScanned: pattern.ports.size,
                        scanType: isSequential ? 'SEQUENTIAL' : 'RANDOM',
                        description: `Port scan detected from ${pattern.srcIP} to ${pattern.dstIP} (${pattern.ports.size} ports)`,
                        timestamp: Date.now()
                    });
                }
            }
        });
    }

    /* ============================================
       DNS EXFILTRATION DETECTION
       ============================================ */

    _detectDNSExfiltration(packets) {
        const dnsSources = {};

        packets.forEach(packet => {
            if (packet.layers.dns?.isQuery) {
                const src = packet.layers.ip.srcIP;
                const domain = packet.layers.dns.queries?.[0]?.name || '';

                if (!dnsSources[src]) {
                    dnsSources[src] = {
                        sourceIP: src,
                        queryCount: 0,
                        domains: new Set(),
                        suspiciousDomains: []
                    };
                }

                dnsSources[src].queryCount++;
                dnsSources[src].domains.add(domain);

                // Detect suspicious domain patterns
                if (this._isDomainSuspicious(domain)) {
                    dnsSources[src].suspiciousDomains.push(domain);
                }
            }
        });

        Object.values(dnsSources).forEach(source => {
            // Excessive DNS queries
            if (source.queryCount > 500) {
                this.threats.push({
                    type: 'DNS_EXFILTRATION',
                    severity: 'HIGH',
                    confidence: 85,
                    sourceIP: source.sourceIP,
                    queryCount: source.queryCount,
                    uniqueDomains: source.domains.size,
                    description: `Excessive DNS queries from ${source.sourceIP} (${source.queryCount} queries)`,
                    timestamp: Date.now()
                });
            }

            // Suspicious domain queries
            if (source.suspiciousDomains.length > 10) {
                this.anomalies.push({
                    type: 'SUSPICIOUS_DNS_QUERIES',
                    severity: 'MEDIUM',
                    sourceIP: source.sourceIP,
                    domains: source.suspiciousDomains.slice(0, 10),
                    description: `Suspicious DNS queries detected from ${source.sourceIP}`
                });
            }
        });
    }

    /* ============================================
       DNS TUNNELING DETECTION
       ============================================ */

    _detectDNSTunneling(packets) {
        const dnsPackets = packets.filter(p => p.layers.dns);
        
        if (dnsPackets.length === 0) return;

        const dnsTraffic = {};

        dnsPackets.forEach(packet => {
            const src = packet.layers.ip.srcIP;
            const payloadSize = packet.size;

            if (!dnsTraffic[src]) {
                dnsTraffic[src] = {
                    sourceIP: src,
                    avgPacketSize: 0,
                    packetSizes: [],
                    totalSize: 0,
                    queryCount: 0
                };
            }

            dnsTraffic[src].packetSizes.push(payloadSize);
            dnsTraffic[src].totalSize += payloadSize;
            dnsTraffic[src].queryCount++;
        });

        Object.values(dnsTraffic).forEach(traffic => {
            traffic.avgPacketSize = traffic.totalSize / traffic.queryCount;

            // DNS packets are typically small, large packets indicate tunneling
            if (traffic.avgPacketSize > 512) {
                this.anomalies.push({
                    type: 'DNS_TUNNELING_SUSPECTED',
                    severity: 'MEDIUM',
                    sourceIP: traffic.sourceIP,
                    avgPacketSize: Math.round(traffic.avgPacketSize),
                    description: `DNS tunneling suspected - unusual packet sizes from ${traffic.sourceIP}`
                });
            }
        });
    }

    /* ============================================
       SSL/TLS ANOMALIES
       ============================================ */

    _detectSSLAnomalies(packets) {
        const sslPackets = packets.filter(p => 
            p.layers.ssl || p.protocol === 'TLS'
        );

        if (sslPackets.length === 0) return;

        const sslConversations = {};

        sslPackets.forEach(packet => {
            const src = `${packet.layers.ip.srcIP}:${packet.layers.tcp?.srcPort}`;
            const dst = `${packet.layers.ip.dstIP}:${packet.layers.tcp?.dstPort}`;
            const key = `${src}-${dst}`;

            if (!sslConversations[key]) {
                sslConversations[key] = {
                    src, dst,
                    packets: 0,
                    hasServerHello: false,
                    hasCertificate: false,
                    duration: 0
                };
            }

            sslConversations[key].packets++;
        });

        // Detect SSL/TLS handshake anomalies
        Object.values(sslConversations).forEach(conv => {
            if (conv.packets === 1) {
                // Incomplete handshake
                this.anomalies.push({
                    type: 'INCOMPLETE_SSL_HANDSHAKE',
                    severity: 'LOW',
                    description: `Incomplete SSL/TLS handshake: ${conv.src} → ${conv.dst}`
                });
            }
        });
    }

    /* ============================================
       HTTP ANOMALIES
       ============================================ */

    _detectHTTPAnomalies(packets) {
        const httpPackets = packets.filter(p => p.layers.http);

        if (httpPackets.length === 0) return;

        httpPackets.forEach(packet => {
            const httpLayer = packet.layers.http;

            // Detect SQLi patterns
            if (this._detectSQLInjection(httpLayer.request?.uri || '')) {
                this.threats.push({
                    type: 'SQL_INJECTION_ATTEMPT',
                    severity: 'CRITICAL',
                    sourceIP: packet.layers.ip.srcIP,
                    targetIP: packet.layers.ip.dstIP,
                    uri: httpLayer.request?.uri,
                    description: `Potential SQL injection detected`,
                    timestamp: Date.now()
                });
            }

            // Detect XSS patterns
            if (this._detectXSS(httpLayer.request?.uri || '')) {
                this.threats.push({
                    type: 'XSS_ATTEMPT',
                    severity: 'HIGH',
                    sourceIP: packet.layers.ip.srcIP,
                    targetIP: packet.layers.ip.dstIP,
                    uri: httpLayer.request?.uri,
                    description: `Potential XSS attack detected`,
                    timestamp: Date.now()
                });
            }

            // Detect malicious user agents
            if (this._isMaliciousUserAgent(httpLayer.request?.userAgent || '')) {
                this.anomalies.push({
                    type: 'SUSPICIOUS_USER_AGENT',
                    severity: 'MEDIUM',
                    userAgent: httpLayer.request?.userAgent,
                    description: `Suspicious HTTP user agent detected`
                });
            }
        });
    }

    /* ============================================
       FRAGMENTATION ATTACK DETECTION
       ============================================ */

    _detectFragmentationAttacks(packets) {
        const fragmentedPackets = packets.filter(p => 
            p.layers.ip?.moreFragments || p.layers.ip?.fragmentOffset > 0
        );

        if (fragmentedPackets.length > 100) {
            const sources = new Map();

            fragmentedPackets.forEach(packet => {
                const src = packet.layers.ip.srcIP;
                sources.set(src, (sources.get(src) || 0) + 1);
            });

            sources.forEach((count, src) => {
                if (count > 50) {
                    this.threats.push({
                        type: 'FRAGMENTATION_ATTACK',
                        severity: 'MEDIUM',
                        sourceIP: src,
                        fragmentCount: count,
                        description: `Excessive IP fragmentation from ${src}`,
                        timestamp: Date.now()
                    });
                }
            });
        }
    }

    /* ============================================
       RECONNAISSANCE ACTIVITY
       ============================================ */

    _detectReconnaissanceActivity(packets) {
        // ICMP echo requests (ping scan)
        const icmpEchoPackets = packets.filter(p => p.protocol === 'ICMP');
        
        if (icmpEchoPackets.length > 100) {
            const sources = new Map();

            icmpEchoPackets.forEach(packet => {
                const src = packet.layers.ip.srcIP;
                sources.set(src, (sources.get(src) || 0) + 1);
            });

            sources.forEach((count, src) => {
                if (count > 50) {
                    this.anomalies.push({
                        type: 'PING_SWEEP',
                        severity: 'MEDIUM',
                        sourceIP: src,
                        echoCount: count,
                        description: `Ping sweep detected from ${src}`
                    });
                }
            });
        }
    }

    /* ============================================
       MALWARE SIGNATURE DETECTION
       ============================================ */

    _detectMalwareSignatures(packets) {
        packets.forEach(packet => {
            const payload = packet.payload || '';

            Object.entries(this.knownAttackSignatures).forEach(([signature, details]) => {
                if (payload.includes(signature)) {
                    this.threats.push({
                        type: 'MALWARE_SIGNATURE_DETECTED',
                        severity: 'CRITICAL',
                        sourceIP: packet.layers.ip.srcIP,
                        signature: details.name,
                        description: `Malware signature detected: ${details.name}`,
                        timestamp: Date.now()
                    });
                }
            });
        });
    }

    /* ============================================
       BRUTE FORCE ATTACK DETECTION
       ============================================ */

    _detectBruteForceAttacks(packets) {
        const failedConnections = {};

        packets.forEach(packet => {
            if (packet.layers.tcp?.flags.RST) {
                const src = packet.layers.ip.srcIP;
                const port = packet.layers.tcp.dstPort;
                const key = `${src}:${port}`;

                failedConnections[key] = (failedConnections[key] || 0) + 1;
            }
        });

        Object.entries(failedConnections).forEach(([key, count]) => {
            if (count > 50) {
                const [src, port] = key.split(':');
                this.threats.push({
                    type: 'BRUTE_FORCE_ATTEMPT',
                    severity: 'HIGH',
                    sourceIP: src,
                    targetPort: parseInt(port),
                    attemptCount: count,
                    description: `Brute force attempt on port ${port} from ${src}`,
                    timestamp: Date.now()
                });
            }
        });
    }

    /* ============================================
       DATA EXFILTRATION DETECTION
       ============================================ */

    _detectDataExfiltration(packets) {
        const uploadTraffic = {};

        packets.forEach(packet => {
            if (packet.layers.ip) {
                const src = packet.layers.ip.srcIP;

                if (!uploadTraffic[src]) {
                    uploadTraffic[src] = { sourceIP: src, totalBytes: 0 };
                }

                uploadTraffic[src].totalBytes += packet.size;
            }
        });

        Object.values(uploadTraffic).forEach(traffic => {
            // More than 500MB from a single IP
            if (traffic.totalBytes > 500000000) {
                this.anomalies.push({
                    type: 'LARGE_DATA_TRANSFER',
                    severity: 'MEDIUM',
                    sourceIP: traffic.sourceIP,
                    totalMB: (traffic.totalBytes / 1000000).toFixed(2),
                    description: `Large data transfer from ${traffic.sourceIP}`
                });
            }
        });
    }

    /* ============================================
       RANSOMWARE PATTERN DETECTION
       ============================================ */

    _detectRansomwarePatterns(packets) {
        // Detect SMB activity (common ransomware vector)
        const smbPackets = packets.filter(p => p.layers.tcp?.dstPort === 445);

        if (smbPackets.length > 1000) {
            const sources = new Map();

            smbPackets.forEach(packet => {
                const src = packet.layers.ip.srcIP;
                sources.set(src, (sources.get(src) || 0) + 1);
            });

            sources.forEach((count, src) => {
                if (count > 500) {
                    this.threats.push({
                        type: 'RANSOMWARE_INDICATOR',
                        severity: 'CRITICAL',
                        sourceIP: src,
                        smbTraffic: count,
                        description: `Potential ransomware activity - excessive SMB traffic from ${src}`,
                        timestamp: Date.now()
                    });
                }
            });
        }
    }

    /* ============================================
       IP SPOOFING DETECTION
       ============================================ */

    _detectIPSpoofing(packets) {
        const ttlPatterns = {};

        packets.forEach(packet => {
            const src = packet.layers.ip.srcIP;
            const ttl = packet.layers.ip.TTL;

            if (!ttlPatterns[src]) {
                ttlPatterns[src] = { sourceIP: src, ttls: [] };
            }

            ttlPatterns[src].ttls.push(ttl);
        });

        Object.values(ttlPatterns).forEach(pattern => {
            const uniqueTTLs = new Set(pattern.ttls);

            // Multiple different TTLs from same IP indicates spoofing
            if (uniqueTTLs.size > 5) {
                this.anomalies.push({
                    type: 'IP_SPOOFING_SUSPECTED',
                    severity: 'MEDIUM',
                    sourceIP: pattern.sourceIP,
                    uniqueTTLs: uniqueTTLs.size,
                    description: `Potential IP spoofing: multiple TTLs from ${pattern.sourceIP}`
                });
            }
        });
    }

    /* ============================================
       DDOS PATTERN DETECTION
       ============================================ */

    _detectDDoSPatterns(packets) {
        const targetTraffic = {};

        packets.forEach(packet => {
            if (packet.layers.ip) {
                const dst = packet.layers.ip.dstIP;

                if (!targetTraffic[dst]) {
                    targetTraffic[dst] = { targetIP: dst, count: 0, sources: new Set() };
                }

                targetTraffic[dst].count++;
                targetTraffic[dst].sources.add(packet.layers.ip.srcIP);
            }
        });

        Object.values(targetTraffic).forEach(traffic => {
            // Many sources targeting single destination
            if (traffic.sources.size > 50 && traffic.count > 10000) {
                this.threats.push({
                    type: 'DDOS_ATTACK',
                    severity: 'CRITICAL',
                    targetIP: traffic.targetIP,
                    sourceCount: traffic.sources.size,
                    packetCount: traffic.count,
                    description: `DDoS attack detected against ${traffic.targetIP}`,
                    timestamp: Date.now()
                });
            }
        });
    }

    /* ============================================
       UNUSUAL BEHAVIOR DETECTION
       ============================================ */

    _detectUnusualBehavior(packets) {
        // Traffic during unusual hours
        const hours = new Map();

        packets.forEach(packet => {
            const hour = new Date(packet.timestampDate).getHours();
            hours.set(hour, (hours.get(hour) || 0) + 1);
        });

        // Check for after-hours activity
        const afterHours = [2, 3, 4, 5]; // 2-6 AM
        afterHours.forEach(hour => {
            if (hours.get(hour) > 1000) {
                this.anomalies.push({
                    type: 'UNUSUAL_TRAFFIC_TIMING',
                    severity: 'LOW',
                    hour: hour,
                    packetCount: hours.get(hour),
                    description: `Unusual traffic volume at ${hour}:00 hours`
                });
            }
        });
    }

    /* ============================================
       HELPER FUNCTIONS
       ============================================ */

    _isDomainSuspicious(domain) {
        const suspiciousPatterns = [
            /\.\w{2,}\.tk$/, // Free TLDs
            /\.\w{2,}\.ml$/,
            /xn--/,          // Punycode
            /^[0-9]{1,3}\.[0-9]{1,3}/, // Numeric domain
            /-{2,}/          // Double dash
        ];

        return suspiciousPatterns.some(pattern => pattern.test(domain));
    }

    _isSequentialScan(ports) {
        if (ports.length < 5) return false;

        let sequential = 0;
        for (let i = 1; i < ports.length; i++) {
            if (ports[i] === ports[i - 1] + 1) {
                sequential++;
            }
        }

        return sequential >= ports.length * 0.7;
    }

    _detectSQLInjection(uri) {
        const sqlPatterns = [
            /union.*select/i,
            /select.*from/i,
            /insert.*into/i,
            /delete.*from/i,
            /drop.*table/i,
            /';.*--/,
            /or.*1.*=.*1/i,
            /\\x27/
        ];

        return sqlPatterns.some(pattern => pattern.test(uri));
    }

    _detectXSS(uri) {
        const xssPatterns = [
            /<script[^>]*>/i,
            /javascript:/i,
            /on\w+\s*=/i,
            /<iframe/i,
            /<img[^>]*onerror/i
        ];

        return xssPatterns.some(pattern => pattern.test(uri));
    }

    _isMaliciousUserAgent(userAgent) {
        const maliciousAgents = [
            /sqlmap/i,
            /nikto/i,
            /nmap/i,
            /nessus/i,
            /acunetix/i,
            /masscan/i
        ];

        return maliciousAgents.some(pattern => pattern.test(userAgent));
    }

    _identifyAffectedService(packets, sourceIP) {
        const services = {};

        packets.filter(p => p.layers.ip?.srcIP === sourceIP && p.layers.tcp)
            .forEach(packet => {
                const port = packet.layers.tcp.dstPort;
                services[port] = (services[port] || 0) + 1;
            });

        return Object.keys(services).sort((a, b) => services[b] - services[a]).slice(0, 5);
    }

    _calculateRiskLevel() {
        let riskScore = 0;

        this.threats.forEach(threat => {
            switch (threat.severity) {
                case 'CRITICAL': riskScore += 100; break;
                case 'HIGH': riskScore += 50; break;
                case 'MEDIUM': riskScore += 25; break;
                case 'LOW': riskScore += 10; break;
            }
        });

        if (riskScore >= 300) return 'CRITICAL';
        if (riskScore >= 150) return 'HIGH';
        if (riskScore >= 50) return 'MEDIUM';
        if (riskScore >= 10) return 'LOW';
        return 'NONE';
    }

    _generateThreatSummary() {
        const summary = {
            totalThreats: this.threats.length,
            totalAnomalies: this.anomalies.length,
            bySeverity: {
                critical: this.threats.filter(t => t.severity === 'CRITICAL').length,
                high: this.threats.filter(t => t.severity === 'HIGH').length,
                medium: this.threats.filter(t => t.severity === 'MEDIUM').length,
                low: this.threats.filter(t => t.severity === 'LOW').length
            },
            threatTypes: {}
        };

        this.threats.forEach(threat => {
            summary.threatTypes[threat.type] = (summary.threatTypes[threat.type] || 0) + 1;
        });

        return summary;
    }

    _loadAttackSignatures() {
        return {
            'cmd.exe': { name: 'Windows Command Execution' },
            '/bin/bash': { name: 'Linux Shell Execution' },
            'powershell': { name: 'PowerShell Execution' },
            'wget http': { name: 'Download Attempt' },
            'curl http': { name: 'Download Attempt' }
        };
    }

    addToWhitelist(ip) {
        this.whitelistIPs.add(ip);
    }

    addToBlacklist(ip) {
        this.blacklistIPs.add(ip);
    }

    isWhitelisted(ip) {
        return this.whitelistIPs.has(ip);
    }

    isBlacklisted(ip) {
        return this.blacklistIPs.has(ip);
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecurityDetector;
}