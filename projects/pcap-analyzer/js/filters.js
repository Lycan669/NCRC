/* ============================================
   NCRC PACKET FILTER ENGINE
   Advanced Filtering & Search System
   ============================================ */

class FilterEngine {
    constructor() {
        this.packets = [];
        this.filters = [];
        this.results = [];
        this.filterHistory = [];
        this.savedFilters = this._loadSavedFilters();
    }

    /* ============================================
       FILTER APPLICATION
       ============================================ */

    applyFilter(filterConfig) {
        if (!this.packets || this.packets.length === 0) {
            return { results: [], count: 0 };
        }

        this.filters.push(filterConfig);
        this.results = this._executeFilters(this.packets, this.filters);
        
        this.filterHistory.push({
            timestamp: Date.now(),
            filter: filterConfig,
            resultCount: this.results.length
        });

        return {
            results: this.results,
            count: this.results.length,
            percentage: ((this.results.length / this.packets.length) * 100).toFixed(2)
        };
    }

    /* ============================================
       EXECUTE FILTER CHAIN
       ============================================ */

    _executeFilters(packets, filters) {
        let filtered = packets;

        filters.forEach(filter => {
            filtered = filtered.filter(packet => {
                return this._matchFilter(packet, filter);
            });
        });

        return filtered;
    }

    /* ============================================
       FILTER MATCHING LOGIC
       ============================================ */

    _matchFilter(packet, filter) {
        switch (filter.type) {
            case 'ip':
                return this._filterByIP(packet, filter);
            case 'port':
                return this._filterByPort(packet, filter);
            case 'protocol':
                return this._filterByProtocol(packet, filter);
            case 'service':
                return this._filterByService(packet, filter);
            case 'size':
                return this._filterBySize(packet, filter);
            case 'time':
                return this._filterByTime(packet, filter);
            case 'flags':
                return this._filterByFlags(packet, filter);
            case 'content':
                return this._filterByContent(packet, filter);
            case 'conversation':
                return this._filterByConversation(packet, filter);
            case 'regex':
                return this._filterByRegex(packet, filter);
            default:
                return true;
        }
    }

    /* ============================================
       IP ADDRESS FILTERS
       ============================================ */

    _filterByIP(packet, filter) {
        if (!packet.layers.ip) return false;

        const srcIP = packet.layers.ip.srcIP;
        const dstIP = packet.layers.ip.dstIP;

        switch (filter.operator) {
            case 'equals':
                return srcIP === filter.value || dstIP === filter.value;
            case 'contains':
                return srcIP.includes(filter.value) || dstIP.includes(filter.value);
            case 'src_equals':
                return srcIP === filter.value;
            case 'dst_equals':
                return dstIP === filter.value;
            case 'src_contains':
                return srcIP.includes(filter.value);
            case 'dst_contains':
                return dstIP.includes(filter.value);
            case 'in_range':
                return this._isIPInRange(srcIP, filter.value) || 
                       this._isIPInRange(dstIP, filter.value);
            case 'not_equals':
                return srcIP !== filter.value && dstIP !== filter.value;
            default:
                return true;
        }
    }

    /* ============================================
       PORT FILTERS
       ============================================ */

    _filterByPort(packet, filter) {
        const ports = [];

        if (packet.layers.tcp) {
            ports.push(packet.layers.tcp.srcPort);
            ports.push(packet.layers.tcp.dstPort);
        }

        if (packet.layers.udp) {
            ports.push(packet.layers.udp.srcPort);
            ports.push(packet.layers.udp.dstPort);
        }

        if (ports.length === 0) return false;

        switch (filter.operator) {
            case 'equals':
                return ports.includes(parseInt(filter.value));
            case 'greater':
                return ports.some(p => p > parseInt(filter.value));
            case 'less':
                return ports.some(p => p < parseInt(filter.value));
            case 'between':
                const [min, max] = filter.value.split('-').map(Number);
                return ports.some(p => p >= min && p <= max);
            case 'in_list':
                const portList = filter.value.split(',').map(p => parseInt(p.trim()));
                return ports.some(p => portList.includes(p));
            case 'not_equals':
                return !ports.includes(parseInt(filter.value));
            default:
                return true;
        }
    }

    /* ============================================
       PROTOCOL FILTERS
       ============================================ */

    _filterByProtocol(packet, filter) {
        switch (filter.operator) {
            case 'equals':
                return packet.protocol === filter.value;
            case 'contains':
                return packet.protocol.includes(filter.value);
            case 'in_list':
                const protocols = filter.value.split(',').map(p => p.trim());
                return protocols.includes(packet.protocol);
            case 'not_equals':
                return packet.protocol !== filter.value;
            default:
                return true;
        }
    }

    /* ============================================
       SERVICE FILTERS
       ============================================ */

    _filterByService(packet, filter) {
        let service = '';

        if (packet.layers.tcp) {
            service = this._getServiceName(packet.layers.tcp.dstPort);
        } else if (packet.layers.udp) {
            service = this._getServiceName(packet.layers.udp.dstPort);
        }

        switch (filter.operator) {
            case 'equals':
                return service === filter.value;
            case 'contains':
                return service.includes(filter.value);
            case 'in_list':
                const services = filter.value.split(',').map(s => s.trim());
                return services.includes(service);
            default:
                return true;
        }
    }

    /* ============================================
       PACKET SIZE FILTERS
       ============================================ */

    _filterBySize(packet, filter) {
        const size = packet.size;

        switch (filter.operator) {
            case 'equals':
                return size === parseInt(filter.value);
            case 'greater':
                return size > parseInt(filter.value);
            case 'less':
                return size < parseInt(filter.value);
            case 'between':
                const [min, max] = filter.value.split('-').map(Number);
                return size >= min && size <= max;
            case 'not_equals':
                return size !== parseInt(filter.value);
            default:
                return true;
        }
    }

    /* ============================================
       TIME FILTERS
       ============================================ */

    _filterByTime(packet, filter) {
        const packetTime = new Date(packet.timestampDate).getTime();
        const filterTime = new Date(filter.value).getTime();

        switch (filter.operator) {
            case 'after':
                return packetTime > filterTime;
            case 'before':
                return packetTime < filterTime;
            case 'between':
                const [startStr, endStr] = filter.value.split(' to ');
                const startTime = new Date(startStr).getTime();
                const endTime = new Date(endStr).getTime();
                return packetTime >= startTime && packetTime <= endTime;
            case 'equals':
                // Match same second
                const packetDate = new Date(packet.timestampDate);
                const filterDate = new Date(filter.value);
                return packetDate.getFullYear() === filterDate.getFullYear() &&
                       packetDate.getMonth() === filterDate.getMonth() &&
                       packetDate.getDate() === filterDate.getDate();
            default:
                return true;
        }
    }

    /* ============================================
       TCP FLAG FILTERS
       ============================================ */

    _filterByFlags(packet, filter) {
        if (!packet.layers.tcp) return false;

        const flags = packet.layers.tcp.flags;

        switch (filter.value) {
            case 'SYN':
                return flags.SYN && !flags.ACK;
            case 'SYN-ACK':
                return flags.SYN && flags.ACK;
            case 'ACK':
                return flags.ACK;
            case 'FIN':
                return flags.FIN;
            case 'RST':
                return flags.RST;
            case 'PSH':
                return flags.PSH;
            case 'URG':
                return flags.URG;
            case 'ALL_FLAGS':
                return Object.values(flags).some(f => f === true);
            case 'NO_FLAGS':
                return !Object.values(flags).some(f => f === true);
            default:
                return true;
        }
    }

    /* ============================================
       CONTENT FILTERS
       ============================================ */

    _filterByContent(packet, filter) {
        const payload = packet.payload || '';
        const searchTerm = filter.value.toLowerCase();

        switch (filter.operator) {
            case 'contains':
                return payload.toLowerCase().includes(searchTerm);
            case 'not_contains':
                return !payload.toLowerCase().includes(searchTerm);
            case 'starts_with':
                return payload.toLowerCase().startsWith(searchTerm);
            case 'ends_with':
                return payload.toLowerCase().endsWith(searchTerm);
            case 'hex_contains':
                try {
                    const hexRegex = new RegExp(filter.value, 'i');
                    return hexRegex.test(payload);
                } catch (e) {
                    return false;
                }
            default:
                return true;
        }
    }

    /* ============================================
       CONVERSATION FILTERS
       ============================================ */

    _filterByConversation(packet, filter) {
        if (!packet.layers.ip) return false;

        const src = packet.layers.ip.srcIP;
        const dst = packet.layers.ip.dstIP;
        const filterValue = filter.value.trim();

        // Parse filter: "IP1:Port1 <-> IP2:Port2"
        const conversationPattern = /^([^:]+):(\d+)\s*<->\s*([^:]+):(\d+)$/;
        const match = filterValue.match(conversationPattern);

        if (!match) {
            // Try simple IP:IP format
            const [ip1, ip2] = filterValue.split('<->').map(s => s.trim());
            return (src === ip1 && dst === ip2) || (src === ip2 && dst === ip1);
        }

        const [, filterSrc, filterSrcPort, filterDst, filterDstPort] = match;

        if (packet.layers.tcp) {
            return (src === filterSrc && dst === filterDst &&
                    packet.layers.tcp.srcPort === parseInt(filterSrcPort) &&
                    packet.layers.tcp.dstPort === parseInt(filterDstPort)) ||
                   (src === filterDst && dst === filterSrc &&
                    packet.layers.tcp.srcPort === parseInt(filterDstPort) &&
                    packet.layers.tcp.dstPort === parseInt(filterSrcPort));
        }

        if (packet.layers.udp) {
            return (src === filterSrc && dst === filterDst &&
                    packet.layers.udp.srcPort === parseInt(filterSrcPort) &&
                    packet.layers.udp.dstPort === parseInt(filterDstPort)) ||
                   (src === filterDst && dst === filterSrc &&
                    packet.layers.udp.srcPort === parseInt(filterDstPort) &&
                    packet.layers.udp.dstPort === parseInt(filterSrcPort));
        }

        return false;
    }

    /* ============================================
       REGEX FILTERS
       ============================================ */

    _filterByRegex(packet, filter) {
        try {
            const regex = new RegExp(filter.value, filter.flags || 'i');
            
            // Search in multiple fields
            const searchableData = [
                packet.layers.ip?.srcIP,
                packet.layers.ip?.dstIP,
                packet.protocol,
                packet.payload,
                JSON.stringify(packet)
            ].filter(Boolean).join(' ');

            return regex.test(searchableData);
        } catch (e) {
            console.error('Invalid regex filter:', e);
            return false;
        }
    }

    /* ============================================
       CLEAR FILTERS
       ============================================ */

    clearFilters() {
        this.filters = [];
        this.results = this.packets;
        return {
            results: this.results,
            count: this.results.length
        };
    }

    clearLastFilter() {
        if (this.filters.length > 0) {
            this.filters.pop();
            this.results = this._executeFilters(this.packets, this.filters);
            return {
                results: this.results,
                count: this.results.length
            };
        }
        return { results: [], count: 0 };
    }

    /* ============================================
       SAVE & LOAD FILTERS
       ============================================ */

    saveFilter(name, filterConfig) {
        const saved = this._loadSavedFilters();
        saved[name] = filterConfig;
        localStorage.setItem('ncrc_saved_filters', JSON.stringify(saved));
        this.savedFilters = saved;
        return true;
    }

    loadSavedFilter(name) {
        const filter = this.savedFilters[name];
        if (filter) {
            return this.applyFilter(filter);
        }
        return null;
    }

    deleteSavedFilter(name) {
        const saved = this._loadSavedFilters();
        delete saved[name];
        localStorage.setItem('ncrc_saved_filters', JSON.stringify(saved));
        this.savedFilters = saved;
        return true;
    }

    getSavedFilters() {
        return this.savedFilters;
    }

    _loadSavedFilters() {
        const saved = localStorage.getItem('ncrc_saved_filters');
        return saved ? JSON.parse(saved) : {};
    }

    /* ============================================
       ADVANCED FILTERS
       ============================================ */

    // Find suspicious patterns
    findSuspiciousPatterns() {
        return this.packets.filter(packet => {
            // SYN Flood detection
            if (packet.layers.tcp?.flags.SYN && !packet.layers.tcp.flags.ACK) {
                const srcIP = packet.layers.ip.srcIP;
                const synCount = this.packets.filter(p => 
                    p.layers.tcp?.srcIP === srcIP && p.layers.tcp?.flags.SYN
                ).length;
                if (synCount > 100) return true;
            }

            // Unusual packet sizes
            if (packet.size > 65000) return true;

            // Fragmented packets
            if (packet.layers.ip?.moreFragments) return true;

            return false;
        });
    }

    // Find port scanning activity
    findPortScanning() {
        const portCounts = {};

        this.packets.forEach(packet => {
            if (packet.layers.tcp?.flags.SYN) {
                const srcIP = packet.layers.ip.srcIP;
                const port = packet.layers.tcp.dstPort;
                const key = `${srcIP}-${port}`;

                if (!portCounts[key]) {
                    portCounts[key] = { srcIP, port, count: 0 };
                }
                portCounts[key].count++;
            }
        });

        return Object.values(portCounts)
            .filter(item => item.count > 10)
            .sort((a, b) => b.count - a.count);
    }

    // Find unusual DNS activity
    findDNSAnomalies() {
        return this.packets.filter(packet => {
            if (packet.layers.dns) {
                // DNS requests with unusual frequency from same source
                const srcIP = packet.layers.ip.srcIP;
                const dnsFromSrc = this.packets.filter(p =>
                    p.layers.dns && p.layers.ip.srcIP === srcIP
                ).length;

                if (dnsFromSrc > 100) return true;

                // Suspicious domain names
                const domain = packet.layers.dns.queries?.[0]?.name || '';
                if (domain.length > 63) return true; // Domain label too long
                if (/[^a-zA-Z0-9\-\.]/.test(domain)) return true; // Invalid chars
            }
            return false;
        });
    }

    // Find data exfiltration attempts
    findDataExfiltration() {
        const largeTransfers = {};

        this.packets.forEach(packet => {
            if (packet.layers.ip) {
                const srcIP = packet.layers.ip.srcIP;
                if (!largeTransfers[srcIP]) {
                    largeTransfers[srcIP] = { ip: srcIP, totalBytes: 0, packets: 0 };
                }
                largeTransfers[srcIP].totalBytes += packet.size;
                largeTransfers[srcIP].packets++;
            }
        });

        return Object.values(largeTransfers)
            .filter(transfer => transfer.totalBytes > 100000000) // > 100MB
            .sort((a, b) => b.totalBytes - a.totalBytes);
    }

    /* ============================================
       HELPER FUNCTIONS
       ============================================ */

    _isIPInRange(ip, range) {
        // CIDR notation: 192.168.1.0/24
        if (range.includes('/')) {
            const [baseIP, maskBits] = range.split('/');
            return this._isIPInCIDR(ip, baseIP, parseInt(maskBits));
        }
        return ip === range;
    }

    _isIPInCIDR(ip, baseIP, maskBits) {
        const ipParts = ip.split('.').map(Number);
        const baseParts = baseIP.split('.').map(Number);

        const maskBytes = Math.floor(maskBits / 8);
        const maskBitsRemainder = maskBits % 8;

        for (let i = 0; i < maskBytes; i++) {
            if (ipParts[i] !== baseParts[i]) return false;
        }

        if (maskBitsRemainder > 0) {
            const maskValue = (0xFF << (8 - maskBitsRemainder)) & 0xFF;
            return (ipParts[maskBytes] & maskValue) === (baseParts[maskBytes] & maskValue);
        }

        return true;
    }

    _getServiceName(port) {
        const services = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'TELNET', 25: 'SMTP',
            53: 'DNS', 67: 'DHCP', 68: 'DHCP', 80: 'HTTP', 110: 'POP3',
            143: 'IMAP', 161: 'SNMP', 389: 'LDAP', 443: 'HTTPS',
            445: 'SMB', 465: 'SMTPS', 587: 'SMTP', 636: 'LDAPS',
            993: 'IMAPS', 995: 'POP3S', 1433: 'MSSQL', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-ALT'
        };
        return services[port] || `Port${port}`;
    }

    exportFilters() {
        return JSON.stringify(this.savedFilters, null, 2);
    }

    importFilters(jsonStr) {
        try {
            const filters = JSON.parse(jsonStr);
            this.savedFilters = { ...this.savedFilters, ...filters };
            localStorage.setItem('ncrc_saved_filters', JSON.stringify(this.savedFilters));
            return true;
        } catch (e) {
            console.error('Invalid JSON:', e);
            return false;
        }
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = FilterEngine;
}