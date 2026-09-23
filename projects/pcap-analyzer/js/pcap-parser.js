/* ============================================
   NCRC PCAP PARSER
   Real Binary PCAP File Format Parser
   Supports: PCAP (libpcap) & PCAPNG formats
   ============================================ */

class PCAPParser {
    constructor() {
        this.packets = [];
        this.fileInfo = {
            filename: '',
            filesize: 0,
            totalPackets: 0,
            captureTime: '',
            datalink: '',
            snaplen: 0,
            timezone: ''
        };
        this.globals = {
            byteOrder: 'little-endian',
            versionMajor: 0,
            versionMinor: 0,
            timezone: 0,
            maxPackets: 10000
        };
        this.stats = {
            totalBytes: 0,
            minPacketSize: Infinity,
            maxPacketSize: 0,
            avgPacketSize: 0
        };
    }

    /* ============================================
       MAIN PARSING FUNCTION
       ============================================ */

    async parseFile(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();

            reader.onload = async (e) => {
                try {
                    const arrayBuffer = e.target.result;
                    const view = new DataView(arrayBuffer);

                    // Check file magic number
                    const magic = view.getUint32(0, true);

                    if (magic === 0xa1b2c3d4 || magic === 0xd4c3b2a1) {
                        // Standard PCAP format
                        this._parsePCAP(view);
                    } else if (magic === 0x0a0d0d0a) {
                        // PCAPNG format
                        this._parsePCAPNG(view);
                    } else {
                        reject(new Error('Invalid PCAP file format'));
                        return;
                    }

                    this.fileInfo.filename = file.name;
                    this.fileInfo.filesize = file.size;
                    this.fileInfo.totalPackets = this.packets.length;
                    this.fileInfo.captureTime = new Date().toISOString();

                    resolve({
                        success: true,
                        packets: this.packets,
                        fileInfo: this.fileInfo,
                        stats: this.stats,
                        globals: this.globals
                    });
                } catch (error) {
                    reject(error);
                }
            };

            reader.onerror = () => {
                reject(new Error('Failed to read file'));
            };

            reader.readAsArrayBuffer(file);
        });
    }

    /* ============================================
       PARSE STANDARD PCAP FORMAT
       ============================================ */

    _parsePCAP(view) {
        let offset = 0;

        // Parse Global Header (24 bytes)
        const globalHeader = this._readPCAPGlobalHeader(view, offset);
        offset += 24;

        this.globals = {
            byteOrder: globalHeader.byteOrder,
            versionMajor: globalHeader.versionMajor,
            versionMinor: globalHeader.versionMinor,
            timezone: globalHeader.timezone,
            maxPackets: globalHeader.maxPackets
        };

        this.fileInfo.datalink = this._getDatalinkType(globalHeader.network);
        this.fileInfo.snaplen = globalHeader.snaplen;

        // Parse packets
        let packetNumber = 0;
        while (offset < view.byteLength && packetNumber < this.globals.maxPackets) {
            try {
                const packetResult = this._readPCAPPacket(view, offset, globalHeader.byteOrder);
                if (!packetResult) break;

                this.packets.push(packetResult.packet);
                offset = packetResult.nextOffset;
                packetNumber++;
            } catch (e) {
                console.warn(`Error parsing packet ${packetNumber}:`, e);
                break;
            }
        }

        // Calculate statistics
        this._calculateStats();
    }

    /* ============================================
       PARSE GLOBAL HEADER (PCAP)
       ============================================ */

    _readPCAPGlobalHeader(view, offset) {
        const magic = view.getUint32(offset, true);
        const littleEndian = magic === 0xa1b2c3d4;

        return {
            magic: magic,
            byteOrder: littleEndian ? 'little-endian' : 'big-endian',
            versionMajor: view.getUint16(offset + 4, littleEndian),
            versionMinor: view.getUint16(offset + 6, littleEndian),
            timezone: view.getInt32(offset + 8, littleEndian),
            timestamp: view.getUint32(offset + 12, littleEndian),
            maxPackets: view.getUint32(offset + 16, littleEndian) || 10000,
            network: view.getUint32(offset + 20, littleEndian),
            snaplen: view.getUint32(offset + 16, littleEndian)
        };
    }

    /* ============================================
       PARSE PCAP PACKET HEADER & DATA
       ============================================ */

    _readPCAPPacket(view, offset, byteOrder) {
        const littleEndian = byteOrder === 'little-endian';

        // Packet header (16 bytes)
        if (offset + 16 > view.byteLength) return null;

        const tsSecLow = view.getUint32(offset + 0, littleEndian);
        const tsMicrosecHigh = view.getUint32(offset + 4, littleEndian);
        const inclLen = view.getUint32(offset + 8, littleEndian);
        const origLen = view.getUint32(offset + 12, littleEndian);

        // Calculate timestamp
        const timestamp = (tsSecLow * 1000) + (tsMicrosecHigh / 1000);
        const timestampDate = new Date(timestamp);

        // Read packet data
        const dataOffset = offset + 16;
        if (dataOffset + inclLen > view.byteLength) {
            console.warn(`Truncated packet at offset ${offset}`);
            return null;
        }

        const packetData = new Uint8Array(view.buffer, dataOffset, inclLen);

        const packet = {
            timestamp: timestamp,
            timestampDate: timestampDate,
            number: this.packets.length + 1,
            size: inclLen,
            originalSize: origLen,
            data: packetData,
            hex: this._bytesToHex(packetData),
            ascii: this._bytesToAscii(packetData),
            layers: {}
        };

        // Update statistics
        this.stats.totalBytes += inclLen;
        this.stats.minPacketSize = Math.min(this.stats.minPacketSize, inclLen);
        this.stats.maxPacketSize = Math.max(this.stats.maxPacketSize, inclLen);

        // Dissect layers
        this._dissectLayers(packet, packetData);

        return {
            packet: packet,
            nextOffset: dataOffset + inclLen
        };
    }

    /* ============================================
       PARSE PCAPNG FORMAT
       ============================================ */

    _parsePCAPNG(view) {
        let offset = 0;

        while (offset < view.byteLength && this.packets.length < this.globals.maxPackets) {
            const blockType = view.getUint32(offset, true);
            const blockLength = view.getUint32(offset + 4, true);

            if (blockLength === 0) break;

            switch (blockType) {
                case 0x0a0d0d0a: // Section Header Block
                    offset += blockLength;
                    break;
                case 0x00000001: // Interface Description Block
                    offset += blockLength;
                    break;
                case 0x00000002: // Packet Block (old format)
                    break;
                case 0x00000006: // Enhanced Packet Block
                    this._readPCAPNGEnhancedPacket(view, offset);
                    offset += blockLength;
                    break;
                default:
                    offset += blockLength;
            }
        }

        this._calculateStats();
    }

    /* ============================================
       LAYER DISSECTION (L2, L3, L4, L7)
       ============================================ */

    _dissectLayers(packet, data) {
        try {
            // Layer 2: Ethernet
            if (data.length >= 14) {
                packet.layers.ethernet = this._dissectEthernet(data);

                // Layer 3: IP
                if (packet.layers.ethernet.protocol === 0x0800 || packet.layers.ethernet.protocol === 0x86dd) {
                    packet.layers.ip = this._dissectIP(
                        data,
                        packet.layers.ethernet.headerLength
                    );

                    // Layer 4: Transport
                    if (packet.layers.ip) {
                        const protocol = packet.layers.ip.version === 4 ? 
                            packet.layers.ip.protocol : 
                            packet.layers.ip.nextHeader;

                        const l4Offset = packet.layers.ethernet.headerLength + packet.layers.ip.headerLength;

                        if (protocol === 6) { // TCP
                            packet.layers.tcp = this._dissectTCP(data, l4Offset);
                            if (packet.layers.tcp) {
                                packet.protocol = 'TCP';
                                // Layer 7: Application
                                this._dissectApplicationLayer(packet, data, l4Offset + packet.layers.tcp.headerLength);
                            }
                        } else if (protocol === 17) { // UDP
                            packet.layers.udp = this._dissectUDP(data, l4Offset);
                            if (packet.layers.udp) {
                                packet.protocol = 'UDP';
                                this._dissectApplicationLayer(packet, data, l4Offset + 8);
                            }
                        } else if (protocol === 1) { // ICMP
                            packet.layers.icmp = this._dissectICMP(data, l4Offset);
                            packet.protocol = 'ICMP';
                        }
                    }
                }
            }
        } catch (e) {
            console.warn('Error dissecting layers:', e);
        }
    }

    /* ============================================
       ETHERNET DISSECTION (L2)
       ============================================ */

    _dissectEthernet(data) {
        if (data.length < 14) return null;

        const destMac = this._getMacAddress(data, 0);
        const srcMac = this._getMacAddress(data, 6);
        const type = (data[12] << 8) | data[13];

        return {
            destMac: destMac,
            srcMac: srcMac,
            protocol: type,
            protocolName: this._getEthernetProtocol(type),
            headerLength: 14
        };
    }

    /* ============================================
       IP DISSECTION (L3) - IPv4 & IPv6
       ============================================ */

    _dissectIP(data, offset) {
        if (data.length < offset + 20) return null;

        const version = (data[offset] >> 4) & 0xf;

        if (version === 4) {
            return this._dissectIPv4(data, offset);
        } else if (version === 6) {
            return this._dissectIPv6(data, offset);
        }

        return null;
    }

    _dissectIPv4(data, offset) {
        const version = (data[offset] >> 4) & 0xf;
        const ihl = (data[offset] & 0xf) * 4;
        const dscp = (data[offset + 1] >> 2) & 0x3f;
        const totalLength = (data[offset + 2] << 8) | data[offset + 3];
        const identification = (data[offset + 4] << 8) | data[offset + 5];
        const flags = (data[offset + 6] >> 5) & 0x7;
        const fragmentOffset = ((data[offset + 6] & 0x1f) << 8) | data[offset + 7];
        const ttl = data[offset + 8];
        const protocol = data[offset + 9];
        const checksum = (data[offset + 10] << 8) | data[offset + 11];
        const srcIP = this._getIPv4Address(data, offset + 12);
        const dstIP = this._getIPv4Address(data, offset + 16);

        return {
            version: version,
            headerLength: ihl,
            dscp: dscp,
            totalLength: totalLength,
            identification: identification,
            flags: flags,
            fragmentOffset: fragmentOffset,
            ttl: ttl,
            protocol: protocol,
            protocolName: this._getIPProtocol(protocol),
            checksum: checksum,
            srcIP: srcIP,
            dstIP: dstIP
        };
    }

    _dissectIPv6(data, offset) {
        if (data.length < offset + 40) return null;

        const version = (data[offset] >> 4) & 0xf;
        const trafficClass = ((data[offset] & 0xf) << 4) | ((data[offset + 1] >> 4) & 0xf);
        const flowLabel = ((data[offset + 1] & 0xf) << 16) | (data[offset + 2] << 8) | data[offset + 3];
        const payloadLength = (data[offset + 4] << 8) | data[offset + 5];
        const nextHeader = data[offset + 6];
        const hopLimit = data[offset + 7];
        const srcIP = this._getIPv6Address(data, offset + 8);
        const dstIP = this._getIPv6Address(data, offset + 24);

        return {
            version: version,
            trafficClass: trafficClass,
            flowLabel: flowLabel,
            payloadLength: payloadLength,
            nextHeader: nextHeader,
            hopLimit: hopLimit,
            srcIP: srcIP,
            dstIP: dstIP,
            headerLength: 40
        };
    }

    /* ============================================
       TCP DISSECTION (L4)
       ============================================ */

    _dissectTCP(data, offset) {
        if (data.length < offset + 20) return null;

        const srcPort = (data[offset] << 8) | data[offset + 1];
        const dstPort = (data[offset + 2] << 8) | data[offset + 3];
        const seqNum = (data[offset + 4] << 24) | (data[offset + 5] << 16) | (data[offset + 6] << 8) | data[offset + 7];
        const ackNum = (data[offset + 8] << 24) | (data[offset + 9] << 16) | (data[offset + 10] << 8) | data[offset + 11];
        const dataOffset = ((data[offset + 12] >> 4) & 0xf) * 4;
        const flags = data[offset + 13];
        const window = (data[offset + 14] << 8) | data[offset + 15];
        const checksum = (data[offset + 16] << 8) | data[offset + 17];
        const urgentPointer = (data[offset + 18] << 8) | data[offset + 19];

        return {
            srcPort: srcPort,
            dstPort: dstPort,
            seqNum: seqNum,
            ackNum: ackNum,
            headerLength: dataOffset,
            flags: this._getTCPFlags(flags),
            flagsRaw: flags,
            window: window,
            checksum: checksum,
            urgentPointer: urgentPointer
        };
    }

    /* ============================================
       UDP DISSECTION (L4)
       ============================================ */

    _dissectUDP(data, offset) {
        if (data.length < offset + 8) return null;

        const srcPort = (data[offset] << 8) | data[offset + 1];
        const dstPort = (data[offset + 2] << 8) | data[offset + 3];
        const length = (data[offset + 4] << 8) | data[offset + 5];
        const checksum = (data[offset + 6] << 8) | data[offset + 7];

        return {
            srcPort: srcPort,
            dstPort: dstPort,
            length: length,
            checksum: checksum
        };
    }

    /* ============================================
       ICMP DISSECTION (L4)
       ============================================ */

    _dissectICMP(data, offset) {
        if (data.length < offset + 8) return null;

        const type = data[offset];
        const code = data[offset + 1];
        const checksum = (data[offset + 2] << 8) | data[offset + 3];
        const restOfHeader = (data[offset + 4] << 24) | (data[offset + 5] << 16) | (data[offset + 6] << 8) | data[offset + 7];

        return {
            type: type,
            typeName: this._getICMPType(type),
            code: code,
            checksum: checksum,
            restOfHeader: restOfHeader
        };
    }

    /* ============================================
       APPLICATION LAYER DISSECTION (L7)
       ============================================ */

    _dissectApplicationLayer(packet, data, offset) {
        if (!packet.layers.tcp && !packet.layers.udp) return;

        const port = packet.layers.tcp ? packet.layers.tcp.dstPort : packet.layers.udp.dstPort;

        // DNS (Port 53)
        if (port === 53 || (packet.layers.udp && packet.layers.udp.srcPort === 53)) {
            packet.layers.dns = this._dissectDNS(data, offset);
            packet.applicationProtocol = 'DNS';
        }

        // HTTP (Port 80)
        if (port === 80 || packet.layers.tcp?.srcPort === 80) {
            packet.layers.http = this._dissectHTTP(data, offset);
            packet.applicationProtocol = 'HTTP';
        }

        // HTTPS (Port 443)
        if (port === 443 || packet.layers.tcp?.srcPort === 443) {
            packet.layers.tls = this._dissectTLS(data, offset);
            packet.applicationProtocol = 'HTTPS';
        }

        // SSH (Port 22)
        if (port === 22 || packet.layers.tcp?.srcPort === 22) {
            packet.applicationProtocol = 'SSH';
        }

        // SMTP (Port 25)
        if (port === 25 || packet.layers.tcp?.srcPort === 25) {
            packet.applicationProtocol = 'SMTP';
        }

        // FTP (Port 21)
        if (port === 21 || packet.layers.tcp?.srcPort === 21) {
            packet.applicationProtocol = 'FTP';
        }
    }

    /* ============================================
       DNS DISSECTION
       ============================================ */

    _dissectDNS(data, offset) {
        if (data.length < offset + 12) return null;

        const transactionID = (data[offset] << 8) | data[offset + 1];
        const flags = (data[offset + 2] << 8) | data[offset + 3];
        const isResponse = (flags & 0x8000) !== 0;
        const questionCount = (data[offset + 4] << 8) | data[offset + 5];
        const answerCount = (data[offset + 6] << 8) | data[offset + 7];
        const authorityCount = (data[offset + 8] << 8) | data[offset + 9];
        const additionalCount = (data[offset + 10] << 8) | data[offset + 11];

        const dns = {
            transactionID: transactionID.toString(16),
            isResponse: isResponse,
            isQuery: !isResponse,
            questionCount: questionCount,
            answerCount: answerCount,
            authorityCount: authorityCount,
            additionalCount: additionalCount,
            queries: [],
            answers: []
        };

        // Parse DNS questions
        let dnsOffset = offset + 12;
        for (let i = 0; i < questionCount && dnsOffset < data.length; i++) {
            const result = this._parseDNSName(data, dnsOffset);
            if (!result) break;

            const qtype = (data[result.offset] << 8) | data[result.offset + 1];
            const qclass = (data[result.offset + 2] << 8) | data[result.offset + 3];

            dns.queries.push({
                name: result.name,
                type: this._getDNSType(qtype),
                typeCode: qtype,
                class: qclass
            });

            dnsOffset = result.offset + 4;
        }

        // Parse DNS answers
        for (let i = 0; i < answerCount && dnsOffset < data.length; i++) {
            const result = this._parseDNSName(data, dnsOffset);
            if (!result) break;

            const type = (data[result.offset] << 8) | data[result.offset + 1];
            const cls = (data[result.offset + 2] << 8) | data[result.offset + 3];
            const ttl = (data[result.offset + 4] << 24) | (data[result.offset + 5] << 16) | (data[result.offset + 6] << 8) | data[result.offset + 7];
            const rdlength = (data[result.offset + 8] << 8) | data[result.offset + 9];

            let rdata = '';
            if (type === 1) { // A record
                rdata = this._getIPv4Address(data, result.offset + 10);
            } else if (type === 28) { // AAAA record
                rdata = this._getIPv6Address(data, result.offset + 10);
            } else if (type === 5) { // CNAME
                const cnameResult = this._parseDNSName(data, result.offset + 10);
                rdata = cnameResult ? cnameResult.name : '';
            } else {
                rdata = this._bytesToHex(new Uint8Array(data.buffer, result.offset + 10, rdlength));
            }

            dns.answers.push({
                name: result.name,
                type: this._getDNSType(type),
                typeCode: type,
                class: cls,
                ttl: ttl,
                rdata: rdata
            });

            dnsOffset = result.offset + 10 + rdlength;
        }

        return dns;
    }

    /* ============================================
       HTTP DISSECTION
       ============================================ */

    _dissectHTTP(data, offset) {
        if (data.length <= offset) return null;

        const httpString = this._bytesToAscii(new Uint8Array(data.buffer, offset, Math.min(500, data.length - offset)));
        const lines = httpString.split('\r\n');

        if (lines.length === 0) return null;

        const requestLine = lines[0].split(' ');
        const http = {
            method: requestLine[0] || '',
            uri: requestLine[1] || '',
            version: requestLine[2] || '',
            headers: {},
            body: ''
        };

        // Parse headers
        for (let i = 1; i < lines.length && lines[i] !== ''; i++) {
            const colonIndex = lines[i].indexOf(':');
            if (colonIndex > 0) {
                const header = lines[i].substring(0, colonIndex).trim();
                const value = lines[i].substring(colonIndex + 1).trim();
                http.headers[header.toLowerCase()] = value;
            }
        }

        return http;
    }

    /* ============================================
       TLS/HTTPS DISSECTION
       ============================================ */

    _dissectTLS(data, offset) {
        if (data.length < offset + 5) return null;

        const contentType = data[offset];
        const version = (data[offset + 1] << 8) | data[offset + 2];
        const length = (data[offset + 3] << 8) | data[offset + 4];

        const contentTypeMap = {
            20: 'Change Cipher Spec',
            21: 'Alert',
            22: 'Handshake',
            23: 'Application Data',
            24: 'Heartbeat'
        };

        const versionMap = {
            0x0301: 'TLS 1.0',
            0x0302: 'TLS 1.1',
            0x0303: 'TLS 1.2',
            0x0304: 'TLS 1.3'
        };

        return {
            contentType: contentTypeMap[contentType] || 'Unknown',
            contentTypeRaw: contentType,
            version: versionMap[version] || `Unknown (${version.toString(16)})`,
            versionRaw: version,
            length: length
        };
    }

    /* ============================================
       HELPER FUNCTIONS - ADDRESS CONVERSION
       ============================================ */

    _getIPv4Address(data, offset) {
        return `${data[offset]}.${data[offset + 1]}.${data[offset + 2]}.${data[offset + 3]}`;
    }

    _getIPv6Address(data, offset) {
        let address = '';
        for (let i = 0; i < 8; i++) {
            const word = (data[offset + i * 2] << 8) | data[offset + i * 2 + 1];
            address += word.toString(16);
            if (i < 7) address += ':';
        }
        return address;
    }

    _getMacAddress(data, offset) {
        const bytes = [];
        for (let i = 0; i < 6; i++) {
            bytes.push(data[offset + i].toString(16).padStart(2, '0').toUpperCase());
        }
        return bytes.join(':');
    }

    /* ============================================
       HELPER FUNCTIONS - PROTOCOL NAMES
       ============================================ */

    _getEthernetProtocol(type) {
        const protocols = {
            0x0800: 'IPv4',
            0x0806: 'ARP',
            0x86dd: 'IPv6',
            0x8100: 'VLAN',
            0x88cc: 'LLDP'
        };
        return protocols[type] || `Unknown (0x${type.toString(16).toUpperCase()})`;
    }

    _getIPProtocol(protocol) {
        const protocols = {
            1: 'ICMP',
            2: 'IGMP',
            6: 'TCP',
            17: 'UDP',
            41: 'IPv6',
            47: 'GRE',
            50: 'ESP',
            51: 'AH',
            103: 'PIM',
            112: 'VRRP'
        };
        return protocols[protocol] || `Unknown (${protocol})`;
    }

    _getTCPFlags(flags) {
        return {
            FIN: (flags & 0x01) !== 0,
            SYN: (flags & 0x02) !== 0,
            RST: (flags & 0x04) !== 0,
            PSH: (flags & 0x08) !== 0,
            ACK: (flags & 0x10) !== 0,
            URG: (flags & 0x20) !== 0,
            ECE: (flags & 0x40) !== 0,
            CWR: (flags & 0x80) !== 0
        };
    }

    _getICMPType(type) {
        const types = {
            0: 'Echo Reply',
            3: 'Destination Unreachable',
            4: 'Source Quench',
            5: 'Redirect',
            6: 'Alternate Host Address',
            8: 'Echo',
            9: 'Router Advertisement',
            10: 'Router Selection',
            11: 'Time Exceeded',
            12: 'Parameter Problem',
            13: 'Timestamp',
            14: 'Timestamp Reply',
            15: 'Information Request',
            16: 'Information Reply',
            17: 'Address Mask Request',
            18: 'Address Mask Reply'
        };
        return types[type] || `Unknown (${type})`;
    }

    _getDNSType(type) {
        const types = {
            1: 'A',
            2: 'NS',
            5: 'CNAME',
            6: 'SOA',
            12: 'PTR',
            15: 'MX',
            16: 'TXT',
            28: 'AAAA',
            33: 'SRV',
            41: 'OPT',
            43: 'DS',
            46: 'RRSIG',
            47: 'NSEC',
            48: 'DNSKEY',
            255: 'ANY'
        };
        return types[type] || `Type${type}`;
    }

    _getDatalinkType(network) {
        const types = {
            1: 'Ethernet',
            6: 'Token Ring',
            7: 'ARCNET',
            8: 'SLIP',
            9: 'PPP',
            10: 'FDDI',
            50: 'PPP Serial',
            51: 'Token Ring Header Compression',
            100: 'ATM',
            101: 'RFC 1483 LLC/SNAP',
            104: 'C-HDLC',
            105: 'IEEE 802.11',
            107: 'SFP',
            108: 'Raw IP',
            113: 'LINUX SLL',
            127: 'Linux cooked capture',
            144: 'Cisco HDLC',
            147: 'Ethernet with FCS',
            162: 'USB',
            163: 'Bluetooth',
            166: 'AX.25'
        };
        return types[network] || `Unknown (${network})`;
    }

    /* ============================================
       DNS NAME PARSING
       ============================================ */

    _parseDNSName(data, offset) {
        let name = '';
        let currentOffset = offset;
        const maxIterations = 255;
        let iterations = 0;

        while (currentOffset < data.length && iterations < maxIterations) {
            iterations++;
            const length = data[currentOffset];

            if (length === 0) {
                return { name: name, offset: currentOffset + 1 };
            }

            if ((length & 0xc0) === 0xc0) {
                // Pointer
                const pointerOffset = ((length & 0x3f) << 8) | data[currentOffset + 1];
                const pointerResult = this._parseDNSName(data, pointerOffset);
                if (pointerResult) {
                    name += pointerResult.name;
                }
                return { name: name, offset: currentOffset + 2 };
            }

            currentOffset++;
            for (let i = 0; i < length && currentOffset < data.length; i++) {
                name += String.fromCharCode(data[currentOffset]);
                currentOffset++;
            }

            if (currentOffset < data.length && data[currentOffset] !== 0) {
                name += '.';
            }
        }

        return null;
    }

    /* ============================================
       DATA CONVERSION UTILITIES
       ============================================ */

    _bytesToHex(bytes) {
        let hex = '';
        for (let i = 0; i < bytes.length; i++) {
            hex += bytes[i].toString(16).padStart(2, '0').toUpperCase();
            if ((i + 1) % 16 === 0) hex += '\n';
            else if ((i + 1) % 8 === 0) hex += '  ';
            else hex += ' ';
        }
        return hex;
    }

    _bytesToAscii(bytes) {
        let ascii = '';
        for (let i = 0; i < bytes.length; i++) {
            const byte = bytes[i];
            if (byte >= 32 && byte < 127) {
                ascii += String.fromCharCode(byte);
            } else {
                ascii += '.';
            }
        }
        return ascii;
    }

    /* ============================================
       STATISTICS CALCULATION
       ============================================ */

    _calculateStats() {
        if (this.packets.length === 0) return;

        this.stats.avgPacketSize = Math.round(this.stats.totalBytes / this.packets.length);

        // More stats can be added here
    }
}

/* ============================================
   EXPORT FOR USE IN MAIN APPLICATION
   ============================================ */

if (typeof module !== 'undefined' && module.exports) {
    module.exports = PCAPParser;
}