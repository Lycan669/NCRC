/**
 * PCAP Parser - Parse le fichier PCAP/PCAPNG
 * Simule un vrai parsing (car les vrais PCAP c'est binaire)
 */

class PCAPParser {
    constructor(file) {
        this.file = file;
        this.packets = [];
        this.metadata = {
            version: '4',
            network: '1',
            timestamp: new Date(),
        };
    }

    /**
     * Parse un fichier PCAP
     * Note: Vrai parsing nécessite wireshark.js ou libpcap
     * On simule ici avec des patterns
     */
    async parse() {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();

            reader.onload = (e) => {
                try {
                    const arrayBuffer = e.target.result;
                    const bytes = new Uint8Array(arrayBuffer);

                    // Vérifier magic number PCAP
                    if (!this.isValidPCAP(bytes)) {
                        throw new Error('Fichier PCAP invalide');
                    }

                    // Parser les packets
                    const packets = this.extractPackets(bytes);
                    this.packets = packets;

                    resolve({
                        success: true,
                        packets: packets,
                        count: packets.length,
                        metadata: this.metadata
                    });
                } catch (error) {
                    reject(error);
                }
            };

            reader.onerror = () => reject(new Error('Erreur de lecture'));
            reader.readAsArrayBuffer(this.file);
        });
    }

    /**
     * Vérifie le magic number PCAP
     */
    isValidPCAP(bytes) {
        if (bytes.length < 24) return false;
        
        // Magic PCAP: 0xA1B2C3D4 ou 0xA1B23C4D (swap)
        const magic = (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
        return magic === 0xA1B2C3D4 || magic === 0xA1B23C4D || magic === 0x0A0D0D0A;
    }

    /**
     * Extrait les packets du fichier PCAP
     */
    extractPackets(bytes) {
        const packets = [];
        let offset = 24; // Sauter le global header

        let packetCount = 0;
        const maxPackets = 10000; // Limite pour la performance

        while (offset < bytes.length && packetCount < maxPackets) {
            try {
                // Packet header (16 bytes)
                if (offset + 16 > bytes.length) break;

                const timestamp = this.readUInt32(bytes, offset);
                const includedLength = this.readUInt32(bytes, offset + 8);
                const originalLength = this.readUInt32(bytes, offset + 12);

                offset += 16;

                // Packet data
                if (offset + includedLength > bytes.length) break;

                const packetData = bytes.slice(offset, offset + includedLength);
                offset += includedLength;

                // Parser le packet
                const packet = this.parsePacketData(packetData, timestamp);
                if (packet) {
                    packets.push(packet);
                    packetCount++;
                }
            } catch (error) {
                console.warn('Erreur parsing packet:', error);
                break;
            }
        }

        return packets;
    }

    /**
     * Parse les données d'un packet (Ethernet frame)
     */
    parsePacketData(data, timestamp) {
        if (data.length < 14) return null;

        try {
            // Ethernet header
            const etherType = (data[12] << 8) | data[13];
            let offset = 14;

            let packet = {
                timestamp: timestamp,
                size: data.length,
                protocol: 'Unknown',
                srcIP: null,
                dstIP: null,
                srcPort: null,
                dstPort: null,
                flags: {}
            };

            // IPv4
            if (etherType === 0x0800 && data.length >= 34) {
                packet.protocol = 'IPv4';
                packet.srcIP = `${data[26]}.${data[27]}.${data[28]}.${data[29]}`;
                packet.dstIP = `${data[30]}.${data[31]}.${data[32]}.${data[33]}`;

                const ipProtocol = data[23];

                // TCP
                if (ipProtocol === 6 && data.length >= 54) {
                    packet.protocol = 'TCP';
                    packet.srcPort = (data[34] << 8) | data[35];
                    packet.dstPort = (data[36] << 8) | data[37];
                    packet.flags = {
                        SYN: (data[47] & 0x02) !== 0,
                        ACK: (data[47] & 0x10) !== 0,
                        FIN: (data[47] & 0x01) !== 0,
                        RST: (data[47] & 0x04) !== 0
                    };
                }
                // UDP
                else if (ipProtocol === 17 && data.length >= 42) {
                    packet.protocol = 'UDP';
                    packet.srcPort = (data[34] << 8) | data[35];
                    packet.dstPort = (data[36] << 8) | data[37];
                }
                // ICMP
                else if (ipProtocol === 1) {
                    packet.protocol = 'ICMP';
                    packet.type = data[24];
                    packet.code = data[25];
                }
            }
            // IPv6
            else if (etherType === 0x86DD) {
                packet.protocol = 'IPv6';
                // Simplified IPv6 parsing
            }

            return packet;
        } catch (error) {
            return null;
        }
    }

    /**
     * Lit un UInt32 little-endian
     */
    readUInt32(bytes, offset) {
        return bytes[offset] | (bytes[offset + 1] << 8) | 
               (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24);
    }
}