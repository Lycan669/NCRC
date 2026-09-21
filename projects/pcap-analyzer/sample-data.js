/**
 * Données d'exemple PCAP
 * Charger ce fichier avant app.js
 */

// Exemple de données PCAP au format JSON
const SAMPLE_PCAP_DATA = [
    // ============ DNS REQUESTS ============
    {
        number: 1,
        timestamp: 1695312000,
        srcIP: "192.168.1.100",
        dstIP: "8.8.8.8",
        srcPort: 54321,
        dstPort: 53,
        protocol: "DNS",
        size: 64,
        flags: "SYN",
        payload: "Query: google.com",
        severity: "low"
    },
    {
        number: 2,
        timestamp: 1695312001,
        srcIP: "8.8.8.8",
        dstIP: "192.168.1.100",
        srcPort: 53,
        dstPort: 54321,
        protocol: "DNS",
        size: 128,
        flags: "SYN-ACK",
        payload: "Response: 142.250.185.46",
        severity: "low"
    },

    // ============ HTTPS TRAFFIC ============
    {
        number: 3,
        timestamp: 1695312002,
        srcIP: "192.168.1.100",
        dstIP: "142.250.185.46",
        srcPort: 54322,
        dstPort: 443,
        protocol: "TCP/TLS",
        size: 1024,
        flags: "PSH-ACK",
        payload: "TLS Handshake - google.com",
        severity: "low"
    },
    {
        number: 4,
        timestamp: 1695312003,
        srcIP: "142.250.185.46",
        dstIP: "192.168.1.100",
        srcPort: 443,
        dstPort: 54322,
        protocol: "TCP/TLS",
        size: 2048,
        flags: "PSH-ACK",
        payload: "TLS Server Hello Certificate",
        severity: "low"
    },

    // ============ SUSPICIOUS: RDP BRUTE FORCE 🔴 ============
    {
        number: 5,
        timestamp: 1695312010,
        srcIP: "203.0.113.45",
        dstIP: "192.168.1.50",
        srcPort: 45000,
        dstPort: 3389,
        protocol: "RDP",
        size: 256,
        flags: "SYN",
        payload: "RDP Connection Attempt 1",
        severity: "critical"
    },
    {
        number: 6,
        timestamp: 1695312011,
        srcIP: "203.0.113.45",
        dstIP: "192.168.1.50",
        srcPort: 45001,
        dstPort: 3389,
        protocol: "RDP",
        size: 256,
        flags: "SYN",
        payload: "RDP Connection Attempt 2",
        severity: "critical"
    },
    {
        number: 7,
        timestamp: 1695312012,
        srcIP: "203.0.113.45",
        dstIP: "192.168.1.50",
        srcPort: 45002,
        dstPort: 3389,
        protocol: "RDP",
        size: 256,
        flags: "SYN",
        payload: "RDP Connection Attempt 3",
        severity: "critical"
    },

    // ============ SUSPICIOUS: C2 COMMUNICATION 🔴 ============
    {
        number: 8,
        timestamp: 1695312020,
        srcIP: "192.168.1.101",
        dstIP: "185.220.101.45",
        srcPort: 52000,
        dstPort: 8080,
        protocol: "HTTP",
        size: 512,
        flags: "PSH-ACK",
        payload: "POST /cmd?id=bot001&status=online",
        severity: "critical"
    },
    {
        number: 9,
        timestamp: 1695312021,
        srcIP: "185.220.101.45",
        dstIP: "192.168.1.101",
        srcPort: 8080,
        dstPort: 52000,
        protocol: "HTTP",
        size: 1024,
        flags: "PSH-ACK",
        payload: "execute: powershell.exe -nop -w hidden...",
        severity: "critical"
    },

    // ============ SUSPICIOUS: ICMP FLOOD 🔴 ============
    {
        number: 10,
        timestamp: 1695312030,
        srcIP: "198.51.100.10",
        dstIP: "192.168.1.1",
        srcPort: 0,
        dstPort: 0,
        protocol: "ICMP",
        size: 56,
        flags: "ECHO",
        payload: "ICMP Echo Request (Flood)",
        severity: "high"
    },
    {
        number: 11,
        timestamp: 1695312031,
        srcIP: "198.51.100.10",
        dstIP: "192.168.1.1",
        srcPort: 0,
        dstPort: 0,
        protocol: "ICMP",
        size: 56,
        flags: "ECHO",
        payload: "ICMP Echo Request (Flood)",
        severity: "high"
    },
    {
        number: 12,
        timestamp: 1695312032,
        srcIP: "198.51.100.10",
        dstIP: "192.168.1.1",
        srcPort: 0,
        dstPort: 0,
        protocol: "ICMP",
        size: 56,
        flags: "ECHO",
        payload: "ICMP Echo Request (Flood)",
        severity: "high"
    },

    // ============ SUSPICIOUS: SQL INJECTION 🔴 ============
    {
        number: 13,
        timestamp: 1695312040,
        srcIP: "192.168.1.102",
        dstIP: "10.0.0.50",
        srcPort: 54323,
        dstPort: 3306,
        protocol: "MySQL",
        size: 512,
        flags: "PSH-ACK",
        payload: "SELECT * FROM users WHERE id=1 OR 1=1--",
        severity: "critical"
    },

    // ============ SUSPICIOUS: DNS EXFILTRATION 🔴 ============
    {
        number: 14,
        timestamp: 1695312050,
        srcIP: "192.168.1.103",
        dstIP: "8.8.8.8",
        srcPort: 54324,
        dstPort: 53,
        protocol: "DNS",
        size: 256,
        flags: "SYN",
        payload: "Query: exfil_data_base64_xxxxx.attacker.com",
        severity: "critical"
    },

    // ============ NORMAL: FTP ============
    {
        number: 15,
        timestamp: 1695312060,
        srcIP: "192.168.1.100",
        dstIP: "10.0.0.100",
        srcPort: 54325,
        dstPort: 21,
        protocol: "FTP",
        size: 256,
        flags: "SYN",
        payload: "USER admin",
        severity: "low"
    },
    {
        number: 16,
        timestamp: 1695312061,
        srcIP: "10.0.0.100",
        dstIP: "192.168.1.100",
        srcPort: 21,
        dstPort: 54325,
        protocol: "FTP",
        size: 128,
        flags: "SYN-ACK",
        payload: "220 Welcome to FTP Server",
        severity: "low"
    },

    // ============ SUSPICIOUS: SMB LATERAL MOVEMENT 🟡 ============
    {
        number: 17,
        timestamp: 1695312070,
        srcIP: "192.168.1.50",
        dstIP: "192.168.1.51",
        srcPort: 54326,
        dstPort: 445,
        protocol: "SMB",
        size: 256,
        flags: "PSH-ACK",
        payload: "\\\\WORKSTATION2\\C$",
        severity: "high"
    },

    // ============ NORMAL: SSH ============
    {
        number: 18,
        timestamp: 1695312080,
        srcIP: "192.168.1.100",
        dstIP: "10.0.0.200",
        srcPort: 54327,
        dstPort: 22,
        protocol: "SSH",
        size: 512,
        flags: "PSH-ACK",
        payload: "SSH-2.0-OpenSSH_7.4",
        severity: "low"
    },

    // ============ SUSPICIOUS: MALWARE SIGNATURE 🔴 ============
    {
        number: 19,
        timestamp: 1695312090,
        srcIP: "192.168.1.105",
        dstIP: "185.220.101.50",
        srcPort: 52001,
        dstPort: 443,
        protocol: "TCP/TLS",
        size: 2048,
        flags: "PSH-ACK",
        payload: "GET /malware/payload.exe HTTP/1.1",
        severity: "critical"
    },

    // ============ NORMAL: NTP ============
    {
        number: 20,
        timestamp: 1695312100,
        srcIP: "192.168.1.100",
        dstIP: "91.189.89.198",
        srcPort: 54328,
        dstPort: 123,
        protocol: "NTP",
        size: 48,
        flags: "SYN",
        payload: "NTP Time Sync",
        severity: "low"
    }
];

console.log('✅ Sample PCAP data loaded:', SAMPLE_PCAP_DATA.length, 'packets');