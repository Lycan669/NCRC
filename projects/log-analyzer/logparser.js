// ============ LOG PARSER ============

class LogParser {
    constructor() {
        this.logs = [];
        this.parsedEntries = [];
    }

    /**
     * Parse les logs en fonction du format
     */
    parse(content, format = 'apache') {
        this.logs = content.split('\n').filter(line => line.trim());
        
        switch(format.toLowerCase()) {
            case 'apache':
                return this.parseApache();
            case 'nginx':
                return this.parseNginx();
            case 'windows':
                return this.parseWindowsEventLog();
            case 'syslog':
                return this.parseSyslog();
            default:
                return this.parseCustom();
        }
    }

    /**
     * Parse les logs Apache
     * Format: IP - - [date] "METHOD path HTTP/1.1" status bytes "referer" "user-agent"
     */
    parseApache() {
        const apacheRegex = /^(\S+) - - \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\S+) "([^"]*)" "([^"]*)"/;
        
        this.logs.forEach((line, index) => {
            const match = line.match(apacheRegex);
            
            if (match) {
                const [, ip, timestamp, method, path, protocol, status, bytes, referer, userAgent] = match;
                
                this.parsedEntries.push({
                    line: index + 1,
                    ip,
                    timestamp,
                    method,
                    path,
                    protocol,
                    statusCode: parseInt(status),
                    bytes: parseInt(bytes) || 0,
                    referer,
                    userAgent,
                    rawLine: line
                });
            }
        });
        
        return this.parsedEntries;
    }

    /**
     * Parse les logs Nginx (similaire à Apache)
     */
    parseNginx() {
        const nginxRegex = /^(\S+) - (\S+) \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"/;
        
        this.logs.forEach((line, index) => {
            const match = line.match(nginxRegex);
            
            if (match) {
                const [, ip, user, timestamp, method, path, protocol, status, bytes, referer, userAgent] = match;
                
                this.parsedEntries.push({
                    line: index + 1,
                    ip,
                    user: user !== '-' ? user : null,
                    timestamp,
                    method,
                    path,
                    protocol,
                    statusCode: parseInt(status),
                    bytes: parseInt(bytes) || 0,
                    referer: referer !== '-' ? referer : null,
                    userAgent: userAgent !== '-' ? userAgent : null,
                    rawLine: line
                });
            }
        });
        
        return this.parsedEntries;
    }

    /**
     * Parse Windows Event Log
     */
    parseWindowsEventLog() {
        const windowsRegex = /(\d+)\s+(\w+)\s+(\d+)\s+(\d+:\d+:\d+)\s+(\S+)\s+(\S+)\s+(\d+)\s+(.*)/;
        
        this.logs.forEach((line, index) => {
            const match = line.match(windowsRegex);
            
            if (match) {
                const [, logid, type, source, time, computer, eventid, status, details] = match;
                
                this.parsedEntries.push({
                    line: index + 1,
                    logid,
                    type,
                    source,
                    time,
                    computer,
                    eventid: parseInt(eventid),
                    status,
                    details,
                    rawLine: line
                });
            } else {
                // Fallback pour lignes non-matchées
                if (line.trim()) {
                    this.parsedEntries.push({
                        line: index + 1,
                        rawLine: line,
                        details: line
                    });
                }
            }
        });
        
        return this.parsedEntries;
    }

    /**
     * Parse Syslog
     */
    parseSyslog() {
        const syslogRegex = /^(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+(\S+)\[(\d+)\]:\s+(.*)/;
        
        this.logs.forEach((line, index) => {
            const match = line.match(syslogRegex);
            
            if (match) {
                const [, timestamp, host, process, pid, message] = match;
                
                this.parsedEntries.push({
                    line: index + 1,
                    timestamp,
                    host,
                    process,
                    pid: parseInt(pid),
                    message,
                    rawLine: line
                });
            }
        });
        
        return this.parsedEntries;
    }

    /**
     * Parse format custom (délimité par espaces)
     */
    parseCustom() {
        this.logs.forEach((line, index) => {
            const parts = line.split(/\s+/);
            
            this.parsedEntries.push({
                line: index + 1,
                parts,
                rawLine: line
            });
        });
        
        return this.parsedEntries;
    }

    /**
     * Compte les entrées
     */
    getCount() {
        return this.parsedEntries.length;
    }

    /**
     * Extrait les IPs uniques
     */
    getUniqueIPs() {
        const ips = new Set();
        this.parsedEntries.forEach(entry => {
            if (entry.ip) ips.add(entry.ip);
        });
        return Array.from(ips);
    }
}