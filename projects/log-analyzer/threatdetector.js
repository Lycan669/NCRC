// ============ THREAT DETECTOR ============

class ThreatDetector {
    constructor() {
        this.threats = [];
        this.suspiciousIPs = new Set();
    }

    /**
     * Analyse les entrées et détecte les menaces
     */
    analyze(entries) {
        this.threats = [];
        
        entries.forEach(entry => {
            const threatsList = [];
            let hasThreats = false;

            // ====== DÉTECTION D'INJECTIONS SQL ======
            if (entry.path && detectSQLInjection(entry.path)) {
                threatsList.push('SQL Injection');
                hasThreats = true;
            }
            
            if (entry.referer && detectSQLInjection(entry.referer)) {
                threatsList.push('SQL Injection');
                hasThreats = true;
            }

            // ====== DÉTECTION XSS ======
            if (entry.path && detectXSS(entry.path)) {
                threatsList.push('XSS');
                hasThreats = true;
            }

            // ====== DÉTECTION PATH TRAVERSAL ======
            if (entry.path && detectPathTraversal(entry.path)) {
                threatsList.push('Path Traversal');
                hasThreats = true;
            }

            // ====== DÉTECTION STATUS CODES SUSPECTS ======
            if (entry.statusCode) {
                if (entry.statusCode === 401 || entry.statusCode === 403) {
                    threatsList.push('Access Denied');
                    hasThreats = true;
                }
                if (entry.statusCode >= 500) {
                    threatsList.push('Server Error');
                    hasThreats = true;
                }
            }

            // ====== DÉTECTION USER-AGENT SUSPECTS ======
            if (entry.userAgent) {
                if (this.isSuspiciousUserAgent(entry.userAgent)) {
                    threatsList.push('Suspicious User-Agent');
                    hasThreats = true;
                }
            }

            // ====== DÉTECTION SHELL UPLOAD ======
            if (entry.path && /\.(php|jsp|aspx|asp|sh|exe|bat|cmd)/.test(entry.path)) {
                if (entry.method !== 'GET') {
                    threatsList.push('Possible Shell Upload');
                    hasThreats = true;
                }
            }

            // ====== CRÉATION DE L'OBJET THREAT ======
            if (hasThreats || entry.statusCode >= 400) {
                const threatObj = {
                    ...entry,
                    threats: threatsList,
                    severity: categorizeSeverity(
                        calculateSeverityScore({ ...entry, threats: threatsList })
                    ),
                    score: calculateSeverityScore({ ...entry, threats: threatsList }),
                    timestamp: entry.timestamp || new Date().toISOString()
                };
                
                this.threats.push(threatObj);
                
                if (entry.ip) {
                    this.suspiciousIPs.add(entry.ip);
                }
            }
        });

        return this.threats;
    }

    /**
     * Détecte les user-agents suspects
     */
    isSuspiciousUserAgent(userAgent) {
        const suspiciousPatterns = [
            /sqlmap/i,
            /nikto/i,
            /nmap/i,
            /nessus/i,
            /masscan/i,
            /metasploit/i,
            /burp/i,
            /zap/i,
            /curl.*nouser/i,
            /wget.*bot/i,
            /python-requests/i,
            /go-http-client/i
        ];
        
        return suspiciousPatterns.some(pattern => pattern.test(userAgent));
    }

    /**
     * Filtre les menaces par sévérité
     */
    filterBySeverity(severity) {
        return this.threats.filter(threat => threat.severity === severity);
    }

    /**
     * Compte les menaces par type
     */
    getThreatCounts() {
        return {
            critical: this.filterBySeverity('critical').length,
            high: this.filterBySeverity('high').length,
            medium: this.filterBySeverity('medium').length,
            low: this.filterBySeverity('low').length,
            total: this.threats.length
        };
    }

    /**
     * Détecte les attaques brute force
     */
    detectBruteForce(entries, timeWindow = 60000, threshold = 10) {
        const ipAttempts = {};
        
        entries.forEach(entry => {
            if (entry.statusCode === 401 || entry.statusCode === 403) {
                if (entry.ip) {
                    ipAttempts[entry.ip] = (ipAttempts[entry.ip] || 0) + 1;
                }
            }
        });
        
        const bruteForcers = {};
        Object.entries(ipAttempts).forEach(([ip, count]) => {
            if (count >= threshold) {
                bruteForcers[ip] = {
                    attempts: count,
                    severity: count >= 50 ? 'critical' : count >= 20 ? 'high' : 'medium'
                };
            }
        });
        
        return bruteForcers;
    }

    /**
     * Retourne les IPs suspectes
     */
    getSuspiciousIPs() {
        return Array.from(this.suspiciousIPs);
    }

    /**
     * Obtient les menaces triées
     */
    getSortedThreats(sortBy = 'score') {
        const sorted = [...this.threats];
        
        switch(sortBy) {
            case 'score':
                return sorted.sort((a, b) => b.score - a.score);
            case 'severity':
                const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
                return sorted.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
            case 'date':
                return sorted.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
            default:
                return sorted;
        }
    }
}