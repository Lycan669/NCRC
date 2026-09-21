// ============ UTILITY FUNCTIONS ============

/**
 * Valide une adresse IP (v4)
 */
function isValidIPv4(ip) {
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipv4Regex.test(ip);
}

/**
 * Détecte si une IP est privée
 */
function isPrivateIP(ip) {
    const privateRanges = [
        /^10\./,
        /^172\.(1[6-9]|2[0-9]|3[01])\./,
        /^192\.168\./,
        /^127\./,
        /^localhost$/i
    ];
    return privateRanges.some(range => range.test(ip));
}

/**
 * Calcule un hash simple pour les données
 */
function simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash;
    }
    return Math.abs(hash).toString(16);
}

/**
 * Formate une date
 */
function formatDate(date) {
    if (!(date instanceof Date)) {
        date = new Date(date);
    }
    return date.toLocaleString('fr-FR');
}

/**
 * Parse une URL
 */
function parseURL(urlString) {
    try {
        return new URL(urlString);
    } catch {
        return null;
    }
}

/**
 * Extrait le domaine d'une URL
 */
function extractDomain(urlString) {
    const url = parseURL(urlString);
    return url ? url.hostname : null;
}

/**
 * Détecte si c'est une tentative de SQL injection
 */
function detectSQLInjection(str) {
    const sqlPatterns = [
        /(\bunion\b.*\bselect\b)/i,
        /(\bor\b.*?['\"]?\s*=\s*['\"])/i,
        /(\bdrop\b.*\btable\b)/i,
        /(\binsert\b.*\binto\b)/i,
        /(\bdelete\b.*\bfrom\b)/i,
        /(\bupdate\b.*\bset\b)/i,
        /(\bexec\b)/i,
        /(\bscript\s*\()/i,
        /['\"];.*--.*/,
        /['\"].*or.*['\"].*=.*['\"]/ 
    ];
    return sqlPatterns.some(pattern => pattern.test(str));
}

/**
 * Détecte si c'est une tentative de XSS
 */
function detectXSS(str) {
    const xssPatterns = [
        /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
        /javascript:/gi,
        /onerror\s*=/gi,
        /onload\s*=/gi,
        /onclick\s*=/gi,
        /eval\(/gi,
        /<iframe/gi,
        /<embed/gi,
        /<object/gi
    ];
    return xssPatterns.some(pattern => pattern.test(str));
}

/**
 * Détecte une tentative de path traversal
 */
function detectPathTraversal(str) {
    const pathPatterns = [
        /\.\.\//g,
        /\.\.\\/g,
        /%2e%2e\//gi,
        /\.\.%2f/gi,
        /etc\/passwd/i,
        /windows\/system32/i
    ];
    return pathPatterns.some(pattern => pattern.test(str));
}

/**
 * Détecte une tentative de brute force
 */
function detectBruteForce(entries, threshold = 10) {
    const ipAttempts = {};
    
    entries.forEach(entry => {
        if (entry.ip) {
            ipAttempts[entry.ip] = (ipAttempts[entry.ip] || 0) + 1;
        }
    });
    
    const bruteForceIPs = {};
    Object.entries(ipAttempts).forEach(([ip, count]) => {
        if (count >= threshold) {
            bruteForceIPs[ip] = count;
        }
    });
    
    return bruteForceIPs;
}

/**
 * Évalue la sévérité sur une échelle 0-100
 */
function calculateSeverityScore(entry) {
    let score = 0;
    
    // Status code
    if (entry.statusCode >= 400 && entry.statusCode < 500) score += 10;
    if (entry.statusCode >= 500) score += 20;
    
    // Threat types
    const threats = entry.threats || [];
    if (threats.includes('SQL Injection')) score += 30;
    if (threats.includes('XSS')) score += 25;
    if (threats.includes('Path Traversal')) score += 25;
    if (threats.includes('Brute Force')) score += 20;
    if (threats.includes('Suspicious User-Agent')) score += 10;
    
    // Private IP = moins dangereux
    if (isPrivateIP(entry.ip)) score *= 0.5;
    
    return Math.min(score, 100);
}

/**
 * Catégorise la sévérité
 */
function categorizeSeverity(score) {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    return 'low';
}

/**
 * Export en CSV
 */
function exportToCSV(data, filename = 'analysis.csv') {
    let csv = 'IP,Type Menace,Sévérité,Détails,Status Code,User-Agent\n';
    
    data.forEach(entry => {
        const threats = (entry.threats || []).join('; ');
        const details = (entry.details || []).join('; ');
        const userAgent = (entry.userAgent || '').replace(/,/g, ';');
        
        csv += `"${entry.ip}","${threats}","${entry.severity}","${details}","${entry.statusCode}","${userAgent}"\n`;
    });
    
    downloadFile(csv, filename, 'text/csv');
}

/**
 * Export en JSON
 */
function exportToJSON(data, filename = 'analysis.json') {
    const json = JSON.stringify(data, null, 2);
    downloadFile(json, filename, 'application/json');
}

/**
 * Télécharge un fichier
 */
function downloadFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}

/**
 * Formate un nombre avec séparateurs
 */
function formatNumber(num) {
    return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}