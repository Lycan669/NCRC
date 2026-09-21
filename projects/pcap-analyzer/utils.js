/**
 * Utils - Fonctions utilitaires
 */

/**
 * Format bytes
 */
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * Math.pow(10, dm)) / Math.pow(10, dm) + ' ' + sizes[i];
}

/**
 * Format duration
 */
function formatDuration(seconds) {
    if (seconds < 1) return Math.round(seconds * 1000) + 'ms';
    if (seconds < 60) return Math.round(seconds) + 's';
    if (seconds < 3600) return (seconds / 60).toFixed(2) + 'min';
    return (seconds / 3600).toFixed(2) + 'h';
}

/**
 * IP to binary
 */
function ipToBinary(ip) {
    return ip.split('.').map(x => {
        const bin = parseInt(x).toString(2);
        return '0'.repeat(8 - bin.length) + bin;
    }).join('.');
}

/**
 * Check if IP is private
 */
function isPrivateIP(ip) {
    const parts = ip.split('.').map(Number);
    return (parts[0] === 10) ||
           (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
           (parts[0] === 192 && parts[1] === 168) ||
           (parts[0] === 127);
}

/**
 * Check if port is well-known
 */
function isWellKnownPort(port) {
    return port < 1024;
}

/**
 * Get port name
 */
function getPortName(port) {
    const portNames = {
        20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet',
        25: 'SMTP', 53: 'DNS', 80: 'HTTP', 110: 'POP3',
        143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
        587: 'SMTP', 993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL',
        3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-Alt',
        8443: 'HTTPS-Alt', 27017: 'MongoDB', 6379: 'Redis'
    };
    return portNames[port] || `Port ${port}`;
}

/**
 * Timestamp to readable date
 */
function formatTimestamp(timestamp) {
    return new Date(timestamp * 1000).toLocaleString();
}

/**
 * Generate random color
 */
function randomColor() {
    const colors = [
        '#00d4ff', '#ff006e', '#00ff41', '#ffa500',
        '#ff0000', '#9d00ff', '#00ffff', '#ff69b4'
    ];
    return colors[Math.floor(Math.random() * colors.length)];
}

/**
 * Deep clone object
 */
function deepClone(obj) {
    return JSON.parse(JSON.stringify(obj));
}

/**
 * Group array by key
 */
function groupBy(array, key) {
    return array.reduce((acc, obj) => {
        const group = obj[key];
        if (!acc[group]) acc[group] = [];
        acc[group].push(obj);
        return acc;
    }, {});
}

/**
 * Sort array by key
 */
function sortBy(array, key, ascending = true) {
    return array.sort((a, b) => {
        const aVal = a[key];
        const bVal = b[key];
        if (aVal < bVal) return ascending ? -1 : 1;
        if (aVal > bVal) return ascending ? 1 : -1;
        return 0;
    });
}

/**
 * Debounce function
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Throttle function
 */
function throttle(func, limit) {
    let inThrottle;
    return function(...args) {
        if (!inThrottle) {
            func.apply(this, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    };
}