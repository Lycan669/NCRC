// ============ MAIN APP ============

let currentParser = null;
let currentDetector = null;
let currentAnalysisData = [];

// ====== DOM ELEMENTS ======
const uploadArea = document.getElementById('uploadArea');
const fileInput = document.getElementById('fileInput');
const logFormat = document.getElementById('logFormat');
const analyzeBtn = document.getElementById('analyzeBtn');
const loadingSpinner = document.getElementById('loadingSpinner');
const statsCard = document.getElementById('statsCard');
const threatOverview = document.getElementById('threatOverview');
const filterCard = document.getElementById('filterCard');
const resultsCard = document.getElementById('resultsCard');
const exportCard = document.getElementById('exportCard');
const searchInput = document.getElementById('searchInput');
const tableBody = document.getElementById('tableBody');

// ====== EVENT LISTENERS ======

/**
 * Upload drag & drop
 */
uploadArea.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadArea.style.borderColor = 'var(--secondary-color)';
    uploadArea.style.backgroundColor = 'rgba(0, 212, 255, 0.15)';
});

uploadArea.addEventListener('dragleave', () => {
    uploadArea.style.borderColor = 'var(--primary-color)';
    uploadArea.style.backgroundColor = 'rgba(0, 102, 204, 0.05)';
});

uploadArea.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadArea.style.borderColor = 'var(--primary-color)';
    uploadArea.style.backgroundColor = 'rgba(0, 102, 204, 0.05)';
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        handleFileSelect(files[0]);
    }
});

uploadArea.addEventListener('click', () => {
    fileInput.click();
});

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFileSelect(e.target.files[0]);
    }
});

/**
 * Gère la sélection du fichier
 */
function handleFileSelect(file) {
    const reader = new FileReader();
    
    reader.onload = (e) => {
        const content = e.target.result;
        
        // Valider que ce n'est pas vide
        if (!content.trim()) {
            alert('Le fichier est vide!');
            return;
        }
        
        analyzeBtn.disabled = false;
        analyzeBtn.textContent = '⚡ Analyser (prêt)';
        uploadArea.innerHTML = `✅ Fichier chargé: ${file.name} (${formatNumber(file.size)} bytes)`;
    };
    
    reader.onerror = () => {
        alert('Erreur lors de la lecture du fichier');
    };
    
    reader.readAsText(file);
}

/**
 * Lance l'analyse
 */
analyzeBtn.addEventListener('click', async () => {
    const file = fileInput.files[0];
    if (!file) {
        alert('Veuillez sélectionner un fichier');
        return;
    }
    
    const reader = new FileReader();
    
    reader.onload = async (e) => {
        const startTime = performance.now();
        const content = e.target.result;
        const format = logFormat.value;
        
        // Affiche le loader
        loadingSpinner.style.display = 'flex';
        analyzeBtn.disabled = true;
        
        try {
            // Parse les logs
            currentParser = new LogParser();
            const parsedLogs = currentParser.parse(content, format);
            
            // Analyse les menaces
            currentDetector = new ThreatDetector();
            currentAnalysisData = currentDetector.analyze(parsedLogs);
            
            const endTime = performance.now();
            const duration = Math.round(endTime - startTime);
            
            // Affiche les résultats
            displayResults(parsedLogs, currentAnalysisData, duration);
            
        } catch (error) {
            console.error('Erreur:', error);
            alert('Erreur lors de l\'analyse: ' + error.message);
        } finally {
            loadingSpinner.style.display = 'none';
            analyzeBtn.disabled = false;
        }
    };
    
    reader.readAsText(file);
});

/**
 * Affiche les résultats
 */
function displayResults(parsedLogs, threats, duration) {
    // ====== STATISTIQUES ======
    const uniqueIPs = new Set(parsedLogs.filter(l => l.ip).map(l => l.ip)).size;
    
    document.getElementById('totalLines').textContent = formatNumber(parsedLogs.length);
    document.getElementById('suspiciousCount').textContent = formatNumber(threats.length);
    document.getElementById('uniqueIPs').textContent = formatNumber(uniqueIPs);
    document.getElementById('duration').textContent = duration + 'ms';
    
    statsCard.style.display = 'block';
    
    // ====== MENACES ======
    const counts = currentDetector.getThreatCounts();
    document.getElementById('criticalCount').textContent = counts.critical;
    document.getElementById('highCount').textContent = counts.high;
    document.getElementById('mediumCount').textContent = counts.medium;
    document.getElementById('lowCount').textContent = counts.low;
    
    threatOverview.style.display = 'block';
    
    // ====== FILTRE & RÉSULTATS ======
    filterCard.style.display = 'block';
    resultsCard.style.display = 'block';
    exportCard.style.display = 'block';
    
    // Affiche le tableau
    displayThreatTable(threats);
    
    // Setup des filtres
    setupFilters(threats);
}

/**
 * Affiche le tableau des menaces
 */
function displayThreatTable(threats, filtered = null) {
    tableBody.innerHTML = '';
    
    const dataToDisplay = filtered || threats;
    
    if (dataToDisplay.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="5" style="text-align: center; padding: 30px;">Aucune menace trouvée</td></tr>';
        return;
    }
    
    dataToDisplay.forEach(threat => {
        const row = document.createElement('tr');
        
        // Sévérité badge
        const severityBadge = `<span class="severity-badge severity-${threat.severity}">${threat.severity.toUpperCase()}</span>`;
        
        // IP avec couleur si privée
        const ipDisplay = isPrivateIP(threat.ip) 
            ? `<code style="color: var(--text-secondary);">${threat.ip}</code>`
            : `<code style="color: var(--secondary-color);">${threat.ip}</code>`;
        
        // Types de menaces
        const threatsDisplay = (threat.threats || [])
            .map(t => `<span style="background: rgba(255,51,51,0.2); padding: 3px 8px; border-radius: 3px; font-size: 0.85em;">${t}</span>`)
            .join(' ');
        
        // Détails
        let details = '';
        if (threat.path) details += `<strong>Path:</strong> ${threat.path}<br>`;
        if (threat.statusCode) details += `<strong>Status:</strong> ${threat.statusCode}<br>`;
        if (threat.method) details += `<strong>Method:</strong> ${threat.method}<br>`;
        
        row.innerHTML = `
            <td>${severityBadge}</td>
            <td>${ipDisplay}</td>
            <td>${threatsDisplay}</td>
            <td style="max-width: 300px; word-break: break-word; font-size: 0.9em;">${details}</td>
            <td>
                <button class="btn btn-secondary" style="padding: 6px 12px; font-size: 0.85em;" onclick="blockIP('${threat.ip}')">
                    🚫 Bloquer
                </button>
            </td>
        `;
        
        tableBody.appendChild(row);
    });
}

/**
 * Setup des filtres
 */
function setupFilters(threats) {
    // Recherche
    searchInput.addEventListener('input', () => {
        const query = searchInput.value.toLowerCase();
        
        const filtered = threats.filter(threat => {
            return threat.ip.includes(query) ||
                   (threat.path && threat.path.toLowerCase().includes(query)) ||
                   (threat.threats && threat.threats.some(t => t.toLowerCase().includes(query)));
        });
        
        applyFilters(threats);
    });
    
    // Checkboxes sévérité
    document.querySelectorAll('.severity-filter-cb').forEach(cb => {
        cb.addEventListener('change', () => {
            applyFilters(threats);
        });
    });
}

/**
 * Applique les filtres
 */
function applyFilters(threats) {
    const query = searchInput.value.toLowerCase();
    const selectedSeverities = Array.from(document.querySelectorAll('.severity-filter-cb:checked'))
        .map(cb => cb.value);
    
    const filtered = threats.filter(threat => {
        // Filtre sévérité
        if (!selectedSeverities.includes(threat.severity)) return false;
        
        // Filtre recherche
        if (query) {
            return threat.ip.includes(query) ||
                   (threat.path && threat.path.toLowerCase().includes(query)) ||
                   (threat.threats && threat.threats.some(t => t.toLowerCase().includes(query)));
        }
        
        return true;
    });
    
    displayThreatTable(threats, filtered);
}

/**
 * Exporte en CSV
 */
document.getElementById('exportCSV')?.addEventListener('click', () => {
    exportToCSV(currentAnalysisData, `log-analysis-${new Date().getTime()}.csv`);
});

/**
 * Exporte en JSON
 */
document.getElementById('exportJSON')?.addEventListener('click', () => {
    exportToJSON(currentAnalysisData, `log-analysis-${new Date().getTime()}.json`);
});

/**
 * Exporte en PDF (basique)
 */
document.getElementById('exportPDF')?.addEventListener('click', () => {
    let pdfContent = 'LOG ANALYZER - RAPPORT D\'ANALYSE\n\n';
    pdfContent += `Généré le: ${new Date().toLocaleString('fr-FR')}\n\n`;
    pdfContent += `Total d\'entrées analysées: ${currentParser.logs.length}\n`;
    pdfContent += `Menaces détectées: ${currentAnalysisData.length}\n\n`;
    pdfContent += '--- MENACES ---\n\n';
    
    currentAnalysisData.forEach(threat => {
        pdfContent += `IP: ${threat.ip}\n`;
        pdfContent += `Sévérité: ${threat.severity}\n`;
        pdfContent += `Menaces: ${(threat.threats || []).join(', ')}\n`;
        pdfContent += `Path: ${threat.path || 'N/A'}\n`;
        pdfContent += '---\n';
    });
    
    downloadFile(pdfContent, `log-analysis-${new Date().getTime()}.txt`, 'text/plain');
});

/**
 * Bloque une IP (simulé)
 */
function blockIP(ip) {
    alert(`IP ${ip} serait bloquée dans un vrai SOC!\n\nActions recommandées:\n✅ Ajouter à la liste noire\n✅ Bloquer au firewall\n✅ Augmenter la surveillance\n✅ Notifier le security team`);
}