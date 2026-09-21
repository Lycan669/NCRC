/**
 * APP.JS - Logique principale
 */

let currentStats = null;
let currentThreats = null;
let currentPackets = null;

// DOM Elements
const fileInput = document.getElementById('fileInput');
const browseBtn = document.getElementById('browseBtn');
const uploadArea = document.getElementById('uploadArea');
const analyzeBtn = document.getElementById('analyzeBtn');
const exportBtn = document.getElementById('exportBtn');
const fileInfo = document.getElementById('fileInfo');
const loadingSpinner = document.getElementById('loadingSpinner');
const tabsContainer = document.getElementById('tabsContainer');
const emptyState = document.getElementById('emptyState');
const tabButtons = document.querySelectorAll('.tab-btn');
const tabContents = document.querySelectorAll('.tab-content');

// Event Listeners
browseBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', handleFileSelect);
analyzeBtn.addEventListener('click', analyzeFile);
exportBtn.addEventListener('click', exportReport);
uploadArea.addEventListener('dragover', handleDragOver);
uploadArea.addEventListener('dragleave', handleDragLeave);
uploadArea.addEventListener('drop', handleDrop);

tabButtons.forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
});

document.getElementById('flowSearch').addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase();
    const flows = document.querySelectorAll('.flow-item');

    flows.forEach(flow => {
        const text = flow.textContent.toLowerCase();
        flow.style.display = text.includes(query) ? 'block' : 'none';
    });
});

/**
 * Handle file selection
 */
function handleFileSelect(e) {
    const file = e.target.files[0];
    if (file) {
        loadFile(file);
    }
}

/**
 * Handle drag and drop
 */
function handleDragOver(e) {
    e.preventDefault();
    uploadArea.classList.add('dragover');
}

function handleDragLeave() {
    uploadArea.classList.remove('dragover');
}

function handleDrop(e) {
    e.preventDefault();
    uploadArea.classList.remove('dragover');
    const file = e.dataTransfer.files[0];
    if (file && (file.name.endsWith('.pcap') || file.name.endsWith('.pcapng'))) {
        loadFile(file);
    }
}

/**
 * Load file
 */
function loadFile(file) {
    document.getElementById('fileName').textContent = file.name;
    document.getElementById('fileSize').textContent = formatBytes(file.size);
    fileInfo.style.display = 'block';
    analyzeBtn.disabled = false;
}

/**
 * Analyze PCAP file
 */
async function analyzeFile() {
    const file = fileInput.files[0];
    if (!file) return;

    loadingSpinner.style.display = 'flex';
    emptyState.style.display = 'none';
    tabsContainer.style.display = 'none';

    try {
        // Parse PCAP
        const parser = new PCAPParser(file);
        currentPackets = await parser.parse();

        if (!currentPackets.length) {
            alert('No packets found in file');
            loadingSpinner.style.display = 'none';
            return;
        }

        // Calculate stats
        const statsCalc = new StatsCalculator(currentPackets);
        currentStats = statsCalc.calculateAll();

        // Analyze threats
        const threatAnalyzer = new ThreatAnalyzer(currentPackets, currentStats);
        currentThreats = threatAnalyzer.analyze();

        // Update UI
        updateUIStats(currentStats, currentThreats);

        // Show results
        loadingSpinner.style.display = 'none';
        tabsContainer.style.display = 'block';
        emptyState.style.display = 'none';
        exportBtn.disabled = false;

    } catch (error) {
        console.error('Error analyzing file:', error);
        alert(`Error: ${error.message}`);
        loadingSpinner.style.display = 'none';
    }
}

/**
 * Switch tabs
 */
function switchTab(tabName) {
    tabButtons.forEach(btn => btn.classList.remove('active'));
    tabContents.forEach(content => content.classList.remove('active'));

    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    document.getElementById(tabName).classList.add('active');
}

/**
 * Export report
 */
function exportReport() {
    if (!currentStats || !currentThreats) return;
    exportReportPDF(currentStats, currentThreats);
}

/**
 * Format bytes utility
 */
function formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}