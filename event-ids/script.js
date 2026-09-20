// ============================================
// DATABASE - Load from data.json
// ============================================
let eventIDs = []; // Will be populated by fetch

// ============================================
// RENDER FUNCTIONS
// ============================================
const eventGrid = document.getElementById('eventGrid');
const searchInput = document.getElementById('searchInput');
const categoryFilter = document.getElementById('categoryFilter');
const resultCount = document.getElementById('resultCount');
const noResults = document.getElementById('noResults');
const modal = document.getElementById('modal');
const modalBody = document.getElementById('modalBody');
const modalClose = document.getElementById('modalClose');

function renderCards(data) {
    eventGrid.innerHTML = '';
    resultCount.textContent = data.length;

    if (data.length === 0) {
        noResults.style.display = 'block';
        return;
    }
    noResults.style.display = 'none';

    data.forEach(event => {
        const card = document.createElement('div');
        card.className = 'event-card';
        card.innerHTML = `
            <div class="event-card-header">
                <span class="event-id-number" style="color:${getSeverityColor(event.severity)}">${event.id}</span>
                <span class="severity-badge severity-${event.severity.toLowerCase()}">${event.severity}</span>
            </div>
            <h3 class="event-title">${event.name}</h3>
            <p class="event-description">${event.description}</p>
            <div class="event-mitre">
                ${event.mitre.map(t => `<span class="mitre-tag">${t}</span>`).join('')}
            </div>
        `;
        card.addEventListener('click', () => openModal(event));
        eventGrid.appendChild(card);
    });
}

function getSeverityColor(sev) {
    const colors = {
        'INFO': '#00d9ff',
        'LOW': '#00ff41',
        'MEDIUM': '#ffa500',
        'HIGH': '#ff4444',
        'CRITICAL': '#ff0000'
    };
    return colors[sev] || '#fff';
}

function openModal(event) {
    const mitreDisplay = event.mitre.map((t, i) => 
        `${t}${event.mitreNames && event.mitreNames[i] ? ' - ' + event.mitreNames[i] : ''}`
    ).join('<br>');

    modalBody.innerHTML = `
        <h2>${event.id} - ${event.name}</h2>
        <span class="severity-badge severity-${event.severity.toLowerCase()}">${event.severity}</span>
        
        <div class="modal-section">
            <h3>📝 Description</h3>
            <p>${event.description}</p>
            <p>${event.detailedDescription}</p>
        </div>

        <div class="modal-section">
            <h3>🎯 MITRE ATT&CK</h3>
            <p>${mitreDisplay || 'N/A'}</p>
        </div>

        <div class="modal-section">
            <h3>⚠️ False Positives</h3>
            <ul>
                ${(event.falsePositives || []).map(fp => `<li>${fp}</li>`).join('')}
            </ul>
        </div>

        <div class="modal-section">
            <h3>🔍 Detection Strategy</h3>
            <p>${event.detectionStrategy || 'N/A'}</p>
        </div>

        <div class="modal-section">
            <h3>🚩 Red Flags</h3>
            <ul>
                ${(event.redFlags || []).map(rf => `<li>${rf}</li>`).join('')}
            </ul>
        </div>

        <div class="modal-section">
            <h3>📊 SPL Query (Splunk)</h3>
            <div class="code-block">${event.queries?.splunk || 'N/A'}</div>
        </div>

        <div class="modal-section">
            <h3>🔷 KQL Query (Sentinel)</h3>
            <div class="code-block">${event.queries?.kql || 'N/A'}</div>
        </div>

        <div class="modal-section">
            <h3>🔗 Related Events</h3>
            <p>${(event.relatedEvents || []).join(', ') || 'None'}</p>
        </div>

        <div class="modal-section">
            <h3>📚 Difficulty</h3>
            <p>${event.difficulty || 'Unknown'}</p>
        </div>
    `;
    modal.classList.add('active');
}

modalClose.addEventListener('click', () => {
    modal.classList.remove('active');
});

modal.addEventListener('click', (e) => {
    if (e.target === modal) modal.classList.remove('active');
});

// ============================================
// FILTER & SEARCH LOGIC
// ============================================
function filterEvents() {
    const searchTerm = searchInput.value.toLowerCase();
    const category = categoryFilter.value;

    const filtered = eventIDs.filter(event => {
        const matchesSearch = 
            event.id.toString().toLowerCase().includes(searchTerm) ||
            event.name.toLowerCase().includes(searchTerm) ||
            event.description.toLowerCase().includes(searchTerm);
        
        const matchesCategory = category === 'all' || event.category === category;

        return matchesSearch && matchesCategory;
    });

    renderCards(filtered);
}

searchInput.addEventListener('input', filterEvents);
categoryFilter.addEventListener('change', filterEvents);

// ============================================
// LOAD DATA FROM JSON & INITIALIZE
// ============================================
async function initializeApp() {
    try {
        console.log('[INIT] Starting Event ID Database...');
        console.log('[FETCH] Loading data.json from:', window.location.pathname);
        
        const response = await fetch('data.json');
        console.log('[FETCH] Response status:', response.status);
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: Failed to load data.json`);
        }
        
        const data = await response.json();
        console.log('[PARSE] Raw data structure:', typeof data, Array.isArray(data) ? 'array' : 'object');
        
        // FIX #1: Handle both array and object with eventIds property
        eventIDs = Array.isArray(data) ? data : (data.eventIds || []);
        
        console.log('[PARSE] Successfully loaded', eventIDs.length, 'events');
        console.log('[SAMPLE] First event:', eventIDs[0]);
        
        renderCards(eventIDs);
        console.log('[RENDER] Cards rendered successfully');
        
    } catch (error) {
        console.error('[ERROR]', error.name, '→', error.message);
        console.error('[STACK]', error.stack);
        eventGrid.innerHTML = `<p style="color: #ff4444;"><strong>❌ ${error.name}:</strong> ${error.message}</p>`;
    }
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', initializeApp);