/* ============================================
   NCRC UI CONTROLLER
   Main Interface Control System
   ============================================ */

class UIController {
    constructor() {
        this.currentTab = 'overview';
        this.selectedPackets = new Set();
        this.isCapturing = false;
        this.packetTable = null;
        this.charts = new Map();
        this.modals = new Map();
        this.notifications = [];
        this.preferences = this._loadPreferences();
        this.darkMode = this.preferences.darkMode !== false;
        this.init();
    }

    /* ============================================
       INITIALIZATION
       ============================================ */

    init() {
        this._setupEventListeners();
        this._setupTheme();
        this._initializeDataTable();
        this._setupDragAndDrop();
        this._setupKeyboardShortcuts();
        this._setupNotificationCenter();
        this._setupStatusBar();
        console.log('✅ UI Controller initialized');
    }

    /* ============================================
       EVENT LISTENERS
       ============================================ */

    _setupEventListeners() {
        // File upload
        const fileInput = document.getElementById('pcap-file-input');
        if (fileInput) {
            fileInput.addEventListener('change', (e) => this._handleFileUpload(e));
        }

        // Tab navigation
        document.querySelectorAll('[data-tab]').forEach(tab => {
            tab.addEventListener('click', (e) => this._switchTab(e.target.dataset.tab));
        });

        // Export buttons
        document.getElementById('export-json')?.addEventListener('click', () => this._exportAs('json'));
        document.getElementById('export-csv')?.addEventListener('click', () => this._exportAs('csv'));
        document.getElementById('export-pcap')?.addEventListener('click', () => this._exportAs('pcap'));
        document.getElementById('export-html')?.addEventListener('click', () => this._exportAs('html'));
        document.getElementById('export-pdf')?.addEventListener('click', () => this._exportAs('pdf'));

        // Filter controls
        document.getElementById('filter-btn')?.addEventListener('click', () => this._openFilterModal());
        document.getElementById('clear-filters')?.addEventListener('click', () => this._clearAllFilters());
        document.getElementById('save-filter')?.addEventListener('click', () => this._saveFilter());

        // Capture controls
        document.getElementById('start-capture')?.addEventListener('click', () => this._startCapture());
        document.getElementById('stop-capture')?.addEventListener('click', () => this._stopCapture());
        document.getElementById('pause-capture')?.addEventListener('click', () => this._pauseCapture());

        // Packet table
        document.getElementById('packet-table')?.addEventListener('click', (e) => this._handlePacketTableClick(e));
        document.getElementById('packet-table')?.addEventListener('dblclick', (e) => this._handlePacketTableDoubleClick(e));

        // Search
        document.getElementById('packet-search')?.addEventListener('input', (e) => this._handleSearch(e.target.value));
        document.getElementById('packet-search')?.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') this._executeSearch(e.target.value);
        });

        // Settings
        document.getElementById('settings-btn')?.addEventListener('click', () => this._openSettings());
        document.getElementById('preferences-save')?.addEventListener('click', () => this._savePreferences());

        // Analytics
        document.getElementById('refresh-analytics')?.addEventListener('click', () => this._refreshAnalytics());

        // Packet details
        document.querySelectorAll('[data-packet-action]').forEach(btn => {
            btn.addEventListener('click', (e) => this._handlePacketAction(e.target.dataset.packetAction));
        });

        // Window events
        window.addEventListener('beforeunload', (e) => this._handleBeforeUnload(e));
        window.addEventListener('resize', () => this._handleWindowResize());
    }

    /* ============================================
       TAB SWITCHING
       ============================================ */

    _switchTab(tabName) {
        // Hide all tabs
        document.querySelectorAll('.tab-content').forEach(tab => {
            tab.classList.remove('active');
            tab.style.display = 'none';
        });

        // Show selected tab
        const selectedTab = document.getElementById(`tab-${tabName}`);
        if (selectedTab) {
            selectedTab.classList.add('active');
            selectedTab.style.display = 'block';
        }

        // Update button state
        document.querySelectorAll('[data-tab]').forEach(btn => {
            btn.classList.remove('active');
        });
        document.querySelector(`[data-tab="${tabName}"]`)?.classList.add('active');

        this.currentTab = tabName;

        // Load tab-specific data
        switch (tabName) {
            case 'overview':
                this._loadOverviewTab();
                break;
            case 'packets':
                this._loadPacketsTab();
                break;
            case 'analysis':
                this._loadAnalysisTab();
                break;
            case 'security':
                this._loadSecurityTab();
                break;
            case 'statistics':
                this._loadStatisticsTab();
                break;
            case 'export':
                this._loadExportTab();
                break;
        }
    }

    /* ============================================
       FILE UPLOAD HANDLING
       ============================================ */

    _handleFileUpload(event) {
        const files = event.target.files;
        if (!files || files.length === 0) return;

        const file = files[0];
        const isValidPcap = file.name.endsWith('.pcap') || 
                           file.name.endsWith('.pcapng') ||
                           file.type === 'application/octet-stream';

        if (!isValidPcap) {
            this._showNotification('Invalid file format. Please upload a PCAP file.', 'error');
            return;
        }

        this._showNotification(`📁 Processing ${file.name}...`, 'info');

        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                const arrayBuffer = e.target.result;
                
                // Emit event to trigger parsing
                window.dispatchEvent(new CustomEvent('pcap-file-selected', {
                    detail: {
                        file: file,
                        buffer: arrayBuffer
                    }
                }));

                this._showNotification(`✅ File loaded. Parsing packets...`, 'success');
            } catch (error) {
                this._showNotification(`❌ Error processing file: ${error.message}`, 'error');
            }
        };

        reader.readAsArrayBuffer(file);
    }

    /* ============================================
       PACKET TABLE INITIALIZATION
       ============================================ */

    _initializeDataTable() {
        const tableContainer = document.getElementById('packet-table-container');
        
        if (!tableContainer) return;

        // Create table structure
        tableContainer.innerHTML = `
            <table id="packet-table" class="packet-table">
                <thead>
                    <tr>
                        <th><input type="checkbox" id="select-all" /></th>
                        <th>#</th>
                        <th>Time</th>
                        <th>Source IP</th>
                        <th>Src Port</th>
                        <th>Destination IP</th>
                        <th>Dst Port</th>
                        <th>Protocol</th>
                        <th>Size</th>
                        <th>Info</th>
                    </tr>
                </thead>
                <tbody id="packet-table-body">
                </tbody>
            </table>
        `;

        // Select all checkbox
        document.getElementById('select-all')?.addEventListener('change', (e) => {
            document.querySelectorAll('.packet-row-checkbox').forEach(cb => {
                cb.checked = e.target.checked;
                const packetNum = cb.dataset.packetNum;
                if (e.target.checked) {
                    this.selectedPackets.add(packetNum);
                } else {
                    this.selectedPackets.delete(packetNum);
                }
            });
        });
    }

    /* ============================================
       POPULATE PACKET TABLE
       ============================================ */

    populatePacketTable(packets) {
        const tbody = document.getElementById('packet-table-body');
        if (!tbody) return;

        tbody.innerHTML = '';

        packets.forEach((packet, idx) => {
            const row = document.createElement('tr');
            row.className = 'packet-row';
            row.dataset.packetNum = packet.number;
            row.dataset.packetIndex = idx;

            const srcIP = packet.layers.ip?.srcIP || '-';
            const dstIP = packet.layers.ip?.dstIP || '-';
            const srcPort = packet.layers.tcp?.srcPort || packet.layers.udp?.srcPort || '-';
            const dstPort = packet.layers.tcp?.dstPort || packet.layers.udp?.dstPort || '-';
            const info = this._getPacketInfo(packet);

            row.innerHTML = `
                <td><input type="checkbox" class="packet-row-checkbox" data-packet-num="${packet.number}" /></td>
                <td><strong>${packet.number}</strong></td>
                <td><small>${packet.timestampDate}</small></td>
                <td class="ip-cell"><strong>${srcIP}</strong></td>
                <td>${srcPort}</td>
                <td class="ip-cell"><strong>${dstIP}</strong></td>
                <td>${dstPort}</td>
                <td><span class="protocol-badge protocol-${packet.protocol.toLowerCase()}">${packet.protocol}</span></td>
                <td><small>${packet.size} B</small></td>
                <td><small>${info}</small></td>
            `;

            // Add click handlers
            row.addEventListener('click', (e) => {
                if (e.target.type === 'checkbox') {
                    if (e.target.checked) {
                        this.selectedPackets.add(packet.number);
                    } else {
                        this.selectedPackets.delete(packet.number);
                    }
                } else {
                    this._showPacketDetails(packet);
                }
            });

            row.addEventListener('contextmenu', (e) => {
                e.preventDefault();
                this._showPacketContextMenu(e, packet);
            });

            tbody.appendChild(row);
        });

        this._updateTableStats(packets);
    }

    /* ============================================
       PACKET DETAILS MODAL
       ============================================ */

    _showPacketDetails(packet) {
        const modal = document.getElementById('packet-details-modal');
        if (!modal) return;

        const content = document.getElementById('packet-details-content');
        
        content.innerHTML = `
            <div class="packet-details">
                <div class="details-section">
                    <h3>Frame Information</h3>
                    <table class="details-table">
                        <tr>
                            <td><strong>Packet Number:</strong></td>
                            <td>${packet.number}</td>
                        </tr>
                        <tr>
                            <td><strong>Timestamp:</strong></td>
                            <td>${packet.timestampDate}</td>
                        </tr>
                        <tr>
                            <td><strong>Frame Length:</strong></td>
                            <td>${packet.size} bytes</td>
                        </tr>
                        <tr>
                            <td><strong>Arrival Time:</strong></td>
                            <td>${new Date(packet.timestamp * 1000).toISOString()}</td>
                        </tr>
                    </table>
                </div>

                ${packet.layers.ethernet ? `
                <div class="details-section">
                    <h3>Ethernet II</h3>
                    <table class="details-table">
                        <tr>
                            <td><strong>Destination MAC:</strong></td>
                            <td><code>${packet.layers.ethernet.dstMac}</code></td>
                        </tr>
                        <tr>
                            <td><strong>Source MAC:</strong></td>
                            <td><code>${packet.layers.ethernet.srcMac}</code></td>
                        </tr>
                        <tr>
                            <td><strong>Type:</strong></td>
                            <td><code>0x${packet.layers.ethernet.type.toString(16).padStart(4, '0')}</code></td>
                        </tr>
                    </table>
                </div>
                ` : ''}

                ${packet.layers.ip ? `
                <div class="details-section">
                    <h3>Internet Protocol Version ${packet.layers.ip.version}</h3>
                    <table class="details-table">
                        <tr>
                            <td><strong>Source IP:</strong></td>
                            <td><strong>${packet.layers.ip.srcIP}</strong></td>
                        </tr>
                        <tr>
                            <td><strong>Destination IP:</strong></td>
                            <td><strong>${packet.layers.ip.dstIP}</strong></td>
                        </tr>
                        <tr>
                            <td><strong>TTL:</strong></td>
                            <td>${packet.layers.ip.TTL}</td>
                        </tr>
                        <tr>
                            <td><strong>Total Length:</strong></td>
                            <td>${packet.layers.ip.totalLength} bytes</td>
                        </tr>
                        <tr>
                            <td><strong>Protocol:</strong></td>
                            <td>${this._getIPProtocolName(packet.layers.ip.protocol)}</td>
                        </tr>
                        <tr>
                            <td><strong>Flags:</strong></td>
                            <td>
                                ${packet.layers.ip.dontFragment ? '<span class="flag-badge">DF</span>' : ''}
                                ${packet.layers.ip.moreFragments ? '<span class="flag-badge">MF</span>' : ''}
                            </td>
                        </tr>
                    </table>
                </div>
                ` : ''}

                ${packet.layers.tcp ? `
                <div class="details-section">
                    <h3>Transmission Control Protocol</h3>
                    <table class="details-table">
                        <tr>
                            <td><strong>Source Port:</strong></td>
                            <td><strong>${packet.layers.tcp.srcPort}</strong></td>
                        </tr>
                        <tr>
                            <td><strong>Destination Port:</strong></td>
                            <td><strong>${packet.layers.tcp.dstPort}</strong></td>
                        </tr>
                        <tr>
                            <td><strong>Sequence Number:</strong></td>
                            <td><code>${packet.layers.tcp.sequence}</code></td>
                        </tr>
                        <tr>
                            <td><strong>Acknowledgment Number:</strong></td>
                            <td><code>${packet.layers.tcp.acknowledgment}</code></td>
                        </tr>
                        <tr>
                            <td><strong>Window Size:</strong></td>
                            <td>${packet.layers.tcp.windowSize}</td>
                        </tr>
                        <tr>
                            <td><strong>Flags:</strong></td>
                            <td>
                                ${packet.layers.tcp.flags.SYN ? '<span class="flag-badge syn">SYN</span>' : ''}
                                ${packet.layers.tcp.flags.ACK ? '<span class="flag-badge ack">ACK</span>' : ''}
                                ${packet.layers.tcp.flags.FIN ? '<span class="flag-badge fin">FIN</span>' : ''}
                                ${packet.layers.tcp.flags.RST ? '<span class="flag-badge rst">RST</span>' : ''}
                                ${packet.layers.tcp.flags.PSH ? '<span class="flag-badge psh">PSH</span>' : ''}
                                ${packet.layers.tcp.flags.URG ? '<span class="flag-badge urg">URG</span>' : ''}
                            </td>
                        </tr>
                    </table>
                </div>
                ` : ''}

                ${packet.layers.udp ? `
                <div class="details-section">
                    <h3>User Datagram Protocol</h3>
                    <table class="details-table">
                        <tr>
                            <td><strong>Source Port:</strong></td>
                            <td><strong>${packet.layers.udp.srcPort}</strong></td>
                        </tr>
                        <tr>
                            <td><strong>Destination Port:</strong></td>
                            <td><strong>${packet.layers.udp.dstPort}</strong></td>
                        </tr>
                        <tr>
                            <td><strong>Length:</strong></td>
                            <td>${packet.layers.udp.length} bytes</td>
                        </tr>
                    </table>
                </div>
                ` : ''}

                ${packet.layers.dns ? `
                <div class="details-section">
                    <h3>Domain Name System</h3>
                    <table class="details-table">
                        <tr>
                            <td><strong>Transaction ID:</strong></td>
                            <td><code>${packet.layers.dns.transactionID}</code></td>
                        </tr>
                        <tr>
                            <td><strong>Type:</strong></td>
                            <td>${packet.layers.dns.isResponse ? 'Response' : 'Query'}</td>
                        </tr>
                        ${packet.layers.dns.queries ? `
                        <tr>
                            <td><strong>Queries:</strong></td>
                            <td>
                                ${packet.layers.dns.queries.map(q => `<div><code>${q}</code></div>`).join('')}
                            </td>
                        </tr>
                        ` : ''}
                        ${packet.layers.dns.answers ? `
                        <tr>
                            <td><strong>Answers:</strong></td>
                            <td>
                                ${packet.layers.dns.answers.map(a => `<div><code>${a}</code></div>`).join('')}
                            </td>
                        </tr>
                        ` : ''}
                    </table>
                </div>
                ` : ''}

                ${packet.layers.http ? `
                <div class="details-section">
                    <h3>HyperText Transfer Protocol</h3>
                    <table class="details-table">
                        ${packet.layers.http.request ? `
                        <tr>
                            <td><strong>Method:</strong></td>
                            <td><span class="http-method">${packet.layers.http.request.method}</span></td>
                        </tr>
                        <tr>
                            <td><strong>URI:</strong></td>
                            <td><code>${packet.layers.http.request.uri}</code></td>
                        </tr>
                        <tr>
                            <td><strong>Version:</strong></td>
                            <td>${packet.layers.http.request.version}</td>
                        </tr>
                        <tr>
                            <td><strong>User-Agent:</strong></td>
                            <td><small>${packet.layers.http.request.userAgent || 'N/A'}</small></td>
                        </tr>
                        ` : ''}
                        ${packet.layers.http.response ? `
                        <tr>
                            <td><strong>Status Code:</strong></td>
                            <td><span class="http-status status-${Math.floor(packet.layers.http.response.statusCode / 100)}xx">${packet.layers.http.response.statusCode}</span></td>
                        </tr>
                        <tr>
                            <td><strong>Status Message:</strong></td>
                            <td>${packet.layers.http.response.statusMessage}</td>
                        </tr>
                        ` : ''}
                    </table>
                </div>
                ` : ''}

                ${packet.payload ? `
                <div class="details-section">
                    <h3>Payload Data</h3>
                    <div class="payload-view">
                        <div class="hex-view">
                            ${this._formatHexPayload(packet.payload)}
                        </div>
                        <div class="ascii-view">
                            ${this._formatAsciiPayload(packet.payload)}
                        </div>
                    </div>
                </div>
                ` : ''}
            </div>
        `;

        // Show modal
        modal.style.display = 'flex';
    }

    /* ============================================
       FILTER MODAL
       ============================================ */

    _openFilterModal() {
        const modal = document.getElementById('filter-modal');
        if (!modal) return;

        const content = document.getElementById('filter-content');
        content.innerHTML = `
            <div class="filter-builder">
                <div class="filter-row">
                    <label>Filter Type:</label>
                    <select id="filter-type-select">
                        <option value="">-- Select --</option>
                        <option value="ip">IP Address</option>
                        <option value="port">Port</option>
                        <option value="protocol">Protocol</option>
                        <option value="size">Packet Size</option>
                        <option value="time">Time Range</option>
                        <option value="flags">TCP Flags</option>
                    </select>
                </div>

                <div id="filter-options" class="filter-options"></div>

                <div class="filter-actions">
                    <button id="apply-filter" class="btn btn-primary">Apply Filter</button>
                    <button id="add-filter-condition" class="btn btn-secondary">Add Condition</button>
                    <button id="reset-filter" class="btn btn-danger">Reset</button>
                </div>
            </div>
        `;

        document.getElementById('filter-type-select')?.addEventListener('change', (e) => {
            this._updateFilterOptions(e.target.value);
        });

        document.getElementById('apply-filter')?.addEventListener('click', () => {
            this._applyCustomFilter();
            modal.style.display = 'none';
        });

        modal.style.display = 'flex';
    }

    _updateFilterOptions(filterType) {
        const optionsDiv = document.getElementById('filter-options');
        
        switch (filterType) {
            case 'ip':
                optionsDiv.innerHTML = `
                    <div class="filter-row">
                        <label>IP Address:</label>
                        <input type="text" id="filter-ip" placeholder="e.g., 192.168.1.1" />
                    </div>
                    <div class="filter-row">
                        <label>Direction:</label>
                        <select id="filter-ip-direction">
                            <option value="any">Any</option>
                            <option value="src">Source Only</option>
                            <option value="dst">Destination Only</option>
                        </select>
                    </div>
                `;
                break;

            case 'port':
                optionsDiv.innerHTML = `
                    <div class="filter-row">
                        <label>Port Number:</label>
                        <input type="number" id="filter-port" placeholder="e.g., 80" />
                    </div>
                    <div class="filter-row">
                        <label>Direction:</label>
                        <select id="filter-port-direction">
                            <option value="any">Any</option>
                            <option value="src">Source Only</option>
                            <option value="dst">Destination Only</option>
                        </select>
                    </div>
                `;
                break;

            case 'protocol':
                optionsDiv.innerHTML = `
                    <div class="filter-row">
                        <label>Protocol:</label>
                        <select id="filter-protocol">
                            <option value="">-- Select --</option>
                            <option value="TCP">TCP</option>
                            <option value="UDP">UDP</option>
                            <option value="ICMP">ICMP</option>
                            <option value="DNS">DNS</option>
                            <option value="HTTP">HTTP</option>
                            <option value="HTTPS">HTTPS</option>
                            <option value="SSH">SSH</option>
                            <option value="FTP">FTP</option>
                        </select>
                    </div>
                `;
                break;

            case 'size':
                optionsDiv.innerHTML = `
                    <div class="filter-row">
                        <label>Minimum Size (bytes):</label>
                        <input type="number" id="filter-size-min" />
                    </div>
                    <div class="filter-row">
                        <label>Maximum Size (bytes):</label>
                        <input type="number" id="filter-size-max" />
                    </div>
                `;
                break;

            case 'time':
                optionsDiv.innerHTML = `
                    <div class="filter-row">
                        <label>Start Time:</label>
                        <input type="datetime-local" id="filter-time-start" />
                    </div>
                    <div class="filter-row">
                        <label>End Time:</label>
                        <input type="datetime-local" id="filter-time-end" />
                    </div>
                `;
                break;

            case 'flags':
                optionsDiv.innerHTML = `
                    <div class="filter-row">
                        <label>TCP Flags:</label>
                        <div class="checkbox-group">
                            <label><input type="checkbox" value="SYN" class="flag-checkbox" /> SYN</label>
                            <label><input type="checkbox" value="ACK" class="flag-checkbox" /> ACK</label>
                            <label><input type="checkbox" value="FIN" class="flag-checkbox" /> FIN</label>
                            <label><input type="checkbox" value="RST" class="flag-checkbox" /> RST</label>
                            <label><input type="checkbox" value="PSH" class="flag-checkbox" /> PSH</label>
                            <label><input type="checkbox" value="URG" class="flag-checkbox" /> URG</label>
                        </div>
                    </div>
                `;
                break;
        }
    }

    /* ============================================
       EXPORT FUNCTIONALITY
       ============================================ */

    _exportAs(format) {
        const selectedCount = this.selectedPackets.size;
        const packets = selectedCount > 0 
            ? Array.from(this.allPackets).filter(p => this.selectedPackets.has(p.number))
            : this.allPackets;

        if (packets.length === 0) {
            this._showNotification('No packets to export', 'warning');
            return;
        }

        this._showNotification(`📤 Exporting ${packets.length} packets as ${format.toUpperCase()}...`, 'info');

        let content, filename, mimeType;

        switch (format) {
            case 'json':
                content = window.exportEngine.exportJSON(packets, { prettify: true });
                filename = `ncrc-export-${Date.now()}.json`;
                mimeType = 'application/json';
                break;

            case 'csv':
                content = window.exportEngine.exportCSV(packets);
                filename = `ncrc-export-${Date.now()}.csv`;
                mimeType = 'text/csv';
                break;

            case 'pcap':
                content = window.exportEngine.exportPCAP(packets);
                filename = `ncrc-export-${Date.now()}.pcap`;
                mimeType = 'application/octet-stream';
                break;

            case 'html':
                content = window.exportEngine.exportHTML(packets, window.analysisEngine.analysis);
                filename = `ncrc-export-${Date.now()}.html`;
                mimeType = 'text/html';
                break;

            case 'pdf':
                this._showNotification('PDF export requires additional library', 'info');
                return;

            case 'xml':
                content = window.exportEngine.exportXML(packets);
                filename = `ncrc-export-${Date.now()}.xml`;
                mimeType = 'application/xml';
                break;
        }

        window.exportEngine.downloadFile(content, filename, mimeType);
        this._showNotification(`✅ Exported as ${filename}`, 'success');
        window.exportEngine.recordExport(filename, format, new Blob([content]).size, 0);
    }

    /* ============================================
       SEARCH FUNCTIONALITY
       ============================================ */

    _handleSearch(query) {
        if (!query) {
            this.populatePacketTable(this.allPackets);
            return;
        }

        const searchResults = this.allPackets.filter(packet => {
            const searchStr = query.toLowerCase();
            return (
                packet.number.toString().includes(searchStr) ||
                packet.layers.ip?.srcIP?.includes(searchStr) ||
                packet.layers.ip?.dstIP?.includes(searchStr) ||
                packet.protocol.toLowerCase().includes(searchStr) ||
                packet.layers.tcp?.srcPort?.toString().includes(searchStr) ||
                packet.layers.tcp?.dstPort?.toString().includes(searchStr) ||
                packet.layers.udp?.srcPort?.toString().includes(searchStr) ||
                packet.layers.udp?.dstPort?.toString().includes(searchStr)
            );
        });

        this.populatePacketTable(searchResults);
        this._showNotification(`Found ${searchResults.length} packets`, 'info');
    }

    /* ============================================
       NOTIFICATION SYSTEM
       ============================================ */

    _setupNotificationCenter() {
        const container = document.createElement('div');
        container.id = 'notification-container';
        container.className = 'notification-container';
        document.body.appendChild(container);
    }

    _showNotification(message, type = 'info', duration = 5000) {
        const container = document.getElementById('notification-container');
        
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <span>${message}</span>
                <button class="notification-close">&times;</button>
            </div>
        `;

        notification.querySelector('.notification-close').addEventListener('click', () => {
            notification.remove();
        });

        container.appendChild(notification);

        if (duration > 0) {
            setTimeout(() => notification.remove(), duration);
        }

        this.notifications.push({
            timestamp: Date.now(),
            message: message,
            type: type
        });
    }

    /* ============================================
       THEME MANAGEMENT
       ============================================ */

    _setupTheme() {
        const root = document.documentElement;
        
        if (this.darkMode) {
            root.setAttribute('data-theme', 'dark');
            document.body.classList.add('dark-mode');
        } else {
            root.setAttribute('data-theme', 'light');
            document.body.classList.remove('dark-mode');
        }
    }

    toggleDarkMode() {
        this.darkMode = !this.darkMode;
        this._setupTheme();
        this._savePreferences();
    }

    /* ============================================
       HELPER FUNCTIONS
       ============================================ */

    _getPacketInfo(packet) {
        if (packet.layers.http) {
            return `HTTP ${packet.layers.http.request?.method || 'Response'}`;
        }
        if (packet.layers.dns) {
            return `DNS ${packet.layers.dns.isResponse ? 'Response' : 'Query'}`;
        }
        if (packet.layers.ssh) {
            return `SSH`;
        }
        return `${packet.protocol} Data`;
    }

    _getIPProtocolName(protocolNumber) {
        const protocols = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP',
            47: 'GRE',
            50: 'ESP',
            51: 'AH'
        };
        return protocols[protocolNumber] || `Unknown (${protocolNumber})`;
    }

    _formatHexPayload(payload) {
        const hex = payload.match(/.{1,2}/g) || [];
        return hex.map(h => `<span class="hex-byte">${h}</span>`).join('');
    }

    _formatAsciiPayload(payload) {
        return payload.split('').map(char => {
            const code = char.charCodeAt(0);
            return (code >= 32 && code <= 126) ? char : '.';
        }).join('');
    }

    _updateTableStats(packets) {
        const stats = document.getElementById('table-stats');
        if (stats) {
            stats.textContent = `Showing ${packets.length} packets`;
        }
    }

    _handleWindowResize() {
        // Resize charts and tables
        if (this.packetTable) {
            this.packetTable.draw();
        }
    }

    _savePreferences() {
        localStorage.setItem('ncrc-preferences', JSON.stringify({
            darkMode: this.darkMode
        }));
    }

    _loadPreferences() {
        const prefs = localStorage.getItem('ncrc-preferences');
        return prefs ? JSON.parse(prefs) : { darkMode: true };
    }

    _startCapture() {
        this.isCapturing = true;
        this._showNotification('🎯 Packet capture started...', 'success');
    }

    _stopCapture() {
        this.isCapturing = false;
        this._showNotification('⏹️ Packet capture stopped', 'info');
    }

    _pauseCapture() {
        this.isCapturing = false;
        this._showNotification('⏸️ Packet capture paused', 'info');
    }

    _loadOverviewTab() {
        console.log('Loading overview tab...');
    }

    _loadPacketsTab() {
        console.log('Loading packets tab...');
    }

    _loadAnalysisTab() {
        console.log('Loading analysis tab...');
    }

    _loadSecurityTab() {
        console.log('Loading security tab...');
    }

    _loadStatisticsTab() {
        console.log('Loading statistics tab...');
    }

    _loadExportTab() {
        console.log('Loading export tab...');
    }

    _handleBeforeUnload(e) {
        if (this.isCapturing) {
            e.preventDefault();
            e.returnValue = 'Packet capture in progress. Are you sure?';
        }
    }

    _setupDragAndDrop() {
        const dropZone = document.getElementById('drop-zone');
        if (!dropZone) return;

        dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            dropZone.classList.add('drag-over');
        });

        dropZone.addEventListener('dragleave', () => {
            dropZone.classList.remove('drag-over');
        });

        dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            dropZone.classList.remove('drag-over');
            
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                const event = new Event('change');
                Object.defineProperty(event, 'target', {
                    value: { files: files },
                    enumerable: false
                });
                this._handleFileUpload(event);
            }
        });
    }

    _setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl+E: Export
            if (e.ctrlKey && e.key === 'e') {
                e.preventDefault();
                document.getElementById('export-json')?.click();
            }

            // Ctrl+F: Filter
            if (e.ctrlKey && e.key === 'f') {
                e.preventDefault();
                this._openFilterModal();
            }

            // Ctrl+S: Save preferences
            if (e.ctrlKey && e.key === 's') {
                e.preventDefault();
                this._savePreferences();
            }

            // Esc: Close modals
            if (e.key === 'Escape') {
                document.querySelectorAll('.modal').forEach(m => m.style.display = 'none');
            }
        });
    }

    _setupStatusBar() {
        const statusBar = document.getElementById('status-bar');
        if (statusBar) {
            statusBar.innerHTML = `
                <div class="status-item">
                    <span id="status-packets">Packets: 0</span>
                </div>
                <div class="status-item">
                    <span id="status-size">Size: 0 MB</span>
                </div>
                <div class="status-item">
                    <span id="status-time">Ready</span>
                </div>
            `;
        }
    }
}

if (typeof module !== 'undefined' && module.exports) {
    module.exports = UIController;
}