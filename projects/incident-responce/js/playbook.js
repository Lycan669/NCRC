/* ============================================
   INCIDENT RESPONSE PLAYBOOK - JAVASCRIPT
   ============================================ */

/* ============================================
   TAB SYSTEM
   ============================================ */

class TabSystem {
  constructor() {
    this.tabs = document.querySelectorAll('.tab-btn');
    this.contents = document.querySelectorAll('.tab-content');
    this.init();
  }

  init() {
    this.tabs.forEach((tab, index) => {
      tab.addEventListener('click', (e) => {
        e.preventDefault();
        this.switchTab(index);
      });
    });

    // Set first tab as active on load
    if (this.tabs.length > 0) {
      this.tabs[0].classList.add('active');
      this.contents[0].classList.add('active');
    }
  }

  switchTab(index) {
    // Remove active class from all tabs and contents
    this.tabs.forEach(tab => tab.classList.remove('active'));
    this.contents.forEach(content => content.classList.remove('active'));

    // Add active class to selected tab and content
    this.tabs[index].classList.add('active');
    this.contents[index].classList.add('active');

    // Log for debugging
    console.log(`Switched to tab ${index + 1}`);
  }
}

/* ============================================
   COPY TO CLIPBOARD
   ============================================ */

class CodeCopier {
  constructor() {
    this.init();
  }

  init() {
    // Create copy button template
    const codeBlocks = document.querySelectorAll('.code-block');
    
    codeBlocks.forEach((block, index) => {
      const copyBtn = document.createElement('button');
      copyBtn.classList.add('copy-btn');
      copyBtn.innerHTML = '📋 Copy Code';
      copyBtn.dataset.index = index;

      // Insert button at the top of code block
      block.parentElement.insertBefore(copyBtn, block);

      copyBtn.addEventListener('click', () => {
        this.copyCode(block, copyBtn);
      });
    });
  }

  copyCode(codeBlock, button) {
    const code = codeBlock.innerText;
    
    navigator.clipboard.writeText(code).then(() => {
      // Change button text temporarily
      const originalText = button.innerHTML;
      button.innerHTML = '✅ Copied!';
      button.classList.add('copied');

      setTimeout(() => {
        button.innerHTML = originalText;
        button.classList.remove('copied');
      }, 2000);

      console.log('Code copied to clipboard');
    }).catch(err => {
      console.error('Failed to copy:', err);
      button.innerHTML = '❌ Failed to copy';
    });
  }
}

/* ============================================
   CHECKLIST HANDLER
   ============================================ */

class ChecklistHandler {
  constructor() {
    this.storageKey = 'playbook-checklist';
    this.init();
  }

  init() {
    const checkboxes = document.querySelectorAll('.checklist input[type="checkbox"]');
    
    checkboxes.forEach((checkbox, index) => {
      // Load saved state from localStorage
      const saved = this.getSavedState(index);
      if (saved) {
        checkbox.checked = true;
      }

      // Save state when changed
      checkbox.addEventListener('change', () => {
        this.saveState(index, checkbox.checked);
        this.updateProgress();
      });
    });

    this.updateProgress();
  }

  getSavedState(index) {
    const saved = localStorage.getItem(this.storageKey);
    if (!saved) return false;
    
    const states = JSON.parse(saved);
    return states[index] || false;
  }

  saveState(index, checked) {
    const saved = localStorage.getItem(this.storageKey);
    const states = saved ? JSON.parse(saved) : {};
    
    states[index] = checked;
    localStorage.setItem(this.storageKey, JSON.stringify(states));
  }

  updateProgress() {
    const checkboxes = document.querySelectorAll('.checklist input[type="checkbox"]');
    const checked = document.querySelectorAll('.checklist input[type="checkbox"]:checked').length;
    const total = checkboxes.length;
    const percentage = (checked / total) * 100;

    console.log(`Checklist progress: ${checked}/${total} (${percentage.toFixed(0)}%)`);
  }

  clearProgress() {
    localStorage.removeItem(this.storageKey);
    document.querySelectorAll('.checklist input[type="checkbox"]').forEach(cb => {
      cb.checked = false;
    });
    this.updateProgress();
  }
}

/* ============================================
   SEARCH & FILTER
   ============================================ */

class SearchFilter {
  constructor() {
    this.searchInput = document.querySelector('.search-input');
    this.cards = document.querySelectorAll('[data-searchable]');
    this.init();
  }

  init() {
    if (!this.searchInput) return;

    this.searchInput.addEventListener('input', (e) => {
      const query = e.target.value.toLowerCase();
      this.filterCards(query);
    });
  }

  filterCards(query) {
    let visibleCount = 0;

    this.cards.forEach(card => {
      const text = card.textContent.toLowerCase();
      
      if (text.includes(query)) {
        card.style.display = '';
        card.style.animation = 'fadeInUp 0.3s ease-out';
        visibleCount++;
      } else {
        card.style.display = 'none';
      }
    });

    console.log(`Search results: ${visibleCount} items found`);
  }
}

/* ============================================
   SYNTAX HIGHLIGHTER
   ============================================ */

class SyntaxHighlighter {
  constructor() {
    this.init();
  }

  init() {
    const codeBlocks = document.querySelectorAll('code');
    codeBlocks.forEach(block => {
      this.highlight(block);
    });
  }

  highlight(block) {
    const language = block.className.replace('language-', '');
    
    // Keywords mapping by language
    const keywords = {
      spl: ['index', 'search', 'stats', 'where', 'by', 'as', 'eval', 'dedup', 'sort'],
      kql: ['index', 'AND', 'OR', 'NOT', 'field', 'fields', 'where'],
      yaml: ['name', 'description', 'rule', 'detection', 'condition', 'action'],
      bash: ['sudo', 'grep', 'find', 'cat', 'echo', 'ls', 'cd', 'rm', 'mv'],
      powershell: ['Get-', 'Set-', 'New-', 'Remove-', 'Invoke-', 'Select-Object']
    };

    const keywords_list = keywords[language] || [];
    
    let html = block.innerHTML;
    keywords_list.forEach(keyword => {
      const regex = new RegExp(`\\b${keyword}\\b`, 'g');
      html = html.replace(regex, `<span class="keyword">${keyword}</span>`);
    });

    block.innerHTML = html;
  }
}

/* ============================================
   NOTIFICATION SYSTEM
   ============================================ */

class NotificationSystem {
  constructor() {
    this.container = document.createElement('div');
    this.container.classList.add('notifications-container');
    document.body.appendChild(this.container);
  }

  show(message, type = 'info', duration = 3000) {
    const notification = document.createElement('div');
    notification.classList.add('notification', `notification-${type}`);
    
    const icons = {
      success: '✅',
      error: '❌',
      warning: '⚠️',
      info: 'ℹ️'
    };

    notification.innerHTML = `
      <span class="notification-icon">${icons[type]}</span>
      <span class="notification-message">${message}</span>
    `;

    this.container.appendChild(notification);

    // Animate in
    setTimeout(() => notification.classList.add('show'), 10);

    // Auto remove
    setTimeout(() => {
      notification.classList.remove('show');
      setTimeout(() => notification.remove(), 300);
    }, duration);
  }

  success(message) {
    this.show(message, 'success');
  }

  error(message) {
    this.show(message, 'error');
  }

  warning(message) {
    this.show(message, 'warning');
  }

  info(message) {
    this.show(message, 'info');
  }
}

/* ============================================
   TIMELINE ANIMATION
   ============================================ */

class TimelineAnimator {
  constructor() {
    this.items = document.querySelectorAll('.timeline-item');
    this.init();
  }

  init() {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.style.animation = 'fadeInUp 0.6s ease-out forwards';
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.1 });

    this.items.forEach(item => {
      item.style.opacity = '0';
      observer.observe(item);
    });
  }
}

/* ============================================
   PRINT HANDLER
   ============================================ */

class PrintHandler {
  constructor() {
    this.createPrintButton();
  }

  createPrintButton() {
    const printBtn = document.createElement('button');
    printBtn.classList.add('print-btn');
    printBtn.innerHTML = '🖨️ Print Playbook';
    printBtn.addEventListener('click', () => this.print());
    
    const hero = document.querySelector('.playbook-hero');
    if (hero) {
      hero.appendChild(printBtn);
    }
  }

  print() {
    window.print();
  }
}

/* ============================================
   EXPORT HANDLER
   ============================================ */

class ExportHandler {
  constructor() {
    this.createExportButtons();
  }

  createExportButtons() {
    const container = document.createElement('div');
    container.classList.add('export-buttons');
    
    const formats = [
      { name: 'PDF', icon: '📄', format: 'pdf' },
      { name: 'JSON', icon: '📋', format: 'json' },
      { name: 'Markdown', icon: '📝', format: 'md' }
    ];

    formats.forEach(fmt => {
      const btn = document.createElement('button');
      btn.classList.add('export-btn');
      btn.innerHTML = `${fmt.icon} Export as ${fmt.name}`;
      btn.addEventListener('click', () => this.export(fmt.format));
      container.appendChild(btn);
    });

    const cta = document.querySelector('.cta-final');
    if (cta) {
      cta.appendChild(container);
    }
  }

  export(format) {
    const title = document.querySelector('h1').textContent;
    
    switch(format) {
      case 'json':
        this.exportJSON(title);
        break;
      case 'md':
        this.exportMarkdown(title);
        break;
      case 'pdf':
        window.print();
        break;
    }
  }

  exportJSON(title) {
    const data = {
      title: title,
      timestamp: new Date().toISOString(),
      content: document.querySelector('main').innerText
    };

    const json = JSON.stringify(data, null, 2);
    this.download(json, `${title.replace(/ /g, '-')}.json`, 'application/json');
  }

  exportMarkdown(title) {
    const content = document.querySelector('main').innerText;
    const markdown = `# ${title}\n\nExported on: ${new Date().toLocaleString()}\n\n${content}`;
    
    this.download(markdown, `${title.replace(/ /g, '-')}.md`, 'text/markdown');
  }

  download(content, filename, type) {
    const blob = new Blob([content], { type });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  }
}

/* ============================================
   DARK MODE TOGGLE
   ============================================ */

class ThemeToggle {
  constructor() {
    this.storageKey = 'playbook-theme';
    this.init();
  }

  init() {
    this.createToggle();
    this.loadTheme();
  }

  createToggle() {
    const toggle = document.createElement('button');
    toggle.classList.add('theme-toggle');
    toggle.innerHTML = '🌙';
    toggle.addEventListener('click', () => this.toggleTheme());
    
    const navbar = document.querySelector('.navbar');
    if (navbar) {
      navbar.appendChild(toggle);
    }
  }

  toggleTheme() {
    const current = localStorage.getItem(this.storageKey) || 'dark';
    const newTheme = current === 'dark' ? 'light' : 'dark';
    
    this.applyTheme(newTheme);
    localStorage.setItem(this.storageKey, newTheme);
  }

  loadTheme() {
    const theme = localStorage.getItem(this.storageKey) || 'dark';
    this.applyTheme(theme);
  }

  applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    const toggle = document.querySelector('.theme-toggle');
    if (toggle) {
      toggle.innerHTML = theme === 'dark' ? '☀️' : '🌙';
    }
  }
}

/* ============================================
   PERFORMANCE MONITORING
   ============================================ */

class PerformanceMonitor {
  constructor() {
    this.init();
  }

  init() {
    if ('PerformanceObserver' in window) {
      try {
        const observer = new PerformanceObserver((list) => {
          for (const entry of list.getEntries()) {
            console.log(`${entry.name}: ${entry.duration.toFixed(2)}ms`);
          }
        });

        observer.observe({ entryTypes: ['measure', 'navigation'] });
      } catch (e) {
        console.log('PerformanceObserver not fully supported');
      }
    }

    // Log page load time
    window.addEventListener('load', () => {
      const perfData = performance.timing;
      const pageLoadTime = perfData.loadEventEnd - perfData.navigationStart;
      console.log(`Page load time: ${pageLoadTime}ms`);
    });
  }
}

/* ============================================
   ANALYTICS TRACKING
   ============================================ */

class AnalyticsTracker {
  constructor() {
    this.init();
  }

  init() {
    // Track tab switches
    document.addEventListener('click', (e) => {
      if (e.target.classList.contains('tab-btn')) {
        this.trackEvent('tab_switch', {
          tab: e.target.textContent
        });
      }
    });

    // Track code copies
    document.addEventListener('click', (e) => {
      if (e.target.classList.contains('copy-btn')) {
        this.trackEvent('code_copied', {
          codeType: e.target.getAttribute('data-index')
        });
      }
    });

    // Track exports
    document.addEventListener('click', (e) => {
      if (e.target.classList.contains('export-btn')) {
        this.trackEvent('export', {
          format: e.target.textContent
        });
      }
    });
  }

  trackEvent(eventName, data = {}) {
    console.log(`📊 Event: ${eventName}`, data);
    
    // You can send this to your analytics service
    // Example: fetch('/api/analytics', { method: 'POST', body: JSON.stringify({ eventName, data }) })
  }
}

/* ============================================
   SCROLL SPY
   ============================================ */

class ScrollSpy {
  constructor() {
    this.sections = document.querySelectorAll('.playbook-section');
    this.init();
  }

  init() {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('in-view');
        }
      });
    }, { threshold: 0.3 });

    this.sections.forEach(section => {
      observer.observe(section);
    });
  }
}

/* ============================================
   KEYBOARD SHORTCUTS
   ============================================ */

class KeyboardShortcuts {
  constructor() {
    this.init();
  }

  init() {
    document.addEventListener('keydown', (e) => {
      // Ctrl/Cmd + P = Print
      if ((e.ctrlKey || e.metaKey) && e.key === 'p') {
        e.preventDefault();
        window.print();
      }

      // Ctrl/Cmd + K = Focus search
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        const searchInput = document.querySelector('.search-input');
        if (searchInput) searchInput.focus();
      }

      // Escape = Clear search
      if (e.key === 'Escape') {
        const searchInput = document.querySelector('.search-input');
        if (searchInput && document.activeElement === searchInput) {
          searchInput.value = '';
          searchInput.dispatchEvent(new Event('input'));
        }
      }
    });
  }
}

/* ============================================
   INITIALIZATION
   ============================================ */

document.addEventListener('DOMContentLoaded', () => {
  console.log('🚀 Initializing Playbook Systems...');

  // Initialize all systems
  new TabSystem();
  new CodeCopier();
  new ChecklistHandler();
  new SearchFilter();
  new SyntaxHighlighter();
  new NotificationSystem();
  new TimelineAnimator();
  new PrintHandler();
  new ExportHandler();
  new ThemeToggle();
  new PerformanceMonitor();
  new AnalyticsTracker();
  new ScrollSpy();
  new KeyboardShortcuts();

  console.log('✅ All systems initialized successfully!');
});

/* ============================================
   UTILITY FUNCTIONS
   ============================================ */

// Smooth scroll to element
function smoothScroll(elementId) {
  const element = document.getElementById(elementId);
  if (element) {
    element.scrollIntoView({ behavior: 'smooth' });
  }
}

// Toggle element visibility
function toggleElement(elementId) {
  const element = document.getElementById(elementId);
  if (element) {
    element.style.display = element.style.display === 'none' ? 'block' : 'none';
  }
}

// Add loading state to button
function setButtonLoading(button, isLoading) {
  if (isLoading) {
    button.disabled = true;
    button.dataset.originalText = button.textContent;
    button.textContent = '⏳ Loading...';
  } else {
    button.disabled = false;
    button.textContent = button.dataset.originalText;
  }
}

// Debounce function
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

// Deep clone object
function deepClone(obj) {
  return JSON.parse(JSON.stringify(obj));
}

// Format timestamp
function formatTimestamp(date) {
  const options = {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit'
  };
  return new Date(date).toLocaleDateString('en-US', options);
}

console.log('%c🛡️ NCRC Incident Response Playbook Loaded', 'color: #00d4ff; font-size: 16px; font-weight: bold;');