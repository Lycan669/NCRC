/* ============================================
   NCRC Portfolio - JavaScript
   ============================================ */

// ============================================
// 1. MENU TOGGLE (Mobile)
// ============================================

const menuToggle = document.querySelector('.menu-toggle');
const navMenu = document.querySelector('.nav-menu');
const navLinks = document.querySelectorAll('.nav-link');

if (menuToggle) {
    menuToggle.addEventListener('click', () => {
        navMenu.classList.toggle('active');
        menuToggle.textContent = navMenu.classList.contains('active') ? '✕' : '☰';
    });

    // Ferme le menu quand on clique sur un lien
    navLinks.forEach(link => {
        link.addEventListener('click', () => {
            navMenu.classList.remove('active');
            menuToggle.textContent = '☰';
        });
    });
}

// ============================================
// 2. SMOOTH SCROLL
// ============================================

navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
        const href = link.getAttribute('href');
        
        if (href.startsWith('#')) {
            e.preventDefault();
            const target = document.querySelector(href);
            
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        }
    });
});

// ============================================
// 3. COUNTER ANIMATIONS (Stats)
// ============================================

function animateCounter(element, target, duration = 2000) {
    const increment = target / (duration / 16);
    let current = 0;

    const timer = setInterval(() => {
        current += increment;
        if (current >= target) {
            element.textContent = target + '+';
            clearInterval(timer);
        } else {
            element.textContent = Math.floor(current);
        }
    }, 16);
}

function startCounters() {
    const statNumbers = document.querySelectorAll('.stat-number');
    const statsSection = document.querySelector('.about-stats');
    
    if (!statsSection) return;

    const observerOptions = {
        threshold: 0.5
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                statNumbers.forEach(stat => {
                    if (!stat.dataset.animated) {
                        const value = parseInt(stat.textContent);
                        animateCounter(stat, value);
                        stat.dataset.animated = 'true';
                    }
                });
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    observer.observe(statsSection);
}

// ============================================
// 4. ANIMATIONS AU SCROLL (Intersection Observer)
// ============================================

function setupScrollAnimations() {
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry, index) => {
            if (entry.isIntersecting) {
                // Animation avec délai
                setTimeout(() => {
                    entry.target.style.opacity = '1';
                    entry.target.style.transform = 'translateY(0)';
                }, index * 100);
                
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    // Elements à animer
    const animateElements = document.querySelectorAll(
        '.project-card, .skill-card, .tool-item, .cert-card'
    );

    animateElements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
        observer.observe(el);
    });
}

// ============================================
// 5. HEADER STICKY & SHADOW
// ============================================

function handleHeaderOnScroll() {
    const header = document.querySelector('header');
    
    if (!header) return;

    window.addEventListener('scroll', () => {
        if (window.scrollY > 10) {
            header.style.boxShadow = '0 4px 20px rgba(212, 175, 55, 0.2)';
        } else {
            header.style.boxShadow = 'none';
        }
    });
}

// ============================================
// 6. ACTIVE NAV LINK HIGHLIGHT
// ============================================

function updateActiveNavLink() {
    const sections = document.querySelectorAll('section');
    const navLinks = document.querySelectorAll('.nav-link');

    const observerOptions = {
        threshold: 0.3,
        rootMargin: '-50% 0px -50% 0px'
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                navLinks.forEach(link => {
                    link.classList.remove('active');
                    if (link.getAttribute('href') === `#${entry.target.id}`) {
                        link.classList.add('active');
                    }
                });
            }
        });
    }, observerOptions);

    sections.forEach(section => {
        if (section.id) {
            observer.observe(section);
        }
    });
}

// ============================================
// 7. SKILL BARS ANIMATION
// ============================================

function animateSkillBars() {
    const skillBars = document.querySelectorAll('.skill-fill');
    
    if (skillBars.length === 0) return;

    const observerOptions = {
        threshold: 0.5
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const bar = entry.target;
                const width = bar.getAttribute('data-width') || bar.style.width;
                
                bar.style.width = '0%';
                bar.style.transition = 'width 0.8s ease-out';
                
                setTimeout(() => {
                    bar.style.width = width;
                }, 100);
                
                observer.unobserve(bar);
            }
        });
    }, observerOptions);

    skillBars.forEach(bar => observer.observe(bar));
}

// ============================================
// 8. CERT PROGRESS BARS ANIMATION
// ============================================

function animateCertProgress() {
    const certProgress = document.querySelectorAll('.cert-fill');
    
    if (certProgress.length === 0) return;

    const observerOptions = {
        threshold: 0.5
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const bar = entry.target;
                const width = bar.getAttribute('data-width') || bar.style.width;
                
                bar.style.width = '0%';
                bar.style.transition = 'width 1s ease-out';
                
                setTimeout(() => {
                    bar.style.width = width;
                }, 150);
                
                observer.unobserve(bar);
            }
        });
    }, observerOptions);

    certProgress.forEach(bar => observer.observe(bar));
}

// ============================================
// 9. GLOW EFFECT HOVER (Cards)
// ============================================

function addGlowEffect() {
    const cards = document.querySelectorAll(
        '.project-card, .skill-card, .tool-item, .cert-card'
    );

    cards.forEach(card => {
        card.addEventListener('mousemove', (e) => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;

            card.style.setProperty('--mouse-x', x + 'px');
            card.style.setProperty('--mouse-y', y + 'px');
        });
    });
}

// ============================================
// 10. COPY TO CLIPBOARD (Contact)
// ============================================

function setupCopyToClipboard() {
    const copyButtons = document.querySelectorAll('[data-copy]');

    copyButtons.forEach(button => {
        button.addEventListener('click', () => {
            const text = button.getAttribute('data-copy');
            
            navigator.clipboard.writeText(text).then(() => {
                const originalText = button.textContent;
                button.textContent = '✓ Copié !';
                button.style.color = 'var(--accent-cyan)';
                
                setTimeout(() => {
                    button.textContent = originalText;
                    button.style.color = '';
                }, 2000);
            }).catch(err => {
                console.error('Erreur lors de la copie:', err);
            });
        });
    });
}

// ============================================
// 11. SCROLL TO TOP BUTTON
// ============================================

function setupScrollToTopButton() {
    const scrollTopBtn = document.querySelector('[data-scroll-top]');
    
    if (!scrollTopBtn) return;

    window.addEventListener('scroll', () => {
        if (window.scrollY > 300) {
            scrollTopBtn.style.display = 'block';
            scrollTopBtn.style.opacity = '1';
        } else {
            scrollTopBtn.style.opacity = '0';
            scrollTopBtn.style.display = 'none';
        }
    });

    scrollTopBtn.addEventListener('click', () => {
        window.scrollTo({
            top: 0,
            behavior: 'smooth'
        });
    });
}

// ============================================
// 12. DARK MODE TOGGLE
// ============================================

function setupDarkModeToggle() {
    const darkModeToggle = document.querySelector('[data-dark-mode]');
    
    if (!darkModeToggle) return;

    // Récupère le thème sauvegardé
    const savedTheme = localStorage.getItem('theme') || 'light';
    if (savedTheme === 'dark') {
        document.documentElement.setAttribute('data-theme', 'dark');
        darkModeToggle.textContent = '☀️';
    }

    darkModeToggle.addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
        
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        
        darkModeToggle.textContent = newTheme === 'dark' ? '☀️' : '🌙';
    });
}

// ============================================
// 13. PAGE LOAD ANIMATION
// ============================================

function setupPageLoadAnimation() {
    window.addEventListener('load', () => {
        document.body.style.opacity = '1';
        document.body.style.animation = 'fadeIn 0.8s ease-out';
    });
}

// ============================================
// 14. LAZY LOAD IMAGES
// ============================================

function setupLazyLoad() {
    const images = document.querySelectorAll('img[data-src]');

    if ('IntersectionObserver' in window) {
        const imageObserver = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    const img = entry.target;
                    img.src = img.getAttribute('data-src');
                    img.removeAttribute('data-src');
                    imageObserver.unobserve(img);
                }
            });
        });

        images.forEach(img => imageObserver.observe(img));
    }
}

// ============================================
// 15. INITIALIZATION
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    console.log('🔥 NCRC Portfolio - Initialisation');

    // Appelle toutes les fonctions
    setupScrollAnimations();
    startCounters();
    handleHeaderOnScroll();
    updateActiveNavLink();
    animateSkillBars();
    animateCertProgress();
    addGlowEffect();
    setupCopyToClipboard();
    setupScrollToTopButton();
    setupDarkModeToggle();
    setupPageLoadAnimation();
    setupLazyLoad();

    console.log('✅ Toutes les animations sont actives !');
});

// ============================================
// 16. UTILITY FUNCTIONS
// ============================================

// Débounce pour performance
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

// Throttle pour les scroll events
function throttle(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            timeout = null;
            func(...args);
        };
        if (!timeout) {
            func(...args);
            timeout = setTimeout(later, wait);
        }
    };
}

// ============================================
// 17. ERROR HANDLING
// ============================================

window.addEventListener('error', (event) => {
    console.error('❌ Erreur JavaScript:', event.error);
});

window.addEventListener('unhandledrejection', (event) => {
    console.error('❌ Promise rejection:', event.reason);
});