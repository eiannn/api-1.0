// FruitInfo Website JavaScript

document.addEventListener('DOMContentLoaded', function() {
    console.log('FruitInfo: Initializing application...');
    
    // Initialize the application
    initApp();
});

function initApp() {
    console.log('FruitInfo: Setting up event listeners...');
    
    // Add event listeners
    setupEventListeners();
    
    // Initialize scroll animations
    initScrollAnimations();
    
    // Add scroll progress bar
    createScrollProgressBar();
    
    // Add back to top button
    createBackToTopButton();
    
    // Check for selected fruit in URL
    checkSelectedFruit();
    
    // Initialize fruit grid animations
    initFruitGridAnimations();
    
    console.log('FruitInfo: Application initialized successfully');
}

function setupEventListeners() {
    console.log('FruitInfo: Setting up event listeners...');
    
    // Search form submission
    const searchForm = document.getElementById('searchForm');
    if (searchForm) {
        searchForm.addEventListener('submit', function(e) {
            e.preventDefault();
            console.log('FruitInfo: Search form submitted');
            
            const searchInput = document.getElementById('searchInput');
            const searchValue = searchInput.value.trim();
            
            if (searchValue === '') {
                // If search is empty, redirect to all fruits
                console.log('FruitInfo: Empty search, redirecting to all fruits');
                window.location.href = '?category=all';
            } else {
                // Show loading state
                console.log('FruitInfo: Performing search for:', searchValue);
                showLoadingState();
                // Submit the form with search query
                this.submit();
            }
        });
    } else {
        console.warn('FruitInfo: Search form not found');
    }
    
    // Add loading state to navigation links
    const navLinks = document.querySelectorAll('a.nav-btn');
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            // Don't show loading for active link
            if (this.classList.contains('active')) {
                e.preventDefault();
                return;
            }
            // Show loading state
            console.log('FruitInfo: Navigation link clicked');
            showLoadingState();
        });
    });
    
    // Mobile menu toggle
    const mobileMenuButton = document.getElementById('mobileMenuButton');
    const navMenu = document.getElementById('navMenu');
    
    if (mobileMenuButton && navMenu) {
        mobileMenuButton.addEventListener('click', function() {
            console.log('FruitInfo: Mobile menu button clicked');
            navMenu.classList.toggle('mobile-open');
            navMenu.classList.toggle('hidden');
            
            // Change menu icon
            const icon = this.querySelector('svg');
            if (navMenu.classList.contains('mobile-open')) {
                icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />';
            } else {
                icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />';
            }
        });
        
        // Close mobile menu when clicking outside
        document.addEventListener('click', function(e) {
            if (!navMenu.contains(e.target) && !mobileMenuButton.contains(e.target)) {
                navMenu.classList.remove('mobile-open');
                navMenu.classList.add('hidden');
                const icon = mobileMenuButton.querySelector('svg');
                icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />';
            }
        });
    } else {
        console.warn('FruitInfo: Mobile menu elements not found');
    }
    
    // Click anywhere to go back to all fruits when in single fruit view
    document.addEventListener('click', function(e) {
        const urlParams = new URLSearchParams(window.location.search);
        const showOnly = urlParams.get('showOnly');
        const selectedFruit = urlParams.get('fruit');
        
        if (showOnly === 'true' && selectedFruit) {
            // Don't trigger if clicking on action buttons, navigation, or fruit cards
            if (!e.target.closest('button') && 
                !e.target.closest('a') && 
                !e.target.closest('.fruit-card') &&
                !e.target.closest('input')) {
                console.log('FruitInfo: Click outside detected, returning to all fruits');
                showAllFruits();
            }
        }
    });
    
    // Navbar scroll effect
    window.addEventListener('scroll', throttle(handleNavbarScroll, 100));
    
    // Progress bar scroll
    window.addEventListener('scroll', throttle(updateProgressBar, 10));
    
    console.log('FruitInfo: Event listeners setup complete');
}

function checkSelectedFruit() {
    const urlParams = new URLSearchParams(window.location.search);
    const selectedFruit = urlParams.get('fruit');
    const showOnly = urlParams.get('showOnly');
    
    console.log('FruitInfo: Checking selected fruit -', selectedFruit, 'showOnly:', showOnly);
    
    if (selectedFruit && showOnly === 'true') {
        // Scroll to selected fruit after a short delay
        setTimeout(() => {
            const selectedCard = document.querySelector(`[data-fruit-name="${selectedFruit}"]`);
            if (selectedCard) {
                console.log('FruitInfo: Scrolling to selected fruit:', selectedFruit);
                selectedCard.scrollIntoView({ 
                    behavior: 'smooth', 
                    block: 'center' 
                });
            } else {
                console.warn('FruitInfo: Selected fruit card not found:', selectedFruit);
            }
        }, 500);
    }
}

function selectFruit(fruitName) {
    console.log('FruitInfo: Selecting fruit:', fruitName);
    
    const url = new URL(window.location);
    const currentFruit = url.searchParams.get('fruit');
    const currentShowOnly = url.searchParams.get('showOnly');
    
    console.log('FruitInfo: Current state - fruit:', currentFruit, 'showOnly:', currentShowOnly);
    
    if (currentFruit === fruitName && currentShowOnly === 'true') {
        // If same fruit is clicked again in single view, go back to all fruits
        console.log('FruitInfo: Same fruit clicked in single view, returning to all fruits');
        showAllFruits();
    } else {
        // Select the fruit and show only that one
        url.searchParams.set('fruit', fruitName);
        url.searchParams.set('showOnly', 'true');
        
        console.log('FruitInfo: Navigating to single fruit view:', url.toString());
        
        // Update URL
        showLoadingState();
        setTimeout(() => {
            window.location.href = url.toString();
        }, 300);
    }
}

function showAllFruits() {
    console.log('FruitInfo: Returning to all fruits view');
    
    const url = new URL(window.location);
    url.searchParams.delete('fruit');
    url.searchParams.delete('showOnly');
    
    // Update URL
    showLoadingState();
    setTimeout(() => {
        console.log('FruitInfo: Navigating to all fruits:', url.toString());
        window.location.href = url.toString();
    }, 300);
}

function initScrollAnimations() {
    console.log('FruitInfo: Initializing scroll animations');
    
    // Initialize Intersection Observer for scroll animations
    const observerOptions = {
        root: null,
        rootMargin: '0px',
        threshold: 0.1
    };

    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                // Add visible class when element is in viewport
                entry.target.classList.add('visible');
                console.log('FruitInfo: Element became visible:', entry.target);
                
                // Stop observing after animation
                observer.unobserve(entry.target);
            }
        });
    }, observerOptions);

    // Observe all elements that should animate on scroll
    const animatedElements = document.querySelectorAll('.fruit-grid-item');
    console.log('FruitInfo: Observing', animatedElements.length, 'elements for scroll animations');
    
    animatedElements.forEach(el => {
        observer.observe(el);
    });
}

function initFruitGridAnimations() {
    console.log('FruitInfo: Initializing fruit grid animations');
    
    // Add staggered animation to fruit cards
    const fruitCards = document.querySelectorAll('.fruit-card');
    console.log('FruitInfo: Animating', fruitCards.length, 'fruit cards');
    
    fruitCards.forEach((card, index) => {
        // Set initial state
        card.style.opacity = '0';
        card.style.transform = 'translateY(30px)';
        
        // Animate in with delay
        setTimeout(() => {
            card.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
            console.log('FruitInfo: Animated fruit card:', card.dataset.fruitName);
        }, (index % 8) * 100);
    });
}

function createScrollProgressBar() {
    console.log('FruitInfo: Creating scroll progress bar');
    
    // Create progress bar element
    const progressBar = document.createElement('div');
    progressBar.className = 'scroll-progress';
    document.body.appendChild(progressBar);
}

function updateProgressBar() {
    const progressBar = document.querySelector('.scroll-progress');
    if (!progressBar) return;

    const windowHeight = window.innerHeight;
    const documentHeight = document.documentElement.scrollHeight - windowHeight;
    const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
    
    const scrollPercentage = (scrollTop / documentHeight) * 100;
    progressBar.style.width = `${scrollPercentage}%`;
}

function createBackToTopButton() {
    console.log('FruitInfo: Creating back to top button');
    
    // Create back to top button
    const backToTopBtn = document.createElement('div');
    backToTopBtn.className = 'back-to-top';
    backToTopBtn.innerHTML = `
        <svg xmlns="http://www.w3.org/2000/svg" class="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 10l7-7m0 0l7 7m-7-7v18" />
        </svg>
    `;
    
    backToTopBtn.setAttribute('aria-label', 'Back to top');
    backToTopBtn.addEventListener('click', scrollToTop);
    document.body.appendChild(backToTopBtn);

    // Show/hide button based on scroll position
    window.addEventListener('scroll', throttle(() => {
        const scrolled = window.pageYOffset;
        if (scrolled > 300) {
            backToTopBtn.classList.add('visible');
        } else {
            backToTopBtn.classList.remove('visible');
        }
    }, 100));
}

function scrollToTop() {
    console.log('FruitInfo: Scrolling to top');
    window.scrollTo({
        top: 0,
        behavior: 'smooth'
    });
}

function handleNavbarScroll() {
    const navbar = document.querySelector('nav');
    const scrolled = window.pageYOffset;
    
    if (scrolled > 50) {
        navbar.classList.add('navbar-scrolled');
    } else {
        navbar.classList.remove('navbar-scrolled');
    }
}

// Utility function to throttle scroll events
function throttle(func, limit) {
    let inThrottle;
    return function() {
        const args = arguments;
        const context = this;
        if (!inThrottle) {
            func.apply(context, args);
            inThrottle = true;
            setTimeout(() => inThrottle = false, limit);
        }
    }
}

function showLoadingState() {
    console.log('FruitInfo: Showing loading state');
    
    const fruitGrid = document.getElementById('fruitGrid');
    const loadingElement = document.getElementById('loading');
    
    if (fruitGrid && loadingElement) {
        fruitGrid.style.opacity = '0.5';
        loadingElement.classList.remove('hidden');
        loadingElement.style.display = 'flex';
    } else {
        console.warn('FruitInfo: Loading state elements not found');
    }
}

function hideLoadingState() {
    console.log('FruitInfo: Hiding loading state');
    
    const fruitGrid = document.getElementById('fruitGrid');
    const loadingElement = document.getElementById('loading');
    
    if (fruitGrid && loadingElement) {
        fruitGrid.style.opacity = '1';
        loadingElement.classList.add('hidden');
        loadingElement.style.display = 'none';
    }
}

// Make functions globally available for onclick attributes
window.selectFruit = selectFruit;
window.showAllFruits = showAllFruits;

console.log('FruitInfo: Script loaded successfully');

        function setupEventListeners() {
            // ... existing search form code ...

            // Mobile menu toggle
            const mobileMenuButton = document.getElementById('mobileMenuButton');
            const mobileNavMenu = document.getElementById('mobileNavMenu');
            
            if (mobileMenuButton && mobileNavMenu) {
                mobileMenuButton.addEventListener('click', function() {
                    mobileNavMenu.classList.toggle('hidden');
                    
                    const icon = this.querySelector('svg');
                    if (mobileNavMenu.classList.contains('hidden')) {
                        icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />';
                    } else {
                        icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />';
                    }
                });
                
                // Close mobile menu when clicking outside
                document.addEventListener('click', function(e) {
                    if (!mobileNavMenu.contains(e.target) && !mobileMenuButton.contains(e.target)) {
                        mobileNavMenu.classList.add('hidden');
                        const icon = mobileMenuButton.querySelector('svg');
                        icon.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />';
                    }
                });
            }
            
            // ... rest of existing code ...
        }