// ===== Configuration =====
const API_URL = '/api/check';

// ===== DOM Elements =====
const urlInput = document.getElementById('urlInput');
const checkBtn = document.getElementById('checkBtn');
const resultsSection = document.getElementById('results');
const analyzedUrl = document.getElementById('analyzedUrl');
const scoreRing = document.getElementById('scoreRing');
const scoreNumber = document.getElementById('scoreNumber');
const verdictBadge = document.getElementById('verdictBadge');
const verdictText = document.getElementById('verdictText');
const verdictDescription = document.getElementById('verdictDescription');
const factorsList = document.getElementById('factorsList');
const checkAnother = document.getElementById('checkAnother');

// ===== UI Functions =====

function animateScore(targetScore) {
    const duration = 1500;
    const startTime = performance.now();
    const circumference = 326.7; // 2 * π * 52 (radius)

    function updateScore(currentTime) {
        const elapsed = currentTime - startTime;
        const progress = Math.min(elapsed / duration, 1);

        // Easing function
        const eased = 1 - Math.pow(1 - progress, 3);

        const currentScore = Math.round(eased * targetScore);
        scoreNumber.textContent = currentScore;

        // Update ring progress
        const offset = circumference - (eased * targetScore / 100) * circumference;
        scoreRing.style.strokeDashoffset = offset;

        // Update ring color based on score
        if (currentScore >= 70) {
            scoreRing.style.stroke = 'var(--success)';
        } else if (currentScore >= 40) {
            scoreRing.style.stroke = 'var(--warning)';
        } else {
            scoreRing.style.stroke = 'var(--danger)';
        }

        if (progress < 1) {
            requestAnimationFrame(updateScore);
        }
    }

    requestAnimationFrame(updateScore);
}

function renderFactors(factors) {
    factorsList.innerHTML = factors.map(factor => {
        const statusClass = factor.passed === true ? 'pass' : (factor.passed === false ? 'fail' : 'warn');

        // Format details if available
        let detailsHtml = '';
        if (factor.details && !factor.details.skipped && !factor.details.error) {
            const detailItems = [];
            if (factor.details.issuer) detailItems.push(`Issuer: ${factor.details.issuer}`);
            if (factor.details.daysRemaining) detailItems.push(`Expires: ${factor.details.daysRemaining} days`);
            if (factor.details.creationDate) detailItems.push(`Created: ${factor.details.creationDate}`);
            if (factor.details.registrar) detailItems.push(`Registrar: ${factor.details.registrar}`);
            if (factor.details.statusCode) detailItems.push(`Status: ${factor.details.statusCode}`);

            if (detailItems.length > 0) {
                detailsHtml = `<div class="factor-details">${detailItems.join(' • ')}</div>`;
            }
        }

        return `
            <div class="factor-item">
                <div class="factor-icon ${statusClass}">
                    ${factor.icon}
                </div>
                <div class="factor-content">
                    <div class="factor-name">${factor.name}</div>
                    <div class="factor-description">${factor.description}</div>
                    ${detailsHtml}
                </div>
                <div class="factor-score">${factor.score}/${factor.maxScore}</div>
            </div>
        `;
    }).join('');
}

function showResults(result) {
    if (result.error) {
        alert(result.error);
        return;
    }

    // Update UI
    analyzedUrl.textContent = result.domain;

    // Reset score ring
    scoreRing.style.strokeDashoffset = 326.7;
    scoreNumber.textContent = '0';

    // Update verdict
    verdictBadge.className = `verdict-badge ${result.verdictClass}`;
    verdictText.textContent = result.verdict;
    verdictDescription.textContent = result.verdictDesc;

    // Render factors
    renderFactors(result.factors);

    // Show results section
    resultsSection.classList.remove('hidden');

    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });

    // Animate score after a short delay
    setTimeout(() => {
        animateScore(result.score);
    }, 300);
}

function showError(message) {
    // Create error toast
    const toast = document.createElement('div');
    toast.className = 'error-toast';
    toast.innerHTML = `
        <span class="error-icon">⚠️</span>
        <span class="error-message">${message}</span>
    `;
    document.body.appendChild(toast);

    // Animate in
    setTimeout(() => toast.classList.add('show'), 10);

    // Remove after 5 seconds
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 5000);
}

function resetUI() {
    resultsSection.classList.add('hidden');
    urlInput.value = '';
    urlInput.focus();

    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

async function handleCheck() {
    const input = urlInput.value.trim();

    if (!input) {
        urlInput.focus();
        return;
    }

    // Show loading state
    checkBtn.classList.add('loading');
    checkBtn.disabled = true;

    try {
        const response = await fetch(API_URL, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: input })
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Failed to analyze URL');
        }

        // Show results
        showResults(result);

    } catch (error) {
        console.error('Error:', error);
        showError(error.message || 'Failed to connect to server. Make sure the server is running.');
    } finally {
        // Hide loading state
        checkBtn.classList.remove('loading');
        checkBtn.disabled = false;
    }
}

// ===== Event Listeners =====

checkBtn.addEventListener('click', handleCheck);

urlInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        handleCheck();
    }
});

checkAnother.addEventListener('click', resetUI);

// Focus input on page load
window.addEventListener('load', () => {
    urlInput.focus();

    // Check server health
    fetch('/api/health')
        .then(res => res.json())
        .then(data => {
            if (!data.hasGoogleAPI || !data.hasVirusTotalAPI) {
                console.log('💡 Tip: Add API keys in .env for more accurate security checks');
            }
        })
        .catch(() => {
            showError('Server not running. Please start the server with: npm start');
        });
});

// Add input animation
urlInput.addEventListener('input', () => {
    if (urlInput.value) {
        urlInput.classList.add('has-value');
    } else {
        urlInput.classList.remove('has-value');
    }
});
