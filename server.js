/**
 * ShopGuard Backend Server
 * Real-time website safety checking with actual API calls
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
// Static files served from root directory
app.use(express.static(__dirname));

// ===== Configuration =====
const CONFIG = {
    trustedDomains: [
        'amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.fr',
        'ebay.com', 'ebay.co.uk', 'ebay.de',
        'walmart.com', 'target.com', 'bestbuy.com',
        'alibaba.com', 'aliexpress.com',
        'etsy.com', 'shopify.com',
        'flipkart.com', 'myntra.com', 'ajio.com',
        'apple.com', 'microsoft.com', 'samsung.com',
        'google.com', 'youtube.com', 'facebook.com', 'instagram.com',
        'twitter.com', 'linkedin.com', 'pinterest.com',
        'nike.com', 'adidas.com', 'puma.com',
        'zara.com', 'hm.com', 'uniqlo.com',
        'ikea.com', 'wayfair.com',
        'costco.com', 'samsclub.com',
        'homedepot.com', 'lowes.com',
        'macys.com', 'nordstrom.com', 'zappos.com',
        'newegg.com', 'bhphotovideo.com',
        'booking.com', 'airbnb.com', 'expedia.com',
        'paypal.com', 'stripe.com', 'razorpay.com'
    ],
    suspiciousTLDs: [
        'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'top', 'buzz', 'icu',
        'club', 'work', 'site', 'online', 'live', 'space', 'fun'
    ],
    typosquattingPatterns: [
        { original: 'amazon', fakes: ['amaz0n', 'amazom', 'amazn', 'amazonn', 'amazone', 'arnazon'] },
        { original: 'ebay', fakes: ['ebey', 'ebaay', 'e-bay', 'ebayy'] },
        { original: 'paypal', fakes: ['paypa1', 'paypall', 'paypa', 'peypal'] },
        { original: 'google', fakes: ['googl', 'g00gle', 'gooogle', 'googlee'] },
        { original: 'apple', fakes: ['app1e', 'applle', 'aple', 'appel'] },
        { original: 'microsoft', fakes: ['micr0soft', 'microsft', 'mircosoft'] },
        { original: 'walmart', fakes: ['wa1mart', 'wallmart', 'walmrt'] },
        { original: 'flipkart', fakes: ['fl1pkart', 'flipkrt', 'fllpkart'] }
    ]
};

// ===== Helper Functions =====

function parseUrl(input) {
    let url = input.trim();
    if (!url.match(/^https?:\/\//i)) {
        url = 'https://' + url;
    }
    try {
        return new URL(url);
    } catch (e) {
        return null;
    }
}

function extractDomain(url) {
    let hostname = url.hostname.toLowerCase();
    hostname = hostname.replace(/^www\./, '');
    return hostname;
}

function getTLD(domain) {
    const parts = domain.split('.');
    return parts[parts.length - 1];
}

// ===== Real Check Functions =====

/**
 * Check if website is reachable and responding
 */
async function checkWebsiteReachability(url) {
    try {
        // Try HEAD first, fallback to GET if HEAD fails
        let response;
        try {
            response = await axios.head(url, {
                timeout: 10000,
                maxRedirects: 5,
                validateStatus: () => true // Accept any status
            });
        } catch (headError) {
            // HEAD failed, try GET with minimal data
            response = await axios.get(url, {
                timeout: 10000,
                maxRedirects: 5,
                validateStatus: () => true,
                maxContentLength: 1000 // Only get first 1KB
            });
        }

        // 405 means method not allowed but server IS responding
        // 2xx, 3xx, 405 = website is reachable
        const isReachable = response.status < 500 || response.status === 405;
        const hasRedirects = response.request._redirectable && response.request._redirectable._redirectCount > 0;

        return {
            name: 'Website Reachability',
            passed: isReachable,
            score: isReachable ? 15 : 0,
            maxScore: 15,
            description: isReachable
                ? `Website is online (HTTP ${response.status})${hasRedirects ? ' with redirects' : ''}`
                : `Website returned error (HTTP ${response.status})`,
            icon: isReachable ? '🌐' : '❌',
            details: {
                statusCode: response.status,
                redirects: hasRedirects
            }
        };
    } catch (error) {
        return {
            name: 'Website Reachability',
            passed: false,
            score: 0,
            maxScore: 15,
            description: `Cannot reach website: ${error.code || error.message}`,
            icon: '❌',
            details: { error: error.message }
        };
    }
}

/**
 * Check SSL certificate details
 */
async function checkSSLCertificate(hostname) {
    try {
        const sslChecker = require('ssl-checker');
        const sslInfo = await sslChecker(hostname, { method: 'GET', port: 443 });

        const isValid = sslInfo.valid;
        const daysRemaining = sslInfo.daysRemaining;
        const issuer = sslInfo.issuer || 'Unknown';

        let score = 0;
        let description = '';

        if (isValid && daysRemaining > 30) {
            score = 20;
            description = `Valid SSL certificate (expires in ${daysRemaining} days)`;
        } else if (isValid && daysRemaining > 0) {
            score = 12;
            description = `SSL certificate expiring soon (${daysRemaining} days)`;
        } else {
            score = 0;
            description = 'Invalid or expired SSL certificate';
        }

        return {
            name: 'SSL Certificate',
            passed: isValid && daysRemaining > 0,
            score,
            maxScore: 20,
            description,
            icon: isValid ? '🔒' : '🔓',
            details: {
                valid: isValid,
                daysRemaining,
                issuer
            }
        };
    } catch (error) {
        // Check if it's just HTTP (no SSL)
        return {
            name: 'SSL Certificate',
            passed: false,
            score: 0,
            maxScore: 20,
            description: 'No SSL certificate found - connection is not encrypted',
            icon: '🔓',
            details: { error: error.message }
        };
    }
}

/**
 * Check domain WHOIS information for age
 */
async function checkDomainAge(domain) {
    try {
        const whois = require('whois-json');
        const whoisData = await whois(domain);

        let creationDate = whoisData.creationDate || whoisData.createdDate || whoisData.created;

        if (creationDate) {
            // Handle array of dates
            if (Array.isArray(creationDate)) {
                creationDate = creationDate[0];
            }

            const created = new Date(creationDate);
            const now = new Date();
            const ageInDays = Math.floor((now - created) / (1000 * 60 * 60 * 24));
            const ageInYears = (ageInDays / 365).toFixed(1);

            let score, description, passed;

            if (ageInDays > 365 * 2) { // Over 2 years
                score = 15;
                passed = true;
                description = `Domain is ${ageInYears} years old (established)`;
            } else if (ageInDays > 365) { // 1-2 years
                score = 10;
                passed = true;
                description = `Domain is ${ageInYears} years old`;
            } else if (ageInDays > 90) { // 3 months - 1 year
                score = 5;
                passed = null;
                description = `Domain is ${ageInDays} days old (relatively new)`;
            } else { // Less than 3 months
                score = 0;
                passed = false;
                description = `Domain is only ${ageInDays} days old (very new - be cautious)`;
            }

            return {
                name: 'Domain Age',
                passed,
                score,
                maxScore: 15,
                description,
                icon: passed ? '📅' : '⚠️',
                details: {
                    creationDate: created.toISOString().split('T')[0],
                    ageInDays,
                    registrar: whoisData.registrar || 'Unknown'
                }
            };
        } else {
            return {
                name: 'Domain Age',
                passed: null,
                score: 5,
                maxScore: 15,
                description: 'Could not determine domain age',
                icon: '❓',
                details: { raw: 'WHOIS data incomplete' }
            };
        }
    } catch (error) {
        return {
            name: 'Domain Age',
            passed: null,
            score: 5,
            maxScore: 15,
            description: 'Could not retrieve WHOIS data',
            icon: '❓',
            details: { error: error.message }
        };
    }
}

/**
 * Check Google Safe Browsing API
 */
async function checkGoogleSafeBrowsing(url) {
    const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;

    if (!apiKey || apiKey === 'your_api_key_here' || apiKey === '' || apiKey.length < 10) {
        return {
            name: 'Google Safe Browsing',
            passed: null,
            score: 10,
            maxScore: 15,
            description: 'API key not configured (optional)',
            icon: '❓',
            details: { skipped: true }
        };
    }

    try {
        const response = await axios.post(
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
            {
                client: {
                    clientId: 'shopguard',
                    clientVersion: '1.0.0'
                },
                threatInfo: {
                    threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
                    platformTypes: ['ANY_PLATFORM'],
                    threatEntryTypes: ['URL'],
                    threatEntries: [{ url }]
                }
            },
            { timeout: 10000 }
        );

        const hasThreats = response.data.matches && response.data.matches.length > 0;

        return {
            name: 'Google Safe Browsing',
            passed: !hasThreats,
            score: hasThreats ? 0 : 15,
            maxScore: 15,
            description: hasThreats
                ? `⚠️ THREAT DETECTED: ${response.data.matches[0].threatType}`
                : 'No threats found in Google database',
            icon: hasThreats ? '🚨' : '✅',
            details: {
                threats: hasThreats ? response.data.matches : []
            }
        };
    } catch (error) {
        // Log detailed error for debugging
        console.log('Google Safe Browsing API Error:', error.response?.data || error.message);

        const errorMsg = error.response?.data?.error?.message || error.message;

        return {
            name: 'Google Safe Browsing',
            passed: null,
            score: 10,
            maxScore: 15,
            description: 'Safe Browsing check skipped',
            icon: '❓',
            details: { error: errorMsg }
        };
    }
}

/**
 * Check VirusTotal API
 */
async function checkVirusTotal(url) {
    const apiKey = process.env.VIRUSTOTAL_API_KEY;

    if (!apiKey || apiKey === 'your_api_key_here' || apiKey === '') {
        return {
            name: 'VirusTotal Scan',
            passed: null,
            score: 8,
            maxScore: 15,
            description: 'API key not configured (optional)',
            icon: '❓',
            details: { skipped: true }
        };
    }

    try {
        // First, submit the URL for scanning
        const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');

        const response = await axios.get(
            `https://www.virustotal.com/api/v3/urls/${urlId}`,
            {
                headers: { 'x-apikey': apiKey },
                timeout: 15000
            }
        );

        const stats = response.data.data.attributes.last_analysis_stats;
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        const harmless = stats.harmless || 0;

        const threatCount = malicious + suspicious;
        let score, passed, description;

        if (threatCount === 0) {
            score = 15;
            passed = true;
            description = `Clean - ${harmless} security vendors found no issues`;
        } else if (threatCount <= 2) {
            score = 8;
            passed = null;
            description = `${threatCount} vendor(s) flagged this URL`;
        } else {
            score = 0;
            passed = false;
            description = `⚠️ ${threatCount} vendors detected threats!`;
        }

        return {
            name: 'VirusTotal Scan',
            passed,
            score,
            maxScore: 15,
            description,
            icon: passed ? '🛡️' : (passed === false ? '🚨' : '⚠️'),
            details: { stats }
        };
    } catch (error) {
        // URL not in VirusTotal database - submit it
        if (error.response && error.response.status === 404) {
            return {
                name: 'VirusTotal Scan',
                passed: null,
                score: 8,
                maxScore: 15,
                description: 'URL not yet scanned by VirusTotal',
                icon: '❓',
                details: { notInDatabase: true }
            };
        }

        return {
            name: 'VirusTotal Scan',
            passed: null,
            score: 8,
            maxScore: 15,
            description: 'Could not check VirusTotal',
            icon: '❓',
            details: { error: error.message }
        };
    }
}

/**
 * Check trusted domain list
 */
function checkTrustedDomain(domain) {
    const isTrusted = CONFIG.trustedDomains.some(trusted =>
        domain === trusted || domain.endsWith('.' + trusted)
    );

    return {
        name: 'Trusted Retailer',
        passed: isTrusted,
        score: isTrusted ? 10 : 2,
        maxScore: 10,
        description: isTrusted
            ? 'Verified major retailer'
            : 'Not in trusted retailer database',
        icon: isTrusted ? '⭐' : '❓',
        details: { trusted: isTrusted }
    };
}

/**
 * Check TLD suspiciousness
 */
function checkTLD(domain) {
    const tld = getTLD(domain);
    const isSuspicious = CONFIG.suspiciousTLDs.includes(tld);
    const isCommon = ['com', 'org', 'net', 'co', 'in', 'uk', 'de', 'fr', 'jp', 'au', 'ca', 'io', 'gov', 'edu'].includes(tld);

    let score, passed, description;

    if (isSuspicious) {
        score = 0;
        passed = false;
        description = `Suspicious TLD ".${tld}" - commonly used for scams`;
    } else if (isCommon) {
        score = 5;
        passed = true;
        description = `Standard domain extension ".${tld}"`;
    } else {
        score = 3;
        passed = null;
        description = `Uncommon TLD ".${tld}"`;
    }

    return {
        name: 'Domain Extension',
        passed,
        score,
        maxScore: 5,
        description,
        icon: passed ? '🌐' : (passed === false ? '⚠️' : '❓')
    };
}

/**
 * Check for typosquatting patterns
 * Only flags if domain contains a typo pattern but NOT the original legitimate domain
 */
function checkTyposquatting(domain) {
    let detected = null;

    // First extract the main domain name (without TLD)
    const domainParts = domain.split('.');
    const mainDomain = domainParts.length >= 2 ? domainParts[domainParts.length - 2] : domain;

    for (const pattern of CONFIG.typosquattingPatterns) {
        // Skip if this IS the legitimate domain
        if (mainDomain === pattern.original) {
            continue;
        }

        // Check for fake patterns
        for (const fake of pattern.fakes) {
            if (mainDomain === fake || domain.includes(fake + '.') || domain.includes(fake + '-')) {
                detected = { fake, original: pattern.original };
                break;
            }
        }
        if (detected) break;
    }

    return {
        name: 'Typosquatting Check',
        passed: !detected,
        score: detected ? 0 : 5,
        maxScore: 5,
        description: detected
            ? `⚠️ Possible fake of "${detected.original}" (uses "${detected.fake}")`
            : 'No typosquatting patterns detected',
        icon: detected ? '🚨' : '✅',
        details: detected
    };
}

// ===== Main API Endpoint =====

app.post('/api/check', async (req, res) => {
    try {
        const { url: inputUrl } = req.body;

        if (!inputUrl) {
            return res.status(400).json({ error: 'URL is required' });
        }

        const url = parseUrl(inputUrl);
        if (!url) {
            return res.status(400).json({ error: 'Invalid URL format' });
        }

        const domain = extractDomain(url);
        const fullUrl = url.href;

        console.log(`\n🔍 Checking: ${fullUrl}`);
        console.log('━'.repeat(50));

        // Run all checks in parallel
        const [
            reachability,
            sslCert,
            domainAge,
            googleSafeBrowsing,
            virusTotal
        ] = await Promise.all([
            checkWebsiteReachability(fullUrl),
            checkSSLCertificate(domain),
            checkDomainAge(domain),
            checkGoogleSafeBrowsing(fullUrl),
            checkVirusTotal(fullUrl)
        ]);

        // Synchronous checks
        const trustedDomain = checkTrustedDomain(domain);
        const tldCheck = checkTLD(domain);
        const typosquatting = checkTyposquatting(domain);

        // Combine all factors
        const factors = [
            reachability,
            sslCert,
            domainAge,
            googleSafeBrowsing,
            virusTotal,
            trustedDomain,
            tldCheck,
            typosquatting
        ];

        // Calculate total score
        const totalScore = factors.reduce((sum, f) => sum + f.score, 0);
        const maxScore = factors.reduce((sum, f) => sum + f.maxScore, 0);
        const percentScore = Math.round((totalScore / maxScore) * 100);

        // Determine verdict
        let verdict, verdictClass, verdictDesc;

        // Check for critical failures
        const hasCriticalFailure = factors.some(f =>
            f.passed === false && (
                f.name === 'Google Safe Browsing' ||
                f.name === 'VirusTotal Scan' ||
                f.name === 'Typosquatting Check'
            )
        );

        if (hasCriticalFailure) {
            verdict = '🚨 DANGEROUS';
            verdictClass = 'unsafe';
            verdictDesc = 'Critical security threats detected! Do NOT enter any personal or payment information.';
        } else if (percentScore >= 75) {
            verdict = '✅ Safe to Shop';
            verdictClass = 'safe';
            verdictDesc = 'This website appears safe for online shopping. Standard precautions still recommended.';
        } else if (percentScore >= 50) {
            verdict = '⚠️ Exercise Caution';
            verdictClass = 'caution';
            verdictDesc = 'Some concerns detected. Verify legitimacy before making purchases.';
        } else {
            verdict = '❌ High Risk';
            verdictClass = 'unsafe';
            verdictDesc = 'Multiple warning signs detected. We recommend avoiding this website.';
        }

        // Log results
        factors.forEach(f => {
            const status = f.passed === true ? '✅' : (f.passed === false ? '❌' : '❓');
            console.log(`${status} ${f.name}: ${f.score}/${f.maxScore} - ${f.description}`);
        });
        console.log('━'.repeat(50));
        console.log(`📊 Final Score: ${percentScore}/100 - ${verdict}`);

        res.json({
            url: fullUrl,
            domain,
            score: percentScore,
            factors,
            verdict: verdict.replace(/[🚨✅⚠️❌]/g, '').trim(),
            verdictClass,
            verdictDesc,
            checkedAt: new Date().toISOString()
        });

    } catch (error) {
        console.error('Error checking URL:', error);
        res.status(500).json({ error: 'Failed to analyze URL: ' + error.message });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        hasGoogleAPI: !!process.env.GOOGLE_SAFE_BROWSING_API_KEY && process.env.GOOGLE_SAFE_BROWSING_API_KEY !== '',
        hasVirusTotalAPI: !!process.env.VIRUSTOTAL_API_KEY && process.env.VIRUSTOTAL_API_KEY !== ''
    });
});

// Serve frontend from root directory
app.use(express.static(__dirname));
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Export app for Vercel
module.exports = app;

// Start server if run directly
if (require.main === module) {
    app.listen(PORT, () => {
        console.log('\n' + '═'.repeat(60));
        console.log('🛡️  ShopGuard - Real-Time Website Safety Checker');
        console.log('═'.repeat(60));
        console.log(`\n🚀 Server running at: http://localhost:${PORT}`);
        console.log('\n📋 API Status:');
        console.log(`   • Google Safe Browsing: ${process.env.GOOGLE_SAFE_BROWSING_API_KEY ? '✅ Configured' : '⚠️  Not configured (optional)'}`);
        console.log(`   • VirusTotal: ${process.env.VIRUSTOTAL_API_KEY ? '✅ Configured' : '⚠️  Not configured (optional)'}`);
        console.log('\n💡 The checker works without API keys but adding them improves accuracy.');
        console.log('   See .env.example for configuration instructions.\n');
    });
}
