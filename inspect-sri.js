#!/usr/bin/env node

/**
 * SRI Validation Script 
 * 
 * This script validates that all external resources have proper SRI (Subresource Integrity) 
 * protection and checks for potential security issues.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');

const INDEX_HTML_PATH = path.join(__dirname, '../src/index.html');

/**
 * Extract external resources from HTML
 */
function extractExternalResources(htmlContent) {
    const resources = [];
    
    // Match <link> tags with external URLs
    const linkRegex = /<link[^>]+href\s*=\s*["']https?:\/\/[^"']+["'][^>]*>/gi;
    const linkMatches = htmlContent.match(linkRegex) || [];
    
    linkMatches.forEach(match => {
        const hrefMatch = match.match(/href\s*=\s*["'](https?:\/\/[^"']+)["']/i);
        const integrityMatch = match.match(/integrity\s*=\s*["']([^"']+)["']/i);
        const crossoriginMatch = match.match(/crossorigin\s*=\s*["']([^"']+)["']/i);
        
        if (hrefMatch) {
            resources.push({
                type: 'link',
                url: hrefMatch[1],
                integrity: integrityMatch ? integrityMatch[1] : null,
                crossorigin: crossoriginMatch ? crossoriginMatch[1] : match.includes('crossorigin'),
                element: match
            });
        }
    });
    
    // Match <script> tags with external URLs
    const scriptRegex = /<script[^>]+src\s*=\s*["']https?:\/\/[^"']+["'][^>]*>/gi;
    const scriptMatches = htmlContent.match(scriptRegex) || [];
    
    scriptMatches.forEach(match => {
        const srcMatch = match.match(/src\s*=\s*["'](https?:\/\/[^"']+)["']/i);
        const integrityMatch = match.match(/integrity\s*=\s*["']([^"']+)["']/i);
        const crossoriginMatch = match.match(/crossorigin\s*=\s*["']([^"']+)["']/i);
        
        if (srcMatch) {
            resources.push({
                type: 'script',
                url: srcMatch[1],
                integrity: integrityMatch ? integrityMatch[1] : null,
                crossorigin: crossoriginMatch ? crossoriginMatch[1] : match.includes('crossorigin'),
                element: match
            });
        }
    });
    
    return resources;
}

/**
 * Validate SRI hash for a given URL
 */
function validateSRI(url, expectedHash) {
    return new Promise((resolve, reject) => {
        https.get(url, (response) => {
            if (response.statusCode !== 200) {
                reject(new Error(`HTTP ${response.statusCode} for ${url}`));
                return;
            }
            
            let data = '';
            response.on('data', (chunk) => {
                data += chunk;
            });
            
            response.on('end', () => {
                // Extract algorithm and hash from integrity attribute
                const match = expectedHash.match(/^(sha256|sha384|sha512)-(.+)$/);
                if (!match) {
                    reject(new Error(`Invalid integrity format: ${expectedHash}`));
                    return;
                }
                
                const [, algorithm, expectedBase64] = match;
                const hash = crypto.createHash(algorithm).update(data, 'utf8').digest('base64');
                
                resolve({
                    valid: hash === expectedBase64,
                    expected: expectedBase64,
                    actual: hash,
                    algorithm
                });
            });
        }).on('error', reject);
    });
}

/**
 * Check security headers in HTML
 */
function checkSecurityHeaders(htmlContent) {
    const issues = [];
    
    // Check for CSP
    if (!htmlContent.includes('Content-Security-Policy')) {
        issues.push('Missing Content-Security-Policy header');
    }
    
    // Check for X-Frame-Options
    if (!htmlContent.includes('X-Frame-Options')) {
        issues.push('Missing X-Frame-Options header');
    }
    
    // Check for X-Content-Type-Options
    if (!htmlContent.includes('X-Content-Type-Options')) {
        issues.push('Missing X-Content-Type-Options header');
    }
    
    // Check for Referrer-Policy
    if (!htmlContent.includes('Referrer-Policy')) {
        issues.push('Missing Referrer-Policy header');
    }
    
    return issues;
}

/**
 * Check if a resource needs SRI protection
 */
function needsSRIProtection(resource) {
    // Preconnect links don't load actual resources
    if (resource.element.includes('rel="preconnect"')) {
        return false;
    }
    
    // Font Awesome kits use dynamic content
    if (resource.url.includes('kit.fontawesome.com')) {
        return false;
    }
    
    // Google Fonts CSS doesn't support SRI due to dynamic content
    if (resource.url.includes('fonts.googleapis.com') && resource.url.includes('css')) {
        return false;
    }
    
    return true;
}

/**
 * Main validation function
 */
async function validateProjectSRI() {
    console.log('🔒 SRI Validation Starting...\n');
    
    // Read index.html
    if (!fs.existsSync(INDEX_HTML_PATH)) {
        console.error('❌ index.html not found at:', INDEX_HTML_PATH);
        process.exit(1);
    }
    
    const htmlContent = fs.readFileSync(INDEX_HTML_PATH, 'utf8');
    const resources = extractExternalResources(htmlContent);
    
    console.log(`📋 Found ${resources.length} external resources:`);
    resources.forEach((resource, index) => {
        console.log(`  ${index + 1}. ${resource.type.toUpperCase()}: ${resource.url}`);
    });
    console.log();
    
    // Validate each resource
    const results = [];
    let issueCount = 0;
    
    for (const resource of resources) {
        console.log(`🔍 Validating: ${resource.url}`);
        
        const needsSRI = needsSRIProtection(resource);
        
        // Check for SRI
        if (!resource.integrity) {
            if (needsSRI) {
                console.log(`  ❌ SRI hash missing for static resource`);
                issueCount++;
            } else {
                if (resource.element.includes('rel="preconnect"')) {
                    console.log(`  ℹ️  Preconnect link - SRI not applicable`);
                } else if (resource.url.includes('kit.fontawesome.com')) {
                    console.log(`  ℹ️  Font Awesome Kit - SRI not available for dynamic content`);
                } else if (resource.url.includes('fonts.googleapis.com')) {
                    console.log(`  ℹ️  Google Fonts CSS - SRI not supported for dynamic content`);
                }
            }
        } else {
            try {
                const validation = await validateSRI(resource.url, resource.integrity);
                if (validation.valid) {
                    console.log(`  ✅ SRI hash valid (${validation.algorithm})`);
                } else {
                    console.log(`  ❌ SRI hash mismatch!`);
                    console.log(`     Expected: ${validation.expected}`);
                    console.log(`     Actual:   ${validation.actual}`);
                    issueCount++;
                }
            } catch (error) {
                console.log(`  ❌ SRI validation failed: ${error.message}`);
                issueCount++;
            }
        }
        
        // Check for crossorigin
        if (!resource.crossorigin) {
            console.log(`  ⚠️  Missing crossorigin attribute`);
            if (needsSRI) {
                issueCount++;
            }
        } else {
            console.log(`  ✅ Crossorigin attribute present`);
        }
        
        console.log();
    }
    
    // Check security headers
    console.log('🛡️  Security Headers Validation:');
    const securityIssues = checkSecurityHeaders(htmlContent);
    if (securityIssues.length === 0) {
        console.log('  ✅ All security headers present');
    } else {
        securityIssues.forEach(issue => {
            console.log(`  ❌ ${issue}`);
            issueCount++;
        });
    }
    
    // Summary
    console.log('\n📊 Validation Summary:');
    console.log(`  External resources: ${resources.length}`);
    console.log(`  Security issues: ${issueCount}`);
    
    if (issueCount === 0) {
        console.log('\n🎉 All SRI validations passed! Your application is secure.');
        process.exit(0);
    } else {
        console.log(`\n⚠️  Found ${issueCount} security issues that should be addressed.`);
        process.exit(1);
    }
}

// Run validation
if (require.main === module) {
    validateProjectSRI().catch(error => {
        console.error('❌ Validation failed:', error.message);
        process.exit(1);
    });
}

module.exports = { validateProjectSRI, extractExternalResources }; 
