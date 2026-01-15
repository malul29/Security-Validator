const axios = require('axios');

/**
 * Check HSTS (HTTP Strict Transport Security) header for a domain
 * @param {string} domain - Domain to check
 * @returns {Promise<Object>} HSTS information
 */
async function checkHSTS(domain) {
    try {
        // Ensure domain has protocol
        let url = domain;
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            url = 'https://' + url;
        }

        const response = await axios.get(url, {
            maxRedirects: 5,
            timeout: 10000,
            validateStatus: () => true, // Accept any status code
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        });

        const hstsHeader = response.headers['strict-transport-security'];

        if (!hstsHeader) {
            return {
                success: true,
                domain: domain,
                enabled: false,
                severity: 'critical',
                status: 'HSTS Not Enabled',
                message: 'HTTP Strict Transport Security policy is not enabled. This allows potential man-in-the-middle attacks.',
                details: {
                    header: null,
                    maxAge: null,
                    includeSubDomains: false,
                    preload: false
                }
            };
        }

        // Parse HSTS header
        const maxAgeMatch = hstsHeader.match(/max-age=(\d+)/i);
        const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1]) : 0;
        const includeSubDomains = /includeSubDomains/i.test(hstsHeader);
        const preload = /preload/i.test(hstsHeader);

        // Calculate days
        const maxAgeDays = Math.floor(maxAge / 86400);

        // Determine severity
        let severity = 'ok';
        let status = 'HSTS Enabled';
        let issues = [];

        if (maxAge === 0) {
            severity = 'critical';
            status = 'HSTS Misconfigured';
            issues.push('max-age is 0 (effectively disabled)');
        } else if (maxAge < 31536000) { // Less than 1 year (recommended minimum)
            severity = 'warning';
            status = 'HSTS Weak Configuration';
            issues.push(`max-age is ${maxAgeDays} days (recommended: at least 365 days)`);
        }

        if (!includeSubDomains) {
            if (severity === 'ok') severity = 'warning';
            issues.push('includeSubDomains directive not set');
        }

        return {
            success: true,
            domain: domain,
            enabled: true,
            severity: severity,
            status: status,
            message: issues.length > 0
                ? `HSTS is enabled but has ${issues.length} issue(s)`
                : `HSTS is properly configured (max-age: ${maxAgeDays} days)`,
            details: {
                header: hstsHeader,
                maxAge: maxAge,
                maxAgeDays: maxAgeDays,
                includeSubDomains: includeSubDomains,
                preload: preload,
                issues: issues
            }
        };
    } catch (error) {
        return {
            success: false,
            domain: domain,
            enabled: false,
            error: error.message,
            severity: 'error',
            status: 'Error',
            message: `Failed to check HSTS: ${error.message}`,
            details: {
                header: null,
                maxAge: null,
                includeSubDomains: false,
                preload: false
            }
        };
    }
}

module.exports = { checkHSTS };
