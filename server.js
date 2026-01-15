const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const { checkSSL } = require('./validators/ssl-checker');
const { checkCookies } = require('./validators/cookie-checker');
const { checkHSTS } = require('./validators/hsts-checker');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(helmet({
    contentSecurityPolicy: false, // Allow inline scripts for development
}));
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ status: 'ok', message: 'Acunetix Vulnerability Validator API is running' });
});

// Check SSL certificate for a single domain
app.get('/api/check-ssl/:domain', async (req, res) => {
    try {
        const domain = req.params.domain;
        const result = await checkSSL(domain);
        res.json(result);
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Check cookies for a single domain
app.get('/api/check-cookies/:domain', async (req, res) => {
    try {
        const domain = req.params.domain;
        const result = await checkCookies(domain);
        res.json(result);
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Check HSTS for a single domain
app.get('/api/check-hsts/:domain', async (req, res) => {
    try {
        const domain = req.params.domain;
        const result = await checkHSTS(domain);
        res.json(result);
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Validate multiple domains (batch processing)
app.post('/api/validate', async (req, res) => {
    try {
        const { domains } = req.body;

        if (!domains || !Array.isArray(domains) || domains.length === 0) {
            return res.status(400).json({
                success: false,
                error: 'Please provide an array of domains'
            });
        }

        const results = [];

        for (const domain of domains) {
            const [sslResult, cookieResult, hstsResult] = await Promise.all([
                checkSSL(domain),
                checkCookies(domain),
                checkHSTS(domain)
            ]);

            results.push({
                domain: domain,
                ssl: sslResult,
                cookies: cookieResult,
                hsts: hstsResult,
                timestamp: new Date().toISOString()
            });
        }

        res.json({
            success: true,
            count: results.length,
            results: results
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Serve index.html for root path
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Acunetix Vulnerability Validator running on http://localhost:${PORT}`);
    console.log(`📊 API endpoints available at http://localhost:${PORT}/api/`);
});
