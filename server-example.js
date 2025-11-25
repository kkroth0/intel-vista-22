// server/proxy.js - Simple Express proxy server
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Rate limiting (open-source: express-rate-limit)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests, please try again later.'
});

app.use('/api/', limiter);

// Proxy endpoint example
app.post('/api/virustotal', async (req, res) => {
    const { query } = req.body;

    try {
        const response = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${query}`, {
            headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY }
        });
        const data = await response.json();
        res.json(data);
    } catch (error) {
        res.status(500).json({ error: 'API request failed' });
    }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Proxy server running on port ${PORT}`));
