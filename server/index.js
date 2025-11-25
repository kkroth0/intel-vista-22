import express from 'express';
import cors from 'cors';
import rateLimit from 'express-rate-limit';
import dotenv from 'dotenv';
import axios from 'axios';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests, please try again later.'
});
app.use('/api/', limiter);

// Helper to detect query type
const detectQueryType = (query) => {
    if (query.startsWith("http://") || query.startsWith("https://")) return "url";
    if (/^[a-fA-F0-9]{32}$/.test(query)) return "hash"; // MD5
    if (/^[a-fA-F0-9]{40}$/.test(query)) return "hash"; // SHA1
    if (/^[a-fA-F0-9]{64}$/.test(query)) return "hash"; // SHA256
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(query)) return "ip";
    return "domain";
};

// --- API Endpoints ---

// VirusTotal
app.post('/api/virustotal', async (req, res) => {
    const { query } = req.body;
    if (!process.env.VIRUSTOTAL_API_KEY) return res.status(500).json({ error: "API Key missing" });

    try {
        const queryType = detectQueryType(query);
        let endpoint = "";

        if (queryType === "ip") endpoint = `https://www.virustotal.com/api/v3/ip_addresses/${query}`;
        else if (queryType === "domain") endpoint = `https://www.virustotal.com/api/v3/domains/${query}`;
        else if (queryType === "hash") endpoint = `https://www.virustotal.com/api/v3/files/${query}`;
        else endpoint = `https://www.virustotal.com/api/v3/urls/${btoa(query).replace(/=/g, "")}`;

        const response = await axios.get(endpoint, {
            headers: { "x-apikey": process.env.VIRUSTOTAL_API_KEY }
        });
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// AbuseIPDB
app.post('/api/abuseipdb', async (req, res) => {
    const { query } = req.body;
    if (!process.env.ABUSEIPDB_API_KEY) return res.status(500).json({ error: "API Key missing" });

    const queryType = detectQueryType(query);
    if (queryType !== "ip") return res.json({ data: { "Status": "IP only" } }); // Return 200 with message to match frontend expectation

    try {
        const response = await axios.get(`https://api.abuseipdb.com/api/v2/check`, {
            params: { ipAddress: query },
            headers: { "Key": process.env.ABUSEIPDB_API_KEY, "Accept": "application/json" }
        });
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// AlienVault OTX
app.post('/api/alienvault', async (req, res) => {
    const { query } = req.body;
    const headers = {};
    if (process.env.ALIENVAULT_API_KEY) headers["X-OTX-API-KEY"] = process.env.ALIENVAULT_API_KEY;

    try {
        const queryType = detectQueryType(query);
        let endpoint = "";

        if (queryType === "ip") endpoint = `https://otx.alienvault.com/api/v1/indicators/IPv4/${query}/general`;
        else if (queryType === "domain") endpoint = `https://otx.alienvault.com/api/v1/indicators/domain/${query}/general`;
        else if (queryType === "hash") endpoint = `https://otx.alienvault.com/api/v1/indicators/file/${query}/general`;
        else endpoint = `https://otx.alienvault.com/api/v1/indicators/url/${encodeURIComponent(query)}/general`;

        const response = await axios.get(endpoint, { headers });
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// Shodan
app.post('/api/shodan', async (req, res) => {
    const { query } = req.body;
    if (!process.env.SHODAN_API_KEY) return res.status(500).json({ error: "API Key missing" });

    const queryType = detectQueryType(query);
    if (queryType !== "ip") return res.json({ data: { "Status": "IP only" } });

    try {
        const response = await axios.get(`https://api.shodan.io/shodan/host/${query}?key=${process.env.SHODAN_API_KEY}`);
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// URLhaus
app.post('/api/urlhaus', async (req, res) => {
    const { query } = req.body;
    try {
        const response = await axios.post(`https://urlhaus-api.abuse.ch/v1/host/`,
            `host=${query}`,
            { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
        );
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// ThreatFox
app.post('/api/threatfox', async (req, res) => {
    const { query } = req.body;
    try {
        const response = await axios.post(`https://threatfox-api.abuse.ch/api/v1/`,
            { query: "search_ioc", search_term: query },
            { headers: { "Content-Type": "application/json" } }
        );
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// MalwareBazaar
app.post('/api/malwarebazaar', async (req, res) => {
    const { query } = req.body;
    const queryType = detectQueryType(query);
    if (queryType !== "hash") return res.json({ data: { "Status": "Hash only" } });

    try {
        const response = await axios.post(`https://mb-api.abuse.ch/api/v1/`,
            `query=get_info&hash=${query}`,
            { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
        );
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// Google Safe Browsing
app.post('/api/googlesafebrowsing', async (req, res) => {
    const { query } = req.body;
    if (!process.env.GOOGLE_SAFE_BROWSING_API_KEY) return res.status(500).json({ error: "API Key missing" });

    try {
        const response = await axios.post(
            `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_SAFE_BROWSING_API_KEY}`,
            {
                client: { clientId: "threat-dashboard", clientVersion: "1.0" },
                threatInfo: {
                    threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
                    platformTypes: ["ANY_PLATFORM"],
                    threatEntryTypes: ["URL", "IP_RANGE"],
                    threatEntries: [{ url: query }],
                },
            }
        );
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// PhishTank
app.post('/api/phishtank', async (req, res) => {
    const { query } = req.body;
    try {
        const body = `url=${encodeURIComponent(query)}&format=json${process.env.PHISHTANK_API_KEY ? `&app_key=${process.env.PHISHTANK_API_KEY}` : ""}`;
        const response = await axios.post(`https://checkurl.phishtank.com/checkurl/`, body, {
            headers: { "Content-Type": "application/x-www-form-urlencoded" }
        });
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// Pulsedive
app.post('/api/pulsedive', async (req, res) => {
    const { query } = req.body;
    const key = process.env.PULSEDIVE_API_KEY || "free";
    try {
        const response = await axios.get(`https://pulsedive.com/api/info.php?indicator=${query}&key=${key}`);
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// ThreatCrowd
app.post('/api/threatcrowd', async (req, res) => {
    const { query } = req.body;
    const queryType = detectQueryType(query);
    if (queryType !== "ip" && queryType !== "domain") return res.json({ data: { "Status": "IP/Domain only" } });

    try {
        const endpoint = queryType === "ip"
            ? `https://www.threatcrowd.org/searchApi/v2/ip/report/?ip=${query}`
            : `https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=${query}`;

        const response = await axios.get(endpoint);
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// Censys
app.post('/api/censys', async (req, res) => {
    const { query } = req.body;
    if (!process.env.CENSYS_API_ID || !process.env.CENSYS_API_SECRET) return res.status(500).json({ error: "API credentials missing" });

    const queryType = detectQueryType(query);
    if (queryType !== "ip") return res.json({ data: { "Status": "IP only" } });

    try {
        const auth = btoa(`${process.env.CENSYS_API_ID}:${process.env.CENSYS_API_SECRET}`);
        const response = await axios.get(`https://search.censys.io/api/v2/hosts/${query}`, {
            headers: { Authorization: `Basic ${auth}` },
        });
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// BinaryEdge
app.post('/api/binaryedge', async (req, res) => {
    const { query } = req.body;
    if (!process.env.BINARYEDGE_API_KEY) return res.status(500).json({ error: "API Key missing" });

    const queryType = detectQueryType(query);
    if (queryType !== "ip") return res.json({ data: { "Status": "IP only" } });

    try {
        const response = await axios.get(`https://api.binaryedge.io/v2/query/ip/${query}`, {
            headers: { "X-Key": process.env.BINARYEDGE_API_KEY },
        });
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// GreyNoise
app.post('/api/greynoise', async (req, res) => {
    const { query } = req.body;
    if (!process.env.GREYNOISE_API_KEY) return res.status(500).json({ error: "API Key missing" });

    const queryType = detectQueryType(query);
    if (queryType !== "ip") return res.json({ data: { "Status": "IP only" } });

    try {
        const response = await axios.get(`https://api.greynoise.io/v3/community/${query}`, {
            headers: { "key": process.env.GREYNOISE_API_KEY },
        });
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// IPQualityScore
app.post('/api/ipqs', async (req, res) => {
    const { query } = req.body;
    if (!process.env.IPQS_API_KEY) return res.status(500).json({ error: "API Key missing" });

    const queryType = detectQueryType(query);
    if (queryType !== "ip") return res.json({ data: { "Status": "IP only" } });

    try {
        const response = await axios.get(`https://ipqualityscore.com/api/json/ip/${process.env.IPQS_API_KEY}/${query}`);
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// Hybrid Analysis
app.post('/api/hybridanalysis', async (req, res) => {
    const { query } = req.body;
    if (!process.env.HYBRID_ANALYSIS_API_KEY) return res.status(500).json({ error: "API Key missing" });

    const queryType = detectQueryType(query);
    if (queryType !== "hash") return res.json({ data: { "Status": "Hash only" } });

    try {
        const response = await axios.post(`https://www.hybrid-analysis.com/api/v2/search/hash`,
            `hash=${query}`,
            {
                headers: {
                    "api-key": process.env.HYBRID_ANALYSIS_API_KEY,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            }
        );
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// CIRCL hashlookup
app.post('/api/circl', async (req, res) => {
    const { query } = req.body;
    const queryType = detectQueryType(query);
    if (queryType !== "hash") return res.json({ data: { "Status": "Hash only" } });

    try {
        const response = await axios.get(`https://hashlookup.circl.lu/lookup/${queryType}/${query}`);
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// Criminal IP
app.post('/api/criminalip', async (req, res) => {
    const { query } = req.body;
    if (!process.env.CRIMINALIP_API_KEY) return res.status(500).json({ error: "API Key missing" });

    const queryType = detectQueryType(query);
    if (queryType !== "ip" && queryType !== "domain") return res.json({ data: { "Status": "IP/Domain only" } });

    try {
        const endpoint = queryType === "ip"
            ? `https://api.criminalip.io/v1/ip/data?ip=${query}`
            : `https://api.criminalip.io/v1/domain/reports?query=${query}`;

        const response = await axios.get(endpoint, {
            headers: { "x-api-key": process.env.CRIMINALIP_API_KEY },
        });
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// MetaDefender
app.post('/api/metadefender', async (req, res) => {
    const { query } = req.body;
    if (!process.env.METADEFENDER_API_KEY) return res.status(500).json({ error: "API Key missing" });

    const queryType = detectQueryType(query);
    if (queryType !== "hash" && queryType !== "ip") return res.json({ data: { "Status": "Hash/IP only" } });

    try {
        const endpoint = queryType === "hash"
            ? `https://api.metadefender.com/v4/hash/${query}`
            : `https://api.metadefender.com/v4/ip/${query}`;

        const response = await axios.get(endpoint, {
            headers: { "apikey": process.env.METADEFENDER_API_KEY },
        });
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// PhishStats
app.post('/api/phishstats', async (req, res) => {
    const { query } = req.body;
    const queryType = detectQueryType(query);
    if (queryType !== "url" && queryType !== "domain") return res.json({ data: { "Status": "URL/Domain only" } });

    try {
        const searchTerm = queryType === "url" ? query : query;
        const response = await axios.get(`https://phishstats.info:2096/api/phishing?_where=(url,like,${encodeURIComponent(searchTerm)})&_sort=-date&_size=5`);
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// Ransomware.live
app.post('/api/ransomwarelive', async (req, res) => {
    const { query } = req.body;
    try {
        const response = await axios.get(`https://www.ransomware.live/api/recentvictims`);
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// WHOIS
app.post('/api/whois', async (req, res) => {
    const { query } = req.body;
    const queryType = detectQueryType(query);
    if (queryType !== "domain") return res.json({ data: { "Status": "Domain only" } });

    try {
        const response = await axios.get(`https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_free&domainName=${query}&outputFormat=JSON`);
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// IP Geolocation
app.post('/api/ipgeo', async (req, res) => {
    const { query } = req.body;
    const queryType = detectQueryType(query);
    if (queryType !== "ip") return res.json({ data: { "Status": "IP only" } });

    try {
        const response = await axios.get(`http://ip-api.com/json/${query}?fields=status,country,regionName,city,isp,org,as,proxy,hosting`);
        res.json(response.data);
    } catch (error) {
        res.status(error.response?.status || 500).json({ error: error.message });
    }
});

// Serve frontend in production
if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.join(__dirname, '../dist')));
    app.get('*', (req, res) => {
        res.sendFile(path.join(__dirname, '../dist/index.html'));
    });
}

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
