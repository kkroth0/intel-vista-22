/// <reference types="vite/client" />
import { ThreatIntelligenceResult, VendorData } from "@/types/threat-intelligence";

// Helper to handle response
const handleResponse = async (response: Response, vendorName: string) => {
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`${vendorName} API error: ${response.status} ${response.statusText} - ${errorText}`);
    }
    return response.json();
};

// Detect IOC type from query
const detectIOCType = (query: string): 'ip' | 'domain' | 'hash' | 'url' => {
    if (query.startsWith('http://') || query.startsWith('https://')) return 'url';
    if (/^[a-fA-F0-9]{32}$/.test(query)) return 'hash'; // MD5
    if (/^[a-fA-F0-9]{40}$/.test(query)) return 'hash'; // SHA1
    if (/^[a-fA-F0-9]{64}$/.test(query)) return 'hash'; // SHA256
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(query)) return 'ip';
    return 'domain';
};

// Map vendors to IOC types they support
export const VENDOR_IOC_SUPPORT: Record<string, ('ip' | 'domain' | 'hash' | 'url')[]> = {
    "IP Geolocation": ['ip'],
    "WHOIS": ['domain'],
    "VirusTotal": ['ip', 'domain', 'hash', 'url'],
    "AbuseIPDB": ['ip'],
    "AlienVault OTX": ['ip', 'domain', 'hash'],
    "Shodan": ['ip'],
    "URLhaus": ['url', 'domain'],
    "ThreatFox": ['ip', 'domain', 'hash'],
    "MalwareBazaar": ['hash'],
    "Google Safe Browsing": ['url', 'domain'],
    "PhishTank": ['url', 'domain'],
    "Pulsedive": ['ip', 'domain', 'hash'],
    "ThreatCrowd": ['ip', 'domain'],
    "Censys": ['ip'],
    "BinaryEdge": ['ip'],
    "GreyNoise": ['ip'],
    "IPQualityScore": ['ip'],
    "Hybrid Analysis": ['hash'],
    "CIRCL hashlookup": ['hash'],
    "Criminal IP": ['ip', 'domain'],
    "MetaDefender": ['ip', 'hash'],
    "PhishStats": ['url', 'domain'],
    "Ransomware.live": ['domain'],
    "IBM X-Force": ['ip', 'domain', 'hash'],
    "Spamhaus": ['ip', 'domain'],
    "Blocklist.de": ['ip'],
};

// Formatting logic moved from individual fetch functions
const formatVendorData = (vendorName: string, data: any, query: string): any => {
    if (data.error) throw new Error(data.error);
    if (data.data?.Status && (data.data.Status.includes("only") || data.data.Status === "No data")) return data.data;

    switch (vendorName) {
        case "VirusTotal":
            // VirusTotal response is wrapped in data property, and backend wraps it in data property
            // So we need data.data.data
            const vtData = data.data?.data ? data.data.data : data.data;
            if (!vtData?.attributes?.last_analysis_stats) return { "Status": "No data available" };
            const vtAttrs = vtData.attributes;

            // Extract ALL detection vendors (not just malicious)
            const allDetections = vtAttrs.last_analysis_results || {};
            const detectionVendors = Object.keys(allDetections).map(engine => ({
                engine,
                category: allDetections[engine].category,
                result: allDetections[engine].result
            }));

            return {
                "Detection Rate": `${vtAttrs.last_analysis_stats.malicious || 0}/${Object.keys(vtAttrs.last_analysis_results || {}).length}`,
                "Status": vtAttrs.last_analysis_stats.malicious > 0 ? "Malicious" : "Clean",
                "Malicious": vtAttrs.last_analysis_stats.malicious || 0,
                "Suspicious": vtAttrs.last_analysis_stats.suspicious || 0,
                "Undetected": vtAttrs.last_analysis_stats.undetected || 0,
                "Harmless": vtAttrs.last_analysis_stats.harmless || 0,
                "Top Detections": Object.values(vtAttrs.last_analysis_results || {})
                    .filter((r: any) => r.category === "malicious")
                    .map((r: any) => r.engine_name)
                    .slice(0, 5).join(", ") || "None",
                "All Vendors": detectionVendors,  // All vendor results for detailed view
                "Reputation": vtAttrs.reputation || 0,
                "Network": vtAttrs.network || "Unknown",
                "AS Owner": vtAttrs.as_owner || "Unknown",
                "ASN": vtAttrs.asn || "Unknown",
                "Country": vtAttrs.country || "Unknown",
                "Last Analysis": vtAttrs.last_analysis_date ? new Date(vtAttrs.last_analysis_date * 1000).toLocaleString() : "Unknown",
                "Tags": vtAttrs.tags?.slice(0, 5).join(", ") || "None",
            };
        case "AbuseIPDB":
            // AbuseIPDB response is wrapped in data property, and backend wraps it in data property
            const abuseData = data.data?.data ? data.data.data : data.data;
            if (!abuseData) return { "Status": "No data available" };

            // Extract reports if available
            const reports = abuseData.reports?.slice(0, 5).map((r: any) => ({
                date: r.reportedAt,
                comment: r.comment || "No comment",
                categories: r.categories || [],
                reporterId: r.reporterId || "Unknown",
                reporterCountry: r.reporterCountryCode || "Unknown"
            })) || [];

            return {
                "Abuse Confidence Score": `${abuseData.abuseConfidenceScore || 0}%`,
                "Total Reports": abuseData.totalReports || 0,
                "Distinct Reporters": abuseData.numDistinctUsers || 0,
                "Last Report": abuseData.lastReportedAt || "Never",
                "Country": abuseData.countryCode || "Unknown",
                "Usage Type": abuseData.usageType || "Unknown",
                "ISP": abuseData.isp || "Unknown",
                "Domain": abuseData.domain || "Unknown",
                "Hostnames": abuseData.hostnames?.slice(0, 3).join(", ") || "None",
                "Is Public": abuseData.isPublic ? "Yes" : "No",
                "Is Whitelisted": abuseData.isWhitelisted ? "Yes" : "No",
                "Reports": reports,  // Last 5 reports with details
            };
        case "AlienVault OTX":
            // OTX response is wrapped by backend in data property
            const otxData = data.data || data;
            if (!otxData.pulse_info) return { "Status": "No data available" };
            return {
                "Pulse Count": `${otxData.pulse_info.count || 0} pulses`,
                "Status": (otxData.pulse_info.count || 0) > 0 ? "Suspicious Activity" : "Clean",
                "Pulses": otxData.pulse_info.pulses?.slice(0, 3).map((p: any) => p.name).join(", ") || "No recent activity",
                "Reputation": otxData.reputation || 0,
                "Country": otxData.country_name || "Unknown",
                "City": otxData.city || "Unknown",
                "ASN": otxData.asn || "Unknown",
                "Sections": otxData.sections?.join(", ") || "None",
            };
        case "Shodan":
            return {
                "Open Ports": data.ports?.slice(0, 5).join(", ") || "None",
                "Services": Array.isArray(data.data) ? data.data.slice(0, 3).map((d: any) => d.product || d.port).join(", ") : "Unknown",
                "Vulnerabilities": data.vulns ? `${Object.keys(data.vulns).length} CVEs` : "0 CVEs",
            };
        case "URLhaus":
            if (data.query_status === "ok") {
                return {
                    "Status": data.urls?.length > 0 ? "Malicious URLs Found" : "Clean",
                    "URL Count": data.urls?.length || 0,
                    "Tags": data.urls?.[0]?.tags || [],
                };
            }
            return { "Status": "No data" };
        case "ThreatFox":
            if (data.query_status === "ok") {
                return {
                    "IOCs Found": data.data?.length || 0,
                    "Threat Type": data.data?.[0]?.threat_type || "Unknown",
                    "Malware": data.data?.[0]?.malware_printable || "Unknown",
                };
            }
            return { "Status": "No IOCs found" };
        case "MalwareBazaar":
            if (data.query_status === "ok") {
                return {
                    "Status": "Sample Found",
                    "File Type": data.data?.[0]?.file_type || "Unknown",
                    "Signature": data.data?.[0]?.signature || "Unknown",
                };
            }
            return { "Status": "No samples found" };
        case "Google Safe Browsing":
            if (data.matches && data.matches.length > 0) {
                return {
                    "Status": "Unsafe",
                    "Threat Type": data.matches[0].threatType,
                };
            }
            return { "Status": "Safe" };
        case "PhishTank":
            return {
                "Status": data.results?.in_database ? (data.results.valid ? "Verified Phishing" : "Not Phishing") : "Unknown",
                "Verified": data.results?.verified ? "Yes" : "No",
            };
        case "Pulsedive":
            return {
                "Risk": data.risk || "Unknown",
                "Threats": Array.isArray(data.threats) ? data.threats.slice(0, 3).map((t: any) => typeof t === 'string' ? t : t.name || t.type || 'Unknown').join(", ") : "None",
                "Feeds": data.feeds?.length || 0,
            };
        case "ThreatCrowd":
            return {
                "Votes": `Malicious: ${data.votes || 0}`,
                "Resolutions": data.resolutions?.length || 0,
                "Hashes": data.hashes?.length || 0,
            };
        case "Censys":
            return {
                "Services": data.result?.services?.length || 0,
                "Protocols": data.result?.services?.slice(0, 3).map((s: any) => s.service_name).join(", ") || "Unknown",
            };
        case "BinaryEdge":
            return {
                "Events": data.events?.length || 0,
                "Ports": data.events?.slice(0, 5).map((e: any) => e.port).join(", ") || "None",
            };
        case "GreyNoise":
            return {
                "Classification": data.classification || "Unknown",
                "Noise": data.noise ? "Yes" : "No",
                "Riot": data.riot ? "Yes" : "No",
                "Last Seen": data.last_seen || "Never",
            };
        case "IPQualityScore":
            return {
                "Fraud Score": `${data.fraud_score}/100`,
                "Proxy": data.proxy ? "Yes" : "No",
                "VPN": data.vpn ? "Yes" : "No",
                "Tor": data.tor ? "Yes" : "No",
                "Status": data.fraud_score > 75 ? "High Risk" : data.fraud_score > 50 ? "Moderate Risk" : "Low Risk",
            };
        case "Hybrid Analysis":
            if (Array.isArray(data) && data.length > 0) {
                return {
                    "Verdict": data[0].verdict || "Unknown",
                    "Threat Score": `${data[0].threat_score}/100`,
                    "AV Detect": `${data[0].av_detect}%`,
                };
            }
            return { "Status": "No analysis found" };
        case "CIRCL hashlookup":
            return {
                "Status": "Found in database",
                "File Name": data.FileName || "Unknown",
                "File Size": data.FileSize || "Unknown",
            };
        case "Criminal IP":
            return {
                "Score": typeof data.score === 'object' ? (data.score?.inbound || data.score?.value || JSON.stringify(data.score)) : (data.score || "Unknown"),
                "Issues": data.issues?.length || 0,
                "Status": data.is_malicious ? "Malicious" : "Clean",
            };
        case "MetaDefender":
            if (data.scan_results) {
                return {
                    "Detection Rate": `${data.scan_results?.total_detected_avs}/${data.scan_results?.total_avs}`,
                    "Status": data.scan_results?.total_detected_avs > 0 ? "Malicious" : "Clean",
                };
            }
            return {
                "Geo Location": data.geo_info?.country?.name || "Unknown",
                "Detected AVs": data.lookup_results?.detected_by || 0,
            };
        case "PhishStats":
            if (Array.isArray(data) && data.length > 0) {
                return {
                    "Status": "Found in Phishing Database",
                    "Records Found": data.length,
                    "Latest Score": data[0].score || "Unknown",
                    "Country": data[0].countrycode || "Unknown",
                };
            }
            return { "Status": "Not found in phishing database" };
        case "Ransomware.live":
            const matches = data.filter((victim: any) =>
                victim.post_url?.includes(query) || victim.website?.includes(query)
            );
            if (matches.length > 0) {
                return {
                    "Status": "Found in Ransomware Victims",
                    "Matches": matches.length,
                    "Group": matches[0].group_name || "Unknown",
                    "Discovered": matches[0].discovered || "Unknown",
                };
            }
            return { "Status": "Not found in ransomware database" };
        case "WHOIS":
            if (data.WhoisRecord) {
                const record = data.WhoisRecord;
                return {
                    "Registrar": record.registrarName || "Unknown",
                    "Created": record.createdDate || "Unknown",
                    "Expires": record.expiresDate || "Unknown",
                    "Status": record.status?.[0] || "Unknown",
                };
            }
            return { "Status": "No WHOIS data available" };

        case "Shodan":
            return {
                "Open Ports": data.ports?.slice(0, 5).join(", ") || "None",
                "Total Ports": data.ports?.length || 0,
                "Services": Array.isArray(data.data) ? data.data.slice(0, 3).map((d: any) => d.product || d.port).join(", ") : "Unknown",
                "Organization": data.org || "Unknown",
                "Hostnames": data.hostnames?.slice(0, 3).join(", ") || "None",
                "Domains": data.domains?.slice(0, 3).join(", ") || "None",
                "OS": data.os || "Unknown",
                "Last Update": data.last_update || "Unknown",
                "ASN": data.asn || "Unknown",
                "ISP": data.isp || "Unknown",
                "Vulnerabilities": data.vulns ? `${Object.keys(data.vulns).length} CVEs` : "0 CVEs",
                "Tags": data.tags?.slice(0, 5).join(", ") || "None"
            };
        default:
            return data;
    }
};


// Helper to get vendor analysis link
const getVendorLink = (vendorName: string, query: string): string | undefined => {
    const encodedQuery = encodeURIComponent(query);
    switch (vendorName) {
        case "VirusTotal":
            if (query.includes(".")) return `https://www.virustotal.com/gui/search/${encodedQuery}`;
            return `https://www.virustotal.com/gui/file/${query}`;
        case "AbuseIPDB": return `https://www.abuseipdb.com/check/${query}`;
        case "AlienVault OTX": return `https://otx.alienvault.com/indicator/ip/${query}`;
        case "Shodan": return `https://www.shodan.io/host/${query}`;
        case "URLhaus": return `https://urlhaus.abuse.ch/browse/search/${encodedQuery}/`;
        case "ThreatFox": return `https://threatfox.abuse.ch/browse/`;
        case "MalwareBazaar": return `https://bazaar.abuse.ch/browse/`;
        case "Google Safe Browsing": return `https://transparencyreport.google.com/safe-browsing/search?url=${encodedQuery}`;
        case "PhishTank": return `https://phishtank.org/`;
        case "Pulsedive": return `https://pulsedive.com/indicator/?ioc=${encodedQuery}`;
        case "ThreatCrowd": return `https://www.threatcrowd.org/ip.php?ip=${query}`;
        case "Censys": return `https://search.censys.io/hosts/${query}`;
        case "BinaryEdge": return `https://app.binaryedge.io/services/query/${query}`;
        case "GreyNoise": return `https://viz.greynoise.io/ip/${query}`;
        case "IPQualityScore": return `https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/${query}`;
        case "Hybrid Analysis": return `https://www.hybrid-analysis.com/search?query=${encodedQuery}`;
        case "CIRCL hashlookup": return `https://hashlookup.circl.lu/`;
        case "Criminal IP": return `https://www.criminalip.io/asset/report/${query}`;
        case "MetaDefender": return `https://metadefender.opswat.com/results/ip/${query}`;
        case "PhishStats": return `https://phishstats.info/`;
        case "Ransomware.live": return `https://ransomware.live/`;
        case "IBM X-Force": return `https://exchange.xforce.ibmcloud.com/ip/${query}`;
        case "Spamhaus": return `https://check.spamhaus.org/`;
        case "Blocklist.de": return `http://www.blocklist.de/en/view.html?ip=${query}`;
        case "OpenPhish": return `https://openphish.com/`;
        case "DShield": return `https://isc.sans.edu/ipinfo.html?ip=${query}`;
        case "Team Cymru": return `https://team-cymru.com/community-services/ip-asn-mapping/`;
        case "WHOIS": return `https://who.is/whois/${query}`;
        case "IP Geolocation": return `https://ip-api.com/#${query}`;
        default: return undefined;
    }
};

// Generic fetcher for backend API
const fetchFromBackend = async (endpoint: string, query: string, vendorName: string): Promise<VendorData> => {
    try {
        const response = await fetch(`/api/${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query })
        });
        const data = await handleResponse(response, vendorName);

        return {
            name: vendorName,
            data: formatVendorData(vendorName, data, query),
            link: getVendorLink(vendorName, query)
        };
    } catch (error) {
        return { name: vendorName, data: {}, error: (error as Error).message };
    }
};

// Exported fetch functions
export const fetchIPGeoData = (query: string) => fetchFromBackend('ipgeo', query, "IP Geolocation");
export const fetchWHOISData = (query: string) => fetchFromBackend('whois', query, "WHOIS");
export const fetchVirusTotalData = (query: string) => fetchFromBackend('virustotal', query, "VirusTotal");
export const fetchAbuseIPDBData = (query: string) => fetchFromBackend('abuseipdb', query, "AbuseIPDB");
export const fetchAlienVaultData = (query: string) => fetchFromBackend('alienvault', query, "AlienVault OTX");
export const fetchShodanData = (query: string) => fetchFromBackend('shodan', query, "Shodan");
export const fetchURLhausData = (query: string) => fetchFromBackend('urlhaus', query, "URLhaus");
export const fetchThreatFoxData = (query: string) => fetchFromBackend('threatfox', query, "ThreatFox");
export const fetchMalwareBazaarData = (query: string) => fetchFromBackend('malwarebazaar', query, "MalwareBazaar");
export const fetchGoogleSafeBrowsingData = (query: string) => fetchFromBackend('googlesafebrowsing', query, "Google Safe Browsing");
export const fetchPhishTankData = (query: string) => fetchFromBackend('phishtank', query, "PhishTank");
export const fetchPulsediveData = (query: string) => fetchFromBackend('pulsedive', query, "Pulsedive");
export const fetchThreatCrowdData = (query: string) => fetchFromBackend('threatcrowd', query, "ThreatCrowd");
export const fetchCensysData = (query: string) => fetchFromBackend('censys', query, "Censys");
export const fetchBinaryEdgeData = (query: string) => fetchFromBackend('binaryedge', query, "BinaryEdge");
export const fetchGreyNoiseData = (query: string) => fetchFromBackend('greynoise', query, "GreyNoise");
export const fetchIPQSData = (query: string) => fetchFromBackend('ipqs', query, "IPQualityScore");
export const fetchHybridAnalysisData = (query: string) => fetchFromBackend('hybridanalysis', query, "Hybrid Analysis");
export const fetchCIRCLData = (query: string) => fetchFromBackend('circl', query, "CIRCL hashlookup");
export const fetchCriminalIPData = (query: string) => fetchFromBackend('criminalip', query, "Criminal IP");
export const fetchMetaDefenderData = (query: string) => fetchFromBackend('metadefender', query, "MetaDefender");
export const fetchPhishStatsData = (query: string) => fetchFromBackend('phishstats', query, "PhishStats");
export const fetchRansomwareLiveData = (query: string) => fetchFromBackend('ransomwarelive', query, "Ransomware.live");
export const fetchXForceData = (query: string) => fetchFromBackend('xforce', query, "IBM X-Force");
export const fetchSpamhausData = (query: string) => fetchFromBackend('spamhaus', query, "Spamhaus");
export const fetchBlocklistDeData = (query: string) => fetchFromBackend('blocklistde', query, "Blocklist.de");
export const fetchOpenPhishData = (query: string) => fetchFromBackend('openphish', query, "OpenPhish");
export const fetchDShieldData = (query: string) => fetchFromBackend('dshield', query, "DShield");
export const fetchTeamCymruData = (query: string) => fetchFromBackend('teamcymru', query, "Team Cymru");

export const fetchThreatData = async (query: string, selectedVendors?: string[]): Promise<ThreatIntelligenceResult> => {
    // Map vendor names to their fetch functions
    const vendorMap: Record<string, () => Promise<VendorData>> = {
        "IP Geolocation": () => fetchIPGeoData(query),
        "WHOIS": () => fetchWHOISData(query),
        "VirusTotal": () => fetchVirusTotalData(query),
        "AbuseIPDB": () => fetchAbuseIPDBData(query),
        "AlienVault OTX": () => fetchAlienVaultData(query),
        "Shodan": () => fetchShodanData(query),
        "URLhaus": () => fetchURLhausData(query),
        "ThreatFox": () => fetchThreatFoxData(query),
        "MalwareBazaar": () => fetchMalwareBazaarData(query),
        "Google Safe Browsing": () => fetchGoogleSafeBrowsingData(query),
        "PhishTank": () => fetchPhishTankData(query),
        "Pulsedive": () => fetchPulsediveData(query),
        "ThreatCrowd": () => fetchThreatCrowdData(query),
        "Censys": () => fetchCensysData(query),
        "BinaryEdge": () => fetchBinaryEdgeData(query),
        "GreyNoise": () => fetchGreyNoiseData(query),
        "IPQualityScore": () => fetchIPQSData(query),
        "Hybrid Analysis": () => fetchHybridAnalysisData(query),
        "CIRCL hashlookup": () => fetchCIRCLData(query),
        "Criminal IP": () => fetchCriminalIPData(query),
        "MetaDefender": () => fetchMetaDefenderData(query),
        "PhishStats": () => fetchPhishStatsData(query),
        "Ransomware.live": () => fetchRansomwareLiveData(query),
        "IBM X-Force": () => fetchXForceData(query),
        "Spamhaus": () => fetchSpamhausData(query),
        "Blocklist.de": () => fetchBlocklistDeData(query),
        "OpenPhish": () => fetchOpenPhishData(query),
        "DShield": () => fetchDShieldData(query),
        "Team Cymru": () => fetchTeamCymruData(query),
    };

    // Detect IOC type
    const iocType = detectIOCType(query);

    // If selectedVendors is provided, only query those vendors
    // Otherwise query all vendors that support this IOC type
    let vendorsToQuery = selectedVendors || Object.keys(vendorMap);

    // Filter by IOC support
    vendorsToQuery = vendorsToQuery.filter(vendor => {
        const supportedTypes = VENDOR_IOC_SUPPORT[vendor];
        return supportedTypes && supportedTypes.includes(iocType);
    });

    const fetchPromises = vendorsToQuery
        .filter(vendor => vendorMap[vendor]) // Ensure vendor exists in map
        .map(vendor => vendorMap[vendor]());

    const results = await Promise.all(fetchPromises);

    let maliciousCount = 0;
    let totalChecked = 0;

    results.forEach(vendor => {
        if (vendor.error || Object.keys(vendor.data).length === 0) return;

        const status = vendor.data["Status"];
        if (status && typeof status === "string") {
            totalChecked++;
            if (status.toLowerCase().includes("malicious") ||
                status.toLowerCase().includes("unsafe") ||
                status.toLowerCase().includes("phishing")) {
                maliciousCount++;
            }
        }
    });

    const abuse = results.find(v => v.name === "AbuseIPDB");
    if (abuse && abuse.data["Abuse Confidence Score"]) {
        if (parseInt(abuse.data["Abuse Confidence Score"] || "0") > 50) maliciousCount++;
        totalChecked++;
    }

    const overallScore = totalChecked > 0 ? Math.round((maliciousCount / totalChecked) * 100) : 0;
    let threatLevel: "safe" | "suspicious" | "malicious" | "unknown" = "unknown";
    if (overallScore > 70) threatLevel = "malicious";
    else if (overallScore > 30) threatLevel = "suspicious";
    else if (totalChecked > 0) threatLevel = "safe";

    return {
        query,
        overallScore,
        threatLevel,
        totalVendors: results.length,
        detections: maliciousCount,
        vendorData: results,
    };
};

export const fetchThreatDataProgressive = async (
    query: string,
    selectedVendors: string[] | undefined,
    onProgress: (data: VendorData) => void
): Promise<ThreatIntelligenceResult> => {
    // Map vendor names to their fetch functions
    const vendorMap: Record<string, () => Promise<VendorData>> = {
        "IP Geolocation": () => fetchIPGeoData(query),
        "WHOIS": () => fetchWHOISData(query),
        "VirusTotal": () => fetchVirusTotalData(query),
        "AbuseIPDB": () => fetchAbuseIPDBData(query),
        "AlienVault OTX": () => fetchAlienVaultData(query),
        "Shodan": () => fetchShodanData(query),
        "URLhaus": () => fetchURLhausData(query),
        "ThreatFox": () => fetchThreatFoxData(query),
        "MalwareBazaar": () => fetchMalwareBazaarData(query),
        "Google Safe Browsing": () => fetchGoogleSafeBrowsingData(query),
        "PhishTank": () => fetchPhishTankData(query),
        "Pulsedive": () => fetchPulsediveData(query),
        "ThreatCrowd": () => fetchThreatCrowdData(query),
        "Censys": () => fetchCensysData(query),
        "BinaryEdge": () => fetchBinaryEdgeData(query),
        "GreyNoise": () => fetchGreyNoiseData(query),
        "IPQualityScore": () => fetchIPQSData(query),
        "Hybrid Analysis": () => fetchHybridAnalysisData(query),
        "CIRCL hashlookup": () => fetchCIRCLData(query),
        "Criminal IP": () => fetchCriminalIPData(query),
        "MetaDefender": () => fetchMetaDefenderData(query),
        "PhishStats": () => fetchPhishStatsData(query),
        "Ransomware.live": () => fetchRansomwareLiveData(query),
        "IBM X-Force": () => fetchXForceData(query),
        "Spamhaus": () => fetchSpamhausData(query),
        "Blocklist.de": () => fetchBlocklistDeData(query),
        "OpenPhish": () => fetchOpenPhishData(query),
        "DShield": () => fetchDShieldData(query),
        "Team Cymru": () => fetchTeamCymruData(query),
    };

    // Detect IOC type
    const iocType = detectIOCType(query);

    // Smart filtering
    let vendorsToQuery = selectedVendors || Object.keys(vendorMap);
    vendorsToQuery = vendorsToQuery.filter(vendor => {
        const supportedTypes = VENDOR_IOC_SUPPORT[vendor];
        return supportedTypes && supportedTypes.includes(iocType);
    });

    // Create promises that call onProgress when they complete
    const fetchPromises = vendorsToQuery
        .filter(vendor => vendorMap[vendor])
        .map(vendor => {
            return vendorMap[vendor]().then(data => {
                onProgress(data);
                return data;
            });
        });

    const results = await Promise.all(fetchPromises);

    // Calculate scores (same logic as above)
    let maliciousCount = 0;
    let totalChecked = 0;

    results.forEach(vendor => {
        if (vendor.error || Object.keys(vendor.data).length === 0) return;
        const status = vendor.data["Status"];
        if (status && typeof status === "string") {
            totalChecked++;
            if (status.toLowerCase().includes("malicious") ||
                status.toLowerCase().includes("unsafe") ||
                status.toLowerCase().includes("phishing")) {
                maliciousCount++;
            }
        }
    });

    const abuse = results.find(v => v.name === "AbuseIPDB");
    if (abuse && abuse.data["Abuse Confidence Score"]) {
        if (parseInt(abuse.data["Abuse Confidence Score"] || "0") > 50) maliciousCount++;
        totalChecked++;
    }

    const overallScore = totalChecked > 0 ? Math.round((maliciousCount / totalChecked) * 100) : 0;
    let threatLevel: "safe" | "suspicious" | "malicious" | "unknown" = "unknown";
    if (overallScore > 70) threatLevel = "malicious";
    else if (overallScore > 30) threatLevel = "suspicious";
    else if (totalChecked > 0) threatLevel = "safe";

    return {
        query,
        overallScore,
        threatLevel,
        totalVendors: results.length,
        detections: maliciousCount,
        vendorData: results,
    };
};
