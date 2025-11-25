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

// Generic fetcher for backend API
const fetchFromBackend = async (endpoint: string, query: string, vendorName: string): Promise<VendorData> => {
    try {
        const response = await fetch(`/api/${endpoint}`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query })
        });
        const data = await handleResponse(response, vendorName);

        // Transform backend response to VendorData format if needed
        // Most backend endpoints return the raw data, so we might need to map it here
        // or the backend could return the formatted data. 
        // For now, let's assume the backend returns the raw 3rd party response 
        // and we keep the formatting logic here to minimize backend complexity.
        return { name: vendorName, data: formatVendorData(vendorName, data, query) };
    } catch (error) {
        return { name: vendorName, data: {}, error: (error as Error).message };
    }
};

// Formatting logic moved from individual fetch functions
const formatVendorData = (vendorName: string, data: any, query: string): any => {
    if (data.error) throw new Error(data.error);
    if (data.data?.Status && (data.data.Status.includes("only") || data.data.Status === "No data")) return data.data;

    switch (vendorName) {
        case "VirusTotal":
            return {
                "Detection Rate": `${data.data.attributes.last_analysis_stats.malicious}/${Object.keys(data.data.attributes.last_analysis_results).length}`,
                "Status": data.data.attributes.last_analysis_stats.malicious > 0 ? "Malicious" : "Clean",
                "Top Detections": Object.values(data.data.attributes.last_analysis_results)
                    .filter((r: any) => r.category === "malicious")
                    .map((r: any) => r.engine_name)
                    .slice(0, 3),
            };
        case "AbuseIPDB":
            return {
                "Abuse Confidence Score": `${data.data.abuseConfidenceScore}%`,
                "Reports": `${data.data.totalReports} reports`,
                "Last Report": data.data.lastReportedAt,
            };
        case "AlienVault OTX":
            return {
                "Pulse Count": `${data.pulse_info.count} pulses`,
                "Status": data.pulse_info.count > 0 ? "Suspicious Activity" : "Clean",
                "Summary": data.pulse_info.pulses.length > 0 ? data.pulse_info.pulses[0].name : "No recent activity",
            };
        case "Shodan":
            return {
                "Open Ports": data.ports?.slice(0, 5).map((p: number) => `${p}`) || [],
                "Services": data.data?.slice(0, 3).map((d: any) => d.product || d.port).join(", ") || "Unknown",
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
                "Threats": data.threats?.slice(0, 3).join(", ") || "None",
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
                "Score": data.score || "Unknown",
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
        case "IP Geolocation":
            if (data.status === "success") {
                return {
                    "Country": `${data.country} (${data.regionName})`,
                    "City": data.city || "Unknown",
                    "ISP": data.isp || "Unknown",
                    "Organization": data.org || "Unknown",
                    "ASN": data.as || "Unknown",
                    "Proxy": data.proxy ? "Yes" : "No",
                    "Hosting": data.hosting ? "Yes" : "No",
                };
            }
            return { "Status": "Location not found" };
        default:
            return data;
    }
};

// Exported fetch functions
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
export const fetchWHOISData = (query: string) => fetchFromBackend('whois', query, "WHOIS");
export const fetchIPGeoData = (query: string) => fetchFromBackend('ipgeo', query, "IP Geolocation");

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
    };

    // If selectedVendors is provided, only query those vendors
    const vendorsToQuery = selectedVendors || Object.keys(vendorMap);
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
