import { useState, useEffect } from "react";
import { useQuery, keepPreviousData } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Shield, AlertTriangle, Bug, FileSearch, Globe, Link as LinkIcon, Radar, Database, Eye, Search, Copy, RefreshCw, BookOpen } from "lucide-react";
import { ThreatSummary } from "@/components/ThreatSummary";
import { VendorCard } from "@/components/VendorCard";
import { VendorContent } from "@/components/VendorContent";
import { VendorFilter } from "@/components/VendorFilter";
import { ThemeToggle } from "@/components/ThemeToggle";
import { Footer } from "@/components/Footer";
import { HistorySidebar } from "@/components/HistorySidebar";

import { ThreatCharts } from "@/components/ThreatCharts";
import { VendorDataTable } from "@/components/VendorDataTable";
import { QuickActions } from "@/components/QuickActions";
import { ViewToggle } from "@/components/ViewToggle";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { fetchThreatData, fetchThreatDataProgressive } from "@/services/threatApi";
import { useToast } from "@/hooks/use-toast";
import { ThreatIntelligenceResult } from "@/types/threat-intelligence";

interface SearchFormProps {
  query: string;
  setQuery: (query: string) => void;
  onSubmit: (e: React.FormEvent) => void;
  isLoading: boolean;
  className?: string;
}

const SearchForm = ({ query, setQuery, onSubmit, isLoading, className = "" }: SearchFormProps) => (
  <form onSubmit={onSubmit} className={`flex gap-2 w-full ${className}`}>
    <Input
      placeholder="Enter IP, domain, or hash (e.g., 1.1.1.1, example.com)"
      value={query}
      onChange={(e) => setQuery(e.target.value)}
      className="flex-1"
    />
    <Button type="submit" disabled={isLoading}>
      {isLoading ? "Analyzing..." : <><Search className="mr-2 h-4 w-4" /> Analyze</>}
    </Button>
  </form>
);

const ALL_VENDORS = [
  "IP Geolocation", "WHOIS", "VirusTotal", "AbuseIPDB", "AlienVault OTX",
  "Shodan", "URLhaus", "ThreatFox", "MalwareBazaar", "Google Safe Browsing",
  "PhishTank", "Pulsedive", "ThreatCrowd", "Censys", "BinaryEdge",
  "GreyNoise", "IPQualityScore", "Hybrid Analysis", "CIRCL hashlookup",
  "Criminal IP", "MetaDefender", "PhishStats", "Ransomware.live",
  "IBM X-Force", "Spamhaus", "Blocklist.de", "OpenPhish", "DShield", "Team Cymru"
];

interface HistoryItem {
  query: string;
  timestamp: number;
  threatLevel: "safe" | "suspicious" | "malicious" | "unknown";
}


const Index = () => {
  const [query, setQuery] = useState("");
  const [selectedVendors, setSelectedVendors] = useState<string[]>(ALL_VENDORS);
  const [history, setHistory] = useState<HistoryItem[]>([]);

  const [data, setData] = useState<ThreatIntelligenceResult | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<"cards" | "table">("cards");
  const { toast } = useToast();

  // Load saved preferences and history
  useEffect(() => {
    const savedVendors = localStorage.getItem("selectedVendors");
    if (savedVendors) {
      try {
        setSelectedVendors(JSON.parse(savedVendors));
      } catch (e) {
        console.error("Failed to parse saved vendors", e);
      }
    }

    const savedHistory = localStorage.getItem("searchHistory");
    if (savedHistory) {
      try {
        setHistory(JSON.parse(savedHistory));
      } catch (e) {
        console.error("Failed to parse history", e);
      }
    }
  }, []);

  const handleSearch = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();

    const trimmedQuery = query.trim();

    if (!trimmedQuery) {
      toast({
        title: "Error",
        description: "Please enter an IP address, domain, or hash",
        variant: "destructive",
      });
      return;
    }

    // Input Validation
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
    const urlRegex = /^(http|https):\/\/[^ "]+$/;

    if (!ipRegex.test(trimmedQuery) &&
      !domainRegex.test(trimmedQuery) &&
      !hashRegex.test(trimmedQuery) &&
      !urlRegex.test(trimmedQuery)) {
      toast({
        title: "Invalid Input",
        description: "Please enter a valid IP address (e.g. 8.8.8.8), Domain (e.g. google.com), Hash (MD5/SHA1/SHA256), or URL.",
        variant: "destructive",
      });
      return;
    }

    setIsAnalyzing(true);
    setError(null);

    // Initialize with loading cards for all selected vendors
    setData({
      query: trimmedQuery,
      overallScore: 0,
      threatLevel: "unknown",
      totalVendors: selectedVendors.length,
      detections: 0,
      vendorData: selectedVendors.map(vendorName => ({
        name: vendorName,
        data: {},
        loading: true
      }))
    });

    try {
      const finalResult = await fetchThreatDataProgressive(trimmedQuery, selectedVendors, (vendorData) => {
        setData(prev => {
          if (!prev) return null;
          // Replace the loading vendor card with actual data
          return {
            ...prev,
            vendorData: prev.vendorData.map(v =>
              v.name === vendorData.name ? { ...vendorData, loading: false } : v
            )
          };
        });
      });

      setData(finalResult);

      // Update history
      setHistory(prev => {
        const filtered = prev.filter(item => item.query !== finalResult.query);
        const newHistory = [
          { query: finalResult.query, timestamp: Date.now(), threatLevel: finalResult.threatLevel },
          ...filtered
        ].slice(0, 50);
        localStorage.setItem("searchHistory", JSON.stringify(newHistory));
        return newHistory;
      });

    } catch (error) {
      console.error("Analysis error:", error);
      setError("Failed to fetch threat data");
      toast({
        title: "Error",
        description: "Failed to fetch threat data",
        variant: "destructive",
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const onPivot = (artifact: string) => {
    setQuery(artifact);
    // Use a timeout to allow state update before triggering search
    setTimeout(() => {
      const form = document.querySelector('form');
      if (form) form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
    }, 100);
  };

  const generateVendorUrls = (searchQuery: string) => {
    const detectType = () => {
      if (/^(\d{1,3}\.){3}\d{1,3}$/.test(searchQuery)) return "ip";
      if (/^[a-fA-F0-9]{32,64}$/.test(searchQuery)) return "hash";
      return "domain";
    };

    const type = detectType();
    const urls: string[] = [];

    if (type === "ip") {
      urls.push(`VirusTotal: https://www.virustotal.com/gui/ip-address/${searchQuery}`);
      urls.push(`AbuseIPDB: https://www.abuseipdb.com/check/${searchQuery}`);
      urls.push(`AlienVault OTX: https://otx.alienvault.com/indicator/ip/${searchQuery}`);
      urls.push(`Shodan: https://www.shodan.io/host/${searchQuery}`);
      urls.push(`Censys: https://search.censys.io/hosts/${searchQuery}`);
      urls.push(`GreyNoise: https://viz.greynoise.io/ip/${searchQuery}`);
      urls.push(`ThreatCrowd: https://www.threatcrowd.org/ip.php?ip=${searchQuery}`);
      urls.push(`IPQualityScore: https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/${searchQuery}`);
      urls.push(`Criminal IP: https://www.criminalip.io/asset/report/${searchQuery}`);
    } else if (type === "domain") {
      urls.push(`VirusTotal: https://www.virustotal.com/gui/domain/${searchQuery}`);
      urls.push(`AlienVault OTX: https://otx.alienvault.com/indicator/domain/${searchQuery}`);
      urls.push(`ThreatCrowd: https://www.threatcrowd.org/domain.php?domain=${searchQuery}`);
      urls.push(`URLhaus: https://urlhaus.abuse.ch/browse.php?search=${searchQuery}`);
      urls.push(`PhishStats: https://phishstats.info/#/search?url=${searchQuery}`);
    } else if (type === "hash") {
      urls.push(`VirusTotal: https://www.virustotal.com/gui/file/${searchQuery}`);
      urls.push(`Hybrid Analysis: https://www.hybrid-analysis.com/search?query=${searchQuery}`);
      urls.push(`MalwareBazaar: https://bazaar.abuse.ch/browse.php?search=hash:${searchQuery}`);
      urls.push(`CIRCL: https://hashlookup.circl.lu/lookup/md5/${searchQuery}`);
    }

    return urls.join("\n\n");
  };

  const copyVendorLinks = () => {
    const links = generateVendorUrls(query);
    navigator.clipboard.writeText(links);
    toast({
      title: "Copied!",
      description: `${links.split("\n\n").length} vendor links copied to clipboard`,
    });
  };



  const getVendorIcon = (name: string) => {
    switch (name) {
      case "VirusTotal": return <Shield className="h-5 w-5 text-primary" />;
      case "AbuseIPDB": return <AlertTriangle className="h-5 w-5 text-primary" />;
      case "AlienVault OTX": return <Eye className="h-5 w-5 text-primary" />;
      case "Shodan": return <Radar className="h-5 w-5 text-primary" />;
      case "URLhaus": return <LinkIcon className="h-5 w-5 text-primary" />;
      case "ThreatFox": return <Database className="h-5 w-5 text-primary" />;
      case "MalwareBazaar": return <Bug className="h-5 w-5 text-primary" />;
      case "Google Safe Browsing": return <Shield className="h-5 w-5 text-primary" />;
      case "PhishTank": return <LinkIcon className="h-5 w-5 text-primary" />;
      case "Pulsedive": return <Radar className="h-5 w-5 text-primary" />;
      case "ThreatCrowd": return <Eye className="h-5 w-5 text-primary" />;
      case "Censys": return <Globe className="h-5 w-5 text-primary" />;
      case "BinaryEdge": return <FileSearch className="h-5 w-5 text-primary" />;
      case "GreyNoise": return <Radar className="h-5 w-5 text-primary" />;
      case "IPQualityScore": return <Shield className="h-5 w-5 text-primary" />;
      case "Hybrid Analysis": return <Bug className="h-5 w-5 text-primary" />;
      case "CIRCL hashlookup": return <Database className="h-5 w-5 text-primary" />;
      case "Criminal IP": return <AlertTriangle className="h-5 w-5 text-primary" />;
      case "MetaDefender": return <Shield className="h-5 w-5 text-primary" />;
      case "PhishStats": return <LinkIcon className="h-5 w-5 text-primary" />;
      case "Ransomware.live": return <Bug className="h-5 w-5 text-primary" />;
      case "WHOIS": return <FileSearch className="h-5 w-5 text-primary" />;
      case "IP Geolocation": return <Globe className="h-5 w-5 text-primary" />;
      default: return <Shield className="h-5 w-5 text-primary" />;
    }
  };

  const getVendorLink = (name: string) => {
    switch (name) {
      case "VirusTotal": return "https://virustotal.com";
      case "AbuseIPDB": return "https://abuseipdb.com";
      case "AlienVault OTX": return "https://otx.alienvault.com";
      case "Shodan": return "https://shodan.io";
      case "URLhaus": return "https://urlhaus.abuse.ch";
      case "ThreatFox": return "https://threatfox.abuse.ch";
      case "MalwareBazaar": return "https://bazaar.abuse.ch";
      case "Google Safe Browsing": return "https://safebrowsing.google.com";
      case "PhishTank": return "https://phishtank.com";
      case "Pulsedive": return "https://pulsedive.com";
      case "ThreatCrowd": return "https://threatcrowd.org";
      case "Censys": return "https://censys.io";
      case "BinaryEdge": return "https://binaryedge.io";
      case "GreyNoise": return "https://greynoise.io";
      case "IPQualityScore": return "https://ipqualityscore.com";
      case "Hybrid Analysis": return "https://hybrid-analysis.com";
      case "CIRCL hashlookup": return "https://hashlookup.circl.lu";
      case "Criminal IP": return "https://criminalip.io";
      case "MetaDefender": return "https://metadefender.opswat.com";
      case "PhishStats": return "https://phishstats.info";
      case "Ransomware.live": return "https://ransomware.live";
      case "WHOIS": return undefined;
      case "IP Geolocation": return undefined;
      default: return undefined;
    }
  };

  if (!data && !isAnalyzing) {
    return (
      <div className="min-h-screen bg-background flex flex-col">
        <div className="absolute top-4 right-4 flex gap-2 animate-fade-in">
          <Link to="/vendors">
            <Button variant="outline" size="icon" title="Vendor Directory">
              <BookOpen className="h-4 w-4" />
            </Button>
          </Link>
          <HistorySidebar
            history={history}
            onSelect={(q) => { setQuery(q); setTimeout(() => document.querySelector('form')?.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true })), 100); }}
            onClear={() => { setHistory([]); localStorage.removeItem("searchHistory"); }}
          />
          <ThemeToggle />
        </div>

        <div className="flex-1 flex flex-col items-center justify-center p-4">
          <div className="max-w-2xl w-full space-y-8 text-center">
            <div className="space-y-2 animate-fade-in">
              <h1 className="text-4xl md:text-6xl font-bold tracking-tight bg-gradient-to-r from-primary to-primary/60 bg-clip-text text-transparent">
                ThreatSumm4ry
              </h1>
              <p className="text-xl text-muted-foreground">
                Aggregated analysis from multiple security vendors
              </p>
            </div>

            <div className="p-6 bg-card rounded-xl border shadow-sm hover:shadow-md transition-all duration-200 animate-fade-in">
              <SearchForm
                query={query}
                setQuery={setQuery}
                onSubmit={handleSearch}
                isLoading={isAnalyzing}
                className="md:h-12"
              />
              <div className="mt-4 flex items-center justify-center gap-2 text-sm text-muted-foreground">
                <Shield className="h-4 w-4" />
                <span>Enter an IP address, domain, or hash to start analysis</span>
              </div>
            </div>

            <p className="text-sm text-muted-foreground animate-fade-in">
              Make sure to configure your API keys in the .env file
            </p>
          </div>
        </div>

        <Footer />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <div className="flex-1 p-4 md:p-8">
        <div className="max-w-7xl mx-auto space-y-6">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8 border-b pb-6 animate-fade-in">
            <div>
              <h1 className="text-3xl font-bold">ThreatSumm4ry Dashboard</h1>
              <p className="text-sm text-muted-foreground mt-1">{selectedVendors.length} vendors enabled</p>
            </div>

            <div className="flex gap-2 items-center flex-wrap">
              <VendorFilter
                selectedVendors={selectedVendors}
                onVendorsChange={setSelectedVendors}
              />
              <Link to="/vendors">
                <Button variant="outline" size="sm" className="gap-2">
                  <BookOpen className="h-4 w-4" />
                  Vendors
                </Button>
              </Link>
              <HistorySidebar
                history={history}
                onSelect={(q) => { setQuery(q); setTimeout(() => document.querySelector('form')?.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true })), 100); }}
                onClear={() => { setHistory([]); localStorage.removeItem("searchHistory"); }}
              />
              <ThemeToggle />
              <div className="w-full md:w-auto md:min-w-[400px]">
                <SearchForm
                  query={query}
                  setQuery={setQuery}
                  onSubmit={handleSearch}
                  isLoading={isAnalyzing}
                />
              </div>
            </div>
          </div>

          {error && (
            <div className="bg-destructive/10 border border-destructive text-destructive px-4 py-3 rounded-lg animate-fade-in">
              <p>Error: {error}</p>
            </div>
          )}

          {data && (
            <>
              <QuickActions
                data={data}
                onRefresh={handleSearch}
                isLoading={isAnalyzing}
                onCopyLinks={copyVendorLinks}
              />

              <ThreatSummary
                query={data.query}
                overallScore={data.overallScore}
                threatLevel={data.threatLevel}
                totalVendors={data.totalVendors}
                detections={data.detections}
                vendorData={data.vendorData}
              />

              <ThreatCharts
                vendorData={data.vendorData}
                detections={data.detections}
                totalVendors={data.totalVendors}
              />

              <div className="flex items-center justify-between mb-4 animate-fade-in">
                <h2 className="text-2xl font-bold">Vendor Results</h2>
                <ViewToggle view={view} onViewChange={setView} />
              </div>

              {view === "table" ? (
                <VendorDataTable
                  vendorData={data.vendorData}
                  getVendorLink={getVendorLink}
                />
              ) : (
                <div className="columns-1 md:columns-2 lg:columns-3 gap-4 space-y-4">
                  {data.vendorData
                    .sort((a, b) => {
                      // Define vendor importance tiers
                      const tier1 = ["VirusTotal", "AbuseIPDB"];
                      const tier2 = ["Shodan", "AlienVault OTX", "Criminal IP"];
                      const tier3 = ["Pulsedive", "URLhaus", "ThreatFox", "PhishTank"];

                      const getTier = (name: string) => {
                        if (tier1.includes(name)) return 1;
                        if (tier2.includes(name)) return 2;
                        if (tier3.includes(name)) return 3;
                        return 4; // Others
                      };

                      const tierA = getTier(a.name);
                      const tierB = getTier(b.name);

                      // Sort by tier first, then alphabetically within tier
                      if (tierA !== tierB) return tierA - tierB;
                      return a.name.localeCompare(b.name);
                    })
                    .map((vendor) => (
                      <VendorCard
                        key={vendor.name}
                        title={vendor.name}
                        icon={getVendorIcon(vendor.name)}
                        externalLink={vendor.link}
                      >
                        <VendorContent vendor={vendor} onPivot={onPivot} />
                      </VendorCard>
                    ))}
                </div>
              )}
            </>
          )}

          {isAnalyzing && (
            <div className="flex flex-col items-center justify-center py-20 animate-fade-in">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mb-4"></div>
              <p className="text-lg text-muted-foreground">Analyzing target...</p>
            </div>
          )}

        </div>
      </div>
      <Footer />
    </div>
  );
};

export default Index;
