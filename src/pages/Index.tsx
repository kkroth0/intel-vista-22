import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { Shield, AlertTriangle, Bug, FileSearch, Globe, Link as LinkIcon, Radar, Database, Eye, Search, BookOpen, Layers, LayoutGrid } from "lucide-react";
import { ThreatSummary } from "@/components/ThreatSummary";
import { VendorCard } from "@/components/VendorCard";
import { VendorContent } from "@/components/VendorContent";
import { VendorFilter } from "@/components/VendorFilter";
import { ThemeToggle } from "@/components/ThemeToggle";
import { Footer } from "@/components/Footer";
import { HistorySidebar } from "@/components/HistorySidebar";
import { LanguageToggle } from "@/components/LanguageToggle";
import { useLanguage } from "@/contexts/LanguageContext";

import { ThreatCharts } from "@/components/ThreatCharts";
import { VendorDataTable } from "@/components/VendorDataTable";
import { QuickActions } from "@/components/QuickActions";
import { ViewToggle } from "@/components/ViewToggle";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { MultiIpSummary } from "@/components/MultiIpSummary";
import { fetchThreatDataProgressive } from "@/services/threatApi";
import { useToast } from "@/hooks/use-toast";
import { ThreatIntelligenceResult } from "@/types/threat-intelligence";

interface SearchFormProps {
  query: string;
  setQuery: (query: string) => void;
  onSubmit: (e: React.FormEvent) => void;
  isLoading: boolean;
  className?: string;
  mode: "single" | "multi";
}

const SearchForm = ({ query, setQuery, onSubmit, isLoading, className = "", mode }: SearchFormProps) => {
  const { t } = useLanguage();

  return (
    <form onSubmit={onSubmit} className={`w-full ${className}`}>
      <div className="flex gap-2">
        {mode === "single" ? (
          <Input
            placeholder={t('searchPlaceholder')}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="flex-1"
          />
        ) : (
          <Textarea
            placeholder="Enter multiple IPs (comma or newline separated, max 5)"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="flex-1 min-h-[80px]"
          />
        )}
        <Button type="submit" disabled={isLoading} className={mode === "multi" ? "h-auto" : ""}>
          {isLoading ? t('analyzing') : <><Search className="mr-2 h-4 w-4" /> {t('analyze')}</>}
        </Button>
      </div>
    </form>
  );
};

const ALL_VENDORS = [
  "IP Geolocation", "WHOIS", "VirusTotal", "AbuseIPDB", "AlienVault OTX",
  "Shodan", "URLhaus", "MalwareBazaar", "Google Safe Browsing",
  "PhishTank", "Pulsedive",
  "Hybrid Analysis", "CIRCL hashlookup",
  "Criminal IP", "MetaDefender", "PhishStats", "Ransomware.live",
  "OpenPhish", "DShield", "Team Cymru"
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
  const [searchMode, setSearchMode] = useState<"single" | "multi">("single");

  // Changed data to results array to support multi-IP
  const [results, setResults] = useState<ThreatIntelligenceResult[]>([]);
  const [activeTab, setActiveTab] = useState<string>("overview");

  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<"cards" | "table">("cards");
  const { toast } = useToast();
  const { t } = useLanguage();

  // Load saved preferences and history
  useEffect(() => {
    const savedVendors = localStorage.getItem("selectedVendors");
    if (savedVendors) {
      try {
        const parsed = JSON.parse(savedVendors);
        // Filter out vendors that are no longer in ALL_VENDORS
        const validVendors = parsed.filter((v: string) => ALL_VENDORS.includes(v));
        setSelectedVendors(validVendors.length > 0 ? validVendors : ALL_VENDORS);
      } catch (e) {
        console.error("Failed to parse saved vendors", e);
        setSelectedVendors(ALL_VENDORS);
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

    const rawQuery = query.trim();

    if (!rawQuery) {
      toast({
        title: t('error'),
        description: t('inputRequired'),
        variant: "destructive",
      });
      return;
    }

    let queries: string[] = [];

    if (searchMode === "single") {
      queries = [rawQuery];
    } else {
      // Split by comma, newline, or space
      queries = rawQuery.split(/[\s,]+/).filter(q => q.length > 0);
      if (queries.length > 5) {
        toast({
          title: "Too many targets",
          description: "Please enter a maximum of 5 IPs.",
          variant: "destructive",
        });
        return;
      }
    }

    // Validation
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;
    const urlRegex = /^(http|https):\/\/[^ "]+$/;

    const invalidQueries = queries.filter(q =>
      !ipRegex.test(q) && !domainRegex.test(q) && !hashRegex.test(q) && !urlRegex.test(q)
    );

    if (invalidQueries.length > 0) {
      toast({
        title: t('invalidInput'),
        description: `Invalid format: ${invalidQueries.join(", ")}`,
        variant: "destructive",
      });
      return;
    }

    setIsAnalyzing(true);
    setError(null);
    setResults([]); // Clear previous results
    setActiveTab("overview");

    try {
      // Initialize results with loading state
      const initialResults: ThreatIntelligenceResult[] = queries.map(q => ({
        query: q,
        overallScore: 0,
        threatLevel: "unknown",
        totalVendors: selectedVendors.length,
        detections: 0,
        vendorData: selectedVendors.map(vendorName => ({
          name: vendorName,
          data: {},
          loading: true
        }))
      }));
      setResults(initialResults);

      // Process each query
      await Promise.all(queries.map(async (q) => {
        const result = await fetchThreatDataProgressive(q, selectedVendors, (vendorData) => {
          setResults(prev => prev.map(r => {
            if (r.query === q) {
              return {
                ...r,
                vendorData: r.vendorData.map(v =>
                  v.name === vendorData.name ? { ...vendorData, loading: false } : v
                )
              };
            }
            return r;
          }));
        });

        // Update final result for this query
        setResults(prev => prev.map(r => r.query === q ? result : r));

        // Update history
        setHistory(prev => {
          const filtered = prev.filter(item => item.query !== result.query);
          const newHistory = [
            { query: result.query, timestamp: Date.now(), threatLevel: result.threatLevel },
            ...filtered
          ].slice(0, 50);
          localStorage.setItem("searchHistory", JSON.stringify(newHistory));
          return newHistory;
        });
      }));

    } catch (error) {
      console.error("Analysis error:", error);
      setError("Failed to fetch threat data");
      toast({
        title: t('error'),
        description: "Failed to fetch threat data",
        variant: "destructive",
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  const onPivot = (artifact: string) => {
    setQuery(artifact);
    setSearchMode("single"); // Force single mode for pivot
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
      urls.push(`Criminal IP: https://www.criminalip.io/asset/report/${searchQuery}`);
    } else if (type === "domain") {
      urls.push(`VirusTotal: https://www.virustotal.com/gui/domain/${searchQuery}`);
      urls.push(`AlienVault OTX: https://otx.alienvault.com/indicator/domain/${searchQuery}`);
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

  const copyVendorLinks = (targetQuery: string) => {
    const links = generateVendorUrls(targetQuery);
    navigator.clipboard.writeText(links);
    toast({
      title: t('linksCopied'),
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
      case "MalwareBazaar": return <Bug className="h-5 w-5 text-primary" />;
      case "Google Safe Browsing": return <Shield className="h-5 w-5 text-primary" />;
      case "PhishTank": return <LinkIcon className="h-5 w-5 text-primary" />;
      case "Pulsedive": return <Radar className="h-5 w-5 text-primary" />;
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
      case "MalwareBazaar": return "https://bazaar.abuse.ch";
      case "Google Safe Browsing": return "https://safebrowsing.google.com";
      case "PhishTank": return "https://phishtank.com";
      case "Pulsedive": return "https://pulsedive.com";
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

  if (results.length === 0 && !isAnalyzing) {
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
            onSelect={(q) => { setQuery(q); setSearchMode("single"); setTimeout(() => document.querySelector('form')?.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true })), 100); }}
            onClear={() => { setHistory([]); localStorage.removeItem("searchHistory"); }}
          />
          <LanguageToggle />
          <ThemeToggle />
        </div>

        <div className="flex-1 flex flex-col items-center justify-center p-4">
          <div className="max-w-2xl w-full space-y-8 text-center">
            <div className="space-y-2 animate-fade-in">
              <h1 className="text-4xl md:text-6xl font-bold tracking-tight bg-gradient-to-r from-primary to-primary/60 bg-clip-text text-transparent">
                {t('appName')}
              </h1>
              <p className="text-xl text-muted-foreground">
                {t('dashboardTitle')}
              </p>
            </div>

            <div className="p-6 bg-card rounded-xl border shadow-sm hover:shadow-md transition-all duration-200 animate-fade-in">
              <div className="flex justify-center mb-4">
                <div className="bg-muted p-1 rounded-lg inline-flex">
                  <Button
                    variant={searchMode === "single" ? "secondary" : "ghost"}
                    size="sm"
                    onClick={() => setSearchMode("single")}
                    className="gap-2"
                  >
                    <Search className="h-4 w-4" /> Single Target
                  </Button>
                  <Button
                    variant={searchMode === "multi" ? "secondary" : "ghost"}
                    size="sm"
                    onClick={() => setSearchMode("multi")}
                    className="gap-2"
                  >
                    <Layers className="h-4 w-4" /> Multi-Target
                  </Button>
                </div>
              </div>

              <SearchForm
                query={query}
                setQuery={setQuery}
                onSubmit={handleSearch}
                isLoading={isAnalyzing}
                className="md:h-auto"
                mode={searchMode}
              />
              <div className="mt-4 flex items-center justify-center gap-2 text-sm text-muted-foreground">
                <Shield className="h-4 w-4" />
                <span>{searchMode === "single" ? t('inputRequired') : "Enter up to 5 targets"}</span>
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
          {/* New Header Design */}
          <div className="flex flex-col gap-6 mb-8 animate-fade-in">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
              <div>
                <h1 className="text-3xl font-bold tracking-tight bg-gradient-to-r from-primary to-primary/60 bg-clip-text text-transparent">
                  {t('appName')}
                </h1>
                <p className="text-sm text-muted-foreground mt-1">
                  {selectedVendors.length} {t('vendorsEnabled')}
                </p>
              </div>

              <div className="flex items-center gap-2 bg-muted/50 p-1 rounded-lg border">
                <Link to="/vendors">
                  <Button variant="ghost" size="sm" className="gap-2 h-8 text-muted-foreground hover:text-foreground hover:bg-background shadow-none">
                    <BookOpen className="h-4 w-4" />
                    {t('vendors')}
                  </Button>
                </Link>
                <div className="w-px h-4 bg-border" />
                <Link to="/dnsbl">
                  <Button variant="ghost" size="sm" className="gap-2 h-8 text-muted-foreground hover:text-foreground hover:bg-background shadow-none">
                    <Shield className="h-4 w-4" />
                    {t('dnsblCheck')}
                  </Button>
                </Link>
              </div>
            </div>

            <div className="flex flex-col md:flex-row gap-4 items-start md:items-center justify-between bg-card p-4 rounded-xl border shadow-sm">
              <div className="flex-1 w-full md:w-auto flex flex-col gap-2">
                <div className="flex gap-2">
                  <Button
                    variant={searchMode === "single" ? "secondary" : "ghost"}
                    size="sm"
                    onClick={() => setSearchMode("single")}
                    className="h-7 text-xs"
                  >
                    Single
                  </Button>
                  <Button
                    variant={searchMode === "multi" ? "secondary" : "ghost"}
                    size="sm"
                    onClick={() => setSearchMode("multi")}
                    className="h-7 text-xs"
                  >
                    Multi
                  </Button>
                </div>
                <SearchForm
                  query={query}
                  setQuery={setQuery}
                  onSubmit={handleSearch}
                  isLoading={isAnalyzing}
                  className="w-full"
                  mode={searchMode}
                />
              </div>

              <div className="flex items-center gap-2 w-full md:w-auto justify-end">
                <div className="h-8 w-px bg-border hidden md:block mx-2" />
                <VendorFilter
                  selectedVendors={selectedVendors}
                  onVendorsChange={setSelectedVendors}
                />
                <HistorySidebar
                  history={history}
                  onSelect={(q) => { setQuery(q); setSearchMode("single"); setTimeout(() => document.querySelector('form')?.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true })), 100); }}
                  onClear={() => { setHistory([]); localStorage.removeItem("searchHistory"); }}
                />
                <LanguageToggle />
                <ThemeToggle />
              </div>
            </div>
          </div>

          {error && (
            <div className="bg-destructive/10 border border-destructive text-destructive px-4 py-3 rounded-lg animate-fade-in">
              <p>{t('error')}: {error}</p>
            </div>
          )}

          {results.length > 0 && (
            <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
              <TabsList className="w-full justify-start overflow-x-auto h-auto p-1 flex-wrap">
                <TabsTrigger value="overview" className="gap-2">
                  <LayoutGrid className="h-4 w-4" /> Overview
                </TabsTrigger>
                {results.map((result, idx) => (
                  <TabsTrigger key={idx} value={result.query} className="gap-2">
                    {result.threatLevel === "malicious" && <AlertTriangle className="h-3 w-3 text-destructive" />}
                    {result.query}
                  </TabsTrigger>
                ))}
              </TabsList>

              <TabsContent value="overview" className="mt-6 animate-fade-in">
                <MultiIpSummary
                  results={results}
                  onViewDetails={(q) => setActiveTab(q)}
                />
              </TabsContent>

              {results.map((data) => (
                <TabsContent key={data.query} value={data.query} className="space-y-6 mt-6 animate-fade-in">
                  <QuickActions
                    data={data}
                    onRefresh={() => handleSearch()}
                    isLoading={isAnalyzing}
                    onCopyLinks={() => copyVendorLinks(data.query)}
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
                    <h2 className="text-2xl font-bold">{t('vendorResults')}</h2>
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
                          const tier3 = ["Pulsedive", "URLhaus", "PhishTank"];

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
                </TabsContent>
              ))}
            </Tabs>
          )}

          {isAnalyzing && results.length === 0 && (
            <div className="flex flex-col items-center justify-center py-20 animate-fade-in">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mb-4"></div>
              <p className="text-lg text-muted-foreground">{t('analyzing')}</p>
            </div>
          )}

        </div>
      </div>
      <Footer />
    </div>
  );
};

export default Index;
