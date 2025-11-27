import { useState } from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, Search, Shield, AlertTriangle, CheckCircle, RotateCw, Home } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { checkDNSBL } from "@/services/threatApi";
import { useToast } from "@/hooks/use-toast";
import { ThemeToggle } from "@/components/ThemeToggle";
import { Footer } from "@/components/Footer";
import { useLanguage } from "@/contexts/LanguageContext";
import { LanguageToggle } from "@/components/LanguageToggle";

const DNSBL_PROVIDERS = [
    "all.s5h.net", "b.barracudacentral.org", "bl.0spam.org", "bl.spamcop.net",
    "blacklist.woody.ch", "bogons.cymru.com", "combined.abuse.ch", "db.wpbl.info",
    "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net", "dnsbl-3.uceprotect.net",
    "dnsbl.dronebl.org", "drone.abuse.ch", "duinv.aupads.org", "dyna.spamrats.com",
    "ips.backscatterer.org", "korea.services.net", "noptr.spamrats.com",
    "orvedb.aupads.org", "proxy.bl.gweep.ca", "psbl.surriel.com", "rbl.0spam.org",
    "relays.bl.gweep.ca", "relays.nether.net", "singular.ttk.pte.hu", "spam.abuse.ch",
    "spam.dnsbl.anonmails.de", "spam.spamrats.com", "spambot.bls.digibase.ca",
    "spamrbl.imp.ch", "spamsources.fabel.dk", "ubl.lashback.com", "ubl.unsubscore.com",
    "virus.rbl.jp", "wormrbl.imp.ch", "z.mailspike.net", "zen.spamhaus.org", "dbl.spamhaus.org"
];

interface DNSBLResult {
    provider: string;
    listed: boolean;
    status: string;
    loading: boolean;
    error?: string;
    addresses?: string[];
    responseTime?: number;
}

const DnsblCheck = () => {
    const [query, setQuery] = useState("");
    const [results, setResults] = useState<DNSBLResult[]>([]);
    const [isScanning, setIsScanning] = useState(false);
    const { toast } = useToast();
    const { t } = useLanguage();

    const handleSearch = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!query) {
            toast({
                title: t('error'),
                description: t('invalidIp'),
                variant: "destructive",
            });
            return;
        }

        // Basic IP validation
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!ipRegex.test(query)) {
            toast({
                title: t('invalidInput'),
                description: t('invalidIp'),
                variant: "destructive",
            });
            return;
        }

        setIsScanning(true);

        // Initialize results
        const initialResults = DNSBL_PROVIDERS.map(provider => ({
            provider,
            listed: false,
            status: t('pending'),
            loading: true
        }));
        setResults(initialResults);

        // Process in batches to avoid overwhelming the browser/backend
        const BATCH_SIZE = 5;
        for (let i = 0; i < DNSBL_PROVIDERS.length; i += BATCH_SIZE) {
            const batch = DNSBL_PROVIDERS.slice(i, i + BATCH_SIZE);
            await Promise.all(batch.map(async (provider) => {
                const startTime = performance.now();
                try {
                    const result = await checkDNSBL(query, provider);
                    const endTime = performance.now();
                    const latency = Math.round(endTime - startTime);

                    setResults(prev => prev.map(r =>
                        r.provider === provider
                            ? { ...r, listed: result.listed, status: result.status, loading: false, addresses: result.addresses, error: result.error, responseTime: latency }
                            : r
                    ));
                } catch (error) {
                    const endTime = performance.now();
                    const latency = Math.round(endTime - startTime);
                    setResults(prev => prev.map(r =>
                        r.provider === provider
                            ? { ...r, listed: false, status: t('error'), loading: false, error: "Failed to check", responseTime: latency }
                            : r
                    ));
                }
            }));
        }

        setIsScanning(false);
    };

    const listedCount = results.filter(r => r.listed).length;
    const totalChecked = results.filter(r => !r.loading).length;

    // Sort results: Listed first, then by provider name
    const sortedResults = [...results].sort((a, b) => {
        if (a.listed && !b.listed) return -1;
        if (!a.listed && b.listed) return 1;
        return a.provider.localeCompare(b.provider);
    });

    return (
        <div className="min-h-screen bg-background flex flex-col">
            {/* Improved Header */}
            <header className="border-b bg-card/50 backdrop-blur-sm sticky top-0 z-10">
                <div className="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
                    <div className="flex items-center gap-4">
                        <Link to="/">
                            <Button variant="ghost" size="sm" className="gap-2">
                                <ArrowLeft className="h-4 w-4" />
                                {t('back')}
                            </Button>
                        </Link>
                        <div className="h-6 w-px bg-border" />
                        <div className="flex items-center gap-2">
                            <Shield className="h-5 w-5 text-primary" />
                            <h1 className="font-semibold text-lg">{t('dnsblTitle')}</h1>
                        </div>
                    </div>
                    <div className="flex items-center gap-2">
                        <LanguageToggle />
                        <ThemeToggle />
                    </div>
                </div>
            </header>

            <div className="flex-1 p-4 md:p-8">
                <div className="max-w-7xl mx-auto space-y-8">

                    <div className="max-w-2xl mx-auto text-center space-y-4">
                        <h2 className="text-3xl font-bold tracking-tight">{t('checkIpReputation')}</h2>
                        <p className="text-muted-foreground">
                            {t('dnsblDescription', { count: DNSBL_PROVIDERS.length })}
                        </p>
                    </div>

                    <div className="max-w-xl mx-auto">
                        <Card className="border-primary/20 shadow-lg">
                            <CardContent className="pt-6">
                                <form onSubmit={handleSearch} className="flex gap-2">
                                    <Input
                                        placeholder={t('enterIp')}
                                        value={query}
                                        onChange={(e) => setQuery(e.target.value)}
                                        className="flex-1 text-lg h-12"
                                    />
                                    <Button type="submit" disabled={isScanning} size="lg" className="h-12 px-8">
                                        {isScanning ? <RotateCw className="mr-2 h-5 w-5 animate-spin" /> : <Search className="mr-2 h-5 w-5" />}
                                        {isScanning ? t('scanning') : t('scan')}
                                    </Button>
                                </form>
                            </CardContent>
                        </Card>
                    </div>

                    {results.length > 0 && (
                        <div className="space-y-6 animate-fade-in">
                            <div className="flex items-center justify-center gap-6 text-center">
                                <div className={`p-6 rounded-xl border shadow-sm transition-colors ${listedCount > 0 ? 'bg-destructive/10 border-destructive/20' : 'bg-card'}`}>
                                    <div className={`text-4xl font-bold ${listedCount > 0 ? 'text-destructive' : 'text-foreground'}`}>{listedCount}</div>
                                    <div className="text-sm font-medium text-muted-foreground mt-1">{t('listed')}</div>
                                </div>
                                <div className="p-6 rounded-xl bg-card border shadow-sm">
                                    <div className="text-4xl font-bold text-primary">{totalChecked}</div>
                                    <div className="text-sm font-medium text-muted-foreground mt-1">{t('checked')}</div>
                                </div>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                {sortedResults.map((result) => (
                                    <Card key={result.provider} className={`transition-all duration-200 ${result.listed ? 'border-destructive/50 bg-destructive/5 shadow-md scale-[1.02]' : 'border-border hover:border-primary/30 hover:bg-accent/5'}`}>
                                        <CardHeader className="pb-2">
                                            <div className="flex items-center justify-between">
                                                <CardTitle className="text-base font-medium truncate" title={result.provider}>
                                                    {result.provider}
                                                </CardTitle>
                                                {result.loading ? (
                                                    <RotateCw className="h-4 w-4 animate-spin text-muted-foreground" />
                                                ) : result.listed ? (
                                                    <Badge variant="destructive" className="gap-1">
                                                        <AlertTriangle className="h-3 w-3" />
                                                        {t('listed')}
                                                    </Badge>
                                                ) : (
                                                    <CheckCircle className="h-4 w-4 text-green-500" />
                                                )}
                                            </div>
                                        </CardHeader>
                                        <CardContent>
                                            <div className="flex flex-col gap-2">
                                                <div className="text-sm flex justify-between items-center">
                                                    {result.loading ? (
                                                        <span className="text-muted-foreground">{t('checking')}</span>
                                                    ) : result.error ? (
                                                        <span className="text-destructive">{result.error}</span>
                                                    ) : (
                                                        <span className={result.listed ? "text-destructive font-medium" : "text-muted-foreground"}>
                                                            {result.listed ? t('listed') : t('clean')}
                                                        </span>
                                                    )}

                                                    {result.responseTime !== undefined && (
                                                        <span className="text-[10px] text-muted-foreground font-mono bg-muted px-1.5 py-0.5 rounded opacity-70">
                                                            {result.responseTime}ms
                                                        </span>
                                                    )}
                                                </div>

                                                {result.addresses && result.addresses.length > 0 && (
                                                    <div className="text-xs bg-background/50 p-2 rounded border border-border/50 font-mono break-all">
                                                        {result.addresses.join(", ")}
                                                    </div>
                                                )}
                                            </div>
                                        </CardContent>
                                    </Card>
                                ))}
                            </div>
                        </div>
                    )}
                </div>
            </div>
            <Footer />
        </div>
    );
};

export default DnsblCheck;
