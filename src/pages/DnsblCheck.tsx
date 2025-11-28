import { useState } from "react";
import { Link } from "react-router-dom";
import { ArrowLeft, Search, Shield, AlertTriangle, CheckCircle, RotateCw, Home, Share2 } from "lucide-react";
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

    const handleShare = () => {
        const listed = results.filter(r => r.listed).map(r => r.provider);
        const cleanCount = results.filter(r => !r.listed && !r.loading).length;

        const text = `DNSBL Check for ${query}\n` +
            `Listed in ${listed.length} blocklists\n` +
            `Clean in ${cleanCount} blocklists\n\n` +
            (listed.length > 0 ? `Listed in:\n${listed.join('\n')}` : "Clean in all checked lists.");

        if (navigator.share) {
            navigator.share({
                title: `DNSBL Report - ${query}`,
                text: text,
            }).catch(() => {
                navigator.clipboard.writeText(text);
                toast({
                    title: t('copied'),
                    description: t('shareLinkCopied'),
                });
            });
        } else {
            navigator.clipboard.writeText(text);
            toast({
                title: t('copied'),
                description: t('shareLinkCopied'),
            });
        }
    };

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
                            <div className="flex flex-col sm:flex-row items-center justify-center gap-6 text-center">
                                <div className={`p-4 rounded-xl border shadow-sm transition-colors w-full sm:w-auto min-w-[150px] ${listedCount > 0 ? 'bg-destructive/10 border-destructive/20' : 'bg-card'}`}>
                                    <div className={`text-3xl font-bold ${listedCount > 0 ? 'text-destructive' : 'text-foreground'}`}>{listedCount}</div>
                                    <div className="text-sm font-medium text-muted-foreground mt-1">{t('listed')}</div>
                                </div>
                                <div className="p-4 rounded-xl bg-card border shadow-sm w-full sm:w-auto min-w-[150px]">
                                    <div className="text-3xl font-bold text-primary">{totalChecked}</div>
                                    <div className="text-sm font-medium text-muted-foreground mt-1">{t('checked')}</div>
                                </div>
                                <Button variant="outline" className="h-auto py-4 px-6 flex-col gap-1 min-w-[100px]" onClick={handleShare}>
                                    <Share2 className="h-5 w-5 mb-1" />
                                    <span className="text-xs font-medium">{t('shareReport')}</span>
                                </Button>
                            </div>

                            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
                                {sortedResults.map((result) => (
                                    <Card key={result.provider} className={`transition-all duration-200 ${result.listed ? 'border-destructive/50 bg-destructive/5 shadow-md scale-[1.02] z-10' : 'border-border hover:border-primary/30 hover:bg-accent/5'}`}>
                                        <CardHeader className="p-3 pb-1">
                                            <div className="flex items-center justify-between gap-2">
                                                <CardTitle className="text-xs font-medium truncate w-full" title={result.provider}>
                                                    {result.provider}
                                                </CardTitle>
                                                {result.loading ? (
                                                    <RotateCw className="h-3 w-3 animate-spin text-muted-foreground shrink-0" />
                                                ) : result.listed ? (
                                                    <AlertTriangle className="h-3 w-3 text-destructive shrink-0" />
                                                ) : (
                                                    <CheckCircle className="h-3 w-3 text-green-500 shrink-0" />
                                                )}
                                            </div>
                                        </CardHeader>
                                        <CardContent className="p-3 pt-1">
                                            <div className="flex flex-col gap-1">
                                                <div className="text-xs flex justify-between items-center">
                                                    {result.loading ? (
                                                        <span className="text-muted-foreground text-[10px]">{t('checking')}</span>
                                                    ) : result.error ? (
                                                        <span className="text-destructive text-[10px]">{result.error}</span>
                                                    ) : (
                                                        <span className={`text-[10px] font-medium ${result.listed ? "text-destructive" : "text-muted-foreground"}`}>
                                                            {result.listed ? t('listed') : t('clean')}
                                                        </span>
                                                    )}

                                                    {result.responseTime !== undefined && (
                                                        <span className="text-[9px] text-muted-foreground font-mono bg-muted px-1 rounded opacity-70">
                                                            {result.responseTime}ms
                                                        </span>
                                                    )}
                                                </div>
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
