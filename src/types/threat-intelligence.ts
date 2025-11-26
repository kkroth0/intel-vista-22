export interface VendorData {
    name: string;
    data: Record<string, any>;
    error?: string;
    isLoading?: boolean;
    quota?: {
        remaining?: string | number;
        limit?: string | number;
        reset?: string | number;
        daily_remaining?: string | number;
    };
    link?: string;
}

export interface ThreatIntelligenceResult {
    query: string;
    overallScore: number;
    threatLevel: "safe" | "suspicious" | "malicious" | "unknown";
    totalVendors: number;
    detections: number;
    vendorData: VendorData[];
}

export interface ApiConfig {
    apiKey: string;
    baseUrl: string;
}
