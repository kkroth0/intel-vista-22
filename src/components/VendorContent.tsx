import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { ThreatBadge } from "@/components/ThreatBadge";
import { VendorData } from "@/types/threat-intelligence";
import { ClickableArtifact } from "@/components/ClickableArtifact";

interface VendorContentProps {
    vendor: VendorData;
    onPivot?: (artifact: string) => void;
}

export const VendorContent = ({ vendor, onPivot }: VendorContentProps) => {
    const { name, data, error } = vendor;

    const renderValue = (value: string) => {
        if (!onPivot) return value;
        return <ClickableArtifact text={value} onPivot={onPivot} />;
    };

    if (error) {
        return <div className="text-destructive text-sm">{error}</div>;
    }

    if (Object.keys(data).length === 0) {
        return <div className="text-muted-foreground text-sm">No data available</div>;
    }

    // Specific rendering for VirusTotal
    if (name === "VirusTotal") {
        const detectionRate = data["Detection Rate"] || "0/0";
        const [detected, total] = detectionRate.split("/").map(Number);
        const percentage = total > 0 ? (detected / total) * 100 : 0;
        const status = data["Status"] || "Unknown";
        const topDetections = data["Top Detections"] || [];

        return (
            <div className="space-y-4">
                <div>
                    <p className="text-sm text-muted-foreground mb-2">Detection Rate</p>
                    <div className="flex items-center gap-3">
                        <Progress value={percentage} className="flex-1" />
                        <span className="font-semibold">{detectionRate}</span>
                    </div>
                </div>
                <div>
                    <p className="text-sm text-muted-foreground mb-2">Status</p>
                    <ThreatBadge
                        level={status === "Malicious" ? "malicious" : status === "Suspicious" ? "suspicious" : "safe"}
                        label={status}
                    />
                </div>
                <div>
                    <p className="text-sm text-muted-foreground mb-2">Top Detections</p>
                    <div className="flex flex-wrap gap-2">
                        {topDetections.map((d: string) => (
                            <Badge key={d} variant="outline">{d}</Badge>
                        ))}
                    </div>
                </div>
            </div>
        );
    }

    // Specific rendering for AbuseIPDB
    if (name === "AbuseIPDB") {
        const score = parseInt(data["Abuse Confidence Score"] || "0");

        return (
            <div className="space-y-4">
                <div>
                    <p className="text-sm text-muted-foreground mb-2">Abuse Confidence Score</p>
                    <div className="flex items-center gap-3">
                        <Progress value={score} className="flex-1" />
                        <span className={`font-semibold ${score > 50 ? "text-destructive" : "text-green-500"}`}>{score}%</span>
                    </div>
                </div>
                <div>
                    <p className="text-sm text-muted-foreground mb-2">Reports</p>
                    <p className="text-2xl font-bold">{data["Reports"]}</p>
                </div>
                <div>
                    <p className="text-sm text-muted-foreground mb-2">Last Report</p>
                    <p className="font-mono text-sm">{data["Last Report"]}</p>
                </div>
            </div>
        );
    }

    // Generic rendering for others
    return (
        <div className="space-y-4">
            {Object.entries(data).map(([key, value]) => (
                <div key={key}>
                    <p className="text-sm text-muted-foreground mb-2">{key}</p>
                    {Array.isArray(value) ? (
                        <div className="flex flex-wrap gap-2">
                            {value.map((v: string) => (
                                <Badge key={v} variant="secondary">
                                    {onPivot ? <ClickableArtifact text={v} onPivot={onPivot} /> : v}
                                </Badge>
                            ))}
                        </div>
                    ) : (
                        <p className="text-sm font-medium">
                            {renderValue(String(value))}
                        </p>
                    )}
                </div>
            ))}
        </div>
    );
};
