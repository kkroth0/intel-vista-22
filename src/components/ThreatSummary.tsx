import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ThreatBadge } from "./ThreatBadge";
import { Copy, Download } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface ThreatSummaryProps {
  query: string;
  overallScore: number;
  threatLevel: "safe" | "suspicious" | "malicious";
  totalVendors: number;
  detections: number;
}

export const ThreatSummary = ({ query, overallScore, threatLevel, totalVendors, detections }: ThreatSummaryProps) => {
  const { toast } = useToast();

  const handleCopy = () => {
    const summary = `Threat Analysis for ${query}\nOverall Score: ${overallScore}/100\nThreat Level: ${threatLevel}\nDetections: ${detections}/${totalVendors} vendors`;
    navigator.clipboard.writeText(summary);
    toast({
      title: "Copied to clipboard",
      description: "Summary has been copied successfully",
    });
  };

  const handleExport = () => {
    toast({
      title: "Export initiated",
      description: "Report will be downloaded shortly",
    });
  };

  return (
    <Card className="border-2">
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span>Threat Intelligence Summary</span>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={handleCopy}>
              <Copy className="h-4 w-4 mr-2" />
              Copy
            </Button>
            <Button variant="outline" size="sm" onClick={handleExport}>
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div>
            <p className="text-sm text-muted-foreground mb-1">Query</p>
            <p className="font-mono font-semibold text-lg">{query}</p>
          </div>
          <div>
            <p className="text-sm text-muted-foreground mb-1">Overall Score</p>
            <p className="text-3xl font-bold">{overallScore}/100</p>
          </div>
          <div>
            <p className="text-sm text-muted-foreground mb-1">Threat Level</p>
            <ThreatBadge level={threatLevel} className="text-sm px-3 py-1" />
          </div>
          <div>
            <p className="text-sm text-muted-foreground mb-1">Detections</p>
            <p className="text-3xl font-bold">
              {detections}<span className="text-lg text-muted-foreground">/{totalVendors}</span>
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
