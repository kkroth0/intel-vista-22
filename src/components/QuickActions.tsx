import { Button } from "@/components/ui/button";
import { Copy, Download, RefreshCw, Share2, Zap } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { ThreatIntelligenceResult } from "@/types/threat-intelligence";

interface QuickActionsProps {
  data: ThreatIntelligenceResult | null;
  onRefresh: () => void;
  isLoading: boolean;
  onCopyLinks: () => void;
  onExport: () => void;
}

export const QuickActions = ({ data, onRefresh, isLoading, onCopyLinks, onExport }: QuickActionsProps) => {
  const { toast } = useToast();

  const handleShare = () => {
    if (!data) return;
    
    const shareText = `Threat Analysis for ${data.query}\nThreat Level: ${data.threatLevel.toUpperCase()}\nScore: ${data.overallScore}%\nDetections: ${data.detections}/${data.totalVendors}`;
    
    if (navigator.share) {
      navigator.share({
        title: `ThreatSumm4ry - ${data.query}`,
        text: shareText,
      }).catch(() => {
        // Fallback to clipboard
        navigator.clipboard.writeText(shareText);
        toast({
          title: "Copied to clipboard",
          description: "Share link copied to clipboard",
        });
      });
    } else {
      navigator.clipboard.writeText(shareText);
      toast({
        title: "Copied to clipboard",
        description: "Analysis summary copied to clipboard",
      });
    }
  };

  const handleQuickRefresh = () => {
    toast({
      title: "Refreshing...",
      description: "Fetching latest threat intelligence data",
    });
    onRefresh();
  };

  return (
    <div className="flex flex-wrap gap-2 animate-fade-in">
      <Button
        variant="outline"
        size="sm"
        onClick={handleQuickRefresh}
        disabled={isLoading || !data}
        className="gap-2 hover-scale"
      >
        <RefreshCw className={`h-4 w-4 ${isLoading ? "animate-spin" : ""}`} />
        Refresh
      </Button>
      
      <Button
        variant="outline"
        size="sm"
        onClick={onCopyLinks}
        disabled={!data}
        className="gap-2 hover-scale"
      >
        <Copy className="h-4 w-4" />
        Copy Links
      </Button>
      
      <Button
        variant="outline"
        size="sm"
        onClick={onExport}
        disabled={!data}
        className="gap-2 hover-scale"
      >
        <Download className="h-4 w-4" />
        Export
      </Button>
      
      <Button
        variant="outline"
        size="sm"
        onClick={handleShare}
        disabled={!data}
        className="gap-2 hover-scale"
      >
        <Share2 className="h-4 w-4" />
        Share
      </Button>

      {data && (
        <div className="ml-auto flex items-center gap-2 text-sm text-muted-foreground">
          <Zap className="h-4 w-4" />
          <span>Quick Actions</span>
        </div>
      )}
    </div>
  );
};
