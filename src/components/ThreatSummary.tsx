import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ThreatBadge } from "./ThreatBadge";
import { Copy, Download } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { VendorData } from "@/types/threat-intelligence";
import { useLanguage } from "@/contexts/LanguageContext";

interface ThreatSummaryProps {
  query: string;
  overallScore: number;
  threatLevel: "safe" | "suspicious" | "malicious" | "unknown";
  totalVendors: number;
  detections: number;
  vendorData?: VendorData[];
}

export const ThreatSummary = ({ query, overallScore, threatLevel, totalVendors, detections, vendorData = [] }: ThreatSummaryProps) => {
  const { toast } = useToast();
  const { t } = useLanguage();

  const formatVendorData = (vendor: VendorData): string => {
    let text = `\n${vendor.name}\n${'='.repeat(vendor.name.length)}\n`;
    Object.entries(vendor.data).forEach(([key, value]) => {
      if (typeof value === 'object' && !Array.isArray(value)) {
        text += `${key}:\n`;
        Object.entries(value).forEach(([subKey, subValue]) => {
          text += `  ${subKey}: ${subValue}\n`;
        });
      } else if (Array.isArray(value)) {
        text += `${key}: ${value.join(', ')}\n`;
      } else {
        text += `${key}: ${value}\n`;
      }
    });
    return text;
  };

  const handleCopy = () => {
    let fullReport = `THREAT INTELLIGENCE REPORT\n${'='.repeat(50)}\n\n`;
    fullReport += `Query: ${query}\n`;
    fullReport += `Overall Score: ${overallScore}/100\n`;
    fullReport += `Threat Level: ${threatLevel.toUpperCase()}\n`;
    fullReport += `Detections: ${detections}/${totalVendors} vendors\n`;
    fullReport += `Generated: ${new Date().toISOString()}\n`;
    fullReport += `\n${'='.repeat(50)}\n`;
    fullReport += `VENDOR DETAILS\n${'='.repeat(50)}`;

    vendorData.forEach(vendor => {
      fullReport += formatVendorData(vendor);
    });

    navigator.clipboard.writeText(fullReport);
    toast({
      title: t('copiedToClipboard'),
      description: t('reportCopied'),
    });
  };

  const handleExport = () => {
    toast({
      title: t('exportInitiated'),
      description: t('exportDesc'),
    });
  };

  return (
    <Card className="border-2">
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span>{t('threatSummary')}</span>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={handleCopy}>
              <Copy className="h-4 w-4 mr-2" />
              {t('copy')}
            </Button>
            <Button variant="outline" size="sm" onClick={handleExport}>
              <Download className="h-4 w-4 mr-2" />
              {t('export')}
            </Button>
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
          <div>
            <p className="text-sm text-muted-foreground mb-1">{t('query')}</p>
            <p className="font-mono font-semibold text-lg">{query}</p>
          </div>
          <div>
            <p className="text-sm text-muted-foreground mb-1">{t('overallScore')}</p>
            <p className="text-3xl font-bold">{overallScore}/100</p>
          </div>
          <div>
            <p className="text-sm text-muted-foreground mb-1">{t('threatLevel')}</p>
            <ThreatBadge level={threatLevel} className="text-sm px-3 py-1" />
          </div>
          <div>
            <p className="text-sm text-muted-foreground mb-1">{t('detections')}</p>
            <p className="text-3xl font-bold">
              {detections}<span className="text-lg text-muted-foreground">/{totalVendors}</span>
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
