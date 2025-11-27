import { Button } from "@/components/ui/button";
import { Copy, Download, RefreshCw, Share2, Zap, FileJson, FileText } from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { ThreatIntelligenceResult } from "@/types/threat-intelligence";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import { useLanguage } from "@/contexts/LanguageContext";

interface QuickActionsProps {
  data: ThreatIntelligenceResult | null;
  onRefresh: () => void | Promise<void>;
  isLoading: boolean;
  onCopyLinks: () => void;
  onExport?: () => void; // Optional now as handled internally
}

export const QuickActions = ({ data, onRefresh, isLoading, onCopyLinks }: QuickActionsProps) => {
  const { toast } = useToast();
  const { t } = useLanguage();

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
          title: t('copiedToClipboard'),
          description: t('shareLinkCopied'),
        });
      });
    } else {
      navigator.clipboard.writeText(shareText);
      toast({
        title: t('copiedToClipboard'),
        description: t('analysisCopied'),
      });
    }
  };

  const handleQuickRefresh = () => {
    toast({
      title: t('refreshing'),
      description: t('refreshingDesc'),
    });
    onRefresh();
  };

  const exportJSON = () => {
    if (!data) return;
    const jsonString = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonString], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `threat-report-${data.query}-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const exportPDF = () => {
    if (!data) return;
    const doc = new jsPDF();
    const timestamp = new Date().toLocaleString();

    // Title
    doc.setFontSize(20);
    doc.setTextColor(40, 40, 40);
    doc.text(t('reportTitle'), 14, 22);

    // Header Info
    doc.setFontSize(12);
    doc.setTextColor(100, 100, 100);
    doc.text(`${t('target')}: ${data.query}`, 14, 32);
    doc.text(`${t('date')}: ${timestamp}`, 14, 38);
    doc.text(`${t('threatLevel')}: ${data.threatLevel.toUpperCase()}`, 14, 44);
    doc.text(`${t('score')}: ${data.overallScore}/100`, 14, 50);

    // Vendor Summary Table
    const tableData = data.vendorData
      .filter(v => Object.keys(v.data).length > 0)
      .map(v => {
        // Extract a summary string from the data
        const summary = Object.entries(v.data)
          .slice(0, 3)
          .map(([key, val]) => `${key}: ${val}`)
          .join("\n");
        return [v.name, summary];
      });

    autoTable(doc, {
      startY: 60,
      head: [[t('vendors'), t('findings')]],
      body: tableData,
      theme: 'grid',
      headStyles: { fillColor: [66, 66, 66] },
      styles: { fontSize: 10, cellPadding: 4 },
      columnStyles: {
        0: { fontStyle: 'bold', cellWidth: 50 },
        1: { cellWidth: 'auto' }
      }
    });

    // Footer
    const pageCount = doc.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.setFontSize(8);
      doc.text(`${t('page')} ${i} ${t('of')} ${pageCount} - ${t('generatedBy')} ThreatSumm4ry`, 14, doc.internal.pageSize.height - 10);
    }

    doc.save(`threat-report-${data.query}.pdf`);
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
        {t('refresh')}
      </Button>

      <Button
        variant="outline"
        size="sm"
        onClick={onCopyLinks}
        disabled={!data}
        className="gap-2 hover-scale"
      >
        <Copy className="h-4 w-4" />
        {t('copyLinks')}
      </Button>

      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="outline"
            size="sm"
            disabled={!data}
            className="gap-2 hover-scale"
          >
            <Download className="h-4 w-4" />
            {t('export')}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem onClick={exportPDF}>
            <FileText className="mr-2 h-4 w-4" />
            {t('downloadPdf')}
          </DropdownMenuItem>
          <DropdownMenuItem onClick={exportJSON}>
            <FileJson className="mr-2 h-4 w-4" />
            {t('downloadJson')}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <Button
        variant="outline"
        size="sm"
        onClick={handleShare}
        disabled={!data}
        className="gap-2 hover-scale"
      >
        <Share2 className="h-4 w-4" />
        {t('share')}
      </Button>

      {data && (
        <div className="ml-auto flex items-center gap-2 text-sm text-muted-foreground">
          <Zap className="h-4 w-4" />
          <span>{t('quickActions')}</span>
        </div>
      )}
    </div>
  );
};
