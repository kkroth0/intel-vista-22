import { Button } from "@/components/ui/button";
import { RefreshCw, Copy, Download, Share2, FileText, Zap, FileJson } from "lucide-react";
import { ThreatIntelligenceResult } from "@/types/threat-intelligence";
import { useToast } from "@/hooks/use-toast";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import { useLanguage } from "@/contexts/LanguageContext";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

interface QuickActionsProps {
  data: ThreatIntelligenceResult;
  onRefresh: () => void;
  isLoading: boolean;
  onCopyLinks: () => void;
}

export const QuickActions = ({ data, onRefresh, isLoading, onCopyLinks }: QuickActionsProps) => {
  const { toast } = useToast();
  const { t } = useLanguage();

  const handleCopy = () => {
    const text = `Threat Report for ${data.query}\nScore: ${data.overallScore}/100\nThreat Level: ${data.threatLevel}\nDetections: ${data.detections}/${data.totalVendors}`;
    navigator.clipboard.writeText(text);
    toast({
      title: t('copied'),
      description: t('summaryCopied'),
    });
  };

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
          title: t('copied'),
          description: t('shareLinkCopied'),
        });
      });
    } else {
      navigator.clipboard.writeText(shareText);
      toast({
        title: t('copied'),
        description: t('analysisCopied'),
      });
    }
  };

  const handleExportPDF = () => {
    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.width;

    // Header
    doc.setFillColor(26, 26, 26); // Dark background
    doc.rect(0, 0, pageWidth, 40, 'F');

    doc.setTextColor(255, 255, 255);
    doc.setFontSize(24);
    doc.setFont("helvetica", "bold");
    doc.text("ThreatSumm4ry", 14, 20);

    doc.setFontSize(12);
    doc.setFont("helvetica", "normal");
    doc.text("Threat Intelligence Report", 14, 30);

    doc.text(new Date().toLocaleString(), pageWidth - 14, 20, { align: "right" });

    // Summary Section
    doc.setTextColor(0, 0, 0);
    doc.setFontSize(14);
    doc.setFont("helvetica", "bold");
    doc.text("Executive Summary", 14, 50);

    const summaryData = [
      ["Target", data.query],
      ["Threat Level", data.threatLevel.toUpperCase()],
      ["Risk Score", `${data.overallScore}/100`],
      ["Detections", `${data.detections}/${data.totalVendors}`]
    ];

    autoTable(doc, {
      startY: 55,
      head: [],
      body: summaryData,
      theme: 'plain',
      styles: { fontSize: 12, cellPadding: 2 },
      columnStyles: {
        0: { fontStyle: 'bold', cellWidth: 40 },
        1: { cellWidth: 'auto' }
      },
      didParseCell: function (data) {
        if (data.section === 'body' && data.column.index === 1) {
          if (data.row.index === 1) { // Threat Level
            if (data.cell.raw === 'MALICIOUS') data.cell.styles.textColor = [220, 38, 38];
            else if (data.cell.raw === 'SUSPICIOUS') data.cell.styles.textColor = [234, 88, 12];
            else data.cell.styles.textColor = [22, 163, 74];
          }
          if (data.row.index === 2) { // Score
            // @ts-ignore
            const score = parseInt(data.cell.raw.split('/')[0]);
            if (score > 70) data.cell.styles.textColor = [220, 38, 38];
            else if (score > 30) data.cell.styles.textColor = [234, 88, 12];
            else data.cell.styles.textColor = [22, 163, 74];
          }
        }
      }
    });

    // Detailed Vendor Results
    // @ts-ignore
    const finalY = doc.lastAutoTable.finalY || 80;

    doc.setFontSize(14);
    doc.setFont("helvetica", "bold");
    doc.text("Vendor Analysis Details", 14, finalY + 15);

    const vendorRows = data.vendorData.map(v => {
      // Extract a summary string from the data
      let details = "";
      if (v.data) {
        const keys = Object.keys(v.data).filter(k => k !== 'Status' && typeof v.data[k] !== 'object').slice(0, 3);
        details = keys.map(k => `${k}: ${v.data[k]}`).join(', ');
      }

      return [
        v.name,
        v.data.Status || "Unknown",
        details
      ];
    });

    autoTable(doc, {
      startY: finalY + 20,
      head: [['Vendor', 'Status', 'Key Findings']],
      body: vendorRows,
      headStyles: { fillColor: [26, 26, 26], textColor: 255 },
      alternateRowStyles: { fillColor: [245, 245, 245] },
      styles: { fontSize: 10, cellPadding: 3 },
      columnStyles: {
        0: { fontStyle: 'bold', cellWidth: 40 },
        1: { cellWidth: 30 },
        2: { cellWidth: 'auto' }
      },
      didParseCell: function (data) {
        if (data.section === 'body' && data.column.index === 1) {
          const status = String(data.cell.raw).toLowerCase();
          if (status.includes('malicious') || status.includes('high')) data.cell.styles.textColor = [220, 38, 38];
          else if (status.includes('suspicious') || status.includes('medium')) data.cell.styles.textColor = [234, 88, 12];
          else if (status.includes('clean') || status.includes('safe') || status.includes('low')) data.cell.styles.textColor = [22, 163, 74];
        }
      }
    });

    // Footer
    const pageCount = doc.getNumberOfPages();
    for (let i = 1; i <= pageCount; i++) {
      doc.setPage(i);
      doc.setFontSize(10);
      doc.setTextColor(150);
      doc.text(`Page ${i} of ${pageCount}`, pageWidth / 2, doc.internal.pageSize.height - 10, { align: 'center' });
    }

    doc.save(`threat-report-${data.query}.pdf`);
    toast({
      title: t('exportSuccess'),
      description: t('pdfDownloaded'),
    });
  };

  const handleExportJSON = () => {
    const jsonString = JSON.stringify(data, null, 2);
    const blob = new Blob([jsonString], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `threat-report-${data.query}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    toast({
      title: t('exportSuccess'),
      description: t('jsonDownloaded'),
    });
  };

  return (
    <div className="flex flex-wrap gap-2 animate-fade-in">
      <Button variant="outline" size="sm" onClick={onRefresh} disabled={isLoading}>
        <RefreshCw className={`mr-2 h-4 w-4 ${isLoading ? "animate-spin" : ""}`} />
        {t('refresh')}
      </Button>
      <Button variant="outline" size="sm" onClick={handleCopy}>
        <Copy className="mr-2 h-4 w-4" />
        {t('copySummary')}
      </Button>
      <Button variant="outline" size="sm" onClick={onCopyLinks}>
        <Share2 className="mr-2 h-4 w-4" />
        {t('copyLinks')}
      </Button>

      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="sm" className="gap-2">
            <Download className="h-4 w-4" />
            {t('export')}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end">
          <DropdownMenuItem onClick={handleExportPDF}>
            <FileText className="mr-2 h-4 w-4" />
            {t('downloadPdf')}
          </DropdownMenuItem>
          <DropdownMenuItem onClick={handleExportJSON}>
            <FileJson className="mr-2 h-4 w-4" />
            {t('downloadJson')}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <Button variant="outline" size="sm" onClick={handleShare}>
        <Zap className="mr-2 h-4 w-4" />
        {t('share')}
      </Button>
    </div>
  );
};
