import {
    Table,
    TableBody,
    TableCell,
    TableHead,
    TableHeader,
    TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ThreatIntelligenceResult } from "@/types/threat-intelligence";
import { ThreatBadge } from "./ThreatBadge";
import { Copy, ArrowRight } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

interface MultiIpSummaryProps {
    results: ThreatIntelligenceResult[];
    onViewDetails: (query: string) => void;
}

export const MultiIpSummary = ({ results, onViewDetails }: MultiIpSummaryProps) => {
    const { toast } = useToast();

    const copyReport = (result: ThreatIntelligenceResult) => {
        const text = `Threat Report for ${result.query}\nScore: ${result.overallScore}/100\nThreat Level: ${result.threatLevel}\nDetections: ${result.detections}/${result.totalVendors}`;
        navigator.clipboard.writeText(text);
        toast({
            title: "Copied",
            description: `Report for ${result.query} copied to clipboard`,
        });
    };

    return (
        <div className="rounded-md border">
            <Table>
                <TableHeader>
                    <TableRow>
                        <TableHead>Target</TableHead>
                        <TableHead>Threat Level</TableHead>
                        <TableHead>Score</TableHead>
                        <TableHead>Detections</TableHead>
                        <TableHead className="text-right">Actions</TableHead>
                    </TableRow>
                </TableHeader>
                <TableBody>
                    {results.map((result) => (
                        <TableRow key={result.query}>
                            <TableCell className="font-mono font-medium">{result.query}</TableCell>
                            <TableCell>
                                <ThreatBadge level={result.threatLevel} />
                            </TableCell>
                            <TableCell>
                                <div className="flex items-center gap-2">
                                    <span className={`font-bold ${result.overallScore > 70 ? "text-destructive" :
                                            result.overallScore > 30 ? "text-orange-500" : "text-green-500"
                                        }`}>
                                        {result.overallScore}
                                    </span>
                                    <span className="text-muted-foreground text-xs">/100</span>
                                </div>
                            </TableCell>
                            <TableCell>
                                {result.detections} <span className="text-muted-foreground">/ {result.totalVendors}</span>
                            </TableCell>
                            <TableCell className="text-right">
                                <div className="flex justify-end gap-2">
                                    <Button variant="ghost" size="icon" onClick={() => copyReport(result)} title="Copy Summary">
                                        <Copy className="h-4 w-4" />
                                    </Button>
                                    <Button variant="ghost" size="icon" onClick={() => onViewDetails(result.query)} title="View Details">
                                        <ArrowRight className="h-4 w-4" />
                                    </Button>
                                </div>
                            </TableCell>
                        </TableRow>
                    ))}
                </TableBody>
            </Table>
        </div>
    );
};
