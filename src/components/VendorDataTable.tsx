import { useState } from "react";
import { VendorData } from "@/types/threat-intelligence";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ArrowUpDown, Search, ExternalLink } from "lucide-react";

interface VendorDataTableProps {
  vendorData: VendorData[];
  getVendorLink?: (name: string) => string | undefined;
}

type SortField = "name" | "status" | "dataCount";
type SortOrder = "asc" | "desc";

export const VendorDataTable = ({ vendorData, getVendorLink }: VendorDataTableProps) => {
  const [searchTerm, setSearchTerm] = useState("");
  const [sortField, setSortField] = useState<SortField>("name");
  const [sortOrder, setSortOrder] = useState<SortOrder>("asc");

  const getStatus = (vendor: VendorData) => {
    if (vendor.error) return "error";
    if (Object.keys(vendor.data).length === 0) return "no-data";
    const status = vendor.data["Status"];
    if (typeof status === "string") {
      if (status.toLowerCase().includes("malicious")) return "malicious";
      if (status.toLowerCase().includes("suspicious")) return "suspicious";
    }
    return "clean";
  };

  const getStatusBadge = (status: string) => {
    const variants = {
      error: { variant: "destructive" as const, label: "Error" },
      "no-data": { variant: "secondary" as const, label: "No Data" },
      malicious: { variant: "destructive" as const, label: "Malicious" },
      suspicious: { variant: "outline" as const, label: "Suspicious" },
      clean: { variant: "default" as const, label: "Clean" },
    };
    const config = variants[status as keyof typeof variants] || variants.clean;
    return <Badge variant={config.variant}>{config.label}</Badge>;
  };

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortOrder("asc");
    }
  };

  const filteredAndSorted = vendorData
    .filter(vendor => 
      vendor.name.toLowerCase().includes(searchTerm.toLowerCase())
    )
    .sort((a, b) => {
      let compareValue = 0;
      if (sortField === "name") {
        compareValue = a.name.localeCompare(b.name);
      } else if (sortField === "status") {
        compareValue = getStatus(a).localeCompare(getStatus(b));
      } else if (sortField === "dataCount") {
        compareValue = Object.keys(a.data).length - Object.keys(b.data).length;
      }
      return sortOrder === "asc" ? compareValue : -compareValue;
    });

  return (
    <Card className="p-6 animate-fade-in">
      <div className="mb-4 flex items-center gap-4">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search vendors..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="pl-9"
          />
        </div>
        <Badge variant="outline">{filteredAndSorted.length} vendors</Badge>
      </div>

      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>
                <Button variant="ghost" onClick={() => handleSort("name")} className="h-8 px-2 hover:bg-muted/50">
                  Vendor
                  <ArrowUpDown className="ml-2 h-4 w-4" />
                </Button>
              </TableHead>
              <TableHead>
                <Button variant="ghost" onClick={() => handleSort("status")} className="h-8 px-2 hover:bg-muted/50">
                  Status
                  <ArrowUpDown className="ml-2 h-4 w-4" />
                </Button>
              </TableHead>
              <TableHead>
                <Button variant="ghost" onClick={() => handleSort("dataCount")} className="h-8 px-2 hover:bg-muted/50">
                  Data Points
                  <ArrowUpDown className="ml-2 h-4 w-4" />
                </Button>
              </TableHead>
              <TableHead>Key Findings</TableHead>
              <TableHead className="w-[100px]">Link</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {filteredAndSorted.map((vendor) => {
              const status = getStatus(vendor);
              const link = getVendorLink?.(vendor.name);
              return (
                <TableRow key={vendor.name} className="hover:bg-muted/50 transition-colors">
                  <TableCell className="font-medium">{vendor.name}</TableCell>
                  <TableCell>{getStatusBadge(status)}</TableCell>
                  <TableCell>
                    <Badge variant="secondary">{Object.keys(vendor.data).length}</Badge>
                  </TableCell>
                  <TableCell className="max-w-md truncate text-sm text-muted-foreground">
                    {vendor.error || Object.entries(vendor.data).slice(0, 2).map(([k, v]) => 
                      `${k}: ${Array.isArray(v) ? v.join(", ") : v}`
                    ).join(" | ") || "No data"}
                  </TableCell>
                  <TableCell>
                    {link && (
                      <Button variant="ghost" size="sm" asChild>
                        <a href={link} target="_blank" rel="noopener noreferrer">
                          <ExternalLink className="h-4 w-4" />
                        </a>
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>
    </Card>
  );
};
