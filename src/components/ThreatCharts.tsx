import { Card } from "@/components/ui/card";
import { VendorData } from "@/types/threat-intelligence";
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Legend } from "recharts";

interface ThreatChartsProps {
  vendorData: VendorData[];
  detections: number;
  totalVendors: number;
}

export const ThreatCharts = ({ vendorData, detections, totalVendors }: ThreatChartsProps) => {
  // Threat Category Breakdown
  const getCategoryBreakdown = () => {
    const categories = {
      Malware: 0,
      Abuse: 0,
      Phishing: 0,
      Suspicious: 0,
      Clean: 0
    };

    vendorData.forEach(vendor => {
      if (vendor.error || !vendor.data || Object.keys(vendor.data).length === 0) return;

      const status = vendor.data["Status"]?.toLowerCase() || "";

      // Categorize based on vendor and status
      if (vendor.name === "VirusTotal" && vendor.data["Malicious"] && vendor.data["Malicious"] > 0) {
        categories.Malware++;
      } else if (vendor.name === "AbuseIPDB" && vendor.data["Abuse Confidence Score"]) {
        const score = parseInt(vendor.data["Abuse Confidence Score"]);
        if (score > 50) categories.Abuse++;
        else categories.Clean++;
      } else if ((vendor.name === "PhishTank" || vendor.name === "Google Safe Browsing" || vendor.name === "PhishStats")
        && (status.includes("phishing") || status.includes("unsafe"))) {
        categories.Phishing++;
      } else if (vendor.name === "AlienVault OTX" && vendor.data["Pulse Count"] && !vendor.data["Pulse Count"].includes("0")) {
        categories.Suspicious++;
      } else if (status.includes("malicious") || status.includes("unsafe")) {
        categories.Malware++;
      } else if (status.includes("suspicious")) {
        categories.Suspicious++;
      } else if (status.includes("clean") || status.includes("safe") || status.includes("low risk")) {
        categories.Clean++;
      }
    });

    return [
      { name: "Malware", value: categories.Malware, color: "#ef4444" },
      { name: "Abuse", value: categories.Abuse, color: "#f97316" },
      { name: "Phishing", value: categories.Phishing, color: "#eab308" },
      { name: "Suspicious", value: categories.Suspicious, color: "#3b82f6" },
      { name: "Clean", value: categories.Clean, color: "hsl(var(--primary))" },
    ].filter(cat => cat.value > 0);
  };

  // Detection Timeline
  const getDetectionTimeline = () => {
    const timeline = {
      "Recent (24h)": 0,
      "This Week": 0,
      "This Month": 0,
      "Older": 0,
      "Unknown": 0
    };

    const now = Date.now();
    const day = 24 * 60 * 60 * 1000;
    const week = 7 * day;
    const month = 30 * day;

    vendorData.forEach(vendor => {
      if (vendor.error || !vendor.data) {
        timeline["Unknown"]++;
        return;
      }

      let timestamp: number | null = null;

      // Extract timestamp based on vendor
      if (vendor.name === "VirusTotal" && vendor.data["Last Analysis"]) {
        timestamp = new Date(vendor.data["Last Analysis"]).getTime();
      } else if (vendor.name === "AbuseIPDB" && vendor.data["Last Report"]) {
        timestamp = new Date(vendor.data["Last Report"]).getTime();
      } else if (vendor.name === "AlienVault OTX") {
        // OTX doesn't have clear timestamps in current format
        timeline["Unknown"]++;
        return;
      } else if (vendor.data["Last Seen"]) {
        timestamp = new Date(vendor.data["Last Seen"]).getTime();
      }

      if (!timestamp || isNaN(timestamp)) {
        timeline["Unknown"]++;
        return;
      }

      const age = now - timestamp;
      if (age < day) timeline["Recent (24h)"]++;
      else if (age < week) timeline["This Week"]++;
      else if (age < month) timeline["This Month"]++;
      else timeline["Older"]++;
    });

    return [
      { name: "Recent (24h)", value: timeline["Recent (24h)"], color: "#ef4444" },
      { name: "This Week", value: timeline["This Week"], color: "#f97316" },
      { name: "This Month", value: timeline["This Month"], color: "#eab308" },
      { name: "Older", value: timeline["Older"], color: "hsl(var(--primary))" },
      { name: "Unknown", value: timeline["Unknown"], color: "#6b7280" },
    ].filter(t => t.value > 0);
  };

  // Vendor Threat Scores
  const getVendorScore = (vendor: VendorData): { score: number, status: string } => {
    const data = vendor.data;
    if (!data || Object.keys(data).length === 0 || vendor.error) return { score: 0, status: "No Data" };

    // VirusTotal
    if (data["Detection Rate"]) {
      const parts = data["Detection Rate"].split("/");
      if (parts.length === 2) {
        return {
          score: Math.round((parseInt(parts[0]) / parseInt(parts[1])) * 100),
          status: data["Status"] || "Unknown"
        };
      }
    }

    // AbuseIPDB
    if (data["Abuse Confidence Score"]) {
      return {
        score: parseInt(data["Abuse Confidence Score"]),
        status: `Confidence: ${data["Abuse Confidence Score"]}`
      };
    }

    // IPQualityScore
    if (data["Fraud Score"]) {
      return {
        score: parseInt(data["Fraud Score"]),
        status: data["Status"] || "Unknown"
      };
    }

    // Hybrid Analysis
    if (data["Threat Score"]) {
      return {
        score: parseInt(data["Threat Score"]),
        status: `Score: ${data["Threat Score"]}`
      };
    }

    // Fallback based on Status string
    const status = (data["Status"] || "").toLowerCase();
    if (status.includes("malicious") || status.includes("unsafe") || status.includes("phishing") || status.includes("high risk")) {
      return { score: 100, status: data["Status"] };
    }
    if (status.includes("suspicious") || status.includes("moderate risk")) {
      return { score: 60, status: data["Status"] };
    }
    if (status.includes("low risk")) {
      return { score: 30, status: data["Status"] };
    }

    return { score: 0, status: data["Status"] || "Clean" };
  };

  const vendorScores = vendorData
    .map(vendor => {
      const { score, status } = getVendorScore(vendor);
      return {
        name: vendor.name,
        score,
        status,
        fill: score > 70 ? "hsl(var(--destructive))" : score > 30 ? "#eab308" : "hsl(var(--primary))"
      };
    })
    .sort((a, b) => b.score - a.score)
    .slice(0, 10);

  const categoryData = getCategoryBreakdown();
  const timelineData = getDetectionTimeline();

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-popover border text-popover-foreground p-2 rounded shadow-md text-sm">
          <p className="font-semibold">{label}</p>
          <p>Score: {payload[0].value}/100</p>
          <p className="text-muted-foreground">{payload[0].payload.status}</p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="grid gap-4 md:grid-cols-3 animate-fade-in">
      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">Threat Categories</h3>
        <ResponsiveContainer width="100%" height={300}>
          <PieChart>
            <Pie
              data={categoryData}
              cx="50%"
              cy="50%"
              labelLine={false}
              label={({ name, percent }) => percent > 0.05 ? `${name}: ${(percent * 100).toFixed(0)}%` : ''}
              outerRadius={70}
              fill="#8884d8"
              dataKey="value"
            >
              {categoryData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip />
          </PieChart>
        </ResponsiveContainer>
      </Card>

      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">Detection Timeline</h3>
        <ResponsiveContainer width="100%" height={300}>
          <PieChart>
            <Pie
              data={timelineData}
              cx="50%"
              cy="50%"
              labelLine={false}
              label={({ name, percent }) => percent > 0.05 ? `${name}: ${(percent * 100).toFixed(0)}%` : ''}
              outerRadius={70}
              fill="#8884d8"
              dataKey="value"
            >
              {timelineData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip />
          </PieChart>
        </ResponsiveContainer>
      </Card>

      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">Vendor Threat Scores (Top 10)</h3>
        <ResponsiveContainer width="100%" height={300}>
          <BarChart data={vendorScores} layout="vertical" margin={{ left: 20 }}>
            <XAxis type="number" domain={[0, 100]} hide />
            <YAxis type="category" dataKey="name" width={100} style={{ fontSize: '12px' }} />
            <Tooltip content={<CustomTooltip />} />
            <Bar dataKey="score" radius={[0, 4, 4, 0]}>
              {vendorScores.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.fill} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </Card>
    </div>
  );
};
