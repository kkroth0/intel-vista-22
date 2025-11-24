import { Shield, AlertTriangle, Bug, FileSearch, Globe, Link as LinkIcon, Radar, Database, Eye } from "lucide-react";
import { ThreatSummary } from "@/components/ThreatSummary";
import { VendorCard } from "@/components/VendorCard";
import { ThreatBadge } from "@/components/ThreatBadge";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";

const Index = () => {
  // Mock data for the dashboard
  const query = "192.168.1.100";

  const vendorData = [
    {
      name: "VirusTotal",
      data: {
        "Detection Rate": "15/65",
        "Status": "Suspicious",
        "Top Detections": ["Kaspersky", "BitDefender", "ESET-NOD32"]
      }
    },
    {
      name: "AbuseIPDB",
      data: {
        "Abuse Confidence Score": "78%",
        "Reports": "142 reports",
        "Last Report": "2025-11-20 14:32 UTC"
      }
    },
    {
      name: "Fortinet FortiGuard",
      data: {
        "Category": "Proxy Avoidance",
        "Risk Level": "High Risk",
        "Additional Info": "Known proxy server, potential malicious activity"
      }
    },
    {
      name: "Kaspersky Threat Intelligence",
      data: {
        "Reputation": "Clean",
        "Context": "No known malicious activity detected in the last 90 days",
        "Categories": ["Infrastructure", "Unknown"]
      }
    },
    {
      name: "Shodan",
      data: {
        "Open Ports": ["22/SSH", "80/HTTP", "443/HTTPS", "3306/MySQL"],
        "Detected Services": "nginx/1.18.0, OpenSSH 8.2, MySQL 5.7",
        "Vulnerabilities": "3 CVEs"
      }
    },
    {
      name: "URLhaus",
      data: {
        "Detection Status": "Malicious URL Detected",
        "Confidence": "95%",
        "Threat Type": "Malware Distribution"
      }
    },
    {
      name: "ThreatFox",
      data: {
        "Botnet Detection": "Emotet C2",
        "Confidence Level": "88%",
        "Tags": ["Emotet", "C2", "Banking Trojan"]
      }
    },
    {
      name: "Hybrid Analysis",
      data: {
        "Threat Score": "65/100",
        "Sample Hashes": "a3f2c9d8e1b4...",
        "Status": "Potentially Malicious"
      }
    },
    {
      name: "AlienVault OTX",
      data: {
        "Pulse Count": "24 pulses",
        "Status": "Suspicious Activity",
        "Summary": "Associated with spam campaigns and phishing attempts"
      }
    },
    {
      name: "Web Categorization",
      data: {
        "BlueCoat": "Suspicious",
        "Sophos": "Uncategorized",
        "Fortinet": "High Risk"
      }
    },
    {
      name: "Cisco Talos",
      data: {
        "Reputation": "Poor",
        "Email Volume": "High",
        "Web Reputation": "Untrusted",
        "Category": "Spam Source"
      }
    },
    {
      name: "IBM X-Force",
      data: {
        "Risk Score": "7.5/10",
        "Category": "Malware",
        "Reports": "89 reports",
        "Geographic Location": "Russia"
      }
    },
    {
      name: "GreyNoise",
      data: {
        "Classification": "Malicious",
        "Scanner Type": "Exploitation",
        "First Seen": "2025-10-15",
        "Tags": ["VPN", "Tor Exit Node"]
      }
    },
    {
      name: "IPVoid",
      data: {
        "Blacklist Status": "5/92 blacklists",
        "Detection Rate": "5%",
        "Location": "Moscow, Russia",
        "ISP": "DigitalOcean"
      }
    }
  ];

  return (
    <div className="min-h-screen bg-background p-4 md:p-8">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-4xl font-bold mb-2">Threat Intelligence Dashboard</h1>
            <p className="text-muted-foreground">Aggregated analysis from multiple security vendors</p>
          </div>
        </div>

        {/* Summary Card */}
        <ThreatSummary 
          query={query}
          overallScore={73}
          threatLevel="suspicious"
          totalVendors={14}
          detections={8}
          vendorData={vendorData}
        />

        {/* Vendor Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {/* VirusTotal */}
          <VendorCard
            title="VirusTotal"
            description="Multi-vendor malware scanner"
            icon={<Shield className="h-5 w-5 text-primary" />}
            externalLink="https://virustotal.com"
          >
            <div className="space-y-4">
              <div>
                <p className="text-sm text-muted-foreground mb-2">Detection Rate</p>
                <div className="flex items-center gap-3">
                  <Progress value={23} className="flex-1" />
                  <span className="font-semibold">15/65</span>
                </div>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Status</p>
                <ThreatBadge level="suspicious" label="Suspicious" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Top Detections</p>
                <div className="flex flex-wrap gap-2">
                  <Badge variant="outline">Kaspersky</Badge>
                  <Badge variant="outline">BitDefender</Badge>
                  <Badge variant="outline">ESET-NOD32</Badge>
                </div>
              </div>
            </div>
          </VendorCard>

          {/* AbuseIPDB */}
          <VendorCard
            title="AbuseIPDB"
            description="IP reputation database"
            icon={<AlertTriangle className="h-5 w-5 text-primary" />}
            externalLink="https://abuseipdb.com"
          >
            <div className="space-y-4">
              <div>
                <p className="text-sm text-muted-foreground mb-2">Abuse Confidence Score</p>
                <div className="flex items-center gap-3">
                  <Progress value={78} className="flex-1" />
                  <span className="font-semibold text-threat-malicious">78%</span>
                </div>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Reports</p>
                <p className="text-2xl font-bold">142 reports</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Last Report</p>
                <p className="font-mono text-sm">2025-11-20 14:32 UTC</p>
              </div>
            </div>
          </VendorCard>

          {/* Fortinet FortiGuard */}
          <VendorCard
            title="Fortinet FortiGuard"
            description="Web filtering & threat intelligence"
            icon={<Shield className="h-5 w-5 text-primary" />}
            externalLink="https://fortiguard.com"
          >
            <div className="space-y-4">
              <div>
                <p className="text-sm text-muted-foreground mb-2">Category</p>
                <Badge variant="secondary" className="text-sm">Proxy Avoidance</Badge>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Risk Level</p>
                <ThreatBadge level="malicious" label="High Risk" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Additional Info</p>
                <p className="text-sm">Known proxy server, potential malicious activity</p>
              </div>
            </div>
          </VendorCard>

          {/* Kaspersky TIP */}
          <VendorCard
            title="Kaspersky Threat Intelligence"
            description="Advanced threat analysis"
            icon={<Bug className="h-5 w-5 text-primary" />}
            externalLink="https://tip.kaspersky.com"
          >
            <div className="space-y-4">
              <div>
                <p className="text-sm text-muted-foreground mb-2">Reputation</p>
                <ThreatBadge level="safe" label="Clean" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Context</p>
                <p className="text-sm">No known malicious activity detected in the last 90 days</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Categories</p>
                <div className="flex flex-wrap gap-2">
                  <Badge variant="outline">Infrastructure</Badge>
                  <Badge variant="outline">Unknown</Badge>
                </div>
              </div>
            </div>
          </VendorCard>

          {/* Shodan */}
          <VendorCard
            title="Shodan"
            description="Internet-connected device search"
            icon={<Radar className="h-5 w-5 text-primary" />}
            externalLink="https://shodan.io"
          >
            <div className="space-y-4">
              <div>
                <p className="text-sm text-muted-foreground mb-2">Open Ports</p>
                <div className="flex flex-wrap gap-2">
                  <Badge variant="secondary">22/SSH</Badge>
                  <Badge variant="secondary">80/HTTP</Badge>
                  <Badge variant="secondary">443/HTTPS</Badge>
                  <Badge variant="secondary">3306/MySQL</Badge>
                </div>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Detected Services</p>
                <p className="text-sm">nginx/1.18.0, OpenSSH 8.2, MySQL 5.7</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Vulnerabilities</p>
                <p className="text-2xl font-bold text-threat-suspicious">3 CVEs</p>
              </div>
            </div>
          </VendorCard>

          {/* URLhaus */}
          <VendorCard
            title="URLhaus"
            description="Malware URL sharing"
            icon={<LinkIcon className="h-5 w-5 text-primary" />}
            externalLink="https://urlhaus.abuse.ch"
          >
            <div className="space-y-4">
              <div>
                <p className="text-sm text-muted-foreground mb-2">Detection Status</p>
                <ThreatBadge level="malicious" label="Malicious URL Detected" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Confidence</p>
                <div className="flex items-center gap-3">
                  <Progress value={95} className="flex-1" />
                  <span className="font-semibold text-threat-malicious">95%</span>
                </div>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Threat Type</p>
                <Badge variant="destructive">Malware Distribution</Badge>
              </div>
            </div>
          </VendorCard>

          {/* ThreatFox */}
          <VendorCard
            title="ThreatFox"
            description="IOC database"
            icon={<Database className="h-5 w-5 text-primary" />}
            externalLink="https://threatfox.abuse.ch"
          >
            <div className="space-y-4">
              <div>
                <p className="text-sm text-muted-foreground mb-2">Botnet Detection</p>
                <ThreatBadge level="malicious" label="Emotet C2" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Confidence Level</p>
                <div className="flex items-center gap-3">
                  <Progress value={88} className="flex-1" />
                  <span className="font-semibold">88%</span>
                </div>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Tags</p>
                <div className="flex flex-wrap gap-2">
                  <Badge variant="outline">Emotet</Badge>
                  <Badge variant="outline">C2</Badge>
                  <Badge variant="outline">Banking Trojan</Badge>
                </div>
              </div>
            </div>
          </VendorCard>

          {/* Hybrid Analysis */}
          <VendorCard
            title="Hybrid Analysis"
            description="Malware analysis sandbox"
            icon={<FileSearch className="h-5 w-5 text-primary" />}
            externalLink="https://hybrid-analysis.com"
          >
            <div className="space-y-4">
              <div>
                <p className="text-sm text-muted-foreground mb-2">Threat Score</p>
                <div className="flex items-center gap-3">
                  <Progress value={65} className="flex-1" />
                  <span className="font-semibold">65/100</span>
                </div>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Sample Hashes</p>
                <p className="font-mono text-xs break-all">a3f2c9d8e1b4...</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Status</p>
                <ThreatBadge level="suspicious" label="Potentially Malicious" />
              </div>
            </div>
          </VendorCard>

          {/* AlienVault OTX */}
          <VendorCard
            title="AlienVault OTX"
            description="Open threat exchange"
            icon={<Eye className="h-5 w-5 text-primary" />}
            externalLink="https://otx.alienvault.com"
          >
            <div className="space-y-4">
              <div>
                <p className="text-sm text-muted-foreground mb-2">Pulse Count</p>
                <p className="text-2xl font-bold">24 pulses</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Status</p>
                <ThreatBadge level="suspicious" label="Suspicious Activity" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Summary</p>
                <p className="text-sm">Associated with spam campaigns and phishing attempts</p>
              </div>
            </div>
          </VendorCard>

          {/* Web Categorization */}
          <VendorCard
            title="Web Categorization"
            description="Multiple vendor classifications"
            icon={<Globe className="h-5 w-5 text-primary" />}
          >
            <div className="space-y-4">
              <div>
                <p className="text-sm text-muted-foreground mb-2">BlueCoat</p>
                <Badge variant="secondary">Suspicious</Badge>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Sophos</p>
                <Badge variant="secondary">Uncategorized</Badge>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Fortinet</p>
                <Badge variant="destructive">High Risk</Badge>
              </div>
            </div>
          </VendorCard>

          {/* Cisco Talos */}
          <VendorCard
            title="Cisco Talos"
            description="Threat intelligence & research"
            icon={<Shield className="h-5 w-5 text-primary" />}
            externalLink="https://talosintelligence.com"
          >
            <div className="space-y-4">
              <div>
                <p className="text-sm text-muted-foreground mb-2">Reputation</p>
                <ThreatBadge level="malicious" label="Poor" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Email Volume</p>
                <Badge variant="destructive">High</Badge>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Web Reputation</p>
                <p className="text-sm">Untrusted - Spam Source</p>
              </div>
            </div>
          </VendorCard>

          {/* IBM X-Force */}
          <VendorCard
            title="IBM X-Force"
            description="Security intelligence platform"
            icon={<Database className="h-5 w-5 text-primary" />}
            externalLink="https://exchange.xforce.ibmcloud.com"
          >
            <div className="space-y-4">
              <div>
                <p className="text-sm text-muted-foreground mb-2">Risk Score</p>
                <div className="flex items-center gap-3">
                  <Progress value={75} className="flex-1" />
                  <span className="font-semibold text-threat-malicious">7.5/10</span>
                </div>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Category</p>
                <Badge variant="destructive">Malware</Badge>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Location</p>
                <p className="text-sm">Russia - 89 reports</p>
              </div>
            </div>
          </VendorCard>

          {/* GreyNoise */}
          <VendorCard
            title="GreyNoise"
            description="Internet scanner detection"
            icon={<Radar className="h-5 w-5 text-primary" />}
            externalLink="https://greynoise.io"
          >
            <div className="space-y-4">
              <div>
                <p className="text-sm text-muted-foreground mb-2">Classification</p>
                <ThreatBadge level="malicious" label="Malicious" />
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Scanner Type</p>
                <Badge variant="destructive">Exploitation</Badge>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Tags</p>
                <div className="flex flex-wrap gap-2">
                  <Badge variant="outline">VPN</Badge>
                  <Badge variant="outline">Tor Exit Node</Badge>
                </div>
              </div>
            </div>
          </VendorCard>

          {/* IPVoid */}
          <VendorCard
            title="IPVoid"
            description="IP blacklist checker"
            icon={<AlertTriangle className="h-5 w-5 text-primary" />}
            externalLink="https://ipvoid.com"
          >
            <div className="space-y-4">
              <div>
                <p className="text-sm text-muted-foreground mb-2">Blacklist Status</p>
                <div className="flex items-center gap-3">
                  <Progress value={5} className="flex-1" />
                  <span className="font-semibold">5/92</span>
                </div>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">Location</p>
                <p className="text-sm">Moscow, Russia</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground mb-2">ISP</p>
                <Badge variant="secondary">DigitalOcean</Badge>
              </div>
            </div>
          </VendorCard>
        </div>
      </div>
    </div>
  );
};

export default Index;
