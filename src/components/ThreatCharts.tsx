import { Card } from "@/components/ui/card";
import { VendorData } from "@/types/threat-intelligence";
import { PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Legend } from "recharts";

interface ThreatChartsProps {
  vendorData: VendorData[];
  detections: number;
  totalVendors: number;
}

export const ThreatCharts = ({ vendorData, detections, totalVendors }: ThreatChartsProps) => {
  const threatDistribution = [
    { name: "Malicious", value: detections, color: "hsl(var(--destructive))" },
    { name: "Clean", value: totalVendors - detections, color: "hsl(var(--primary))" },
  ];

  const vendorResponseData = vendorData.map(vendor => ({
    name: vendor.name.substring(0, 15),
    status: vendor.error ? "Error" : Object.keys(vendor.data).length > 0 ? "Success" : "No Data",
    value: vendor.error ? 0 : Object.keys(vendor.data).length > 0 ? 1 : 0.5,
  }));

  return (
    <div className="grid gap-4 md:grid-cols-2 animate-fade-in">
      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">Threat Detection Overview</h3>
        <ResponsiveContainer width="100%" height={250}>
          <PieChart>
            <Pie
              data={threatDistribution}
              cx="50%"
              cy="50%"
              labelLine={false}
              label={({ name, percent }) => `${name}: ${(percent * 100).toFixed(0)}%`}
              outerRadius={80}
              fill="#8884d8"
              dataKey="value"
            >
              {threatDistribution.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip />
          </PieChart>
        </ResponsiveContainer>
      </Card>

      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">Vendor Response Status</h3>
        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={vendorResponseData.slice(0, 8)} layout="vertical">
            <XAxis type="number" domain={[0, 1]} hide />
            <YAxis type="category" dataKey="name" width={100} style={{ fontSize: '12px' }} />
            <Tooltip />
            <Bar dataKey="value" fill="hsl(var(--primary))" radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      </Card>
    </div>
  );
};
