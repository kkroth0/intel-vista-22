import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

type ThreatLevel = "safe" | "suspicious" | "malicious" | "unknown";

interface ThreatBadgeProps {
  level: ThreatLevel;
  label?: string;
  className?: string;
}

export const ThreatBadge = ({ level, label, className }: ThreatBadgeProps) => {
  const getBadgeStyles = () => {
    switch (level) {
      case "safe":
        return "bg-threat-safe text-threat-safe-foreground";
      case "suspicious":
        return "bg-threat-suspicious text-threat-suspicious-foreground";
      case "malicious":
        return "bg-threat-malicious text-threat-malicious-foreground";
      default:
        return "bg-muted text-muted-foreground";
    }
  };

  const displayLabel = label || level.charAt(0).toUpperCase() + level.slice(1);

  return (
    <Badge className={cn(getBadgeStyles(), className)} variant="secondary">
      {displayLabel}
    </Badge>
  );
};
