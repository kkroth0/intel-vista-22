import { ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";

interface ClickableArtifactProps {
    text: string;
    onPivot: (artifact: string) => void;
}

export function ClickableArtifact({ text, onPivot }: ClickableArtifactProps) {
    // Regex patterns for artifacts
    const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
    const domainRegex = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/;
    const hashRegex = /\b[a-fA-F0-9]{32,64}\b/;

    // Check if the text matches any artifact type
    const isArtifact = ipRegex.test(text) || domainRegex.test(text) || hashRegex.test(text);

    if (!isArtifact) {
        return <span>{text}</span>;
    }

    return (
        <Button
            variant="link"
            className="h-auto p-0 text-primary hover:underline inline-flex items-center gap-1 font-mono"
            onClick={(e) => {
                e.stopPropagation();
                onPivot(text);
            }}
            title={`Pivot to analyze ${text}`}
        >
            {text}
            <ExternalLink className="h-3 w-3 opacity-50" />
        </Button>
    );
}
