import { Button } from "@/components/ui/button";
import { useLanguage } from "@/contexts/LanguageContext";
import { Languages } from "lucide-react";
import {
    DropdownMenu,
    DropdownMenuContent,
    DropdownMenuItem,
    DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

export function LanguageToggle() {
    const { language, setLanguage } = useLanguage();

    return (
        <DropdownMenu>
            <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon" title="Switch Language">
                    <Languages className="h-[1.2rem] w-[1.2rem]" />
                    <span className="sr-only">Toggle language</span>
                </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => setLanguage("en")} className={language === "en" ? "bg-accent" : ""}>
                    English
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setLanguage("pt")} className={language === "pt" ? "bg-accent" : ""}>
                    Português
                </DropdownMenuItem>
            </DropdownMenuContent>
        </DropdownMenu>
    );
}
