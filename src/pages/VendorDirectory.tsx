import { ArrowLeft, ExternalLink, Shield } from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { VENDOR_IOC_SUPPORT } from "@/services/threatApi";
import { Badge } from "@/components/ui/badge";

const VendorDirectory = () => {
    const vendors = Object.entries(VENDOR_IOC_SUPPORT).sort((a, b) => a[0].localeCompare(b[0]));

    return (
        <div className="min-h-screen bg-background p-4 md:p-8">
            <div className="max-w-7xl mx-auto space-y-8">
                <div className="flex items-center gap-4">
                    <Link to="/">
                        <Button variant="ghost" size="icon">
                            <ArrowLeft className="h-4 w-4" />
                        </Button>
                    </Link>
                    <div>
                        <h1 className="text-3xl font-bold">Vendor Directory</h1>
                        <p className="text-muted-foreground">
                            Integrated threat intelligence sources and their capabilities
                        </p>
                    </div>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                    {vendors.map(([name, types]) => (
                        <div key={name} className="p-6 rounded-xl border bg-card shadow-sm hover:shadow-md transition-shadow">
                            <div className="flex items-start justify-between mb-4">
                                <div className="flex items-center gap-2">
                                    <Shield className="h-5 w-5 text-primary" />
                                    <h3 className="font-semibold text-lg">{name}</h3>
                                </div>
                            </div>

                            <div className="space-y-4">
                                <div>
                                    <p className="text-sm text-muted-foreground mb-2">Supported IOC Types:</p>
                                    <div className="flex flex-wrap gap-2">
                                        {types.map(type => (
                                            <Badge key={type} variant="secondary" className="uppercase">
                                                {type}
                                            </Badge>
                                        ))}
                                    </div>
                                </div>
                            </div>
                        </div>
                    ))}
                </div>
            </div>
        </div>
    );
};

export default VendorDirectory;
