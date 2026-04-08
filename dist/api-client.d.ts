export interface ScanOptions {
    severityThreshold?: 'low' | 'medium' | 'high' | 'critical';
    failOn?: ('low' | 'medium' | 'high' | 'critical')[];
    include?: string[];
    exclude?: string[];
    apiKey?: string;
    apiUrl?: string;
    config?: Record<string, unknown>;
}
export interface GateOptions {
    files: Record<string, string>;
    frameworks?: string[];
    severityThreshold?: 'low' | 'medium' | 'high' | 'critical';
    failOn?: ('low' | 'medium' | 'high' | 'critical')[];
    apiKey?: string;
    apiUrl?: string;
    config?: Record<string, unknown>;
}
export declare class ComplianceApiClient {
    private apiUrl;
    private apiKey;
    constructor(apiUrl?: string, apiKey?: string);
    validate(files: Record<string, string>, frameworks: string[], options?: ScanOptions): Promise<any>;
    hook(files: Record<string, string>, frameworks: string[]): Promise<any>;
    private post;
}
