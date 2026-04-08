import { ScanOptions, GateOptions } from './api-client';
export * from './api-client';
export * from './formatters/table';
export * from './formatters/prompt';
export * from './formatters/sarif';
/**
 * Scan a repository by collecting files and sending them to the API
 */
export declare function scan(params: {
    repoPath: string;
    frameworks?: string[];
    options?: ScanOptions;
}): Promise<{
    passed: boolean;
    exitCode: number;
    findings: never[];
    report: null;
    summary?: undefined;
} | {
    passed: any;
    exitCode: number;
    findings: any;
    report: any;
    summary: any;
}>;
/**
 * Gate code strings directly without writing to disk
 */
export declare function gate(options: GateOptions): Promise<{
    passed: any;
    exitCode: number;
    findings: any;
    prompt: any;
    summary: any;
}>;
/**
 * Run local hook
 */
export declare function runHook(params: {
    frameworks?: string[];
    filePath?: string;
}): Promise<number>;
/**
 * Run API hook
 */
export declare function runHookApi(params: {
    apiUrl?: string;
    apiKey?: string;
    frameworks?: string[];
}): Promise<number>;
