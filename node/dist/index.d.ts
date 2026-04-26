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
    passed: boolean;
    exitCode: number;
    findings: unknown[];
    report: unknown;
    summary: unknown;
}>;
/**
 * Gate code strings directly without writing to disk
 */
export declare function gate(options: GateOptions): Promise<{
    passed: boolean;
    exitCode: number;
    findings: unknown[];
    prompt: string | undefined;
    summary: unknown;
}>;
