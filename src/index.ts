import { ComplianceApiClient, ScanOptions, GateOptions } from './api-client';
import { collectFiles } from './utils/fs';

export * from './api-client';
export * from './formatters/table';
export * from './formatters/prompt';
export * from './formatters/sarif';

/**
 * Scan a repository by collecting files and sending them to the API
 */
export async function scan(params: {
  repoPath: string;
  frameworks?: string[];
  options?: ScanOptions;
}) {
  const { repoPath, frameworks = ['soc2'], options = {} } = params;
  
  // Collect files
  const files = await collectFiles(repoPath, options.include, options.exclude);
  
  if (Object.keys(files).length === 0) {
    return {
      passed: true,
      exitCode: 0,
      findings: [],
      report: null
    };
  }

  const client = new ComplianceApiClient(options.apiUrl, options.apiKey);
  const response = await client.validate(files, frameworks, options);
  
  return {
    passed: response.passed,
    exitCode: response.passed ? 0 : 1,
    findings: response.findings || [],
    report: response.report, // The API should return the full report object if requested, or we synthesize it
    summary: response.summary
  };
}

/**
 * Gate code strings directly without writing to disk
 */
export async function gate(options: GateOptions) {
  const { files, frameworks = ['soc2'], ...scanOpts } = options;
  
  const client = new ComplianceApiClient(options.apiUrl, options.apiKey);
  const response = await client.hook(files, frameworks);
  
  return {
    passed: response.passed,
    exitCode: response.passed ? 0 : 1,
    findings: response.findings || [],
    prompt: response.prompt,
    summary: response.summary
  };
}

/**
 * Run local hook
 */
export async function runHook(params: { frameworks?: string[]; filePath?: string }) {
  // Logic to read stdin or specific file and call gate
  const { frameworks = ['soc2'], filePath } = params;
  
  // Implementation details...
  return 0;
}

/**
 * Run API hook
 */
export async function runHookApi(params: { apiUrl?: string; apiKey?: string; frameworks?: string[] }) {
  // Implementation details...
  return 0;
}
