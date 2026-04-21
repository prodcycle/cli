#!/usr/bin/env node

import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import { scan, gate } from './index';
import { formatTable } from './formatters/table';
import { formatSarif } from './formatters/sarif';
import { formatPrompt } from './formatters/prompt';

type Format = 'json' | 'sarif' | 'table' | 'prompt';

const KNOWN_COMMANDS = new Set([
  'scan',
  'gate',
  'hook',
  'init',
  'help',
  '--help',
  '-h',
  '--version',
  '-V',
]);

/**
 * Back-compat shim: `prodcycle .` used to scan the current directory with no
 * subcommand. Preserve that behavior by injecting `scan` when the first arg
 * isn't a known subcommand or a global flag.
 */
function injectScanDefault(argv: string[]): string[] {
  const args = argv.slice(2);
  if (args.length === 0) return [...argv.slice(0, 2), 'scan'];
  if (KNOWN_COMMANDS.has(args[0])) return argv;
  return [...argv.slice(0, 2), 'scan', ...args];
}

function renderReport(response: unknown, format: Format): string {
  switch (format) {
    case 'json':
      return JSON.stringify(response, null, 2);
    case 'sarif':
      return JSON.stringify(formatSarif(response), null, 2);
    case 'prompt':
      return formatPrompt(response);
    case 'table':
    default:
      return formatTable(response);
  }
}

function writeOutput(text: string, outFile?: string): void {
  if (outFile) {
    fs.writeFileSync(outFile, text);
  } else {
    process.stdout.write(text.endsWith('\n') ? text : text + '\n');
  }
}

function parseList(val?: string): string[] | undefined {
  if (!val) return undefined;
  return val
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

const program = new Command();

program
  .name('prodcycle')
  .description(
    'Multi-framework policy-as-code compliance scanner for infrastructure and application code.',
  )
  .version('0.2.2');

// ── scan ────────────────────────────────────────────────────────────────────
program
  .command('scan [repo_path]')
  .description('Scan a repository for compliance violations')
  .option('--framework <ids>', 'Comma-separated framework IDs to evaluate', 'soc2')
  .option('--format <format>', 'Output format: json, sarif, table, prompt', 'table')
  .option('--severity-threshold <severity>', 'Minimum severity to include in report', 'low')
  .option(
    '--fail-on <levels>',
    'Comma-separated severities that cause non-zero exit',
    'critical,high',
  )
  .option('--include <patterns>', 'Comma-separated glob patterns to include')
  .option('--exclude <patterns>', 'Comma-separated glob patterns to exclude')
  .option('--output <file>', 'Write report to file')
  .option('--api-url <url>', 'Compliance API base URL (or PC_API_URL env)')
  .option('--api-key <key>', 'API key for compliance API (or PC_API_KEY env)')
  .action(async (repoPath: string | undefined, opts: Record<string, any>) => {
    try {
      const target = repoPath ?? '.';
      const frameworks = parseList(opts.framework) ?? ['soc2'];
      const failOn = parseList(opts.failOn) ?? ['critical', 'high'];
      const format = (opts.format ?? 'table') as Format;

      console.error(`Scanning ${path.resolve(target)} for ${frameworks.join(', ')}...`);

      const response = await scan({
        repoPath: target,
        frameworks,
        options: {
          severityThreshold: opts.severityThreshold,
          failOn: failOn as any,
          include: parseList(opts.include),
          exclude: parseList(opts.exclude),
          apiUrl: opts.apiUrl,
          apiKey: opts.apiKey,
        },
      });

      writeOutput(renderReport(response, format), opts.output);
      process.exit(response.exitCode);
    } catch (error: any) {
      console.error(`\u2717 Error: ${error.message}`);
      process.exit(2);
    }
  });

// ── gate ────────────────────────────────────────────────────────────────────
program
  .command('gate')
  .description('Evaluate a JSON payload of files from stdin (low-latency hook endpoint)')
  .option('--framework <ids>', 'Comma-separated framework IDs to evaluate', 'soc2')
  .option('--format <format>', 'Output format: json, sarif, table, prompt', 'prompt')
  .option('--output <file>', 'Write report to file')
  .option('--api-url <url>', 'Compliance API base URL (or PC_API_URL env)')
  .option('--api-key <key>', 'API key for compliance API (or PC_API_KEY env)')
  .action(async (opts: Record<string, any>) => {
    try {
      const frameworks = parseList(opts.framework) ?? ['soc2'];
      const format = (opts.format ?? 'prompt') as Format;

      const stdin = await readStdin();
      if (!stdin.trim()) {
        console.error('gate: no input on stdin. Expected JSON payload: {"files": {...}}');
        process.exit(2);
      }

      let payload: { files?: Record<string, string> };
      try {
        payload = JSON.parse(stdin);
      } catch (e: any) {
        console.error(`gate: invalid JSON on stdin: ${e.message}`);
        process.exit(2);
        return;
      }

      if (!payload.files || typeof payload.files !== 'object') {
        console.error('gate: payload must include a "files" object of {path: content}');
        process.exit(2);
        return;
      }

      const response = await gate({
        files: payload.files,
        frameworks,
        apiUrl: opts.apiUrl,
        apiKey: opts.apiKey,
      });

      writeOutput(renderReport(response, format), opts.output);
      process.exit(response.exitCode);
    } catch (error: any) {
      console.error(`\u2717 Error: ${error.message}`);
      process.exit(2);
    }
  });

// ── hook ────────────────────────────────────────────────────────────────────
program
  .command('hook')
  .description('Run as coding-agent post-edit hook (reads stdin)')
  .option('--framework <ids>', 'Comma-separated framework IDs to evaluate', 'soc2')
  .option('--file <path>', 'File path for hook mode (alternative to stdin)')
  .option('--api', 'Use hosted compliance API (default: true)', true)
  .action(() => {
    console.error(
      'prodcycle hook: not yet implemented. ' +
        'Use `prodcycle gate` to POST a JSON {files:{...}} payload against the hook endpoint.',
    );
    process.exit(2);
  });

// ── init ────────────────────────────────────────────────────────────────────
program
  .command('init')
  .description('Configure compliance hooks for coding agents')
  .option('--agent <agents>', 'Comma-separated agents to configure (claude, cursor, ...)')
  .action(() => {
    console.error(
      'prodcycle init: not yet implemented. ' +
        'Manual setup: configure your agent to pipe its post-edit file to `prodcycle gate`.',
    );
    process.exit(2);
  });

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    if (process.stdin.isTTY) {
      resolve('');
      return;
    }
    const chunks: Buffer[] = [];
    process.stdin.on('data', (c) => chunks.push(c));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', reject);
  });
}

program.parse(injectScanDefault(process.argv));
