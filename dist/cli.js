#!/usr/bin/env node
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const commander_1 = require("commander");
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const index_1 = require("./index");
const program = new commander_1.Command();
program
    .name('compliance-code-scanner')
    .description('Multi-framework policy-as-code compliance scanner for infrastructure and application code.')
    .version('0.1.0')
    .argument('[repo_path]', 'Path to the repository to scan', '.')
    .option('--framework <ids>', 'Comma-separated framework IDs to evaluate', 'soc2')
    .option('--format <format>', 'Output format: json, sarif, table, prompt', 'table')
    .option('--severity-threshold <severity>', 'Minimum severity to include in report', 'low')
    .option('--fail-on <levels>', 'Comma-separated severities that cause non-zero exit', 'critical,high')
    .option('--include <patterns>', 'Comma-separated glob patterns to include')
    .option('--exclude <patterns>', 'Comma-separated glob patterns to exclude')
    .option('--output <file>', 'Write report to file')
    .option('--api-url <url>', 'Compliance API base URL (or PC_API_URL env)')
    .option('--api-key <key>', 'API key for compliance API (or PC_API_KEY env)')
    .option('--hook', 'Run as coding agent post-edit hook (reads stdin)')
    .option('--hook-file <path>', 'File path for hook mode (alternative to stdin)')
    .option('--hook-api', 'Run as API-based hook (calls hosted compliance API)')
    .option('--init', 'Set up compliance hooks for coding agents')
    .option('--agent <agents>', 'Comma-separated agents to configure')
    .action(async (repoPath, opts) => {
    try {
        if (opts.hook || opts.hookApi) {
            // Implement hook logic here
            console.log('Hook mode executed.');
            process.exit(0);
        }
        if (opts.init) {
            // Implement init logic here
            console.log('Init mode executed.');
            process.exit(0);
        }
        const frameworks = opts.framework.split(',').map((s) => s.trim());
        const failOn = opts.failOn.split(',').map((s) => s.trim());
        const include = opts.include ? opts.include.split(',') : undefined;
        const exclude = opts.exclude ? opts.exclude.split(',') : undefined;
        console.log(`Scanning ${path.resolve(repoPath)} for ${frameworks.join(', ')}...`);
        const response = await (0, index_1.scan)({
            repoPath,
            frameworks,
            options: {
                severityThreshold: opts.severityThreshold,
                failOn,
                include,
                exclude,
                apiUrl: opts.apiUrl,
                apiKey: opts.apiKey,
            }
        });
        if (opts.format === 'json') {
            const output = JSON.stringify(response, null, 2);
            if (opts.output) {
                fs.writeFileSync(opts.output, output);
            }
            else {
                console.log(output);
            }
        }
        else {
            console.log(`Passed: ${response.passed}`);
            console.log(`Findings: ${response.findings.length}`);
        }
        process.exit(response.exitCode);
    }
    catch (error) {
        console.error(`\u2717 Error: ${error.message}`);
        process.exit(2);
    }
});
program.parse();
