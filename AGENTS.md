# Agent Guidelines for compliance-code-scanner

## Project Overview

This is the npm CLI wrapper package (`@prodcycle/compliance-code-scanner`) that scans repositories for SOC 2, HIPAA, and NIST CSF compliance violations via the ProdCycle REST API. It acts as a lightweight Node.js client (using Commander) connecting to `https://api.prodcycle.com/v1/compliance/validate` and `https://api.prodcycle.com/v1/compliance/hook`.

## Architecture

```
src/
  cli.ts          # CLI Entry point: parses inputs using Commander
  index.ts        # Programmatic Node.js API (scan(), gate(), runHook())
  api-client.ts   # Calls POST /v1/compliance/validate and /v1/compliance/hook
  utils/
    fs.ts         # File collection using glob and limits (256 KB max per file, 500 files max)
  formatters/     # Output transformation (table, sarif, prompt)
dist/             # Compiled TypeScript output
```

## Key Commands

- `npm run build` — compile TypeScript into `dist/`
- `npm publish` — build and publish package to npm

## Critical Rules

### Private vs Public Package
This package is intended to be published publicly on npm, therefore it must NOT contain any proprietary OPA/Rego policies. All actual evaluation happens server-side on the ProdCycle API.

### File collection constraints

In `src/utils/fs.ts`, scanned files are subject to:

- **256 KB per-file limit** — files larger than this are silently skipped to respect the backend API limit
- **500 file cap** — remaining files beyond this are skipped with a warning
- **Binary skipping** — basic heuristic to skip non-text files

### Error handling in the API client

- The client must throw an actionable error if `PC_API_KEY` is missing or invalid.
- The ProdCycle API handles rate limiting and payload validation, the CLI should bubble these errors up gracefully.

### Testing

*(Tests to be implemented using Vitest/Jest mocking the global fetch)*
