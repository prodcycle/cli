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
/**
 * ComplianceApiClient — thin client for the ProdCycle compliance API.
 *
 * Phase 2b additions:
 *
 *   1. Per-file content hashing — `sha256(content)` is computed locally so
 *      the server-side cache can return prior verdicts without re-running
 *      OPA.
 *   2. Chunked scan sessions — when `/validate` returns 413 with
 *      `suggestedEndpoint: '/v1/compliance/scans'`, the client transparently
 *      opens a session, splits the file map into chunks of the
 *      server-recommended size, uploads them with bounded concurrency, and
 *      finalizes. The caller sees the same response shape as a one-shot
 *      `/validate`.
 *   3. Exponential backoff on 429 / 503 — honors `Retry-After` when
 *      present, otherwise uses jittered exponential backoff. Configurable
 *      via `RetryOptions`.
 *
 * No proprietary policy code ships with the CLI — all evaluation happens
 * server-side. The client only walks files and posts them.
 */
export declare class ComplianceApiClient {
    private apiUrl;
    private apiKey;
    private retryOptions;
    private chunkConcurrency;
    constructor(apiUrl?: string, apiKey?: string, options?: {
        retry?: RetryOptions;
        chunkConcurrency?: number;
    });
    /**
     * Run a CI/PR validation scan. Auto-falls-back to the chunked-session
     * path (`POST /v1/compliance/scans`) when the request is too large for
     * the single-payload `/validate` endpoint — the server tells us so via
     * a 413 with `suggestedEndpoint: '/v1/compliance/scans'` (Phase 1c).
     */
    validate(files: Record<string, string>, frameworks: string[], options?: ScanOptions): Promise<ScanApiResponse>;
    /**
     * Coding agent file-write hook. Single-payload only — agents send 1
     * file at a time, so chunking would be pure overhead.
     */
    hook(files: Record<string, string>, frameworks: string[], options?: ScanOptions): Promise<ScanApiResponse>;
    /**
     * Run a scan via the chunked-session endpoint. Splits files into chunks
     * sized for the server's `/validate` cap, uploads them with bounded
     * concurrency, and finalizes. Returns a shape compatible with `/validate`
     * so callers don't need to special-case.
     */
    scanChunked(files: Record<string, string>, frameworks: string[], options?: ScanOptions, serverHints?: {
        chunkSizeBytes?: number | undefined;
        maxFilesPerChunk?: number | undefined;
    }): Promise<ChunkedScanResult>;
    /**
     * Compute the SHA-256 of file content. Exposed so callers can pre-hash
     * locally and decide what to send (e.g. skip files whose hash hasn't
     * changed since the last scan). The server's per-content cache uses
     * the same algorithm, so a hit on the client-side cache is a hit on
     * the server-side cache.
     */
    static sha256(content: string): string;
    /**
     * Internal POST with retry/backoff on transient errors.
     *
     * Retries:
     *   - 429 Too Many Requests — honor `Retry-After` header if present
     *   - 503 Service Unavailable — same
     *   - Network errors (fetch throws) — retry with backoff
     *
     * Does NOT retry:
     *   - 4xx other than 429 — caller's bug; surface immediately
     *   - 5xx other than 503 — server bug; surface immediately
     *   - 413 Payload Too Large — caller is expected to handle this (e.g.
     *     fall back to chunked)
     */
    private post;
}
export interface RetryOptions {
    /** Total attempts including the first try. Default 4. */
    maxAttempts?: number;
    /** Backoff base (ms) for the first retry. Default 500. */
    initialDelayMs?: number;
    /** Cap on backoff (ms). Default 30000. */
    maxDelayMs?: number;
    /** Multiplier between attempts. Default 2 (full jitter applied). */
    backoffMultiplier?: number;
}
/**
 * Shape returned by /validate, /hook, and the chunked-session orchestration.
 * Every caller can rely on `passed` + `findings` + `summary` regardless of
 * which path actually ran. Extra fields like `prompt` and `report` may be
 * populated depending on the server's options.
 */
export interface ScanApiResponse {
    passed: boolean;
    findingsCount?: number;
    findings?: unknown[];
    summary?: unknown;
    prompt?: string;
    report?: unknown;
    scanId?: string;
}
export interface ChunkedScanResult {
    scanId: string;
    passed: boolean;
    findingsCount: number;
    findings: unknown[];
    summary: unknown;
    durationMs: number;
    /** Files served from the per-content cache (no OPA invocation). */
    cachedFiles: number;
    /** Files that needed a fresh OPA scan. */
    scannedFiles: number;
}
/**
 * Split a file map into chunks bounded by total byte size AND file count.
 * Files larger than `maxBytes` are placed in their own chunk (the server
 * will 413 them with a per-file size error — surfacing that at the
 * server boundary keeps client logic simple).
 */
export declare function splitIntoChunks(files: Record<string, string>, maxBytes: number, maxFiles: number): Record<string, string>[];
/**
 * Run an async task over each item with at most `concurrency` workers
 * in flight. Errors propagate; remaining tasks are abandoned (the
 * server-side session expires via TTL — no client-side cleanup needed).
 */
export declare function runWithConcurrency<T>(concurrency: number, items: T[], fn: (item: T) => Promise<void>): Promise<void>;
