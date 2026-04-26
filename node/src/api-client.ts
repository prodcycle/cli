import * as crypto from 'crypto';

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
 * Server-side recommendation returned in 413 details when /validate is too
 * large. The CLI uses this to decide whether to auto-fall-back to the
 * chunked-session endpoint (Phase 1d on the server).
 */
interface PayloadTooLargeDetails {
  maxBytes?: number;
  maxFiles?: number;
  receivedBytes?: number;
  receivedFiles?: number;
  chunkSizeBytes?: number;
  suggestedEndpoint?: string;
}

interface ApiError extends Error {
  status?: number;
  retryAfter?: number;
  details?: PayloadTooLargeDetails | undefined;
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
export class ComplianceApiClient {
  private apiUrl: string;
  private apiKey: string;
  private retryOptions: Required<RetryOptions>;
  private chunkConcurrency: number;

  constructor(
    apiUrl?: string,
    apiKey?: string,
    options: { retry?: RetryOptions; chunkConcurrency?: number } = {},
  ) {
    this.apiUrl = apiUrl || process.env.PC_API_URL || 'https://api.prodcycle.com';
    this.apiKey = apiKey || process.env.PC_API_KEY || '';
    this.retryOptions = {
      maxAttempts: options.retry?.maxAttempts ?? 4,
      initialDelayMs: options.retry?.initialDelayMs ?? 500,
      maxDelayMs: options.retry?.maxDelayMs ?? 30_000,
      backoffMultiplier: options.retry?.backoffMultiplier ?? 2,
    };
    this.chunkConcurrency = options.chunkConcurrency ?? 4;

    if (!this.apiKey && process.env.NODE_ENV !== 'test') {
      console.warn('Warning: PC_API_KEY is not set. API calls will likely fail.');
    }
  }

  /**
   * Run a CI/PR validation scan. Auto-falls-back to the chunked-session
   * path (`POST /v1/compliance/scans`) when the request is too large for
   * the single-payload `/validate` endpoint — the server tells us so via
   * a 413 with `suggestedEndpoint: '/v1/compliance/scans'` (Phase 1c).
   */
  async validate(
    files: Record<string, string>,
    frameworks: string[],
    options: ScanOptions = {},
  ): Promise<ScanApiResponse> {
    try {
      return (await this.post('/v1/compliance/validate', {
        files,
        frameworks,
        options: {
          severity_threshold: options.severityThreshold,
          fail_on: options.failOn,
          ...options.config,
        },
      })) as ScanApiResponse;
    } catch (err) {
      const apiErr = err as ApiError;
      if (apiErr.status === 413 && apiErr.details?.suggestedEndpoint === '/v1/compliance/scans') {
        // Server says: too big for /validate, use chunked. Honor its size hint.
        const chunked = await this.scanChunked(files, frameworks, options, {
          chunkSizeBytes: apiErr.details.chunkSizeBytes,
          maxFilesPerChunk: apiErr.details.maxFiles,
        });
        return {
          passed: chunked.passed,
          findingsCount: chunked.findingsCount,
          findings: chunked.findings,
          summary: chunked.summary,
          scanId: chunked.scanId,
        };
      }
      throw err;
    }
  }

  /**
   * Coding agent file-write hook. Single-payload only — agents send 1
   * file at a time, so chunking would be pure overhead.
   */
  async hook(
    files: Record<string, string>,
    frameworks: string[],
    options: ScanOptions = {},
  ): Promise<ScanApiResponse> {
    return (await this.post('/v1/compliance/hook', {
      files,
      frameworks,
      options: {
        severity_threshold: options.severityThreshold,
        fail_on: options.failOn,
        ...options.config,
      },
    })) as ScanApiResponse;
  }

  /**
   * Run a scan via the chunked-session endpoint. Splits files into chunks
   * sized for the server's `/validate` cap, uploads them with bounded
   * concurrency, and finalizes. Returns a shape compatible with `/validate`
   * so callers don't need to special-case.
   */
  async scanChunked(
    files: Record<string, string>,
    frameworks: string[],
    options: ScanOptions = {},
    serverHints: { chunkSizeBytes?: number | undefined; maxFilesPerChunk?: number | undefined } = {},
  ): Promise<ChunkedScanResult> {
    // Step 1 — open the session. The server returns its own recommended
    // chunk size; trust it over the 413 hint if present (it knows the
    // current /chunks cap exactly).
    const session = (await this.post('/v1/compliance/scans', {
      frameworks,
      options: {
        severity_threshold: options.severityThreshold,
        fail_on: options.failOn,
        ...options.config,
      },
    })) as { scanId: string; chunkSizeBytes: number; maxFilesPerChunk: number };

    const chunkBytes = serverHints.chunkSizeBytes ?? session.chunkSizeBytes ?? 5 * 1024 * 1024;
    const chunkFiles = serverHints.maxFilesPerChunk ?? session.maxFilesPerChunk ?? 200;

    // Step 2 — split the file map into chunks bounded by both byte size
    // and file count.
    const chunks = splitIntoChunks(files, chunkBytes, chunkFiles);

    // Step 3 — upload chunks with bounded concurrency. Each chunk POST
    // benefits from the server's per-content findings cache (Phase 1d):
    // unchanged files re-scanned across runs return cached verdicts in
    // milliseconds without invoking OPA.
    let totalCachedFiles = 0;
    let totalScannedFiles = 0;
    const allFindings: unknown[] = [];

    await runWithConcurrency(this.chunkConcurrency, chunks, async (chunk) => {
      const chunkResult = (await this.post(
        `/v1/compliance/scans/${session.scanId}/chunks`,
        { files: chunk },
      )) as ChunkResponse;
      totalCachedFiles += chunkResult.cachedFiles ?? 0;
      totalScannedFiles += chunkResult.scannedFiles ?? 0;
      if (Array.isArray(chunkResult.chunkFindings)) {
        allFindings.push(...chunkResult.chunkFindings);
      }
    });

    // Step 4 — finalize. Server flips status to COMPLETED, computes the
    // summary, and triggers reconcile against the previous scan.
    const finalResult = (await this.post(
      `/v1/compliance/scans/${session.scanId}/complete`,
      {},
    )) as { passed: boolean; findingsCount: number; summary: unknown; durationMs: number };

    return {
      scanId: session.scanId,
      passed: finalResult.passed,
      findingsCount: finalResult.findingsCount,
      findings: allFindings,
      summary: finalResult.summary,
      durationMs: finalResult.durationMs,
      cachedFiles: totalCachedFiles,
      scannedFiles: totalScannedFiles,
    };
  }

  /**
   * Compute the SHA-256 of file content. Exposed so callers can pre-hash
   * locally and decide what to send (e.g. skip files whose hash hasn't
   * changed since the last scan). The server's per-content cache uses
   * the same algorithm, so a hit on the client-side cache is a hit on
   * the server-side cache.
   */
  static sha256(content: string): string {
    return crypto.createHash('sha256').update(content, 'utf8').digest('hex');
  }

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
  private async post(endpoint: string, data: unknown): Promise<unknown> {
    const url = `${this.apiUrl}${endpoint}`;
    let attempt = 0;
    let delay = this.retryOptions.initialDelayMs;

    while (true) {
      attempt++;
      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${this.apiKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(data),
        });

        if (response.ok) {
          return await unwrapEnvelope(response);
        }

        // Non-2xx — decide whether to retry or throw.
        const errorBody = await safeReadJson(response);
        const apiError = buildApiError(response, errorBody);

        const isRetryable = response.status === 429 || response.status === 503;
        if (!isRetryable || attempt >= this.retryOptions.maxAttempts) {
          throw apiError;
        }

        // Honor Retry-After if the server gave us one; otherwise use
        // exponential backoff with full jitter.
        const retryAfterHeader = response.headers.get('retry-after');
        const waitMs = retryAfterHeader
          ? parseRetryAfterMs(retryAfterHeader)
          : jitteredBackoff(delay);
        await sleep(waitMs);
        delay = Math.min(delay * this.retryOptions.backoffMultiplier, this.retryOptions.maxDelayMs);
      } catch (err) {
        const apiErr = err as ApiError;
        // ApiError from above (status set) — already decided not to retry.
        if (apiErr.status !== undefined) {
          throw apiErr;
        }

        // Network error (fetch threw before getting a response).
        if (attempt >= this.retryOptions.maxAttempts) {
          throw new Error(
            `Failed to connect to ProdCycle API at ${url}: ${apiErr.message}`,
          );
        }
        await sleep(jitteredBackoff(delay));
        delay = Math.min(delay * this.retryOptions.backoffMultiplier, this.retryOptions.maxDelayMs);
      }
    }
  }
}

// =============================================================================
// SUPPORTING TYPES
// =============================================================================

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

interface ChunkResponse {
  scanId: string;
  cachedFiles: number;
  scannedFiles: number;
  chunkFindings: unknown[];
  totals: { files: number; findings: number };
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

// =============================================================================
// HELPERS (unexported — kept module-local to avoid bloating the public API)
// =============================================================================

/**
 * Split a file map into chunks bounded by total byte size AND file count.
 * Files larger than `maxBytes` are placed in their own chunk (the server
 * will 413 them with a per-file size error — surfacing that at the
 * server boundary keeps client logic simple).
 */
export function splitIntoChunks(
  files: Record<string, string>,
  maxBytes: number,
  maxFiles: number,
): Record<string, string>[] {
  const chunks: Record<string, string>[] = [];
  let current: Record<string, string> = {};
  let currentBytes = 0;
  let currentCount = 0;

  for (const [path, content] of Object.entries(files)) {
    const fileBytes = Buffer.byteLength(content, 'utf8');

    // Pre-check — if adding this file would push the chunk over either cap,
    // close the current chunk first.
    if (
      (currentBytes + fileBytes > maxBytes && currentCount > 0) ||
      currentCount >= maxFiles
    ) {
      chunks.push(current);
      current = {};
      currentBytes = 0;
      currentCount = 0;
    }

    current[path] = content;
    currentBytes += fileBytes;
    currentCount += 1;
  }

  if (currentCount > 0) chunks.push(current);
  return chunks;
}

/**
 * Run an async task over each item with at most `concurrency` workers
 * in flight. Errors propagate; remaining tasks are abandoned (the
 * server-side session expires via TTL — no client-side cleanup needed).
 */
export async function runWithConcurrency<T>(
  concurrency: number,
  items: T[],
  fn: (item: T) => Promise<void>,
): Promise<void> {
  let cursor = 0;
  const workers: Promise<void>[] = [];
  const next = async (): Promise<void> => {
    while (cursor < items.length) {
      const i = cursor++;
      await fn(items[i]!);
    }
  };
  for (let i = 0; i < Math.max(1, Math.min(concurrency, items.length)); i++) {
    workers.push(next());
  }
  await Promise.all(workers);
}

/**
 * Parse the `Retry-After` HTTP header. Per RFC 7231 it can be either a
 * delta-seconds integer or an HTTP-date. We only handle the integer form
 * because the API never emits HTTP-date Retry-After.
 */
function parseRetryAfterMs(header: string): number {
  const seconds = parseInt(header, 10);
  if (!isNaN(seconds) && seconds >= 0) return seconds * 1000;
  return 1000; // sensible fallback
}

/** Full-jitter exponential backoff (AWS recommended pattern). */
function jitteredBackoff(baseMs: number): number {
  return Math.floor(Math.random() * baseMs);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function safeReadJson(response: Response): Promise<Record<string, unknown> | null> {
  try {
    return (await response.json()) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/**
 * Build a structured ApiError carrying status, Retry-After, and the
 * server's `error.details` blob (used by the validate→chunked fallback).
 */
function buildApiError(response: Response, body: Record<string, unknown> | null): ApiError {
  const errorObj =
    body && typeof body === 'object' && body['error'] && typeof body['error'] === 'object'
      ? (body['error'] as Record<string, unknown>)
      : undefined;
  const message =
    (errorObj?.['message'] as string | undefined) ||
    `API request failed with status ${response.status}`;
  const err = new Error(message) as ApiError;
  err.status = response.status;
  const retryAfterHeader = response.headers.get('retry-after');
  if (retryAfterHeader) {
    err.retryAfter = parseRetryAfterMs(retryAfterHeader) / 1000;
  }
  if (errorObj?.['details'] && typeof errorObj['details'] === 'object') {
    err.details = errorObj['details'] as PayloadTooLargeDetails;
  }
  return err;
}

/**
 * Unwrap the `{status, statusCode, data, error}` ApiResponse envelope. The
 * inner `data` is what the caller actually wants; we keep the unwrap so
 * the CLI doesn't need to know about the envelope shape. Falls through
 * to the bare body for older deployments that don't wrap.
 */
async function unwrapEnvelope(response: Response): Promise<unknown> {
  const body = (await response.json()) as unknown;
  if (
    body &&
    typeof body === 'object' &&
    'data' in body &&
    'status' in body &&
    (body as { status: unknown }).status === 'success'
  ) {
    return (body as { data: unknown }).data;
  }
  return body;
}
