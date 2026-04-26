/**
 * Render a coding-agent-oriented prompt describing findings. If the server
 * returned a pre-built `prompt` field (hook endpoint), prefer that.
 */
export declare function formatPrompt(report: unknown): string;
