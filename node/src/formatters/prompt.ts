interface Finding {
  severity?: string;
  rule_id?: string;
  ruleId?: string;
  title?: string;
  message?: string;
  description?: string;
  file?: string;
  path?: string;
  line?: number;
  framework?: string;
}

interface PromptLikeResponse {
  passed?: boolean;
  findings?: Finding[];
  prompt?: string;
}

/**
 * Render a coding-agent-oriented prompt describing findings. If the server
 * returned a pre-built `prompt` field (hook endpoint), prefer that.
 */
export function formatPrompt(report: unknown): string {
  const r = (report ?? {}) as PromptLikeResponse;
  if (typeof r.prompt === 'string' && r.prompt.trim()) return r.prompt;

  const findings = r.findings ?? [];
  if (findings.length === 0) return 'No compliance violations detected.';

  const lines: string[] = [];
  lines.push(`Compliance scan found ${findings.length} violation(s) that need to be addressed:`);
  lines.push('');
  for (const f of findings) {
    const sev = (f.severity ?? 'unknown').toUpperCase();
    const rule = f.rule_id ?? f.ruleId ?? 'unknown';
    const loc = locOf(f);
    const title = f.title ?? f.message ?? '';
    lines.push(`- [${sev}] ${rule}${loc ? ` (${loc})` : ''}: ${title}`);
    if (f.description && f.description !== title) {
      lines.push(`    ${f.description}`);
    }
  }
  lines.push('');
  lines.push('Please update the code to resolve these issues before continuing.');
  return lines.join('\n');
}

function locOf(f: Finding): string {
  const file = f.file ?? f.path;
  if (!file) return '';
  return f.line ? `${file}:${f.line}` : file;
}
