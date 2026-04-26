"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatTable = formatTable;
const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
function sevRank(s) {
    const i = SEVERITY_ORDER.indexOf((s ?? '').toLowerCase());
    return i === -1 ? SEVERITY_ORDER.length : i;
}
function formatTable(report) {
    const r = (report ?? {});
    const findings = r.findings ?? [];
    if (findings.length === 0) {
        return r.passed === false ? 'Scan failed but no findings returned.' : '\u2713 No compliance violations found.';
    }
    const sorted = [...findings].sort((a, b) => sevRank(a.severity) - sevRank(b.severity));
    const counts = new Map();
    for (const f of findings) {
        const sev = (f.severity ?? 'unknown').toLowerCase();
        counts.set(sev, (counts.get(sev) ?? 0) + 1);
    }
    const lines = [];
    lines.push(`Findings: ${findings.length}`);
    const summaryParts = SEVERITY_ORDER.filter((s) => counts.has(s)).map((s) => `${counts.get(s)} ${s}`);
    if (summaryParts.length > 0)
        lines.push(`  ${summaryParts.join(', ')}`);
    lines.push('');
    for (const f of sorted) {
        const sev = (f.severity ?? 'unknown').toUpperCase().padEnd(8);
        const rule = f.rule_id ?? f.ruleId ?? '';
        const loc = locOf(f);
        const title = f.title ?? f.message ?? f.description ?? '';
        lines.push(`  [${sev}] ${rule}  ${title}`);
        if (loc)
            lines.push(`            ${loc}`);
    }
    return lines.join('\n');
}
function locOf(f) {
    const file = f.file ?? f.path;
    if (!file)
        return '';
    return f.line ? `${file}:${f.line}` : file;
}
