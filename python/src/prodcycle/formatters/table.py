SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info']


def _sev_rank(s):
    try:
        return SEVERITY_ORDER.index((s or '').lower())
    except ValueError:
        return len(SEVERITY_ORDER)


def _loc(f):
    file_ = f.get('file') or f.get('path')
    if not file_:
        return ''
    line = f.get('line')
    return f"{file_}:{line}" if line else file_


def format_table(report):
    if not report:
        return 'No report data'

    findings = report.get('findings', []) if isinstance(report, dict) else []

    if not findings:
        if isinstance(report, dict) and report.get('passed') is False:
            return 'Scan failed but no findings returned.'
        return '\u2713 No compliance violations found.'

    sorted_findings = sorted(findings, key=lambda f: _sev_rank(f.get('severity')))

    counts = {}
    for f in findings:
        sev = (f.get('severity') or 'unknown').lower()
        counts[sev] = counts.get(sev, 0) + 1

    lines = [f"Findings: {len(findings)}"]
    summary_parts = [f"{counts[s]} {s}" for s in SEVERITY_ORDER if s in counts]
    if summary_parts:
        lines.append('  ' + ', '.join(summary_parts))
    lines.append('')

    for f in sorted_findings:
        sev = (f.get('severity') or 'unknown').upper().ljust(8)
        rule = f.get('rule_id') or f.get('ruleId') or ''
        loc = _loc(f)
        title = f.get('title') or f.get('message') or f.get('description') or ''
        lines.append(f"  [{sev}] {rule}  {title}")
        if loc:
            lines.append(f"            {loc}")

    return '\n'.join(lines)
