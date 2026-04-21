def _loc(f):
    file_ = f.get('file') or f.get('path')
    if not file_:
        return ''
    line = f.get('line')
    return f"{file_}:{line}" if line else file_


def format_prompt(report):
    """Render a coding-agent-oriented prompt describing findings. If the
    server returned a pre-built `prompt` field (hook endpoint), prefer that.
    """
    if not report:
        return ''

    if isinstance(report, dict):
        prebuilt = report.get('prompt')
        if isinstance(prebuilt, str) and prebuilt.strip():
            return prebuilt

    findings = report.get('findings', []) if isinstance(report, dict) else []
    if not findings:
        return 'No compliance violations detected.'

    lines = [f"Compliance scan found {len(findings)} violation(s) that need to be addressed:", '']
    for f in findings:
        sev = (f.get('severity') or 'unknown').upper()
        rule = f.get('rule_id') or f.get('ruleId') or 'unknown'
        loc = _loc(f)
        title = f.get('title') or f.get('message') or ''
        suffix = f" ({loc})" if loc else ''
        lines.append(f"- [{sev}] {rule}{suffix}: {title}")
        desc = f.get('description')
        if desc and desc != title:
            lines.append(f"    {desc}")
    lines.append('')
    lines.append('Please update the code to resolve these issues before continuing.')
    return '\n'.join(lines)
