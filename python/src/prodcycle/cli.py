import argparse
import json
import os
import sys

from prodcycle import scan, gate
from prodcycle.formatters.table import format_table
from prodcycle.formatters.sarif import format_sarif
from prodcycle.formatters.prompt import format_prompt

KNOWN_COMMANDS = {'scan', 'gate', 'hook', 'init', 'help', '--help', '-h', '--version', '-V'}


def _inject_scan_default(argv):
    """Back-compat: `prodcycle .` used to scan the current directory with no
    subcommand. Preserve that behavior by injecting `scan` when the first arg
    isn't a known subcommand or a global flag."""
    args = argv[1:]
    if not args:
        return [argv[0], 'scan']
    if args[0] in KNOWN_COMMANDS:
        return argv
    return [argv[0], 'scan', *args]


def _parse_list(val):
    if not val:
        return None
    return [s.strip() for s in val.split(',') if s.strip()]


def _render(response, fmt):
    if fmt == 'json':
        return json.dumps(response, indent=2, default=str)
    if fmt == 'sarif':
        return json.dumps(format_sarif(response), indent=2, default=str)
    if fmt == 'prompt':
        return format_prompt(response)
    return format_table(response)


def _write_output(text, out_file):
    if out_file:
        with open(out_file, 'w') as f:
            f.write(text)
    else:
        if not text.endswith('\n'):
            text = text + '\n'
        sys.stdout.write(text)


def _add_common_scan_args(parser):
    parser.add_argument('--framework', default='soc2', help='Comma-separated framework IDs to evaluate')
    parser.add_argument('--format', default='table', help='Output format: json, sarif, table, prompt')
    parser.add_argument('--severity-threshold', default='low', help='Minimum severity to include in report')
    parser.add_argument('--fail-on', default='critical,high', help='Comma-separated severities that cause non-zero exit')
    parser.add_argument('--include', help='Comma-separated glob patterns to include')
    parser.add_argument('--exclude', help='Comma-separated glob patterns to exclude')
    parser.add_argument('--output', help='Write report to file')
    parser.add_argument('--api-url', help='Compliance API base URL (or PC_API_URL env)')
    parser.add_argument('--api-key', help='API key for compliance API (or PC_API_KEY env)')


def _cmd_scan(args):
    repo_path = args.repo_path or '.'
    frameworks = _parse_list(args.framework) or ['soc2']
    fail_on = _parse_list(args.fail_on) or ['critical', 'high']
    fmt = args.format or 'table'

    print(f"Scanning {os.path.abspath(repo_path)} for {', '.join(frameworks)}...", file=sys.stderr)

    response = scan(
        repo_path=repo_path,
        frameworks=frameworks,
        options={
            'severityThreshold': args.severity_threshold,
            'failOn': fail_on,
            'include': _parse_list(args.include),
            'exclude': _parse_list(args.exclude),
            'apiUrl': args.api_url,
            'apiKey': args.api_key,
        },
    )

    _write_output(_render(response, fmt), args.output)
    sys.exit(response.get('exitCode', 1))


def _cmd_gate(args):
    frameworks = _parse_list(args.framework) or ['soc2']
    fmt = args.format or 'prompt'

    if sys.stdin.isatty():
        print('gate: no input on stdin. Expected JSON payload: {"files": {...}}', file=sys.stderr)
        sys.exit(2)

    raw = sys.stdin.read()
    if not raw.strip():
        print('gate: empty stdin', file=sys.stderr)
        sys.exit(2)

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f'gate: invalid JSON on stdin: {e}', file=sys.stderr)
        sys.exit(2)

    files = payload.get('files') if isinstance(payload, dict) else None
    if not isinstance(files, dict):
        print('gate: payload must include a "files" object of {path: content}', file=sys.stderr)
        sys.exit(2)

    response = gate(
        files=files,
        frameworks=frameworks,
        api_url=args.api_url,
        api_key=args.api_key,
    )

    _write_output(_render(response, fmt), args.output)
    sys.exit(response.get('exitCode', 1))


def _cmd_hook(_args):
    print(
        'prodcycle hook: not yet implemented. '
        'Use `prodcycle gate` to POST a JSON {"files":{...}} payload against the hook endpoint.',
        file=sys.stderr,
    )
    sys.exit(2)


def _cmd_init(_args):
    print(
        'prodcycle init: not yet implemented. '
        'Manual setup: configure your agent to pipe its post-edit file to `prodcycle gate`.',
        file=sys.stderr,
    )
    sys.exit(2)


def main():
    argv = _inject_scan_default(sys.argv)

    parser = argparse.ArgumentParser(
        prog='prodcycle',
        description='Multi-framework policy-as-code compliance scanner for infrastructure and application code.',
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    # scan
    p_scan = subparsers.add_parser('scan', help='Scan a repository for compliance violations')
    p_scan.add_argument('repo_path', nargs='?', default='.', help='Path to the repository to scan')
    _add_common_scan_args(p_scan)
    p_scan.set_defaults(func=_cmd_scan)

    # gate
    p_gate = subparsers.add_parser('gate', help='Evaluate a JSON payload of files from stdin')
    p_gate.add_argument('--framework', default='soc2', help='Comma-separated framework IDs to evaluate')
    p_gate.add_argument('--format', default='prompt', help='Output format: json, sarif, table, prompt')
    p_gate.add_argument('--output', help='Write report to file')
    p_gate.add_argument('--api-url', help='Compliance API base URL (or PC_API_URL env)')
    p_gate.add_argument('--api-key', help='API key for compliance API (or PC_API_KEY env)')
    p_gate.set_defaults(func=_cmd_gate)

    # hook
    p_hook = subparsers.add_parser('hook', help='Run as coding-agent post-edit hook (reads stdin)')
    p_hook.add_argument('--framework', default='soc2')
    p_hook.add_argument('--file', help='File path for hook mode (alternative to stdin)')
    p_hook.set_defaults(func=_cmd_hook)

    # init
    p_init = subparsers.add_parser('init', help='Configure compliance hooks for coding agents')
    p_init.add_argument('--agent', help='Comma-separated agents to configure (claude, cursor, ...)')
    p_init.set_defaults(func=_cmd_init)

    args = parser.parse_args(argv[1:])

    try:
        args.func(args)
    except SystemExit:
        raise
    except Exception as e:
        print(f"\u2717 Error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == '__main__':
    main()
