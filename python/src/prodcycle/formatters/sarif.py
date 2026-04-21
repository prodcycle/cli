"""
SARIF 2.1.0 formatter.
Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
"""


def _sarif_level(sev):
    s = (sev or '').lower()
    if s in ('critical', 'high'):
        return 'error'
    if s == 'medium':
        return 'warning'
    return 'note'


def format_sarif(report):
    findings = report.get('findings', []) if isinstance(report, dict) else []

    rules_by_id = {}
    results = []

    for f in findings:
        rule_id = f.get('rule_id') or f.get('ruleId') or 'unknown'

        if rule_id not in rules_by_id:
            rule = {
                'id': rule_id,
                'name': rule_id,
                'shortDescription': {'text': f.get('title') or rule_id},
            }
            desc = f.get('description')
            if desc:
                rule['fullDescription'] = {'text': desc}
            rules_by_id[rule_id] = rule

        file_ = f.get('file') or f.get('path') or ''
        start_line = f.get('line')
        end_line = f.get('end_line') or f.get('endLine')

        result = {
            'ruleId': rule_id,
            'level': _sarif_level(f.get('severity')),
            'message': {'text': f.get('message') or f.get('title') or rule_id},
        }

        if file_:
            physical = {'artifactLocation': {'uri': file_}}
            if start_line:
                region = {'startLine': start_line}
                if end_line:
                    region['endLine'] = end_line
                physical['region'] = region
            result['locations'] = [{'physicalLocation': physical}]

        results.append(result)

    return {
        'version': '2.1.0',
        '$schema': 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        'runs': [
            {
                'tool': {
                    'driver': {
                        'name': 'ProdCycle Compliance Scanner',
                        'informationUri': 'https://docs.prodcycle.com',
                        'rules': list(rules_by_id.values()),
                    }
                },
                'results': results,
            }
        ],
    }
