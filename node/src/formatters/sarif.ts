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
  end_line?: number;
  endLine?: number;
  framework?: string;
}

interface ScanLikeResponse {
  findings?: Finding[];
}

/**
 * SARIF 2.1.0 level mapping for compliance severities.
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
 */
function sarifLevel(sev?: string): 'error' | 'warning' | 'note' {
  const s = (sev ?? '').toLowerCase();
  if (s === 'critical' || s === 'high') return 'error';
  if (s === 'medium') return 'warning';
  return 'note';
}

export function formatSarif(report: unknown): object {
  const r = (report ?? {}) as ScanLikeResponse;
  const findings = r.findings ?? [];

  const rulesById = new Map<string, object>();
  const results = findings.map((f) => {
    const ruleId = f.rule_id ?? f.ruleId ?? 'unknown';
    if (!rulesById.has(ruleId)) {
      rulesById.set(ruleId, {
        id: ruleId,
        name: ruleId,
        shortDescription: { text: f.title ?? ruleId },
        ...(f.description ? { fullDescription: { text: f.description } } : {}),
      });
    }

    const file = f.file ?? f.path ?? '';
    const startLine = f.line;
    const endLine = f.end_line ?? f.endLine;

    return {
      ruleId,
      level: sarifLevel(f.severity),
      message: { text: f.message ?? f.title ?? ruleId },
      ...(file
        ? {
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: file },
                  ...(startLine
                    ? {
                        region: {
                          startLine,
                          ...(endLine ? { endLine } : {}),
                        },
                      }
                    : {}),
                },
              },
            ],
          }
        : {}),
    };
  });

  return {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'ProdCycle Compliance Scanner',
            informationUri: 'https://docs.prodcycle.com',
            rules: [...rulesById.values()],
          },
        },
        results,
      },
    ],
  };
}
