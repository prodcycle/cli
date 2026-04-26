"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatSarif = formatSarif;
/**
 * SARIF 2.1.0 level mapping for compliance severities.
 * Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
 */
function sarifLevel(sev) {
    const s = (sev ?? '').toLowerCase();
    if (s === 'critical' || s === 'high')
        return 'error';
    if (s === 'medium')
        return 'warning';
    return 'note';
}
function formatSarif(report) {
    const r = (report ?? {});
    const findings = r.findings ?? [];
    const rulesById = new Map();
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
