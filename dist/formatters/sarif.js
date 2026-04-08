"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatSarif = formatSarif;
function formatSarif(report) {
    return {
        version: '2.1.0',
        runs: [{ tool: { driver: { name: 'ProdCycle Compliance Scanner' } }, results: [] }]
    };
}
