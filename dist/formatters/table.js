"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatTable = formatTable;
function formatTable(report) {
    // Simplistic table formatter
    if (!report)
        return 'No report data';
    return `Scan Results: ${report.summary?.passed || 0} passed, ${report.summary?.failed || 0} failed.`;
}
