"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.formatPrompt = formatPrompt;
function formatPrompt(report) {
    if (!report)
        return '';
    return 'Please fix the compliance issues found in this repository.';
}
