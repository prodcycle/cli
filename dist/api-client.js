"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ComplianceApiClient = void 0;
class ComplianceApiClient {
    apiUrl;
    apiKey;
    constructor(apiUrl, apiKey) {
        this.apiUrl = apiUrl || process.env.PC_API_URL || 'https://api.prodcycle.com';
        this.apiKey = apiKey || process.env.PC_API_KEY || '';
        if (!this.apiKey && process.env.NODE_ENV !== 'test') {
            console.warn('Warning: PC_API_KEY is not set. API calls will likely fail.');
        }
    }
    async validate(files, frameworks, options = {}) {
        return this.post('/v1/compliance/validate', {
            files,
            frameworks,
            options: {
                severity_threshold: options.severityThreshold,
                fail_on: options.failOn,
                ...options.config,
            },
        });
    }
    async hook(files, frameworks) {
        return this.post('/v1/compliance/hook', {
            files,
            frameworks,
        });
    }
    async post(endpoint, data) {
        const url = `${this.apiUrl}${endpoint}`;
        try {
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.apiKey}`,
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(data),
            });
            const responseData = await response.json();
            if (!response.ok) {
                throw new Error(responseData.error?.message || `API request failed with status ${response.status}`);
            }
            return responseData;
        }
        catch (error) {
            throw new Error(`Failed to connect to ProdCycle API: ${error.message}`);
        }
    }
}
exports.ComplianceApiClient = ComplianceApiClient;
