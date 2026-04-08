"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.collectFiles = collectFiles;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const glob_1 = require("glob");
const MAX_FILE_SIZE = 256 * 1024; // 256 KB
const MAX_TOTAL_FILES = 500;
async function collectFiles(baseDir, includePatterns, excludePatterns) {
    // Simple implementation using glob
    const patterns = includePatterns && includePatterns.length > 0 ? includePatterns : ['**/*'];
    const ignore = ['node_modules/**', '.git/**', '.terraform/**', 'dist/**', 'build/**', '**/__pycache__/**'];
    if (excludePatterns && excludePatterns.length > 0) {
        ignore.push(...excludePatterns);
    }
    const matches = await (0, glob_1.glob)(patterns, {
        cwd: baseDir,
        ignore,
        nodir: true,
    });
    const files = {};
    let count = 0;
    for (const match of matches) {
        if (count >= MAX_TOTAL_FILES) {
            console.warn(`Reached max file limit (${MAX_TOTAL_FILES}). Some files were skipped.`);
            break;
        }
        const fullPath = path.join(baseDir, match);
        const stats = fs.statSync(fullPath);
        // Skip large files
        if (stats.size > MAX_FILE_SIZE) {
            continue;
        }
        // Basic heuristic to skip binary files
        const buffer = fs.readFileSync(fullPath);
        if (isBinary(buffer)) {
            continue;
        }
        files[match] = buffer.toString('utf8');
        count++;
    }
    return files;
}
function isBinary(buffer) {
    for (let i = 0; i < Math.min(buffer.length, 1024); i++) {
        if (buffer[i] === 0)
            return true;
    }
    return false;
}
