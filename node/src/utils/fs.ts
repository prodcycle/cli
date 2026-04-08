import * as fs from 'fs';
import * as path from 'path';
import { glob } from 'glob';

const MAX_FILE_SIZE = 256 * 1024; // 256 KB
const MAX_TOTAL_FILES = 500;

export async function collectFiles(
  baseDir: string,
  includePatterns?: string[],
  excludePatterns?: string[]
): Promise<Record<string, string>> {
  // Simple implementation using glob
  const patterns = includePatterns && includePatterns.length > 0 ? includePatterns : ['**/*'];
  const ignore = ['node_modules/**', '.git/**', '.terraform/**', 'dist/**', 'build/**', '**/__pycache__/**'];
  
  if (excludePatterns && excludePatterns.length > 0) {
    ignore.push(...excludePatterns);
  }

  const matches = await glob(patterns, {
    cwd: baseDir,
    ignore,
    nodir: true,
  });

  const files: Record<string, string> = {};
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

function isBinary(buffer: Buffer): boolean {
  for (let i = 0; i < Math.min(buffer.length, 1024); i++) {
    if (buffer[i] === 0) return true;
  }
  return false;
}
