import { readdir, readFile } from 'node:fs/promises';
import { join, relative } from 'node:path';

const root = new URL('..', import.meta.url).pathname;
const srcDir = join(root, 'src');

const forbiddenFetchMethods = [
  /method\s*:\s*['"]POST['"]/i,
  /method\s*:\s*['"]PUT['"]/i,
  /method\s*:\s*['"]PATCH['"]/i,
  /method\s*:\s*['"]DELETE['"]/i
];

const forbiddenUiPatterns = [
  /作成|更新|削除|復号|修復|再生成/,
  /decrypt/i,
  /createSecret|rotateSecret|deleteSecret|repair|regenerate/i
];

const allowedUiPatternFiles = new Set(['src/redaction.ts']);

const writeFormPattern = /<form[\s\S]*?(secret|ledger|audit)/i;

const walk = async (dir) => {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await walk(path)));
    } else if (/\.(ts|tsx)$/.test(entry.name)) {
      files.push(path);
    }
  }
  return files;
};

const failures = [];
const files = await walk(srcDir);

for (const file of files) {
  const text = await readFile(file, 'utf8');
  const relativePath = relative(root, file);
  for (const pattern of forbiddenFetchMethods) {
    if (pattern.test(text)) {
      failures.push(`${relativePath}: write-capable HTTP method is forbidden (${pattern})`);
    }
  }

  if (writeFormPattern.test(text) && !/Supabase Auth の監査担当者アカウント/.test(text)) {
    failures.push(`${relativePath}: write-oriented form is forbidden (${writeFormPattern})`);
  }

  if (!allowedUiPatternFiles.has(relativePath)) {
    for (const pattern of forbiddenUiPatterns) {
      if (pattern.test(text)) {
        failures.push(`${relativePath}: forbidden write/decrypt UI affordance marker (${pattern})`);
      }
    }
  }
}

if (failures.length > 0) {
  console.error(failures.join('\n'));
  process.exit(1);
}

console.log('readonly UI guard passed');