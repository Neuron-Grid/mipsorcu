import { access, readdir, readFile } from "node:fs/promises";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const srcDir = join(root, "src");
const testsDir = join(root, "tests");

const forbiddenFetchMethods = [
    /method\s*:\s*['"]POST['"]/i,
    /method\s*:\s*['"]PUT['"]/i,
    /method\s*:\s*['"]PATCH['"]/i,
    /method\s*:\s*['"]DELETE['"]/i,
];

const forbiddenServerEnvPatterns = [
    /MIPSORCU_SUPABASE_SERVICE_ROLE_KEY/,
    /MIPSORCU_MASTER_KEY/,
    /MIPSORCU_LEDGER_SIGNING_KEY/,
    /MIPSORCU_ALIAS_ENCRYPTION_KEY/,
    /MIPSORCU_ALIAS_FINGERPRINT_KEY/,
    /\bservice_role\b/i,
    /\bmaster_key\b/i,
    /\bledger_signing_key\b/i,
    /\balias_encryption_key\b/i,
    /\balias_fingerprint_key\b/i,
];

const forbiddenDecryptApiPatterns = [
    /\/v1\/secrets\/[^/]+\/decrypt/i,
    /\/v1\/secrets[^"']*decrypt/i,
];

const forbiddenUiPatterns = [
    /作成|更新|削除|復号|修復|再生成/,
    /decrypt/i,
    /createSecret|rotateSecret|deleteSecret|repair|regenerate/i,
];

const allowedUiPatternFiles = new Set(["src/redaction.ts"]);
const allowedSecretFixtureFiles = new Set(["src/redaction.ts", "tests/e2e/audit-ui.spec.ts"]);

const writeFormPattern = /<form[\s\S]*?(secret|ledger|audit)/i;

const pathExists = async (path: string): Promise<boolean> => {
    try {
        await access(path);
        return true;
    } catch {
        return false;
    }
};

const walk = async (dir: string): Promise<string[]> => {
    const entries = await readdir(dir, { withFileTypes: true });
    const files: string[] = [];
    for (const entry of entries) {
        const path = join(dir, entry.name);
        if (entry.isDirectory()) {
            if (entry.name === "node_modules" || entry.name === "dist") {
                continue;
            }
            files.push(...(await walk(path)));
        } else if (/\.(ts|tsx|js|jsx)$/.test(entry.name)) {
            files.push(path);
        }
    }
    return files;
};

const failures: string[] = [];
const srcFiles = await walk(srcDir);
const testFiles = (await pathExists(testsDir)) ? await walk(testsDir) : [];
const allFiles = [...srcFiles, ...testFiles];

for (const file of allFiles) {
    const text = await readFile(file, "utf8");
    const relativePath = relative(root, file);
    for (const pattern of forbiddenFetchMethods) {
        if (pattern.test(text)) {
            failures.push(`${relativePath}: write-capable HTTP method is forbidden (${pattern})`);
        }
    }

    if (!allowedSecretFixtureFiles.has(relativePath)) {
        for (const pattern of forbiddenServerEnvPatterns) {
            if (pattern.test(text)) {
                failures.push(
                    `${relativePath}: server-only key reference is forbidden (${pattern})`,
                );
            }
        }
    }

    for (const pattern of forbiddenDecryptApiPatterns) {
        if (pattern.test(text)) {
            failures.push(`${relativePath}: decrypt API reference is forbidden (${pattern})`);
        }
    }
}

for (const file of srcFiles) {
    const text = await readFile(file, "utf8");
    const relativePath = relative(root, file);

    if (writeFormPattern.test(text) && !/Supabase Auth の監査担当者アカウント/.test(text)) {
        failures.push(`${relativePath}: write-oriented form is forbidden (${writeFormPattern})`);
    }

    if (!allowedUiPatternFiles.has(relativePath)) {
        for (const pattern of forbiddenUiPatterns) {
            if (pattern.test(text)) {
                failures.push(
                    `${relativePath}: forbidden write/decrypt UI affordance marker (${pattern})`,
                );
            }
        }
    }
}

if (failures.length > 0) {
    console.error(failures.join("\n"));
    process.exit(1);
}

console.log("readonly UI guard passed");
