import fs from 'fs';
import path from 'path';
import { glob } from 'glob';
import { getRulesForFile } from '../rules/index.mjs';

export class ZKNScanner {
  constructor(basePath) {
    this.basePath = basePath;
  }

  async findFiles() {
    const patterns = [
      '**/*.sol', '**/*.circom', '**/*.noir', '**/*.nr',
      '**/*.toml', '**/*.yaml', '**/*.yml',
      '**/*.js', '**/*.jsx', '**/*.ts', '**/*.tsx',
      '**/*.py', '**/*.rs', '**/*.go',
      '**/*.json', '**/*.md', '**/*.sh',
      '**/*.env*', '**/.gitignore',
      '**/hardhat.config.*', '**/*.service',
      '**/Dockerfile*',
    ];
    const excludePatterns = [
      '**/node_modules/**', '**/target/**', '**/dist/**',
      '**/build/**', '**/.git/**', '**/cache/**',
      '**/artifacts/**', '**/.nargo-cache/**',
      '**/.deps/**', '**/out/**',
      '**/vendor/**', '**/third_party/**', '**/thirdparty/**',
      '**/*/lib/forge-std/**', '**/*/lib/openzeppelin*/**',
      '**/*/lib/solady/**', '**/*/lib/permit2/**',
      '**/*/lib/v4-periphery/**', '**/*/lib/blocknumberish/**',
      '**/*/lib/cca*/**',
      '**/generated/**', '**/.next/**',
      '**/coverage/**', '**/.nyc_output/**',
    ];

    let files = [];
    for (const pattern of patterns) {
      try {
        const matches = await glob(pattern, {
          cwd: this.basePath,
          nodir: true,
          ignore: excludePatterns,
          dot: true,
        });
        files.push(...matches);
      } catch (e) {
        console.error(`Glob error for ${pattern}: ${e.message}`);
      }
    }
    return [...new Set(files)];
  }

  async scanFile(relativePath) {
    const fullPath = path.join(this.basePath, relativePath);
    let content;
    try {
      content = fs.readFileSync(fullPath, 'utf-8');
    } catch {
      return { file: relativePath, findings: [], error: 'Could not read file' };
    }

    const rules = getRulesForFile(relativePath);
    const findings = [];

    for (const rule of rules) {
      try {
        let matches;
        if (rule.check.constructor.name === 'AsyncFunction') {
          matches = await rule.check(fullPath, content);
        } else {
          matches = rule.check(content);
        }
        if (matches && matches.length > 0) {
          findings.push({
            ruleId: rule.id,
            severity: rule.severity,
            category: rule.category,
            title: rule.title,
            description: rule.description,
            evidence: matches,
            fix: rule.fix || null,
          });
        }
      } catch (e) {
        console.error(`Rule ${rule.id} error on ${relativePath}: ${e.message}`);
      }
    }

    return { file: relativePath, findings };
  }

  async scanAll(progressCallback) {
    const files = await this.findFiles();
    const results = [];

    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      const result = await this.scanFile(file);
      if (result.findings.length > 0) {
        results.push(result);
      }
      if (progressCallback) {
        progressCallback(i + 1, files.length, file, result.findings.length);
      }
    }

    return results;
  }
}
