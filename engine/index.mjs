import { ZKNScanner } from './scanner.mjs';
import { EvidenceGate } from './evidence.mjs';
import { FixGenerator } from './fixer.mjs';
import { PatchGenerator } from './patcher.mjs';

export class ZKNAuditEngine {
  constructor(basePath) {
    this.basePath = basePath;
    this.scanner = new ZKNScanner(basePath);
    this.evidenceGate = new EvidenceGate();
    this.fixer = new FixGenerator(basePath);
    this.patcher = new PatchGenerator(basePath);
    this.lastResults = null;
  }

  async runAudit(categories, onProgress) {
    const rawResults = await this.scanner.scanAll((current, total, file, count) => {
      if (onProgress) onProgress(`Scanning [${current}/${total}]: ${file} (${count} issues)`);
    });

    const allFindings = [];
    for (const result of rawResults) {
      const gated = this.evidenceGate.gatedFindings(
        result.findings.map(f => ({ ...f, file: result.file }))
      );
      allFindings.push(...gated);
    }

    const filtered = categories && categories.length > 0
      ? allFindings.filter(f => categories.includes(f.category))
      : allFindings;

    const fixPlan = this.fixer.generateFixPlan(filtered);
    const summary = this._generateSummary(filtered, rawResults.length);

    this.lastResults = { findings: filtered, fixPlan, summary, rawCount: rawResults.length };
    return this.lastResults;
  }

  getFixPrompt() {
    if (!this.lastResults) return null;
    return this.fixer.generatePrompt(this.lastResults.findings);
  }

  _generateSummary(findings, scannedFiles) {
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
    const byCategory = {};
    const byEvidence = { confirmed: 0, likely: 0, plausible: 0, unconfirmed: 0 };

    for (const f of findings) {
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
      byCategory[f.category] = byCategory[f.category] || { count: 0, label: f.category };
      byCategory[f.category].count++;
      byEvidence[f.evidenceLevel] = (byEvidence[f.evidenceLevel] || 0) + 1;
    }

    return {
      totalFindings: findings.length,
      filesScanned: scannedFiles,
      bySeverity,
      byCategory: Object.fromEntries(
        Object.entries(byCategory).map(([k, v]) => [k, v.count])
      ),
      byEvidence,
      ...this.lastResults?.fixPlan?.summary || {},
    };
  }
}
