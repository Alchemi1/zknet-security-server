import { getRuleById } from '../rules/index.mjs';

export class FixGenerator {
  constructor(basePath) {
    this.basePath = basePath;
    this.fixHistory = [];
  }

  generateFixPlan(findings) {
    const plan = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      summary: {
        autoFixable: 0,
        requiresReview: 0,
        total: findings.length,
      },
    };

    for (const finding of findings) {
      const category = finding.passedGate ? 'critical' : 'high';
      const entry = {
        ruleId: finding.ruleId,
        severity: finding.severity,
        file: finding.file,
        title: finding.title,
        description: finding.description,
        fix: finding.fix || this._getDefaultFix(finding),
        evidenceLevel: finding.evidenceLevel,
        autoFixable: !!finding.fix && finding.evidenceLevel === 'confirmed',
      };

      plan[finding.severity].push(entry);
      if (entry.autoFixable) plan.summary.autoFixable++;
      else plan.summary.requiresReview++;
    }

    return plan;
  }

  _getDefaultFix(finding) {
    const rule = getRuleById(finding.ruleId);
    return rule ? rule.fix : 'Manual review required - no automated fix available.';
  }

  generatePrompt(findings) {
    const plan = this.generateFixPlan(findings);
    let prompt = '# ZKN Security Fix Plan\n\n';

    for (const severity of ['critical', 'high', 'medium']) {
      if (plan[severity].length === 0) continue;
      prompt += `## ${severity.toUpperCase()} Priority\n\n`;
      for (const entry of plan[severity]) {
        prompt += `### ${entry.ruleId}: ${entry.title}\n`;
        prompt += `**File:** \`${entry.file}\`\n`;
        prompt += `**Evidence:** ${entry.evidenceLevel}\n`;
        prompt += `**Auto-fixable:** ${entry.autoFixable ? 'Yes' : 'No'}\n`;
        prompt += `\n${entry.fix}\n\n`;
      }
    }

    return prompt;
  }

  recordFix(findingId, action) {
    this.fixHistory.push({
      findingId,
      action,
      timestamp: new Date().toISOString(),
    });
  }
}
