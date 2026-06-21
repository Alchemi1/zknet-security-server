import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import path from "path";
import fs from "fs";
import { ZKNAuditEngine } from "./engine/index.mjs";
import { ALL_RULES, RULE_CATEGORIES, getRuleById } from "./rules/index.mjs";

const server = new McpServer({
  name: "zkn-security-server",
  version: "1.0.0",
  description: "ZKNetwork Platform Security Auditor — evidence-gated, phase-chained audit for ZK crypto, smart contracts, mixnet, dApps, and infrastructure.",
});

let auditEngine = null;
let lastFindings = [];

function getEngine(targetPath) {
  const basePath = targetPath || process.env.ZKN_PATH || process.cwd();
  if (!auditEngine) {
    auditEngine = new ZKNAuditEngine(basePath);
  }
  return auditEngine;
}

server.tool(
  "zkn_audit",
  "Run a full ZKNetwork security audit across all categories: smart contracts, ZK cryptography, mixnet, infrastructure, dApps, and supply chain.",
  {
    path: z.string().optional().describe("Target project path (defaults to ZKN_PATH or cwd)"),
    categories: z.array(z.string()).optional().describe("Filter by categories: smart-contracts, zk-cryptography, mixnet, infrastructure, dapp, supply-chain"),
    minSeverity: z.enum(["low", "medium", "high", "critical"]).optional().describe("Minimum severity to report"),
  },
  async ({ path: targetPath, categories, minSeverity }) => {
    const engine = getEngine(targetPath);
    const result = await engine.runAudit(categories, (msg) => {
      console.error(msg);
    });

    lastFindings = result.findings;
    const lines = [];

    const sevColors = { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵" };
    const evColors = { confirmed: "✓", likely: "~", plausible: "?", unconfirmed: " " };

    lines.push(`# ZKN Security Audit Results\n`);
    lines.push(`**Files Scanned:** ${result.summary.filesScanned}`);
    lines.push(`**Total Findings:** ${result.summary.totalFindings}`);
    lines.push(`**Auto-fixable:** ${result.summary.autoFixable}`);
    lines.push(`**Requires Review:** ${result.summary.requiresReview}\n`);

    lines.push(`## Severity Breakdown`);
    for (const [sev, count] of Object.entries(result.summary.bySeverity)) {
      if (count > 0) lines.push(`- ${sevColors[sev] || "•"} **${sev}**: ${count}`);
    }

    lines.push(`\n## Evidence Breakdown`);
    for (const [level, count] of Object.entries(result.summary.byEvidence)) {
      if (count > 0) lines.push(`- ${evColors[level] || "•"} **${level}**: ${count}`);
    }

    lines.push(`\n## Findings\n`);
    for (const f of result.findings) {
      const gateIcon = f.passedGate ? "✓" : "✗";
      lines.push(`### ${f.ruleId} ${gateIcon} — ${f.title}`);
      lines.push(`**Severity:** ${f.severity} | **Evidence:** ${f.evidenceLevel} | **File:** \`${f.file}\``);
      if (f.evidence && f.evidence.length > 0) {
        lines.push(`**Evidence:**`);
        for (const ev of f.evidence) {
          lines.push(`- \`${(ev.match || ev).substring(0, 120)}\``);
        }
      }
      if (f.fix) {
        lines.push(`**Fix:** ${f.fix.substring(0, 200)}${f.fix.length > 200 ? '...' : ''}`);
      }
      lines.push('');
    }

    return { content: [{ type: "text", text: lines.join("\n") }] };
  }
);

server.tool(
  "zkn_fix",
  "Generate a prioritized fix plan for the last audit results. Outputs a structured remediation prompt.",
  {
    format: z.enum(["prompt", "json"]).optional().describe("Output format: prompt (default) or json"),
  },
  async ({ format }) => {
    if (!lastFindings || lastFindings.length === 0) {
      return { content: [{ type: "text", text: "No audit results found. Run zkn_audit first." }] };
    }

    const engine = getEngine();
    const plan = engine.fixer.generateFixPlan(lastFindings);

    if (format === "json") {
      return { content: [{ type: "text", text: JSON.stringify(plan, null, 2) }] };
    }

    const prompt = engine.getFixPrompt();
    return { content: [{ type: "text", text: prompt || "No fix plan generated." }] };
  }
);

server.tool(
  "zkn_scan_file",
  "Scan a single file against ZKNetwork security rules. Useful for quick checks during development.",
  {
    filePath: z.string().describe("Absolute path to the file to scan"),
  },
  async ({ filePath }) => {
    const engine = getEngine(path.dirname(filePath));
    const relativePath = path.relative(engine.basePath, filePath);
    const result = await engine.scanner.scanFile(relativePath);
    const gated = engine.evidenceGate.gatedFindings(
      result.findings.map(f => ({ ...f, file: relativePath }))
    );

    if (gated.length === 0) {
      return { content: [{ type: "text", text: `✅ No security issues found in \`${relativePath}\`` }] };
    }

    const lines = [`## Scan: \`${relativePath}\`\n`];
    for (const f of gated) {
      lines.push(`### ${f.ruleId} — ${f.title}`);
      lines.push(`**Severity:** ${f.severity} | **Evidence:** ${f.evidenceLevel}`);
      if (f.evidence && f.evidence.length > 0) {
        for (const ev of f.evidence) {
          lines.push(`- \`${(ev.match || ev).substring(0, 100)}\``);
        }
      }
      lines.push('');
    }

    return { content: [{ type: "text", text: lines.join("\n") }] };
  }
);

server.tool(
  "zkn_preview_fix",
  "Preview auto-fix patches for confirmed critical findings. Shows the exact text changes needed.",
  {
    ruleId: z.string().optional().describe("Filter by rule ID (e.g., ZKN-SC-001, ZKN-SC-005)"),
    file: z.string().optional().describe("Filter by file path pattern"),
  },
  async ({ ruleId: filterRule, file: filterFile }) => {
    if (!lastFindings || lastFindings.length === 0) {
      return { content: [{ type: "text", text: "No audit results found. Run zkn_audit first." }] };
    }

    const engine = getEngine();
    const targetFindings = lastFindings.filter(f =>
      f.severity === 'critical' &&
      f.evidenceLevel === 'confirmed' &&
      (!filterRule || f.ruleId === filterRule) &&
      (!filterFile || f.file.includes(filterFile))
    );

    if (targetFindings.length === 0) {
      return { content: [{ type: "text", text: "No matching confirmed critical findings." }] };
    }

    const lines = [`# Fix Patch Preview (${targetFindings.length} findings)\n`];
    let totalChanges = 0;

    for (const finding of targetFindings) {
      const fullPath = path.join(engine.basePath, finding.file);
      let content;
      try {
        content = fs.readFileSync(fullPath, 'utf-8');
      } catch {
        lines.push(`\n### ${finding.ruleId} — ${finding.title}\n⚠ Could not read: ${finding.file}\n`);
        continue;
      }

      const patches = engine.patcher.generatePatch(finding, content);
      if (!patches || patches.error) {
        lines.push(`\n### ${finding.ruleId} — ${finding.title}\n⚠ No auto-fix available for ${finding.file}\n`);
        continue;
      }

      const dryRun = engine.patcher.dryRunPatch(fullPath, patches);
      if (dryRun.changes.length > 0) {
        totalChanges += dryRun.changes.length;
        lines.push(`\n### ${finding.ruleId} — ${finding.title}\n**File:** \`${finding.file}\`\n**Changes:** ${dryRun.changes.length}\n`);
        for (const c of dryRun.changes) {
          lines.push(`- Line ${c.line}: \`${c.newString}\``);
        }
      }
    }

    lines.push(`\n---\n**Total changes previewed:** ${totalChanges}`);
    return { content: [{ type: "text", text: lines.join("\n") }] };
  }
);

server.tool(
  "zkn_apply_fix",
  "Apply auto-fix patches for confirmed critical findings. Writes changes directly to files.",
  {
    ruleId: z.string().optional().describe("Filter by rule ID (e.g., ZKN-SC-001)"),
    file: z.string().optional().describe("Filter by file path pattern"),
    dryRun: z.boolean().optional().describe("If true, show changes without applying (default: false)"),
  },
  async ({ ruleId: filterRule, file: filterFile, dryRun }) => {
    if (!lastFindings || lastFindings.length === 0) {
      return { content: [{ type: "text", text: "No audit results found. Run zkn_audit first." }] };
    }

    const engine = getEngine();
    const targetFindings = lastFindings.filter(f =>
      f.severity === 'critical' &&
      f.evidenceLevel === 'confirmed' &&
      (!filterRule || f.ruleId === filterRule) &&
      (!filterFile || f.file.includes(filterFile))
    );

    if (targetFindings.length === 0) {
      return { content: [{ type: "text", text: "No matching confirmed critical findings." }] };
    }

    const results = [];
    const seenFiles = new Set();

    for (const finding of targetFindings) {
      const fullPath = path.join(engine.basePath, finding.file);
      const cacheKey = `${fullPath}:${finding.ruleId}`;
      if (seenFiles.has(cacheKey)) continue;
      seenFiles.add(cacheKey);

      let content;
      try {
        content = fs.readFileSync(fullPath, 'utf-8');
      } catch {
        results.push({ file: finding.file, ruleId: finding.ruleId, status: 'error', detail: 'Could not read file' });
        continue;
      }

      const patches = engine.patcher.generatePatch(finding, content);
      if (!patches || patches.error) {
        results.push({ file: finding.file, ruleId: finding.ruleId, status: 'skipped', detail: patches?.error || 'No auto-fix available' });
        continue;
      }

      if (dryRun) {
        const preview = engine.patcher.dryRunPatch(fullPath, patches);
        results.push({ file: finding.file, ruleId: finding.ruleId, status: 'preview', changes: preview.changes });
      } else {
        try {
          const applyResult = await engine.patcher.applyPatch(fullPath, patches);
          results.push({ file: finding.file, ruleId: finding.ruleId, status: 'applied', changes: applyResult.applied });
        } catch (e) {
          results.push({ file: finding.file, ruleId: finding.ruleId, status: 'error', detail: e.message });
        }
      }
    }

    const byStatus = {};
    for (const r of results) byStatus[r.status] = (byStatus[r.status] || 0) + 1;

    const lines = [`# Fix Application Results\n`];
    lines.push(`| Status | Count |`);
    lines.push(`|---|---|`);
    for (const [status, count] of Object.entries(byStatus)) {
      lines.push(`| ${status} | ${count} |`);
    }

    if (dryRun) {
      lines.push(`\n## Preview Changes\n`);
      for (const r of results) {
        if (r.changes && r.changes.length > 0) {
          lines.push(`\n### \`${r.file}\` — ${r.ruleId}`);
          for (const c of r.changes) {
            lines.push(`- Line ${c.line}: \`${c.oldString}\` → \`${c.newString}\``);
          }
        }
      }
    }

    return { content: [{ type: "text", text: lines.join("\n") }] };
  }
);

server.tool(
  "zkn_list_rules",
  "List all available ZKNetwork security rules, optionally filtered by category.",
  {
    category: z.string().optional().describe("Filter by category (smart-contracts, zk-cryptography, zk-circuits, mixnet, infrastructure, dapp, supply-chain)"),
    severity: z.enum(["critical", "high", "medium", "low"]).optional().describe("Filter by minimum severity"),
  },
  async ({ category, severity }) => {
    let rules = category ? RULE_CATEGORIES[category]?.rules || [] : ALL_RULES;
    if (severity) {
      const order = { critical: 0, high: 1, medium: 2, low: 3 };
      const min = order[severity];
      rules = rules.filter(r => order[r.severity] >= min);
    }

    const byCategory = {};
    for (const r of rules) {
      const cat = r.category || 'uncategorized';
      if (!byCategory[cat]) byCategory[cat] = [];
      byCategory[cat].push(r);
    }

    const sevColors = { critical: "🔴", high: "🟠", medium: "🟡", low: "🔵" };
    const lines = [`# ZKN Security Rules (${rules.length})`];

    for (const [cat, catRules] of Object.entries(byCategory)) {
      lines.push(`\n## ${cat}`);
      for (const r of catRules) {
        lines.push(`- ${sevColors[r.severity] || "•"} **${r.id}**: ${r.title} _(applies to: ${r.appliesTo.join(', ')})_`);
      }
    }

    return { content: [{ type: "text", text: lines.join("\n") }] };
  }
);

server.tool(
  "zkn_summary",
  "Get a summary of the last audit results without the full finding details.",
  {},
  async () => {
    if (!lastFindings || lastFindings.length === 0) {
      return { content: [{ type: "text", text: "No audit results available. Run zkn_audit first." }] };
    }

    const engine = getEngine();
    const summary = engine.lastResults?.summary;
    if (!summary) {
      return { content: [{ type: "text", text: "No summary available." }] };
    }

    return {
      content: [{
        type: "text",
        text: JSON.stringify(summary, null, 2),
      }],
    };
  }
);

server.tool(
  "zkn_rule_info",
  "Get detailed information about a specific security rule by its ID (e.g., ZKN-SC-001, ZKN-CR-003).",
  {
    ruleId: z.string().describe("Rule ID (e.g., ZKN-SC-001, ZKN-CR-003, ZKN-MX-001, ZKN-IN-001, ZKN-DA-001)"),
  },
  async ({ ruleId }) => {
    const rule = getRuleById(ruleId);
    if (!rule) {
      return { content: [{ type: "text", text: `Rule ${ruleId} not found. Use zkn_list_rules to see all available rules.` }] };
    }

    const lines = [
      `## ${rule.id}: ${rule.title}`,
      `**Severity:** ${rule.severity}`,
      `**Category:** ${rule.category}`,
      `**Applies to:** ${rule.appliesTo.join(', ')}`,
      ``,
      `**Description:** ${rule.description}`,
      ``,
      `**Fix:** ${rule.fix || 'No automated fix available.'}`,
      ``,
      `**Pattern:** \`${rule.pattern || 'N/A (custom check)'}\``,
    ];

    return { content: [{ type: "text", text: lines.join("\n") }] };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
console.error("ZKN Security MCP Server running on stdio");
console.error(`Rules loaded: ${ALL_RULES.length}`);
