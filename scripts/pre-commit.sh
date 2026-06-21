#!/usr/bin/env bash
# ZKN Security Audit - Pre-commit Hook
# Install: ln -sf ../../mcp-servers/zkn-security-server/scripts/pre-commit.sh .git/hooks/pre-commit
# This hook runs zkn_audit on staged .sol, .nr, .circom, .toml files only (fast check).

set -euo pipefail

echo "[zkn-security] Running pre-commit audit scan..."

STAGED=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(sol|nr|circom|toml|rs|py)$' || true)

if [ -z "$STAGED" ]; then
  echo "[zkn-security] No relevant files staged. Skipping."
  exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_DIR="$(dirname "$SCRIPT_DIR")"
REPORT_DIR="$SERVER_DIR/reports"
mkdir -p "$REPORT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
REPORT="$REPORT_DIR/precommit_$TIMESTAMP.json"

echo "[zkn-security] Scanning $(echo "$STAGED" | wc -l) files..."

# Run audit via MCP tool invocation (node inline)
node --input-type=module -e "
import { ZKNScanner } from '$SERVER_DIR/engine/scanner.mjs';
import { EvidenceGate } from '$SERVER_DIR/engine/evidence.mjs';
import { FixGenerator } from '$SERVER_DIR/engine/fixer.mjs';
import { writeFileSync } from 'fs';

const files = \`$STAGED\`.split('\n').filter(Boolean);
const scanner = new ZKNScanner(process.cwd());
const results = [];
for (const f of files) {
  try {
    const r = await scanner.scanFile(f);
    if (r.findings.length > 0) results.push(r);
  } catch (e) {
    console.error('  Error scanning', f, e.message);
  }
}

const flat = results.flatMap(r => r.findings.map(f => ({ ...f, file: r.file })));
const gate = new EvidenceGate();
const gated = gate.gatedFindings(flat);
const fixer = new FixGenerator(process.cwd());
const fixPlan = fixer.generateFixPlan(gated);

const critical = fixPlan.critical.length;
const autoFixable = fixPlan.summary.autoFixable;
const total = fixPlan.summary.total;

writeFileSync('$REPORT', JSON.stringify({ files: results.length, total, critical, autoFixable, findings: gated }, null, 2));

if (critical > 0) {
  console.log('\\n[zkn-security] FAILED: ' + critical + ' critical finding(s) detected!');
  console.log('[zkn-security] Run: node $SERVER_DIR/scripts/audit-report.mjs to view details');
  process.exit(1);
} else {
  console.log('[zkn-security] PASSED: ' + total + ' finding(s), 0 critical. Report saved.');
}
" && exit 0 || exit $?
