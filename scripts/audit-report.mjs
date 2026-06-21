#!/usr/bin/env node
// View the latest pre-commit audit report

import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';

const reportsDir = new URL('../reports', import.meta.url).pathname;
const files = readdirSync(reportsDir).filter(f => f.startsWith('precommit_')).sort();

if (files.length === 0) {
  console.log('No audit reports found in', reportsDir);
  process.exit(0);
}

const latest = join(reportsDir, files[files.length - 1]);
const report = JSON.parse(readFileSync(latest, 'utf-8'));

console.log(`\nReport: ${files[files.length - 1]}`);
console.log(`Files scanned: ${report.files}`);
console.log(`Total findings: ${report.total}`);
console.log(`Critical: ${report.critical}`);
console.log(`Auto-fixable: ${report.autoFixable}`);
console.log('='.repeat(50));

if (report.findings) {
  const bySev = {};
  const byFile = {};
  for (const f of report.findings) {
    bySev[f.severity] = (bySev[f.severity] || 0) + 1;
    byFile[f.file] = (byFile[f.file] || 0) + 1;
  }
  console.log('\nBy severity:', JSON.stringify(bySev));
  console.log('\nFiles with most findings:');
  Object.entries(byFile)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .forEach(([file, count]) => console.log(`  ${file}: ${count}`));

  console.log('\nConfirmed critical findings:');
  for (const f of report.findings) {
    if (f.severity === 'critical' && f.evidenceLevel === 'confirmed') {
      console.log(`  [${f.ruleId}] ${f.title} - ${f.file}`);
      if (f.fix) console.log(`    Fix: ${f.fix}`);
    }
  }
}
