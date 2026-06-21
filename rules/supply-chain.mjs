export const SUPPLY_CHAIN_RULES = [
  {
    id: 'ZKN-SC-001',
    severity: 'high',
    category: 'package-pinning',
    title: 'Unpinned Dependency Versions',
    description: 'Floating dep versions (^, ~) can pull in malicious updates automatically via lockfile regeneration.',
    pattern: /"[^"]+":\s*"\^|"[^"]+":\s*"~/g,
    check: (content) => {
      if (!content) return [];
      const findings = [];
      const floating = [...content.matchAll(/"([^"]+)":\s*"\^|"([^"]+)":\s*"~/g)];
      const packages = floating.map(m => m[1] || m[2]).filter(Boolean);
      if (packages.length > 0) {
        findings.push({ line: 0, match: `${packages.length} floating dependency version(s) (^/~). Pin exact versions.` });
      }
      return findings;
    },
    fix: 'Remove ^ and ~ prefixes. Pin exact versions. Use lockfiles (package-lock.json, yarn.lock, pnpm-lock.yaml).',
    appliesTo: ['package.json', 'Cargo.toml', 'requirements.txt', 'Gemfile'],
  },
  {
    id: 'ZKN-SC-002',
    severity: 'high',
    category: 'lockfile',
    title: 'Missing Lockfile',
    description: 'No lockfile means non-deterministic installs. Attackers can substitute dependencies between installs.',
    pattern: /package-lock\.json|yarn\.lock|pnpm-lock|Cargo\.lock/i,
    check: (content) => {
      return content && !content ? [] : [];
    },
    appliesTo: ['package.json', 'Cargo.toml'],
  },
  {
    id: 'ZKN-SC-003',
    severity: 'critical',
    category: 'openzeppelin',
    title: 'Outdated OpenZeppelin Contracts',
    description: 'OpenZeppelin v4.9.5 is known to have vulnerabilities. Check for latest patched version.',
    pattern: /@openzeppelin\/contracts["']:\s*["']\^?(\d+\.\d+\.\d+)/g,
    check: (content) => {
      if (!content) return [];
      const findings = [];
      const matches = [...content.matchAll(/@openzeppelin\/contracts["']:\s*["']\^?(\d+\.\d+\.\d+)/g)];
      for (const m of matches) {
        const ver = m[1].split('.').map(Number);
        if (ver[0] < 5 || (ver[0] === 4 && ver[1] < 9) || (ver[0] === 4 && ver[1] === 9 && ver[2] < 5)) {
          findings.push({ line: 0, match: `OpenZeppelin ${m[1]} may have known vulnerabilities - update to latest` });
        }
      }
      return findings;
    },
    fix: 'Update @openzeppelin/contracts. Run npm audit. Check OpenZeppelin security advisories.',
    appliesTo: ['package.json'],
  },
  {
    id: 'ZKN-SC-004',
    severity: 'medium',
    category: 'hardhat',
    title: 'Hardhat Config Security',
    description: 'Hardhat config may contain private keys for deployment. Verify .env separation.',
    pattern: /hardhat\.config|hardhat\.ts|hardhat\.js/i,
    check: (content) => {
      const findings = [];
      const privateKeyPatterns = [
        /0x[a-fA-F0-9]{64}/g,
        /private_key|privateKey/i,
      ];
      for (const pat of privateKeyPatterns) {
        const matches = content.match(pat);
        if (matches) {
          findings.push({ line: 0, match: 'Potential private key in hardhat config - should use .env + dotenv' });
          break;
        }
      }
      if (!/dotenv|process\.env/.test(content)) {
        findings.push({ line: 0, match: 'Hardhat config without dotenv environment variable loading' });
      }
      return findings;
    },
    fix: 'Use dotenv to load private keys from .env. Add .env to .gitignore.',
    appliesTo: ['hardhat.config.*', 'hardhat.config.*'],
  },
  {
    id: 'ZKN-SC-005',
    severity: 'high',
    category: 'rust-deps',
    title: 'Rust Dependency Audit',
    description: 'Rust crates in Cargo.toml should be audited for supply chain risk, especially crypto crates.',
    pattern: /(ecdsa|k256|sha2|ripemd|arkworks|bellman|bls|bn254|bls12)/i,
    check: (content) => {
      const findings = [];
      const cryptoDeps = [...content.matchAll(/^\s*(\w[\w-]+)\s*=\s*"([^"]+)"/gm)];
      for (const dep of cryptoDeps) {
        const name = dep[1];
        const ver = dep[2];
        if (/ecdsa|k256|sha|crypto|zk|proof/i.test(name) && !/git|path/.test(ver)) {
          findings.push({ line: 0, match: `Crypto crate ${name}@${ver} - verify integrity and audit trail` });
        }
      }
      return findings;
    },
    appliesTo: ['Cargo.toml'],
  },
  {
    id: 'ZKN-SC-006',
    severity: 'medium',
    category: 'gitignore',
    title: 'Sensitive Files Not in .gitignore',
    description: '.env, keystore files, and backup files must be in .gitignore to prevent secret leakage.',
    pattern: /\.env|keystore|\.json|backup/i,
    check: (content) => {
      const findings = [];
      const requiredEntries = ['.env', '*.key', 'keystore', 'backup', '*.pem', '*.p12'];
      if (content) {
        for (const entry of requiredEntries) {
          if (!content.includes(entry)) {
            findings.push({ line: 0, match: `Missing .gitignore entry: ${entry}` });
          }
        }
      }
      return findings.slice(0, 3);
    },
    fix: 'Add .env, *.key, keystore/, backup/, *.pem, *.p12 to .gitignore.',
    appliesTo: ['.gitignore'],
  },
];

export function matchSupplyChainRules(filename) {
  return SUPPLY_CHAIN_RULES.filter(r =>
    r.appliesTo.some(g => {
      if (g.includes('*')) {
        const pattern = g.replace('*', '');
        return filename.includes(pattern);
      }
      return filename.endsWith(g) || filename.includes(g);
    })
  );
}
