export const DAPP_RULES = [
  {
    id: 'ZKN-DA-001',
    severity: 'critical',
    category: 'secret-exposure',
    title: 'Hardcoded Secrets in Frontend',
    description: 'NEXT_PUBLIC_, VITE_, REACT_APP_ env vars are bundled into client code. Never put secrets here.',
    pattern: /(VITE_|NEXT_PUBLIC_|REACT_APP_)(API_KEY|SECRET|PASSWORD|PRIVATE_KEY|SEED|MNEMONIC)/gi,
    check: (content) => {
      const findings = [];
      const secretPatterns = [
        /VITE_[A-Z_]+/g, /REACT_APP_[A-Z_]+/g, /NEXT_PUBLIC_[A-Z_]+/g,
        /sk-[a-zA-Z0-9]{20,}/g, /pk-[a-zA-Z0-9]{20,}/g,
      ];
      for (const pattern of secretPatterns) {
        const matches = content.match(pattern);
        if (matches) {
          findings.push({ line: 0, match: `Potential secret in client bundle: ${matches[0].substring(0, 30)}...` });
        }
      }
      return findings;
    },
    fix: 'Remove secrets from client env. Use server-side proxy or backend API to inject secrets server-side.',
    appliesTo: ['*.js', '*.jsx', '*.ts', '*.tsx', '*.env', '*.env.*'],
  },
  {
    id: 'ZKN-DA-002',
    severity: 'high',
    category: 'rpc-calls',
    title: 'Direct RPC Calls from Client',
    description: 'Direct ethereum RPC calls from browser expose endpoint and risk API key leakage.',
    pattern: /ethers|web3|provider|JsonRpcProvider|ethers\./gi,
    check: (content) => {
      const findings = [];
      if (!content || typeof content !== 'string') return [];
      const rpcUrls = [...content.matchAll(/(https?:\/\/[^\s"'`]+(?:rpc|infura|alchemy|publicnode)[^\s"'`]*)/gi)];
      if (rpcUrls.length > 0) {
        findings.push({ line: 0, match: `Direct RPC URL in client code: ${rpcUrls[0][0].substring(0, 50)}...` });
      }
      if (content.includes('privateKey') || content.includes('PRIVATE_KEY')) {
        findings.push({ line: 0, match: 'Private key reference in frontend code - CRITICAL' });
      }
      return findings;
    },
    fix: 'Route all RPC calls through a backend proxy or walletshield mixnet. Never expose RPC URLs or API keys in client.',
    appliesTo: ['*.js', '*.jsx', '*.ts', '*.tsx'],
  },
  {
    id: 'ZKN-DA-003',
    severity: 'high',
    category: 'auth',
    title: 'Client-Only Authorization',
    description: 'Auth checks only in frontend can be bypassed via DevTools. Verify server-side enforcement.',
    pattern: /(if\s*\(!wallet|if\s*\(!user|if\s*\(!account|requireAuth|ProtectedRoute)/gi,
    check: (content) => {
      const findings = [];
      if (/wallet|account|user/.test(content)) {
        const clientChecks = content.match(/if\s*\(!(wallet|account|user|address|signer)/gi);
        if (clientChecks && !/server|api|backend|middleware/.test(content)) {
          findings.push({ line: 0, match: 'Client-only auth check without server-side enforcement' });
        }
      }
      return findings;
    },
    fix: 'Implement server-side auth middleware. Client checks are UX-only, not security.',
    appliesTo: ['*.js', '*.jsx', '*.ts', '*.tsx'],
  },
  {
    id: 'ZKN-DA-004',
    severity: 'medium',
    category: 'input-validation',
    title: 'Unvalidated User Input',
    description: 'User input rendered without sanitization can lead to XSS in dApp.',
    pattern: /(dangerouslySetInnerHTML|innerHTML|v-html|\$\{|template.*`)/gi,
    check: (content) => {
      const findings = [];
      const dangerous = content.match(/dangerouslySetInnerHTML|innerHTML(?!=)/gi);
      if (dangerous) {
        findings.push({ line: 0, match: `Dangerous HTML rendering: ${dangerous.length} occurrence(s)` });
      }
      return findings;
    },
    fix: 'Use DOMPurify for any HTML rendering. Prefer React JSX or template literals with auto-escaping.',
    appliesTo: ['*.js', '*.jsx', '*.ts', '*.tsx'],
  },
  {
    id: 'ZKN-DA-005',
    severity: 'high',
    category: 'dependency',
    title: 'Outdated Critical Dependency',
    description: 'Check for known CVEs in dependencies like ethers.js, React, Vite.',
    pattern: /"ethers":|"react":|"vite":|"next":/gi,
    check: (content) => {
      const findings = [];
      const deps = {
        ethers: { min: '6.9.0', regex: /"ethers":\s*"\^?(\d+\.\d+\.\d+)"/ },
        react: { min: '18.2.0', regex: /"react":\s*"\^?(\d+\.\d+\.\d+)"/ },
      };
      for (const [name, dep] of Object.entries(deps)) {
        const match = content.match(dep.regex);
        if (match) {
          const ver = match[1].split('.').map(Number);
          const minVer = dep.min.split('.').map(Number);
          for (let i = 0; i < 3; i++) {
            if ((ver[i] || 0) < minVer[i]) {
              findings.push({ line: 0, match: `${name}@${match[1]} is below minimum recommended ${dep.min}` });
              break;
            }
          }
        }
      }
      return findings;
    },
    fix: 'Update dependencies to latest stable versions and run npm audit regularly.',
    appliesTo: ['package.json'],
  },
  {
    id: 'ZKN-DA-006',
    severity: 'medium',
    category: 'cors',
    title: 'CORS Configuration',
    description: 'Overly permissive CORS can allow unauthorized dApps to interact with wallet.',
    pattern: /cors|Access-Control-Allow-Origin/i,
    check: (content) => {
      const findings = [];
      if (/\*\s*\/\//.test(content) || /Allow-Origin:\s*\*/.test(content)) {
        findings.push({ line: 0, match: 'Wildcard CORS - restricts browser security model' });
      }
      return findings;
    },
    fix: 'Set explicit allowed origins. Never use * in production.',
    appliesTo: ['*.js', '*.ts', '*.py', '*.rs', '*.go'],
  },
  {
    id: 'ZKN-DA-007',
    severity: 'high',
    category: 'local-storage',
    title: 'Sensitive Data in Browser Storage',
    description: 'Never store private keys, mnemonics, or tokens in localStorage/sessionStorage.',
    pattern: /localStorage|sessionStorage/i,
    check: (content) => {
      const findings = [];
      if (!content) return findings;
      const storageOps = content.match(/localStorage|sessionStorage/gi);
      if (storageOps) {
        const sensitiveTerms = /key|secret|token|private|mnemonic|seed|password|wallet/i;
        if (sensitiveTerms.test(content)) {
          findings.push({ line: 0, match: `localStorage/sessionStorage used near sensitive data` });
        }
      }
      return findings;
    },
    fix: 'Use httpOnly cookies with Secure+SameSite flags. Never store secrets in browser storage.',
    appliesTo: ['*.js', '*.jsx', '*.ts', '*.tsx'],
  },
];

export function matchDappRules(filename) {
  const ext = filename.split('.').pop();
  return DAPP_RULES.filter(r =>
    r.appliesTo.some(g => {
      const pattern = g.replace('*', '');
      return filename === g || filename.endsWith(pattern);
    })
  );
}
