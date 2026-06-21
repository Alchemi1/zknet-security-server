export const INFRA_RULES = [
  {
    id: 'ZKN-IN-001',
    severity: 'critical',
    category: 'exposure',
    title: 'Port Exposure Audit',
    description: 'Verify only necessary ports are exposed. Mixnet ports 30001-30009, SSH 30022 should be firewalled.',
    pattern: /(Port|port)\s*[:=]\s*\d+|listens\s*:\s*\d+/gi,
    check: (content) => {
      const findings = [];
      const ports = [...content.matchAll(/(\d{4,5})/g)].map(m => parseInt(m[1]));
      const infraPorts = [22, 9200, 12000, 64331, 30001, 30002, 30003, 30004, 30007, 30009, 30022];
      const foundInfra = ports.filter(p => infraPorts.includes(p));
      if (ports.some(p => p < 1024 && p !== 22 && p !== 80 && p !== 443)) {
        findings.push({ line: 0, match: `Privileged port in use: ${ports.filter(p => p < 1024 && p !== 22).join(', ')}` });
      }
      return findings;
    },
    appliesTo: ['*.md', '*.toml', '*.py', '*.sh', '*.json'],
  },
  {
    id: 'ZKN-IN-002',
    severity: 'high',
    category: 'service-management',
    title: 'Systemd Service Hardening',
    description: 'Systemd services should use Restart=always, PrivateTmp, NoNewPrivileges, ProtectSystem.',
    pattern: /\[Service\]|Restart=|systemctl/gi,
    check: (content) => {
      const findings = [];
      if (!/Restart=always/.test(content) && !/Restart\s*=\s*always/.test(content)) {
        findings.push({ line: 0, match: 'Missing Restart=always in service configuration' });
      }
      if (!/PrivateTmp|NoNewPrivileges|ProtectSystem|ProtectHome/i.test(content)) {
        findings.push({ line: 0, match: 'Missing systemd hardening directives (PrivateTmp, NoNewPrivileges, ProtectSystem)' });
      }
      return findings;
    },
    appliesTo: ['*.service', '*.md', '*.sh'],
  },
  {
    id: 'ZKN-IN-003',
    severity: 'critical',
    category: 'autonomi',
    title: 'Autonomi Node Security',
    description: 'Autonomi (ant-node) P2P node must verify peer identity, data storage limits, and reward address.',
    pattern: /ant-node|autonomi|ant\.node/gi,
    check: (content) => {
      const findings = [];
      if (/0x[a-fA-F0-9]{40}/.test(content)) {
        const addrs = content.match(/0x[a-fA-F0-9]{40}/g);
        if (addrs && addrs.length > 0) {
          findings.push({ line: 0, match: `Autonomi reward address detected: ${addrs[0].substring(0, 20)}...` });
        }
      }
      if (/rewards|payout/.test(content) && !/multi.?sig|cold.?wallet/i.test(content)) {
        findings.push({ line: 0, match: 'Autonomi rewards to single address - consider multi-sig for reward accumulation' });
      }
      return findings;
    },
    appliesTo: ['*.md', '*.toml', '*.sh', '*.py', '*.json'],
  },
  {
    id: 'ZKN-IN-004',
    severity: 'high',
    category: 'monitoring',
    title: 'Monitoring Coverage',
    description: 'Monitor.sh checks wallet, walletshield, ant-node. Consider adding disk, memory, and SSL cert checks.',
    pattern: /monitor\.sh|monitoring|health.?check/i,
    check: (content) => {
      const findings = [];
      const checks = ['balance', 'walletshield', 'ant-node', 'disk', 'memory', 'ssl', 'cert', 'cpu'];
      const found = checks.filter(c => content.toLowerCase().includes(c));
      const missing = checks.filter(c => !content.toLowerCase().includes(c));
      if (missing.length > 0) {
        findings.push({ line: 0, match: `Missing monitoring checks: ${missing.join(', ')}` });
      }
      return findings;
    },
    appliesTo: ['*.sh', '*.md', '*.py'],
  },
  {
    id: 'ZKN-IN-005',
    severity: 'high',
    category: 'backup',
    title: 'Backup and Disaster Recovery',
    description: 'Verify backup strategy for zymkey keys, wallet addresses, and mixnet configs.',
    pattern: /backup|recovery|disaster|restore/i,
    check: (content) => {
      const findings = [];
      if (!content || !/backup|recovery|restore/i.test(content)) {
        findings.push({ line: 0, match: 'No backup or disaster recovery procedure referenced' });
      }
      return findings;
    },
    appliesTo: ['*.md', '*.sh', '*.py', '*.toml'],
  },
  {
    id: 'ZKN-IN-006',
    severity: 'critical',
    category: 'docker',
    title: 'Docker Container Security',
    description: 'Docker containers should not run as root, use read-only rootfs, and have resource limits.',
    pattern: /docker|Dockerfile|container/i,
    check: (content) => {
      const findings = [];
      if (/Dockerfile|docker/i.test(content)) {
        if (!/USER\s+(?!root)/i.test(content)) {
          findings.push({ line: 0, match: 'Docker container running as root - use non-root user' });
        }
        if (!/read.?only|--read-only/i.test(content)) {
          findings.push({ line: 0, match: 'Docker rootfs not read-only' });
        }
        if (!/memory|--memory|cpu|--cpus/i.test(content)) {
          findings.push({ line: 0, match: 'Docker container without resource limits' });
        }
      }
      return findings;
    },
    appliesTo: ['*Dockerfile*', '*.yml', '*.yaml', '*.md', '*.sh'],
  },
  {
    id: 'ZKN-IN-007',
    severity: 'medium',
    category: 'network',
    title: 'Network Segmentation',
    description: 'CM4, VPS, and client should be on separate network segments with firewall rules.',
    pattern: /192\.168\.|VPS|217\.60\.|CM4|zknode/i,
    check: (content) => {
      const findings = [];
      const ips = [...content.matchAll(/(\d+\.\d+\.\d+\.\d+)/g)];
      const subnets = new Set(ips.map(i => i[1].split('.').slice(0, 2).join('.')));
      if (subnets.size < 2) {
        findings.push({ line: 0, match: `Single subnet detected (${[...subnets].join(', ')}) - consider network segmentation` });
      }
      return findings;
    },
    appliesTo: ['*.md', '*.toml', '*.sh', '*.py'],
  },
];

export function matchInfraRules(filename) {
  return INFRA_RULES.filter(r =>
    r.appliesTo.some(g => {
      const pattern = g.replace('*', '');
      return filename.endsWith(pattern) || filename.includes(pattern.replace('*', ''));
    })
  );
}
