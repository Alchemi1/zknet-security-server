export const MIXNET_RULES = [
  {
    id: 'ZKN-MX-001',
    severity: 'critical',
    category: 'directory-auth',
    title: 'Directory Authority Compromise',
    description: 'Mixnet directory authorities (dirauth) control PKI. Three dirauths with simple majority risks cartel.',
    pattern: /dirauth|directory.*authority|authority.*cert|auth[123]/gi,
    check: (content) => {
      const findings = [];
      const authCount = [...content.matchAll(/dirauth|directory.?authority/gi)].length;
      if (authCount < 3) {
        findings.push({ line: 0, match: `Only ${authCount || 0} directory authorities - need >=3 for Byzantine fault tolerance` });
      }
      if (!/threshold|quorum|consensus/i.test(content)) {
        findings.push({ line: 0, match: 'No consensus threshold specified for directory authority decisions' });
      }
      return findings;
    },
    appliesTo: ['*.toml', '*.yaml', '*.yml', '*.md', '*.go', '*.sh'],
  },
  {
    id: 'ZKN-MX-002',
    severity: 'high',
    category: 'tunnel',
    title: 'SSH Tunnel Key Management',
    description: 'SSH tunnel keys must be rotated and scoped. Dedicated key is good, verify rotation schedule.',
    pattern: /tunnel_key|kpclientd-tunnel|SSH.*tunnel/gi,
    check: (content) => {
      const findings = [];
      if (/tunnel_key/.test(content) && !/rotate|expir|renew/i.test(content)) {
        findings.push({ line: 0, match: 'SSH tunnel key without rotation schedule' });
      }
      if (/64331|30022/.test(content) && !/firewall|allowlist|iptables/i.test(content)) {
        findings.push({ line: 0, match: 'Tunnel port exposed without explicit firewall rule verification' });
      }
      return findings;
    },
    appliesTo: ['*.md', '*.toml', '*.sh', '*.py'],
  },
  {
    id: 'ZKN-MX-003',
    severity: 'high',
    category: 'mix-route',
    title: '5-Hop Mix Route Security',
    description: '5-hop route provides strong anonymity but latency trade-off. Verify no exit node compromise.',
    pattern: /5.hop|mix[123]|gateway|servicenode|5.hop\s*SURB/gi,
    check: (content) => {
      const findings = [];
      const hopCount = [...content.matchAll(/mix\d|layer\d|hop/gi)].length;
      if (hopCount < 5) {
        findings.push({ line: 0, match: `Only ~${hopCount} mix hops detected - 5-hop recommended for strong anonymity` });
      }
      if (/\bhttp_proxy\b/.test(content) && !/plugin|sandbox|isolation/i.test(content)) {
        findings.push({ line: 0, match: 'HTTP proxy plugin without explicit sandbox/isolation from mix node' });
      }
      return findings;
    },
    appliesTo: ['*.toml', '*.yaml', '*.yml', '*.md', '*.go', '*.rs'],
  },
  {
    id: 'ZKN-MX-004',
    severity: 'high',
    category: 'rpc-gateway',
    title: 'RPC Gateway Abuse Prevention',
    description: 'Service node http_proxy forwards RPC to public nodes. Verify no RPC abuse (rate limit, auth).',
    pattern: /http_proxy|RPC.*gateway|servicenode.*plugin/gi,
    check: (content) => {
      const findings = [];
      if (/ethereum-rpc|publicnode|infura|alchemy/i.test(content) && !/rate.?limit|auth|key|token/i.test(content)) {
        findings.push({ line: 0, match: 'Public RPC forwarding without rate limiting or authentication' });
      }
      const rpcEndpoints = [...content.matchAll(/(https?:\/\/[^\s"']+)/gi)];
      const publicRpcs = rpcEndpoints.filter(r => /publicnode|\.io|\.com/.test(r[0]));
      if (publicRpcs.length > 0 && !/backup|failover|redundant/i.test(content)) {
        findings.push({ line: 0, match: `${publicRpcs.length} RPC endpoints without failover strategy` });
      }
      return findings;
    },
    appliesTo: ['*.toml', '*.md', '*.go', '*.yaml', '*.yml'],
  },
  {
    id: 'ZKN-MX-005',
    severity: 'critical',
    category: 'pki-client',
    title: 'PKI Client Timeout Vulnerability',
    description: 'PKI client patched timeout (kpclientd_fixed) suggests original had timeout issues leading to DoS.',
    pattern: /kpclientd|pki\.go|kpclientd_fixed|patched.*timeout/gi,
    check: (content) => {
      const findings = [];
      if (/kpclientd_fixed|patched/.test(content)) {
        findings.push({ line: 0, match: 'Patched kpclientd binary in use - verify patch is upstreamed and audited' });
      }
      if (/timeout.*fix|patched.*timeout/i.test(content) && !/retry|backoff|circuit.?breaker/i.test(content)) {
        findings.push({ line: 0, match: 'Timeout fix without retry/backoff strategy creates single-point-of-failure' });
      }
      return findings;
    },
    appliesTo: ['*.go', '*.md', '*.toml', '*.sh'],
  },
  {
    id: 'ZKN-MX-006',
    severity: 'medium',
    category: 'linkability',
    title: 'Timing Analysis Resistance',
    description: 'Mixnet round-trip of 40-45s is a timing signature that could deanonymize transactions.',
    pattern: /round.trip|latency|40.*45.*s|5.hop.*SURB|timing/gi,
    check: (content) => {
      const findings = [];
      if (/\b40.*45.*s\b|\b45s\b/.test(content)) {
        findings.push({ line: 0, match: '40-45s round trip creates identifiable timing signature - consider variable delays' });
      }
      if (!/cover.?traffic|cover_traffic|padding|dummy.?packet/i.test(content)) {
        findings.push({ line: 0, match: 'No cover traffic mechanism detected - timing analysis could deanonymize' });
      }
      return findings;
    },
    appliesTo: ['*.md', '*.toml', '*.go', '*.rs'],
  },
  {
    id: 'ZKN-MX-007',
    severity: 'high',
    category: 'pigeonhole',
    title: 'Pigeonhole Storage Security',
    description: 'Pigeonhole protocol for anonymous storage must verify data expiration and access controls.',
    pattern: /pigeonhole|courier|anonymous.*storage/gi,
    check: (content) => {
      const findings = [];
      if (!/expir|ttl|timeout|delete/i.test(content)) {
        findings.push({ line: 0, match: 'Pigeonhole storage without explicit data expiration/cleanup' });
      }
      if (!/encrypt|cipher|aes/i.test(content)) {
        findings.push({ line: 0, match: 'Pigeonhole stored data may not be encrypted at rest' });
      }
      return findings;
    },
    appliesTo: ['*.md', '*.toml', '*.go', '*.rs'],
  },
  {
    id: 'ZKN-MX-008',
    severity: 'high',
    category: 'wallet-shield',
    title: 'WalletShield RPC Privacy',
    description: 'WalletShield routes Ethereum RPC through mixnet. Verify no metadata leak in HTTP headers.',
    pattern: /walletshield|wallet.*shield|thin.*client|9200/gi,
    check: (content) => {
      const findings = [];
      if (/9200/.test(content) && !/localhost|127\.0\.0\.1/i.test(content)) {
        findings.push({ line: 0, match: 'WalletShield port exposed beyond localhost' });
      }
      if (/Content-Type|User-Agent|X-Forwarded/i.test(content)) {
        findings.push({ line: 0, match: 'Potential HTTP metadata leakage through walletshield headers' });
      }
      return findings;
    },
    appliesTo: ['*.toml', '*.py', '*.md', '*.rs', '*.ts'],
  },
];

export function matchMixnetRules(filename) {
  return MIXNET_RULES.filter(r =>
    r.appliesTo.some(g => {
      const pattern = g.replace('*', '');
      return filename.endsWith(pattern);
    })
  );
}
