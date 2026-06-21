export const CIRCUIT_RULES = [
  {
    id: 'ZKN-ZK-001',
    severity: 'critical',
    category: 'circuit-inputs',
    title: 'Unconstrained Public Inputs',
    description: 'All public inputs must be constrained by assertions. Unconstrained public inputs allow a malicious prover to make the verifier accept invalid witnesses.',
    pattern: /fn\s+main|pub\s+/g,
    check: async (filePath, content) => {
      if (!content || typeof content !== 'string') return [];
      const findings = [];
      const lines = content.split('\n');
      let insideMain = false;
      let unconstrainedDecl = false;
      let hasAsserts = false;
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/fn\s+main/.test(line)) insideMain = true;
        if (/unconstrained\s+fn/.test(line)) unconstrainedDecl = true;
        if (/assert|constrain/.test(line)) hasAsserts = true;
      }
      if (insideMain && !hasAsserts && !unconstrainedDecl) {
        findings.push({ line: 1, match: 'main() without any assert/constrain statements' });
      }
      return findings;
    },
    appliesTo: ['*.nr', '*.circom'],
    fix: 'Add assert() or constrain statements for every public input in fn main(). Never trust unconstrained public inputs.',
  },
  {
    id: 'ZKN-ZK-002',
    severity: 'high',
    category: 'circuit-inputs',
    title: 'Public Input Not Marked pub',
    description: 'Values intended as public inputs must be declared with pub. Private-by-default outputs cannot be verified on-chain.',
    pattern: /fn\s+main\s*\([^)]*\)[\s\S]*?\{/g,
    check: (content) => {
      const findings = [];
      const mainSig = content.match(/fn\s+main\s*\(([^)]*)\)/);
      if (mainSig) {
        const params = mainSig[1].split(',').map(p => p.trim()).filter(Boolean);
        for (const p of params) {
          if (!p.startsWith('pub ') && !p.startsWith('mut ')) {
            const cleaned = p.replace(/\s+/g, ' ').trim();
            if (cleaned.length > 0 && !cleaned.startsWith('//')) {
              findings.push({ line: 0, match: `Missing pub on main() parameter: ${cleaned}` });
            }
          }
        }
      }
      return findings;
    },
    appliesTo: ['*.nr', '*.circom'],
    fix: 'Prefix public inputs with pub in fn main() signature.',
  },
  {
    id: 'ZKN-ZK-003',
    severity: 'high',
    category: 'merkle-tree',
    title: 'Weak Merkle Tree Depth',
    description: 'Merkle tree depth < 20 creates collision risk. ZK identity and membership proofs need sufficient depth.',
    pattern: /merkle|Merkle|compute_merkle_root/gi,
    check: (content) => {
      const findings = [];
      const depthMatches = content.match(/depth\s*[=:]\s*(\d+)/gi);
      if (depthMatches) {
        for (const m of depthMatches) {
          const d = parseInt(m.match(/\d+/)[0]);
          if (d < 20) {
            findings.push({ line: 0, match: `Merkle depth ${d} < 20 - collision attack risk` });
          }
        }
      }
      if (/compute_merkle_root/.test(content) && !content.match(/depth\s*[=:]\s*(\d+)/i)) {
        findings.push({ line: 0, match: 'Merkle root computed but depth convention not verified' });
      }
      return findings;
    },
    appliesTo: ['*.nr', '*.circom'],
    fix: 'Use Merkle tree depth >= 20. For high-value identity circuits, use depth >= 32.',
  },
  {
    id: 'ZKN-ZK-004',
    severity: 'critical',
    category: 'nullifier',
    title: 'Missing Nullifier in Private State',
    description: 'Private state transitions must emit a nullifier to prevent double-spending. Missing nullifier allows replay attacks.',
    pattern: /nullifier|nullify/i,
    check: (content) => {
      const findings = [];
      const hasPrivateExternal = /#\[external\(.*private.*\)\]/.test(content) || /fn\s+\w+\(.*private/.test(content);
      const hasNullifier = /nullifier|nullify|push_nullifier/.test(content);
      if (hasPrivateExternal && !hasNullifier) {
        findings.push({ line: 0, match: 'Private external function without nullifier emission' });
      }
      return findings;
    },
    appliesTo: ['*.nr'],
    fix: 'Add push_nullifier(hash([note_commitment, nonce])) in every private function that consumes notes.',
  },
  {
    id: 'ZKN-ZK-005',
    severity: 'high',
    category: 'hash-collision',
    title: 'Poseidon2 Without Domain Separator',
    description: 'Poseidon2 hash across different domains (nullifiers, commitments, notes) without domain separator enables cross-domain collisions.',
    pattern: /poseidon2_hash|poseidon2\b/gi,
    check: (content) => {
      const findings = [];
      const poseidonCalls = [...content.matchAll(/poseidon2_hash\s*\(([^)]*)\)/gi)];
      for (const call of poseidonCalls) {
        if (!call[1].includes('domain') && !call[1].includes('tag') && !call[1].includes('context')) {
          findings.push({ line: 0, match: 'poseidon2_hash without domain separator' });
        }
      }
      return findings;
    },
    appliesTo: ['*.nr'],
    fix: 'Use domain-separated hashing: poseidon2_hash([domain_tag, ...inputs]) where domain_tag is unique per application domain.',
  },
  {
    id: 'ZKN-ZK-006',
    severity: 'high',
    category: 'ecdsa-verification',
    title: 'ECDSA Signature Without Public Key Validation',
    description: 'ECDSA verification in circuits must validate the public key is on the curve and not the point at infinity.',
    pattern: /ecdsa.*verify/gi,
    check: (content) => {
      const findings = [];
      if (/ecdsa_secp256k1::verify_signature|ecdsa_secp256r1::verify_signature/.test(content)) {
        const hasPKCheck = /on_curve|is_valid|validate.*pub|pubkey.*check/i.test(content);
        if (!hasPKCheck) {
          findings.push({ line: 0, match: 'ECDSA verify without public key validation (on-curve check)' });
        }
      }
      return findings;
    },
    appliesTo: ['*.nr'],
    fix: 'Validate the public key is on the curve and not identity before ECDSA verification. Add assert(pubkey_on_curve(pk)).',
  },
  {
    id: 'ZKN-ZK-007',
    severity: 'medium',
    category: 'block-env',
    title: 'Block Environment Dependency in Circuit',
    description: 'Using block_number or block_timestamp inside a circuit makes proofs expire and ties them to chain state.',
    pattern: /block_number|block_timestamp|block\.timestamp|std::env::block/gi,
    check: (content) => {
      const findings = [];
      const matches = [...content.matchAll(/(block_number|block_timestamp|std::env::block::\w+)/gi)];
      for (const m of matches) {
        findings.push({ line: 0, match: `Circuit depends on block environment: ${m[1]}` });
      }
      return findings;
    },
    appliesTo: ['*.nr', '*.circom'],
    fix: 'Pass block-dependent values as public inputs rather than reading them inside the circuit. Document proof expiry model.',
  },
  {
    id: 'ZKN-ZK-008',
    severity: 'high',
    category: 'recursion',
    title: 'Recursive Proof Without Verification Key Check',
    description: 'Recursive proof verification must verify the inner proof verification key hash to prevent proof substitution.',
    pattern: /verify.*proof|verify_proof/gi,
    check: (content) => {
      const findings = [];
      const hasVerifyProof = /std::verify_proof_with_type|verify_honk_proof|verify_proof/.test(content);
      const hasVKeyCheck = /verification_key|vk_hash|vkey|verify_key/i.test(content);
      if (hasVerifyProof && !hasVKeyCheck) {
        findings.push({ line: 0, match: 'Proof verification without verification key hash check - proof substitution risk' });
      }
      return findings;
    },
    appliesTo: ['*.nr'],
    fix: 'Hash the inner circuit verification key and constrain it as a public input. Use std::verify_proof_with_type with explicit vk.',
  },
  {
    id: 'ZKN-ZK-009',
    severity: 'medium',
    category: 'loop-bounds',
    title: 'Missing Loop Bound Constraint',
    description: 'Loops in circuits must have compile-time known bounds. Variable-length loops break constraint generation.',
    pattern: /for\s+/g,
    check: (content) => {
      const findings = [];
      const loops = [...content.matchAll(/for\s+(\w+)\s+in\s+([^\{]+)/g)];
      for (const loop of loops) {
        const bounds = loop[2].trim();
        if (/\.len\(\)|\.length|\.len|array_var/.test(bounds) && !/\d+/.test(bounds)) {
          findings.push({ line: 0, match: `Loop bound depends on runtime value: ${bounds}` });
        }
      }
      return findings;
    },
    appliesTo: ['*.nr', '*.circom'],
    fix: 'Use compile-time constant bounds for all circuit loops. If dynamic iteration is needed, use a maximum bound and conditional exits.',
  },
  {
    id: 'ZKN-ZK-010',
    severity: 'high',
    category: 'type-safety',
    title: 'Unsafe Type Casting in Circuit',
    description: 'Casting between Field and integer types without range check can cause silent truncation or overflow.',
    pattern: /as\s+\w+/g,
    check: (content) => {
      const findings = [];
      const casts = [...content.matchAll(/(\w+)\s+as\s+(u\d+|i\d+|Field)/g)];
      for (const cast of casts) {
        const from = cast[1];
        const to = cast[2];
        if (to !== 'Field' && !content.includes(`assert(${from}`) && !content.includes(`assert_eq(${from}`)) {
          findings.push({ line: 0, match: `Casting ${from} as ${to} without range assert` });
        }
      }
      return findings;
    },
    appliesTo: ['*.nr'],
    fix: 'Add assert() or range check before casting. Prefer Field type for circuit-internal values.',
  },
  {
    id: 'ZKN-ZK-011',
    severity: 'high',
    category: 'unconstrained',
    title: 'Unconstrained Function Used in Circuit',
    description: 'Unconstrained functions are not proving anything. Using them for critical constraints breaks soundness.',
    pattern: /unconstrained\s+fn/g,
    check: (content) => {
      const findings = [];
      const ufns = [...content.matchAll(/unconstrained\s+fn\s+(\w+)/g)];
      for (const ufn of ufns) {
        const fnName = ufn[1];
        if (!fnName.startsWith('_') && fnName !== 'main') {
          findings.push({ line: 0, match: `Unconstrained function used: ${fnName} - verify it is not used for proving` });
        }
      }
      return findings;
    },
    appliesTo: ['*.nr'],
    fix: 'Mark functions as unconstrained only for non-critical helpers (test helpers, formatting). Constrain all proving-related logic.',
  },
  {
    id: 'ZKN-ZK-012',
    severity: 'critical',
    category: 'honk-security',
    title: 'Non-ZK Honk Proof in Production',
    description: 'Honk proofs without ZK mode (verify_honk_proof_non_zk) leak witness data. Use ZK variant for production.',
    pattern: /verify_honk_proof_non_zk/g,
    check: (content) => {
      const matches = [...content.matchAll(/verify_honk_proof_non_zk/g)];
      return matches.length > 0
        ? [{ line: 0, match: `Non-ZK Honk proof used ${matches.length} time(s) - witness data may leak` }]
        : [];
    },
    appliesTo: ['*.nr'],
    fix: 'Replace verify_honk_proof_non_zk with verify_honk_proof (ZK variant) for production circuits.',
  },
];

export function matchCircuitRules(filename) {
  const ext = filename.split('.').pop();
  return CIRCUIT_RULES.filter(r =>
    r.appliesTo.some(g => {
      const pattern = g.replace('*', '');
      return filename.endsWith(pattern);
    })
  );
}
