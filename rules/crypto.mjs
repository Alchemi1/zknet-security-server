export const CRYPTO_RULES = [
  {
    id: 'ZKN-CR-001',
    severity: 'critical',
    category: 'zk-circuit',
    title: 'Unconstrained Public Inputs',
    description: 'Public inputs in ZK circuits MUST be constrained. Unconstrained inputs allow prover to cheat.',
    pattern: /(circom|noir)/gi,
    check: async (filePath, content) => {
      if (!content || typeof content !== 'string') return [];
      const findings = [];
      if (content.includes('signal input') && content.includes('signal output')) {
        const inputSignals = [...content.matchAll(/signal\s+(input|output)\s+(\w+)/gs)];
        const publicInputs = inputSignals.filter(s => s[1] === 'input');
        if (publicInputs.length > 0 && !content.includes('component main')) {
          findings.push({ line: 0, match: `Circuit with ${publicInputs.length} public inputs - verify constraints` });
        }
      }
      if (content.includes('.circom') && content.includes('pragma')) {
        const templateCount = [...content.matchAll(/template\s+(\w+)/gs)].length;
        if (templateCount > 5) {
          findings.push({ line: 0, match: `Complex circuit with ${templateCount} templates - review constraint system` });
        }
      }
      return findings;
    },
    appliesTo: ['*.circom', '*.noir', '*.nr'],
    fix: 'Ensure all public signals are constrained in the circuit. Add constraint assertions for every public input.',
  },
  {
    id: 'ZKN-CR-002',
    severity: 'critical',
    category: 'zk-pki',
    title: 'ZK-PKI Trust Root Compromise',
    description: 'ZK-PKI trust root must be decentralized. Single point of trust compromise breaks the entire PKI.',
    pattern: /ZKP?(PKI|Trust|Registry|Root)/gi,
    check: (content) => {
      const findings = [];
      if (/single\s+(authority|issuer|signer)/gi.test(content)) {
        findings.push({ line: 0, match: 'Centralized trust root detected' });
      }
      if (!/multi(\s*sig|party|authority)/gi.test(content)) {
        findings.push({ line: 0, match: 'No evidence of multi-party trust root distribution' });
      }
      return findings;
    },
    appliesTo: ['*.sol', '*.md', '*.ts', '*.js', '*.rs'],
    fix: 'Implement multi-party computation (MPC) for the PKI trust root setup ceremony. Use threshold signatures to distribute trust across multiple independent parties.',
  },
  {
    id: 'ZKN-CR-003',
    severity: 'high',
    category: 'ecdsa',
    title: 'ECDSA Nonce Reuse / Weak Nonce',
    description: 'ECDSA nonce reuse leaks the private key. zymkey deterministic signing must use RFC 6979.',
    pattern: /zymkey|sign_digest|ecdsa_sign|deterministic.*sign/gi,
    check: (content) => {
      const findings = [];
      if (/y_parity.*brute.*force|ecrecover/.test(content)) {
        findings.push({ line: 0, match: 'y_parity brute-force via ecrecover - verify RFC 6979 compliance' });
      }
      if (/sign_digest/.test(content) && !/rfc6979|k?nonce/i.test(content)) {
        findings.push({ line: 0, match: 'Deterministic signing without explicit RFC 6979 reference' });
      }
      return findings;
    },
    appliesTo: ['*.py', '*.rs', '*.ts', '*.js', '*.md'],
  },
  {
    id: 'ZKN-CR-004',
    severity: 'critical',
    category: 'verification',
    title: 'Improper ZK Proof Verification',
    description: 'ZK proofs must verify all public inputs. Missing constraints allow forged proofs.',
    pattern: /verify|verifier|Verifier|prove|Prove/gi,
    check: (content) => {
      const findings = [];
      if (/verifyProof|verify_proof/.test(content)) {
        if (!/public|input|signal/.test(content)) {
          findings.push({ line: 0, match: 'Verification without explicit public input binding' });
        }
      }
      if (/\.circom/.test(content) || /.sol/.test(content)) {
        if (content.includes('verifier') && !content.includes('Pairing')) {
          findings.push({ line: 0, match: 'Verifier contract without explicit pairing check reference' });
        }
      }
      return findings;
    },
    appliesTo: ['*.sol', '*.circom', '*.ts', '*.js', '*.py'],
  },
  {
    id: 'ZKN-CR-005',
    severity: 'critical',
    category: 'toxic-waste',
    title: 'Powers of Tau / Toxic Waste Handling',
    description: 'Ceremony output files (Toxic Waste) must be deleted after proving key generation.',
    pattern: /powersOfTau|ptau|ceremony|toxic.*waste|initial.*contribution/gi,
    check: (content) => {
      const findings = [];
      if (/ptau|powers.*tau/.test(content) && !/delete|remove|discard|cleanup/i.test(content)) {
        findings.push({ line: 0, match: 'Powers of Tau referenced but no toxic waste cleanup procedure found' });
      }
      return findings;
    },
    appliesTo: ['*.md', '*.sh', '*.toml', '*.yaml', '*.yml'],
  },
  {
    id: 'ZKN-CR-006',
    severity: 'high',
    category: 'mixnet',
    title: 'Mixnet Cryptographic Weakness',
    description: 'Echomix mixnet uses post-quantum crypto. Verify Kyber/Dilithium parameter selection.',
    pattern: /echomix|mixnet|kpclientd|katzenpost|SURB|surb/gi,
    check: (content) => {
      const findings = [];
      if (/kyber|dilithium|sphincs|frodokem/i.test(content)) {
        const params = content.match(/kyber\d+|dilithium\d+/gi);
        if (params && params.some(p => /512|2$/.test(p))) {
          findings.push({ line: 0, match: `Low-security PQ parameter: ${params.join(', ')} - consider Kyber768/Dilithium3` });
        }
      } else {
        findings.push({ line: 0, match: 'No post-quantum algorithm reference found in mixnet config' });
      }
      return findings;
    },
    appliesTo: ['*.toml', '*.yaml', '*.yml', '*.conf', '*.go', '*.rs'],
  },
  {
    id: 'ZKN-CR-007',
    severity: 'high',
    category: 'funion',
    title: 'Funion AI Inference Privacy',
    description: 'Funion anonymous AI inference must verify sender-receiver unlinkability and timing obfuscation.',
    pattern: /funion|anonymous.*inference|ai.*privacy/gi,
    check: (content) => {
      const findings = [];
      if (!/timing|latency|bucket/i.test(content)) {
        findings.push({ line: 0, match: 'Funion without explicit timing obfuscation (latency bucketing)' });
      }
      if (!/quantize|quantization/i.test(content)) {
        findings.push({ line: 0, match: 'Funion without quantization strategy for execution timing' });
      }
      return findings;
    },
    appliesTo: ['*.md', '*.ts', '*.py', '*.rs'],
  },
  {
    id: 'ZKN-CR-008',
    severity: 'critical',
    category: 'hash-function',
    title: 'Weak Hash Function Usage',
    description: 'Poseidon is ZK-friendly but must use correct parameters. Merkle tree depth impacts security.',
    pattern: /poseidon|pedersen|sha256|hash|merkle/i,
    check: (content) => {
      const findings = [];
      if (/poseidon/i.test(content) && !/constant|parameter|round/i.test(content)) {
        findings.push({ line: 0, match: 'Poseidon hash without explicit parameter/round specification' });
      }
      if (/merkle.*tree|MerkleTree/i.test(content)) {
        const depths = [...content.matchAll(/depth\s*[=:]\s*(\d+)/gi)];
        if (depths.length > 0 && depths.some(d => parseInt(d[1]) < 10)) {
          findings.push({ line: 0, match: `Shallow Merkle tree depth (${depths.map(d => d[1]).join(', ')}) - collision risk` });
        }
      }
      return findings;
    },
    appliesTo: ['*.circom', '*.noir', '*.nr', '*.sol', '*.ts', '*.rs'],
  },
  {
    id: 'ZKN-CR-009',
    severity: 'high',
    category: 'key-management',
    title: 'HSM/Zymkey Key Management',
    description: 'Hardware key slot management must verify slot isolation and backup procedures.',
    pattern: /zymkey|slot\s*\d+|hsm|secure\s*element/gi,
    check: (content) => {
      const findings = [];
      if (/slot\s+(16|21)/.test(content)) {
        findings.push({ line: 0, match: 'zymkey slot usage detected - verify slot isolation and access control' });
      }
      if (/BIP39|seed|mnemonic/i.test(content) && !/encrypt|backup|shamir/i.test(content)) {
        findings.push({ line: 0, match: 'Seed phrase without explicit encryption or backup procedure' });
      }
      return findings;
    },
    appliesTo: ['*.py', '*.md', '*.sh', '*.rs', '*.toml'],
  },
  {
    id: 'ZKN-CR-010',
    severity: 'medium',
    category: 'randomness',
    title: 'On-chain Randomness Source',
    description: 'Block hash or timestamp used as randomness source can be manipulated by validators.',
    pattern: /blockhash|block\.hash|block\.timestamp|block\.difficulty/gi,
    check: (content) => {
      const matches = [...content.matchAll(/(blockhash|block\.hash|block\.timestamp)/gi)];
      return matches.length > 0
        ? [{ line: 0, match: `On-chain randomness via ${matches[0][0]} - manipulable by validators` }]
        : [];
    },
    appliesTo: ['*.sol'],
    fix: 'Use a VRF (Chainlink VRF) or commit-reveal scheme for on-chain randomness.',
  },
];

export function matchCryptoRules(filename) {
  const ext = filename.split('.').pop();
  return CRYPTO_RULES.filter(r =>
    r.appliesTo.some(g => {
      const pattern = g.replace('*', '');
      return filename.endsWith(pattern);
    })
  );
}
