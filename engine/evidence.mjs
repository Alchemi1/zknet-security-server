export const EVIDENCE_LEVELS = {
  CONFIRMED: 'confirmed',
  LIKELY: 'likely',
  PLAUSIBLE: 'plausible',
  UNCONFIRMED: 'unconfirmed',
};

export class EvidenceGate {
  constructor() {
    this.evidenceStore = new Map();
  }

  recordEvidence(findingId, evidence) {
    if (!this.evidenceStore.has(findingId)) {
      this.evidenceStore.set(findingId, []);
    }
    this.evidenceStore.get(findingId).push(evidence);
  }

  classifyFinding(findingId, severity, category) {
    const evidence = this.evidenceStore.get(findingId) || [];
    const hasCodeEvidence = evidence.some(e => e.type === 'code_match');
    const hasConfigEvidence = evidence.some(e => e.type === 'config_issue');
    const hasSecretEvidence = evidence.some(e => e.type === 'secret_leak');
    const evidenceCount = evidence.length;

    if (hasSecretEvidence || (severity === 'critical' && hasCodeEvidence)) {
      return EVIDENCE_LEVELS.CONFIRMED;
    }
    if (hasCodeEvidence && evidenceCount >= 2) {
      return EVIDENCE_LEVELS.LIKELY;
    }
    if (hasConfigEvidence || evidenceCount >= 1) {
      return EVIDENCE_LEVELS.PLAUSIBLE;
    }
    return EVIDENCE_LEVELS.UNCONFIRMED;
  }

  gatedFindings(rawFindings) {
    const gated = [];
    for (const f of rawFindings) {
      const findingId = `${f.ruleId}:${f.file}`;
      for (const match of (f.evidence || [])) {
        this.recordEvidence(findingId, {
          type: this._evidenceType(f.category, match),
          detail: match.match || match,
          line: match.line,
          file: f.file,
        });
      }
      const level = this.classifyFinding(findingId, f.severity, f.category);
      gated.push({
        ...f,
        evidenceLevel: level,
        passedGate: level !== EVIDENCE_LEVELS.UNCONFIRMED,
      });
    }
    return gated.sort((a, b) => {
      const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
      const aSev = sevOrder[a.severity] ?? 99;
      const bSev = sevOrder[b.severity] ?? 99;
      if (aSev !== bSev) return aSev - bSev;
      const evOrder = [EVIDENCE_LEVELS.CONFIRMED, EVIDENCE_LEVELS.LIKELY, EVIDENCE_LEVELS.PLAUSIBLE, EVIDENCE_LEVELS.UNCONFIRMED];
      return evOrder.indexOf(a.evidenceLevel) - evOrder.indexOf(b.evidenceLevel);
    });
  }

  _evidenceType(category, match) {
    if (category === 'secret-exposure') return 'secret_leak';
    if (['key-management', 'rpc-calls'].includes(category)) return 'secret_leak';
    if (['zk-circuit', 'verification', 'ecdsa', 'hash-function'].includes(category)) return 'crypto_weakness';
    if (['directory-auth', 'tunnel', 'mix-route', 'rpc-gateway', 'pki-client', 'linkability'].includes(category)) return 'config_issue';
    if (['access-control', 'reentrancy', 'arithmetic', 'approve'].includes(category)) return 'code_match';
    return 'config_issue';
  }
}
