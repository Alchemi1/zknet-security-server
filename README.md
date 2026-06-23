# ZKN Security Server

MCP (Model Context Protocol) server for automated ZKNetwork security auditing. Provides evidence-gated, phase-chained audit for smart contracts, ZK circuits, mixnet, infrastructure, dApps, and supply chain.

Part of the **ZKNet Security Audit Toolkit** — a two-part system:

| Component | Location | Purpose |
|-----------|----------|---------|
| **zkn-security-server** (this) | `mcp-servers/zkn-security-server/` | MCP server + CLI for ZK-specific rule auditing (Node.js) |
| **zknet-audit-toolkit** | `src/ETHERIX/zknet-audit-toolkit/` | Python CLI for general web/backend security scanning (17 checks) |

---

## Quick Start

```bash
# Install dependencies
$ npm install

# Serve as MCP server (stdio)
$ ./zkn-audit serve

# Or use the CLI directly
$ ./zkn-audit scan /path/to/project
$ ./zkn-audit scan-file contract.sol
$ ./zkn-audit rules zk-circuits
$ ./zkn-audit rule ZKN-ZK-001
```

### MCP Tools (via stdio)

Connect this server to any MCP-compatible client (Claude, Continue, etc.) to get these tools:

| Tool | Description |
|------|-------------|
| `zkn_audit` | Run full ZKNetwork security audit across all categories |
| `zkn_fix` | Generate a prioritized fix plan from last audit results |
| `zkn_scan_file` | Scan a single file against ZKNetwork security rules |
| `zkn_preview_fix` | Preview auto-fix patches for confirmed critical findings |
| `zkn_apply_fix` | Apply auto-fix patches to files (with dry-run) |
| `zkn_list_rules` | List all rules, optionally filtered by category/severity |
| `zkn_summary` | Get summary of last audit results |
| `zkn_rule_info` | Get detailed info on a specific rule by ID |

### CLI Commands

```bash
$ zkn-audit scan [path]        # Run full audit
$ zkn-audit scan-file <file>   # Scan single file
$ zkn-audit fix [path]         # Show fix plan
$ zkn-audit apply [path]       # Apply auto-fixes
$ zkn-audit rules [category]   # List rules
$ zkn-audit rule <id>          # Show rule detail
$ zkn-audit serve              # Start MCP server
```

Options: `--min-severity`, `--category`, `--dry-run`, `--json`, `--rule-id`, `--output`, `--quiet`

---

## Architecture

```
zkn-security-server/
├── zkn-audit                 CLI entry point (bash)
├── index.mjs                 MCP server (8 tools via @modelcontextprotocol/sdk)
├── engine/
│   ├── index.mjs             ZKNAuditEngine — orchestrator
│   ├── scanner.mjs           ZKNScanner — file discovery + rule dispatch
│   ├── evidence.mjs          EvidenceGate — evidence level classification
│   ├── fixer.mjs             FixGenerator — fix plan + prompt generation
│   └── patcher.mjs           PatchGenerator — auto-fix patching (Solidity)
├── rules/
│   ├── index.mjs             Rule registry + matcher dispatch
│   ├── contracts.mjs         10 rules for Solidity smart contracts
│   ├── crypto.mjs            10 rules for ZK cryptography
│   ├── circuits.mjs          12 rules for Noir/Circom circuits
│   ├── mixnet.mjs             8 rules for mixnet communication
│   ├── infra.mjs              7 rules for infrastructure/deployment
│   ├── dapp.mjs               7 rules for dApp/frontend
│   └── supply-chain.mjs       6 rules for supply chain/dependencies
├── scripts/
│   ├── audit-report.mjs      View latest pre-commit audit report
│   ├── ci.yml                GitHub Actions workflow template
│   └── pre-commit.sh         Pre-commit hook for staged files
├── reports/                  Audit report output directory
└── package.json
```

### Audit Pipeline

```
Source Files
    │
    ▼
ZKNScanner.findFiles() — glob patterns for .sol, .nr, .circom, .toml, etc.
    │
    ▼
ZKNScanner.scanFile() — dispatches matching rules per file
    │
    ▼
60 Security Rules across 7 categories
    │
    ▼
EvidenceGate.gatedFindings() — classifies findings:
  - confirmed:   secret leak or critical + code evidence
  - likely:      code evidence with 2+ matches
  - plausible:   config evidence or 1+ match
  - unconfirmed: no evidence (filtered out)
    │
    ▼
FixGenerator.generateFixPlan() — priorities by severity
    │
    ▼
PatchGenerator — auto-fixes for Solidity (Ownable2Step, ReentrancyGuard, SafeCast, pragma lock)
```

---

## Scanner

`engine/scanner.mjs` discovers files using glob patterns, excluding build artifacts and vendored dependencies.

### File Patterns Scanned

| Pattern | Description |
|---------|-------------|
| `*.sol` | Solidity smart contracts |
| `*.circom`, `*.noir`, `*.nr` | ZK circuit source |
| `*.toml`, `*.yaml`, `*.yml` | Config files |
| `*.js`, `*.jsx`, `*.ts`, `*.tsx` | JavaScript/TypeScript |
| `*.py`, `*.rs`, `*.go` | Python, Rust, Go |
| `*.json`, `*.md`, `*.sh` | JSON, Markdown, Shell |
| `*.env*`, `.gitignore` | Environment/secrets |
| `hardhat.config.*` | Hardhat config |
| `*Dockerfile*`, `*.service` | Docker, systemd |

### Excluded Directories

`node_modules/`, `target/`, `dist/`, `build/`, `.git/`, `cache/`, `artifacts/`, `.nargo-cache/`, `.deps/`, `out/`, `vendor/`, `third_party/`, `lib/forge-std/`, `lib/openzeppelin*/`, `generated/`, `.next/`, `coverage/`, `.nyc_output/`

---

## 60 Security Rules

### Smart Contracts (10 rules) — `rules/contracts.mjs`

| ID | Severity | Title | Fix |
|----|----------|-------|-----|
| ZKN-SC-001 | **CRITICAL** | Ownable Without Two-Step Transfer | Replace Ownable with Ownable2Step |
| ZKN-SC-002 | **CRITICAL** | Missing ReentrancyGuard | Add ReentrancyGuard + nonReentrant |
| ZKN-SC-003 | HIGH | Centralized Mint Risk | Add timelock/multi-sig + MAX_SUPPLY |
| ZKN-SC-004 | HIGH | Centralized Pause/Role Management | Use TimelockController |
| ZKN-SC-005 | **CRITICAL** | Unsafe Cast/Truncation | Use SafeCast library |
| ZKN-SC-006 | HIGH | DEFAULT_ADMIN_ROLE Not Renounced | Transfer to timelock, renounce deployer |
| ZKN-SC-007 | HIGH | Unsafe forceApprove | Use safeApprove with reset to 0 |
| ZKN-SC-008 | MEDIUM | Inefficient Loop Patterns | Add max iteration bound |
| ZKN-SC-009 | HIGH | Unprotected receive() | Add revert in receive() |
| ZKN-SC-010 | MEDIUM | Floating Pragma | Lock pragma to exact version |

### ZK Cryptography (10 rules) — `rules/crypto.mjs`

| ID | Severity | Title | Category |
|----|----------|-------|----------|
| ZKN-CR-001 | **CRITICAL** | Unconstrained Public Inputs | zk-circuit |
| ZKN-CR-002 | **CRITICAL** | ZK-PKI Trust Root Compromise | zk-pki |
| ZKN-CR-003 | HIGH | ECDSA Nonce Reuse / Weak Nonce | ecdsa |
| ZKN-CR-004 | **CRITICAL** | Improper ZK Proof Verification | verification |
| ZKN-CR-005 | **CRITICAL** | Powers of Tau / Toxic Waste Handling | toxic-waste |
| ZKN-CR-006 | HIGH | Mixnet Cryptographic Weakness | mixnet |
| ZKN-CR-007 | HIGH | Funion AI Inference Privacy | funion |
| ZKN-CR-008 | **CRITICAL** | Weak Hash Function Usage | hash-function |
| ZKN-CR-009 | HIGH | HSM/Zymkey Key Management | key-management |
| ZKN-CR-010 | MEDIUM | On-chain Randomness Source | randomness |

### Noir/Circom Circuits (12 rules) — `rules/circuits.mjs`

| ID | Severity | Title | Category |
|----|----------|-------|----------|
| ZKN-ZK-001 | **CRITICAL** | Unconstrained Public Inputs | circuit-inputs |
| ZKN-ZK-002 | HIGH | Public Input Not Marked pub | circuit-inputs |
| ZKN-ZK-003 | HIGH | Weak Merkle Tree Depth | merkle-tree |
| ZKN-ZK-004 | **CRITICAL** | Missing Nullifier in Private State | nullifier |
| ZKN-ZK-005 | HIGH | Poseidon2 Without Domain Separator | hash-collision |
| ZKN-ZK-006 | HIGH | ECDSA Sig Without Public Key Validation | ecdsa-verification |
| ZKN-ZK-007 | MEDIUM | Block Environment Dependency | block-env |
| ZKN-ZK-008 | HIGH | Recursive Proof Without VK Check | recursion |
| ZKN-ZK-009 | MEDIUM | Missing Loop Bound Constraint | loop-bounds |
| ZKN-ZK-010 | HIGH | Unsafe Type Casting | type-safety |
| ZKN-ZK-011 | HIGH | Unconstrained Function Used | unconstrained |
| ZKN-ZK-012 | **CRITICAL** | Non-ZK Honk Proof in Production | honk-security |

### Mixnet (8 rules) — `rules/mixnet.mjs`

| ID | Severity | Title | Category |
|----|----------|-------|----------|
| ZKN-MX-001 | **CRITICAL** | Directory Authority Compromise | directory-auth |
| ZKN-MX-002 | HIGH | SSH Tunnel Key Management | tunnel |
| ZKN-MX-003 | HIGH | 5-Hop Mix Route Security | mix-route |
| ZKN-MX-004 | HIGH | RPC Gateway Abuse Prevention | rpc-gateway |
| ZKN-MX-005 | **CRITICAL** | PKI Client Timeout Vulnerability | pki-client |
| ZKN-MX-006 | MEDIUM | Timing Analysis Resistance | linkability |
| ZKN-MX-007 | HIGH | Pigeonhole Storage Security | pigeonhole |
| ZKN-MX-008 | HIGH | WalletShield RPC Privacy | wallet-shield |

### Infrastructure (7 rules) — `rules/infra.mjs`

| ID | Severity | Title | Category |
|----|----------|-------|----------|
| ZKN-IN-001 | **CRITICAL** | Port Exposure Audit | exposure |
| ZKN-IN-002 | HIGH | Systemd Service Hardening | service-management |
| ZKN-IN-003 | **CRITICAL** | Autonomi Node Security | autonomi |
| ZKN-IN-004 | HIGH | Monitoring Coverage | monitoring |
| ZKN-IN-005 | HIGH | Backup and Disaster Recovery | backup |
| ZKN-IN-006 | **CRITICAL** | Docker Container Security | docker |
| ZKN-IN-007 | MEDIUM | Network Segmentation | network |

### dApp (7 rules) — `rules/dapp.mjs`

| ID | Severity | Title | Category |
|----|----------|-------|----------|
| ZKN-DA-001 | **CRITICAL** | Hardcoded Secrets in Frontend | secret-exposure |
| ZKN-DA-002 | HIGH | Direct RPC Calls from Client | rpc-calls |
| ZKN-DA-003 | HIGH | Client-Only Authorization | auth |
| ZKN-DA-004 | MEDIUM | Unvalidated User Input | input-validation |
| ZKN-DA-005 | HIGH | Outdated Critical Dependency | dependency |
| ZKN-DA-006 | MEDIUM | CORS Configuration | cors |
| ZKN-DA-007 | HIGH | Sensitive Data in Browser Storage | local-storage |

### Supply Chain (6 rules) — `rules/supply-chain.mjs`

| ID | Severity | Title |
|----|----------|-------|
| ZKN-SC-001 | HIGH | Unpinned Dependency Versions |
| ZKN-SC-002 | HIGH | Missing Lockfile |
| ZKN-SC-003 | **CRITICAL** | Outdated OpenZeppelin Contracts |
| ZKN-SC-004 | MEDIUM | Hardhat Config Security |
| ZKN-SC-005 | HIGH | Rust Dependency Audit |
| ZKN-SC-006 | MEDIUM | Sensitive Files Not in .gitignore |

---

## Evidence Gate

`engine/evidence.mjs` classifies every finding into four evidence levels:

| Level | Condition |
|-------|-----------|
| `confirmed` | Secret leak detected, or critical severity + code match |
| `likely` | Code match with 2+ evidence items |
| `plausible` | Config issue or 1+ evidence item |
| `unconfirmed` | No evidence — **filtered out** from results |

Only `confirmed` + `critical` findings are eligible for auto-fix application.

---

## Auto-Fix Patcher

`engine/patcher.mjs` provides automated fix patching for Solidity contracts:

| Rule | Patch |
|------|-------|
| ZKN-SC-001 | `Ownable` → `Ownable2Step` (import + contract inheritance + constructor) |
| ZKN-SC-002 | Add `ReentrancyGuard` import + inheritance + `nonReentrant` modifiers |
| ZKN-SC-005 | Wrap unsafe casts with `SafeCast.toUint*()` + import SafeCast |
| ZKN-SC-010 | Replace `pragma solidity ^X.Y.Z` with `pragma solidity X.Y.Z` |

Patches back up the original file before modification.

---

## CI/CD Integration

### GitHub Actions

Copy `scripts/ci.yml` to `.github/workflows/zkn-security-audit.yml`. The workflow:

1. Checks out code
2. Installs dependencies
3. Runs full security audit via node inline
4. Uploads audit report as artifact
5. Posts PR comment with results (on failure)
6. **Blocks PRs with critical findings**

### Pre-commit Hook

```bash
$ ln -sf ../../mcp-servers/zkn-security-server/scripts/pre-commit.sh .git/hooks/pre-commit
```

Scans only staged `.sol`, `.nr`, `.circom`, `.toml`, `.rs`, `.py` files for fast pre-commit checks. Saves reports to `reports/precommit_*.json`.

---

## Relationship to zknet-audit-toolkit

The two tools complement each other:

| Aspect | zkn-security-server | zknet-audit-toolkit |
|--------|-------------------|-------------------|
| Runtime | Node.js (MCP + CLI) | Python (stdlib) |
| Focus | ZK-specific: circuits, contracts, mixnet, crypto | General: secrets, CORS, SQLi, XSS, headers |
| Rules | 60 rules across 7 ZK-specific categories | 17 checks for web/backend security |
| Interface | MCP protocol + bash CLI | Python CLI |
| Evidence | 4-level evidence gating (confirmed→unconfirmed) | Simple pass/fail |
| Fixes | Targeted Solidity patches | Code generation for middleware/config |

Use **zkn-security-server** for ZKNetwork-specific auditing (circuits, contracts, mixnet).  
Use **zknet-audit-toolkit** for general web/backend security scanning (secrets, headers, dependencies).

---

## Requirements

- **Node.js 18+**
- npm dependencies: `@modelcontextprotocol/sdk`, `zod`, `glob`, `minimatch`
