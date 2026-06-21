export const CONTRACT_RULES = [
  {
    id: 'ZKN-SC-001',
    severity: 'critical',
    category: 'access-control',
    title: 'Ownable Without Two-Step Transfer',
    description: 'Ownable contracts should use two-step ownership transfer to prevent accidental transfer to zero address.',
    pattern: /Ownable[\s\S]{0,500}?function\s+transferOwnership\b(?!.*function\s+acceptOwnership)/gs,
    check: (ast) => {
      const hasOwnable = ast.includes('Ownable');
      const hasTwoStep = ast.includes('acceptOwnership') || ast.includes('Ownable2Step');
      return hasOwnable && !hasTwoStep ? [{ line: 0, match: 'Ownable without two-step transfer' }] : [];
    },
    fix: 'Replace Ownable with Ownable2Step from OpenZeppelin. Import Ownable2Step and inherit from it instead of Ownable.',
    appliesTo: ['*.sol'],
  },
  {
    id: 'ZKN-SC-002',
    severity: 'critical',
    category: 'reentrancy',
    title: 'Missing ReentrancyGuard',
    description: 'Functions that transfer ETH or tokens before state changes need reentrancy protection.',
    pattern: /\.(transfer|send|call)\s*\{[^}]*\}\s*[^;]*[\.\w]+\s*=/gs,
    check: (ast) => {
      const hasSafeTransfer = ast.includes('safeTransfer') || ast.includes('safeTransferFrom');
      const hasReentrancyGuard = ast.includes('ReentrancyGuard') || ast.includes('nonReentrant');
      const hasExternalTransfer = /\.(transfer|send|call)\s*\{/.test(ast) || /safeTransfer\(/.test(ast);
      return hasExternalTransfer && !hasReentrancyGuard
        ? [{ line: 0, match: 'External transfer without reentrancy guard' }]
        : [];
    },
    fix: 'Import ReentrancyGuard from OpenZeppelin and inherit from it. Add nonReentrant modifier to functions that make external transfers.',
    appliesTo: ['*.sol'],
  },
  {
    id: 'ZKN-SC-003',
    severity: 'high',
    category: 'access-control',
    title: 'Centralized Mint Risk',
    description: 'Mint functions restricted to admin roles create centralization risk. Admins can mint unlimited tokens.',
    pattern: /function\s+mint\s*\([^)]*\)\s*(external|public)\s+.*(onlyRole|onlyOwner|require\s*\([^)]*admin[^)]*\))/gs,
    check: (ast) => {
      const matches = [...ast.matchAll(/function\s+mint\s*\([^)]*\)\s*(external|public)\s+.*(onlyRole|onlyOwner)/gs)];
      return matches.map(m => ({ line: 0, match: m[0].substring(0, 80) }));
    },
    fix: 'Consider a timelock or multi-sig for mint authority. Add a MAX_SUPPLY cap if not present.',
    appliesTo: ['*.sol'],
  },
  {
    id: 'ZKN-SC-004',
    severity: 'high',
    category: 'access-control',
    title: 'Centralized Pause/Role Management',
    description: 'Pause functions and role management should not be controlled by a single EOA.',
    pattern: /(function\s+(pause|unpause|setMinter|setOperator|updateContracts|setConversionRate|grantRole)\s*\([^)]*\)\s*(external|public)\s+only(Role|Owner))/gs,
    check: (ast) => {
      const matches = [...ast.matchAll(/(function\s+(pause|unpause|grantRole|setConversionRate|updateContracts)\s*\([^)]*\)\s*(external|public)\s+onlyRole)/gs)];
      return matches.map(m => ({ line: 0, match: m[0].substring(0, 80) }));
    },
    fix: 'Use a timelock controller (OpenZeppelin TimelockController) for admin functions. Renounce admin role after setup.',
    appliesTo: ['*.sol'],
  },
  {
    id: 'ZKN-SC-005',
    severity: 'critical',
    category: 'arithmetic',
    title: 'Unsafe Cast/Truncation',
    description: 'Downcasting uint256 to smaller types without overflow check can cause truncation.',
    pattern: /uint\d+\s*\([^)]*\b(balance|amount|total|value|supply|rate)\b[^)]*\)/gs,
    check: (ast) => {
      const matches = [...ast.matchAll(/uint(8|16|32|64|128)\s*\([^)]*\)/gs)];
      return matches.map(m => ({ line: 0, match: m[0].substring(0, 60) }));
    },
    fix: 'Use OpenZeppelin SafeCast library to check overflow on downcast, or use Solidity 0.8+ built-in overflow checks.',
    appliesTo: ['*.sol'],
  },
  {
    id: 'ZKN-SC-006',
    severity: 'high',
    category: 'access-control',
    title: 'DEFAULT_ADMIN_ROLE Not Renounced',
    description: 'DEFAULT_ADMIN_ROLE should be transferred to a timelock or renounced after initial setup.',
    pattern: /_grantRole\(DEFAULT_ADMIN_ROLE,\s*msg\.sender\)/gs,
    check: (ast) => {
      const hasGrant = /_grantRole\(DEFAULT_ADMIN_ROLE,\s*msg\.sender\)/.test(ast);
      const hasTimelock = ast.includes('TimelockController') || ast.includes('timelock');
      const hasRenounce = ast.includes('renounceRole(DEFAULT_ADMIN_ROLE');
      return hasGrant && !hasRenounce && !hasTimelock
        ? [{ line: 0, match: 'DEFAULT_ADMIN_ROLE granted to deployer, not renounced or moved to timelock' }]
        : [];
    },
    fix: 'Transfer DEFAULT_ADMIN_ROLE to a TimelockController or multi-sig, then renounce from deployer.',
    appliesTo: ['*.sol'],
  },
  {
    id: 'ZKN-SC-007',
    severity: 'high',
    category: 'approve',
    title: 'Unsafe ERC20 forceApprove',
    description: 'forceApprove on variable token can fail. Standard approve + require pattern recommended.',
    pattern: /\.forceApprove\(/gs,
    check: (ast) => {
      const matches = [...ast.matchAll(/\.forceApprove\(/gs)];
      return matches.length > 0
        ? [{ line: 0, match: `forceApprove used ${matches.length} time(s)` }]
        : [];
    },
    fix: 'Use safeApprove with explicit reset to 0 first, or verify token compatibility before using forceApprove.',
    appliesTo: ['*.sol'],
  },
  {
    id: 'ZKN-SC-008',
    severity: 'medium',
    category: 'gas',
    title: 'Inefficient Loop Patterns',
    description: 'Loops over dynamic arrays can run out of gas. Use pagination or bounded arrays.',
    pattern: /for\s*\([^)]*\)\s*\{[^}]*[a-zA-Z]+\.(length|push)/gs,
    check: (ast) => {
      const matches = [...ast.matchAll(/for\s*\(uint[^)]+\).*\{[^}]*\.(length|push)/gs)];
      return matches.map(m => ({ line: 0, match: 'Unbounded loop over dynamic array' }));
    },
    fix: 'Add a maximum iteration bound or use paginated patterns. Consider using EnumerableSet.',
    appliesTo: ['*.sol'],
  },
  {
    id: 'ZKN-SC-009',
    severity: 'high',
    category: 'access-control',
    title: 'Unprotected receive()',
    description: 'Contracts that reject ETH should use revert, not accept and lock funds.',
    pattern: /receive\s*\(\s*\)\s*(external|public)\s+payable\s*\{[^}]*revert[^}]*\}/gs,
    check: (ast) => {
      const hasReceive = /receive\s*\(\s*\)\s*external\s+payable/.test(ast);
      const hasProperReject = /receive\s*\(\s*\)\s*external\s+payable\s*\{[^}]*revert/.test(ast);
      return hasReceive && hasProperReject ? [] : [];
    },
    fix: 'Add receive() external payable { revert("Contract: does not accept ETH"); }',
    appliesTo: ['*.sol'],
  },
  {
    id: 'ZKN-SC-010',
    severity: 'medium',
    category: 'solidity-version',
    title: 'Floating Pragma',
    description: 'Floating pragma ^0.8.19 can accidentally deploy with a different compiler version.',
    pattern: /pragma\s+solidity\s+\^/gs,
    check: (ast) => {
      const matches = [...ast.matchAll(/pragma\s+solidity\s+\^(\d+\.\d+\.\d+)/gs)];
      return matches.map(m => ({ line: 0, match: `Floating pragma ^${m[1]}` }));
    },
    fix: 'Lock pragma to exact version: pragma solidity 0.8.19;',
    appliesTo: ['*.sol'],
  },
];

export function matchContractRules(filename) {
  if (!filename.endsWith('.sol')) return [];
  return CONTRACT_RULES.filter(r => r.appliesTo.some(g => filename.endsWith(g.replace('*', ''))));
}
