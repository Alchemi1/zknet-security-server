import { CONTRACT_RULES, matchContractRules } from './contracts.mjs';
import { CRYPTO_RULES, matchCryptoRules } from './crypto.mjs';
import { MIXNET_RULES, matchMixnetRules } from './mixnet.mjs';
import { INFRA_RULES, matchInfraRules } from './infra.mjs';
import { DAPP_RULES, matchDappRules } from './dapp.mjs';
import { SUPPLY_CHAIN_RULES, matchSupplyChainRules } from './supply-chain.mjs';
import { CIRCUIT_RULES, matchCircuitRules } from './circuits.mjs';

export const ALL_RULES = [
  ...CONTRACT_RULES,
  ...CRYPTO_RULES,
  ...MIXNET_RULES,
  ...INFRA_RULES,
  ...DAPP_RULES,
  ...SUPPLY_CHAIN_RULES,
  ...CIRCUIT_RULES,
];

export const RULE_CATEGORIES = {
  'smart-contracts': { rules: CONTRACT_RULES, label: 'Smart Contract Security' },
  'zk-cryptography': { rules: CRYPTO_RULES, label: 'ZK Cryptography' },
  'zk-circuits': { rules: CIRCUIT_RULES, label: 'Noir/Circom Circuit Security' },
  'mixnet': { rules: MIXNET_RULES, label: 'Mixnet & Communication' },
  'infrastructure': { rules: INFRA_RULES, label: 'Infrastructure & Deployment' },
  'dapp': { rules: DAPP_RULES, label: 'dApp & Frontend' },
  'supply-chain': { rules: SUPPLY_CHAIN_RULES, label: 'Supply Chain & Dependencies' },
};

export function getRulesForFile(filename) {
  const matchers = [
    matchContractRules,
    matchCryptoRules,
    matchCircuitRules,
    matchMixnetRules,
    matchInfraRules,
    matchDappRules,
    matchSupplyChainRules,
  ];
  return matchers.flatMap(m => m(filename));
}

export function getRulesByCategory(category) {
  if (!category) return ALL_RULES;
  return ALL_RULES.filter(r => r.category === category);
}

export function getRuleById(id) {
  return ALL_RULES.find(r => r.id === id);
}
