import fs from 'fs';
import path from 'path';

export class PatchGenerator {
  constructor(basePath) {
    this.basePath = basePath;
  }

  generatePatch(finding, content) {
    const { ruleId } = finding;
    try {
      switch (ruleId) {
        case 'ZKN-SC-001': return this._fixOwnable2Step(content, finding.file);
        case 'ZKN-SC-002': return this._fixReentrancyGuard(content, finding.file);
        case 'ZKN-SC-005': return this._fixSafeCast(content, finding.file);
        default: return null;
      }
    } catch (e) {
      return { error: e.message };
    }
  }

  _detectImportStyle(content) {
    if (/import\s+{/.test(content)) return 'named';
    if (/import\s+"/.test(content)) return 'bare';
    return 'bare';
  }

  _fixOwnable2Step(content, file) {
    const patches = [];

    if (content.includes('Ownable2Step')) return null;

    const style = this._detectImportStyle(content);

    if (style === 'bare') {
      const oldImport = `import "@openzeppelin/contracts/access/Ownable.sol";`;
      const newImport = `import "@openzeppelin/contracts/access/Ownable2Step.sol";`;
      if (content.includes(oldImport)) {
        patches.push({ oldString: oldImport, newString: newImport });
      }
    } else {
      const oldImport = /import\s*\{[^}]*Ownable[^}]*\}\s*from\s*"@openzeppelin\/contracts\/access\/Ownable\.sol"\s*;/g;
      const match = content.match(oldImport);
      if (match) {
        for (const m of match) {
          const replacement = m.replace(/\bOwnable\b/g, 'Ownable2Step');
          patches.push({ oldString: m, newString: replacement });
        }
      }
    }

    const contractMatch = content.match(/(contract\s+\w+\s+is\s+)(\w+(?:\s*,\s*\w+)*)/);
    if (contractMatch) {
      const baseContracts = contractMatch[2].split(',').map(s => s.trim());
      if (baseContracts.includes('Ownable')) {
        const newBases = baseContracts.map(b => b === 'Ownable' ? 'Ownable2Step' : b).join(', ');
        patches.push({
          oldString: contractMatch[0],
          newString: `${contractMatch[1]}${newBases}`,
        });
      }
    }

    const ctorMatch = content.match(/(\w+)\(msg\.sender\)\s*\{/);
    if (ctorMatch && ctorMatch[1] === 'Ownable') {
      patches.push({
        oldString: `Ownable(msg.sender) {`,
        newString: `Ownable2Step(msg.sender) {`,
      });
    }

    return patches.length > 0 ? patches : null;
  }

  _fixReentrancyGuard(content, file) {
    const patches = [];

    if (content.includes('ReentrancyGuard')) return null;

    const style = this._detectImportStyle(content);

    if (style === 'bare') {
      const importPath = `@openzeppelin/contracts/security/ReentrancyGuard.sol`;
      const lastImport = [...content.matchAll(/^import\s+"[^"]+"\s*;/gm)];
      if (lastImport.length > 0) {
        const last = lastImport[lastImport.length - 1];
        patches.push({
          oldString: last[0],
          newString: `${last[0]}\nimport "${importPath}";`,
        });
      }
    } else {
      const lastImport = [...content.matchAll(/^import\s*\{[^}]*\}\s*from\s*"[^"]+"\s*;/gm)];
      if (lastImport.length > 0) {
        const last = lastImport[lastImport.length - 1];
        patches.push({
          oldString: last[0],
          newString: `${last[0]}\nimport {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";`,
        });
      }
    }

    const contractMatch = content.match(/(contract\s+\w+\s+is\s+)([\w,\s]+)/);
    if (contractMatch) {
      const bases = contractMatch[2].split(',').map(s => s.trim());
      if (!bases.includes('ReentrancyGuard')) {
        bases.push('ReentrancyGuard');
        patches.push({
          oldString: contractMatch[0],
          newString: `${contractMatch[1]}${bases.join(', ')}`,
        });
      }
    }

    const externalCalls = [...content.matchAll(/(function\s+\w+\s*\([^)]*\)\s*(?:external|public)[^;]*?\{[^}]*\.(?:transferFrom|safeTransfer|safeTransferFrom|call\s*\{)[^}]*\})/gs)];
    for (const call of externalCalls) {
      const funcBody = call[1];
      if (!funcBody.includes('nonReentrant')) {
        const funcSig = funcBody.match(/(function\s+\w+\s*\([^)]*\)\s*(?:external|public))/);
        if (funcSig) {
          patches.push({
            oldString: funcSig[0],
            newString: `${funcSig[0]} nonReentrant`,
          });
        }
      }
    }

    return patches.length > 0 ? patches : null;
  }

  _fixSafeCast(content, file) {
    const patches = [];

    const unsafeCasts = [...content.matchAll(/uint(8|16|32|64|128)\s*\(([^)]*)\)/g)];
    if (unsafeCasts.length === 0) return null;

    for (const cast of unsafeCasts) {
      const castStr = cast[0];
      const type = cast[1];
      const inner = cast[2].trim();

      if (patches.some(p => p.oldString === castStr)) continue;

      const after = `SafeCast.toUint${type}(${inner})`;
      patches.push({ oldString: castStr, newString: after });
    }

    if (patches.length > 0 && !content.includes('using SafeCast')) {
      const importMatch = [...content.matchAll(/^import\s*\{[^}]*\}\s*from\s*(['"])[^'"]+\1\s*;$/gm)];
      if (importMatch.length > 0) {
        const lastImport = importMatch[importMatch.length - 1][0];
        const quote = importMatch[importMatch.length - 1][1];
        patches.unshift({
          oldString: lastImport,
          newString: `${lastImport}\nimport {SafeCast} from ${quote}@openzeppelin/contracts/utils/math/SafeCast.sol${quote};`
        });
        const uc = [...content.matchAll(/using\s+\w+\s+for\s+\w+\s*;/g)];
        if (uc.length > 0) {
          patches.unshift({
            oldString: uc[uc.length - 1][0],
            newString: `${uc[uc.length - 1][0]}\n    using SafeCast for uint256;`
          });
        }
      } else {
        const bareImports = [...content.matchAll(/^import\s+(['"])[^'"]+\1\s*;$/gm)];
        if (bareImports.length > 0) {
          const lastImport = bareImports[bareImports.length - 1][0];
          const quote = bareImports[bareImports.length - 1][1];
          patches.unshift({
            oldString: lastImport,
            newString: `${lastImport}\nimport ${quote}@openzeppelin/contracts/utils/math/SafeCast.sol${quote};`
          });
          const uc = [...content.matchAll(/using\s+\w+\s+for\s+\w+\s*;/g)];
          if (uc.length > 0) {
            patches.unshift({
              oldString: uc[uc.length - 1][0],
              newString: `${uc[uc.length - 1][0]}\n    using SafeCast for uint256;`
            });
          }
        }
      }
    }

    return patches.length > 0 ? patches : null;
  }

  async applyPatch(filePath, patches) {
    if (!patches || patches.length === 0) return { applied: 0, file: filePath };
    let content = fs.readFileSync(filePath, 'utf-8');
    let count = 0;

    for (const patch of patches) {
      if (content.includes(patch.oldString)) {
        content = content.replaceAll(patch.oldString, patch.newString);
        const occ = content.split(patch.newString).length - 1;
        count += occ;
      }
    }

    fs.writeFileSync(filePath, content, 'utf-8');
    return { applied: count, total: patches.length, file: filePath };
  }

  dryRunPatch(filePath, patches) {
    if (!patches || patches.length === 0) return { changes: [], file: filePath };
    const content = fs.readFileSync(filePath, 'utf-8');
    const changes = [];

    for (const patch of patches) {
      const idx = content.indexOf(patch.oldString);
      if (idx !== -1) {
        const lineNum = content.substring(0, idx).split('\n').length;
        changes.push({
          line: lineNum,
          oldString: patch.oldString.substring(0, 80) + (patch.oldString.length > 80 ? '...' : ''),
          newString: patch.newString.substring(0, 80) + (patch.newString.length > 80 ? '...' : ''),
        });
      }
    }

    return { changes, total: patches.length, file: filePath };
  }
}
