'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

/**
 * Lockfile types supported
 */
const LOCKFILE_TYPES = {
  NPM_V2: 'npm-v2',
  NPM_V1: 'npm-v1',
  YARN_CLASSIC: 'yarn-classic',
  YARN_BERRY: 'yarn-berry',
  PNPM: 'pnpm',
  BUN: 'bun',
};

/**
 * Build an index from lockfile for fast lookups
 * @param {string|null} lockPath - Path to lockfile
 * @returns {Object} Lock index with lookup maps
 */
function buildLockIndex(lockPath) {
  const emptyIndex = {
    indexByPath: new Map(),
    indexByName: new Map(),
    lockVersion: null,
    lockPresent: false,
    lockType: null,
  };

  if (!lockPath || !fs.existsSync(lockPath)) {
    return emptyIndex;
  }

  const filename = path.basename(lockPath);
  
  try {
    if (filename === 'package-lock.json' || filename === 'npm-shrinkwrap.json') {
      return parseNpmLockfile(lockPath);
    }
    if (filename === 'yarn.lock') {
      return parseYarnLockfile(lockPath);
    }
    if (filename === 'pnpm-lock.yaml') {
      return parsePnpmLockfile(lockPath);
    }
    if (filename === 'bun.lock' || filename === 'bun.lockb') {
      return parseBunLockfile(lockPath);
    }
  } catch (err) {
    console.warn(`Warning: Cannot parse lockfile ${lockPath}: ${err.message}`);
    return emptyIndex;
  }

  return emptyIndex;
}

/**
 * Parse npm package-lock.json or npm-shrinkwrap.json
 */
function parseNpmLockfile(lockPath) {
  const content = fs.readFileSync(lockPath, 'utf8');
  const lock = JSON.parse(content);
  
  const indexByPath = new Map();
  const indexByName = new Map();
  const lockVersion = lock.lockfileVersion || 1;
  const lockType = lockVersion >= 2 ? LOCKFILE_TYPES.NPM_V2 : LOCKFILE_TYPES.NPM_V1;

  if (lock.packages && typeof lock.packages === 'object') {
    // npm lockfile v2/v3
    for (const [pkgPath, meta] of Object.entries(lock.packages)) {
      if (!pkgPath) continue; // Skip root package
      
      const relPath = pkgPath.startsWith('node_modules/')
        ? pkgPath.slice('node_modules/'.length)
        : pkgPath;
      
      const name = meta.name || extractNameFromPath(relPath);
      const version = meta.version || 'unknown';
      const resolved = meta.resolved || null;
      const integrity = meta.integrity || null;

      indexByPath.set(relPath, { name, version, resolved, integrity });
      
      // Only set by name if not already set (first occurrence wins, usually top-level)
      if (!indexByName.has(name)) {
        indexByName.set(name, { version, resolved, integrity });
      }
    }
  } else if (lock.dependencies && typeof lock.dependencies === 'object') {
    // npm lockfile v1 fallback
    walkNpmV1Dependencies(lock.dependencies, indexByName);
  }

  return {
    indexByPath,
    indexByName,
    lockVersion,
    lockPresent: true,
    lockType,
  };
}

/**
 * Recursively walk npm v1 dependencies
 */
function walkNpmV1Dependencies(deps, indexByName, prefix = '') {
  for (const [name, meta] of Object.entries(deps)) {
    const fullName = prefix ? `${prefix}/node_modules/${name}` : name;
    
    if (!indexByName.has(name)) {
      indexByName.set(name, {
        version: meta.version,
        resolved: meta.resolved || null,
        integrity: meta.integrity || null,
      });
    }

    if (meta.dependencies) {
      walkNpmV1Dependencies(meta.dependencies, indexByName, fullName);
    }
  }
}

/**
 * Parse yarn.lock file (classic and berry formats)
 */
function parseYarnLockfile(lockPath) {
  const content = fs.readFileSync(lockPath, 'utf8');
  const indexByPath = new Map();
  const indexByName = new Map();

  // Check if it's Yarn Berry (v2+) format - starts with __metadata
  const isBerry = content.includes('__metadata:');
  const lockType = isBerry ? LOCKFILE_TYPES.YARN_BERRY : LOCKFILE_TYPES.YARN_CLASSIC;

  if (isBerry) {
    parseYarnBerryLock(content, indexByName);
  } else {
    parseYarnClassicLock(content, indexByName);
  }

  return {
    indexByPath,
    indexByName,
    lockVersion: isBerry ? 2 : 1,
    lockPresent: true,
    lockType,
  };
}

/**
 * Parse Yarn Classic (v1) lock format
 */
function parseYarnClassicLock(content, indexByName) {
  // Simple parser for yarn.lock v1 format
  // Format: "package@version":\n  version "x.y.z"\n  resolved "url"\n  integrity "sha..."
  const lines = content.split('\n');
  let currentPackages = [];
  let currentVersion = null;
  let currentResolved = null;
  let currentIntegrity = null;

  for (const line of lines) {
    // Package declaration line (e.g., "lodash@^4.17.0", "lodash@~4.17.0":)
    if (line.match(/^"?[@\w]/) && line.includes('@') && line.endsWith(':')) {
      // Save previous package if exists
      if (currentPackages.length > 0 && currentVersion) {
        for (const pkg of currentPackages) {
          const name = extractPackageName(pkg);
          if (name && !indexByName.has(name)) {
            indexByName.set(name, {
              version: currentVersion,
              resolved: currentResolved,
              integrity: currentIntegrity,
            });
          }
        }
      }

      // Parse new package declarations
      currentPackages = line
        .slice(0, -1) // Remove trailing :
        .split(',')
        .map(s => s.trim().replace(/^"|"$/g, ''));
      currentVersion = null;
      currentResolved = null;
      currentIntegrity = null;
    } else if (line.startsWith('  version ')) {
      currentVersion = line.match(/version "([^"]+)"/)?.[1] || null;
    } else if (line.startsWith('  resolved ')) {
      currentResolved = line.match(/resolved "([^"]+)"/)?.[1] || null;
    } else if (line.startsWith('  integrity ')) {
      currentIntegrity = line.match(/integrity ([^\s]+)/)?.[1] || null;
    }
  }

  // Handle last package
  if (currentPackages.length > 0 && currentVersion) {
    for (const pkg of currentPackages) {
      const name = extractPackageName(pkg);
      if (name && !indexByName.has(name)) {
        indexByName.set(name, {
          version: currentVersion,
          resolved: currentResolved,
          integrity: currentIntegrity,
        });
      }
    }
  }
}

/**
 * Parse Yarn Berry (v2+) lock format
 */
function parseYarnBerryLock(content, indexByName) {
  // Yarn Berry uses YAML-like format
  // Format: "package@npm:version":\n  version: x.y.z\n  resolution: "..."
  const lines = content.split('\n');
  let currentPackages = [];
  let currentVersion = null;
  let currentResolution = null;
  let currentChecksum = null;

  for (const line of lines) {
    // Skip metadata and comments
    if (line.startsWith('__metadata:') || line.startsWith('#')) continue;

    // Package declaration (quoted string with colon at end)
    if (line.match(/^"[^"]+":$/) || line.match(/^'[^']+':$/)) {
      // Save previous
      if (currentPackages.length > 0 && currentVersion) {
        for (const pkg of currentPackages) {
          const name = extractPackageNameBerry(pkg);
          if (name && !indexByName.has(name)) {
            indexByName.set(name, {
              version: currentVersion,
              resolved: currentResolution,
              integrity: currentChecksum,
            });
          }
        }
      }

      currentPackages = [line.slice(1, -2)]; // Remove quotes and colon
      currentVersion = null;
      currentResolution = null;
      currentChecksum = null;
    } else if (line.match(/^\s+version:/)) {
      currentVersion = line.split(':')[1]?.trim().replace(/^"|"$/g, '') || null;
    } else if (line.match(/^\s+resolution:/)) {
      currentResolution = line.split('resolution:')[1]?.trim().replace(/^"|"$/g, '') || null;
    } else if (line.match(/^\s+checksum:/)) {
      currentChecksum = line.split('checksum:')[1]?.trim() || null;
    }
  }

  // Handle last package
  if (currentPackages.length > 0 && currentVersion) {
    for (const pkg of currentPackages) {
      const name = extractPackageNameBerry(pkg);
      if (name && !indexByName.has(name)) {
        indexByName.set(name, {
          version: currentVersion,
          resolved: currentResolution,
          integrity: currentChecksum,
        });
      }
    }
  }
}

/**
 * Parse pnpm-lock.yaml
 */
function parsePnpmLockfile(lockPath) {
  const content = fs.readFileSync(lockPath, 'utf8');
  const indexByPath = new Map();
  const indexByName = new Map();

  // Simple YAML-like parsing for pnpm-lock.yaml
  // We're looking for packages under 'packages:' key
  const lines = content.split('\n');
  let inPackages = false;
  let currentPkg = null;
  let currentVersion = null;
  let currentResolution = null;

  for (const line of lines) {
    if (line === 'packages:') {
      inPackages = true;
      continue;
    }

    if (inPackages) {
      // New package entry (indented path like "  /lodash@4.17.21:")
      const pkgMatch = line.match(/^\s{2}[/'"]?([^:'"]+)['":]?:/);
      if (pkgMatch) {
        // Save previous
        if (currentPkg && currentVersion) {
          const name = extractPnpmPackageName(currentPkg);
          if (name && !indexByName.has(name)) {
            indexByName.set(name, {
              version: currentVersion,
              resolved: currentResolution,
              integrity: null,
            });
          }
        }

        currentPkg = pkgMatch[1];
        currentVersion = null;
        currentResolution = null;
      } else if (line.match(/^\s{4}version:/)) {
        currentVersion = line.split(':')[1]?.trim().replace(/^['"]|['"]$/g, '') || null;
      } else if (line.match(/^\s{4}resolution:/)) {
        currentResolution = line.split('resolution:')[1]?.trim().replace(/^['"]|['"]$/g, '') || null;
      } else if (!line.startsWith(' ') && line.length > 0) {
        // End of packages section
        break;
      }
    }
  }

  // Handle last package
  if (currentPkg && currentVersion) {
    const name = extractPnpmPackageName(currentPkg);
    if (name && !indexByName.has(name)) {
      indexByName.set(name, {
        version: currentVersion,
        resolved: currentResolution,
        integrity: null,
      });
    }
  }

  return {
    indexByPath,
    indexByName,
    lockVersion: null,
    lockPresent: true,
    lockType: LOCKFILE_TYPES.PNPM,
  };
}

/**
 * Parse bun.lock file (JSON format)
 * Format: { lockfileVersion, workspaces, packages }
 * packages is an object where keys are package names and values are arrays:
 * [full_name@version, registry_path, options_object, integrity_hash]
 */
function parseBunLockfile(lockPath) {
  let content = fs.readFileSync(lockPath, 'utf8');
  const indexByPath = new Map();
  const indexByName = new Map();

  // Check if it's binary format (bun.lockb)
  if (content.charCodeAt(0) === 0 || !content.startsWith('{')) {
    console.warn('Warning: bun.lockb (binary) format is not supported. Use bun.lock (text) instead.');
    console.warn('Run "bun install --save-text-lockfile" to generate a text lockfile.');
    return {
      indexByPath,
      indexByName,
      lockVersion: null,
      lockPresent: false,
      lockType: null,
    };
  }

  let lock;
  try {
    // bun.lock uses JSONC-like format with trailing commas
    // Remove trailing commas before parsing
    content = content.replace(/,(\s*[}\]])/g, '$1');
    lock = JSON.parse(content);
  } catch (err) {
    console.warn(`Warning: Cannot parse bun.lock: ${err.message}`);
    return {
      indexByPath,
      indexByName,
      lockVersion: null,
      lockPresent: false,
      lockType: null,
    };
  }

  const lockVersion = lock.lockfileVersion || 1;

  // Parse packages object
  // Format: { "package-name": ["package-name@version", "", {...}, "sha512-..."] }
  if (lock.packages && typeof lock.packages === 'object') {
    for (const [, pkgData] of Object.entries(lock.packages)) {
      if (!Array.isArray(pkgData) || pkgData.length === 0) continue;

      const fullSpec = pkgData[0]; // e.g., "@cloudflare/kv-asset-handler@0.3.4"
      const integrity = pkgData[3] || null; // sha512 hash

      // Extract name and version from full spec
      const { name, version } = extractBunPackageInfo(fullSpec);
      
      if (name && version) {
        const entry = {
          version,
          resolved: null,
          integrity,
        };

        indexByPath.set(name, entry);
        
        if (!indexByName.has(name)) {
          indexByName.set(name, entry);
        }
      }
    }
  }

  // Also parse workspace dependencies if available
  if (lock.workspaces && typeof lock.workspaces === 'object') {
    for (const [, wsData] of Object.entries(lock.workspaces)) {
      if (!wsData) continue;
      
      // Parse dependencies, devDependencies, etc.
      const depTypes = ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies'];
      for (const depType of depTypes) {
        if (wsData[depType] && typeof wsData[depType] === 'object') {
          for (const depName of Object.keys(wsData[depType])) {
            // Workspace deps only have version spec (e.g., "^1.0.0"), not resolved version
            // The actual resolved version is in the packages section
            if (!indexByName.has(depName)) {
              // We'll mark it as present but version comes from packages
              indexByName.set(depName, { version: null, resolved: null, integrity: null });
            }
          }
        }
      }
    }
  }

  return {
    indexByPath,
    indexByName,
    lockVersion,
    lockPresent: true,
    lockType: LOCKFILE_TYPES.BUN,
  };
}

/**
 * Extract package name and version from bun lockfile spec
 * e.g., "@cloudflare/kv-asset-handler@0.3.4" -> { name: "@cloudflare/kv-asset-handler", version: "0.3.4" }
 */
function extractBunPackageInfo(spec) {
  if (!spec || typeof spec !== 'string') {
    return { name: null, version: null };
  }

  // Handle scoped packages: @scope/name@version
  if (spec.startsWith('@')) {
    const lastAtIndex = spec.lastIndexOf('@');
    if (lastAtIndex > 0) {
      return {
        name: spec.slice(0, lastAtIndex),
        version: spec.slice(lastAtIndex + 1),
      };
    }
    return { name: spec, version: null };
  }

  // Regular package: name@version
  const atIndex = spec.indexOf('@');
  if (atIndex > 0) {
    return {
      name: spec.slice(0, atIndex),
      version: spec.slice(atIndex + 1),
    };
  }

  return { name: spec, version: null };
}

/**
 * Extract package name from path like "@scope/pkg/node_modules/dep"
 */
function extractNameFromPath(relPath) {
  const parts = relPath.split('node_modules/');
  const last = parts[parts.length - 1];
  return last.split('/').slice(0, last.startsWith('@') ? 2 : 1).join('/');
}

/**
 * Extract package name from yarn classic spec like "lodash@^4.17.0"
 */
function extractPackageName(spec) {
  // Handle scoped packages: @scope/name@version
  if (spec.startsWith('@')) {
    const atIndex = spec.indexOf('@', 1);
    return atIndex > 0 ? spec.slice(0, atIndex) : spec;
  }
  // Regular package: name@version
  const atIndex = spec.indexOf('@');
  return atIndex > 0 ? spec.slice(0, atIndex) : spec;
}

/**
 * Extract package name from yarn berry spec like "lodash@npm:4.17.21"
 */
function extractPackageNameBerry(spec) {
  // Format: package@npm:version or @scope/package@npm:version
  const npmIndex = spec.indexOf('@npm:');
  if (npmIndex > 0) {
    return spec.slice(0, npmIndex);
  }
  return extractPackageName(spec);
}

/**
 * Extract package name from pnpm path like "/lodash@4.17.21" or "/@scope/pkg@1.0.0"
 */
function extractPnpmPackageName(pkgPath) {
  // Remove leading slash
  const path = pkgPath.startsWith('/') ? pkgPath.slice(1) : pkgPath;
  
  // Handle scoped packages
  if (path.startsWith('@')) {
    const match = path.match(/^(@[^/]+\/[^@]+)@/);
    return match ? match[1] : path;
  }
  
  // Regular package
  const match = path.match(/^([^@]+)@/);
  return match ? match[1] : path;
}

/**
 * Parse an integrity string (e.g., "sha512-abc123..." or "sha1-xyz...")
 * @param {string} integrity - Integrity string from lockfile
 * @returns {Object|null} Parsed integrity with algorithm and hash
 */
function parseIntegrity(integrity) {
  if (!integrity || typeof integrity !== 'string') {
    return null;
  }

  // Handle multiple hashes (space-separated, prefer sha512)
  const hashes = integrity.trim().split(/\s+/);
  
  // Prefer sha512, then sha384, then sha256, then sha1
  const preferenceOrder = ['sha512', 'sha384', 'sha256', 'sha1'];
  
  for (const preferred of preferenceOrder) {
    const match = hashes.find(h => h.startsWith(`${preferred}-`));
    if (match) {
      const dashIndex = match.indexOf('-');
      return {
        algorithm: match.slice(0, dashIndex),
        hash: match.slice(dashIndex + 1),
        raw: match,
      };
    }
  }

  // Fallback to first hash
  const first = hashes[0];
  if (first && first.includes('-')) {
    const dashIndex = first.indexOf('-');
    return {
      algorithm: first.slice(0, dashIndex),
      hash: first.slice(dashIndex + 1),
      raw: first,
    };
  }

  return null;
}

/**
 * Compute integrity hash of a package directory
 * Uses package.json content as the primary verification target
 * @param {string} pkgDir - Path to package directory
 * @param {string} algorithm - Hash algorithm (sha512, sha256, sha1)
 * @returns {string|null} Base64-encoded hash or null on error
 */
function computePackageIntegrity(pkgDir, algorithm = 'sha512') {
  try {
    const pkgJsonPath = path.join(pkgDir, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) {
      return null;
    }

    const content = fs.readFileSync(pkgJsonPath);
    const hash = crypto.createHash(algorithm);
    hash.update(content);
    return hash.digest('base64');
  } catch (err) {
    console.warn(`Warning: Cannot compute package integrity for ${pkgDir}: ${err.message}`);
    return null;
  }
}

/**
 * Verify package integrity against lockfile
 * @param {Object} pkg - Package object with dir property
 * @param {Object} lockEntry - Lockfile entry with integrity property
 * @returns {Object} Verification result
 */
function verifyPackageIntegrity(pkg, lockEntry) {
  const result = {
    verified: false,
    expected: null,
    actual: null,
    algorithm: null,
    error: null,
    skipped: false,
  };

  if (!lockEntry || !lockEntry.integrity) {
    result.skipped = true;
    result.error = 'No integrity hash in lockfile';
    return result;
  }

  const parsed = parseIntegrity(lockEntry.integrity);
  if (!parsed) {
    result.skipped = true;
    result.error = 'Cannot parse integrity hash';
    return result;
  }

  result.expected = parsed.hash;
  result.algorithm = parsed.algorithm;

  const actualHash = computePackageIntegrity(pkg.dir, parsed.algorithm);
  if (!actualHash) {
    result.error = 'Cannot compute package hash';
    return result;
  }

  result.actual = actualHash;
  result.verified = actualHash === parsed.hash;

  return result;
}

/**
 * Compute integrity hash for a tarball/file (for accurate npm integrity verification)
 * Note: npm's integrity is computed on the tarball, not individual files
 * This is a best-effort verification using package.json as a proxy
 * @param {string} filePath - Path to file
 * @param {string} algorithm - Hash algorithm
 * @returns {string|null} Formatted integrity string or null
 */
function computeFileIntegrity(filePath, algorithm = 'sha512') {
  try {
    const content = fs.readFileSync(filePath);
    const hash = crypto.createHash(algorithm);
    hash.update(content);
    return `${algorithm}-${hash.digest('base64')}`;
  } catch (err) {
    console.warn(`Warning: Cannot compute file integrity for ${filePath}: ${err.message}`);
    return null;
  }
}

module.exports = {
  buildLockIndex,
  LOCKFILE_TYPES,
  parseIntegrity,
  computePackageIntegrity,
  verifyPackageIntegrity,
  computeFileIntegrity,
};
