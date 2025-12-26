'use strict';

const fs = require('fs');
const path = require('path');

// ==================== Detection Patterns ====================

/**
 * Install lifecycle scripts that run automatically
 */
const INSTALL_SCRIPT_NAMES = new Set([
  'preinstall',
  'install', 
  'postinstall',
  'prepare',
  'prepack',
  'prepublish',
  'prepublishOnly',
]);

/**
 * Network/download command patterns (high risk in install scripts)
 */
const NETWORK_PATTERNS = [
  // Unix download tools
  /\bcurl\s/i,
  /\bwget\s/i,
  /\bfetch\s/i,
  // Windows
  /invoke-webrequest/i,
  /invoke-restmethod/i,
  /\bpowershell\b.*\b(iwr|irm|downloadstring|downloadfile)\b/i,
  /\bcertutil\b.*-urlcache/i,
  /\bbitsadmin\b.*\/transfer/i,
  // Network tools
  /\bnc\s+-[^l]/i, // nc but not listening mode
  /\bnetcat\b/i,
  /\bssh\s/i,
  /\bscp\s/i,
  /\bftp\s/i,
  /\btftp\s/i,
  /\brsync\s.*:/i,
];

/**
 * Shell execution patterns (medium-high risk)
 */
const SHELL_EXEC_PATTERNS = [
  /\bbash\s+-c\b/i,
  /\bsh\s+-c\b/i,
  /\bzsh\s+-c\b/i,
  /\bpowershell\s+-c/i,
  /\bcmd\s+\/c\b/i,
];

/**
 * Code execution patterns (high risk)
 */
const CODE_EXEC_PATTERNS = [
  /\bnode\s+-e\b/i,
  /\bnode\s+--eval\b/i,
  /\bpython[23]?\s+-c\b/i,
  /\bruby\s+-e\b/i,
  /\bperl\s+-e\b/i,
];

/**
 * Dangerous eval-like patterns in JS code
 */
const EVAL_PATTERNS = [
  /\beval\s*\(/,
  /\bnew\s+Function\s*\(/,
  /\bFunction\s*\(/,
  /\bsetTimeout\s*\(\s*['"`]/,
  /\bsetInterval\s*\(\s*['"`]/,
  /\bvm\.runInContext\s*\(/,
  /\bvm\.runInNewContext\s*\(/,
  /\bvm\.runInThisContext\s*\(/,
  /\bvm\.compileFunction\s*\(/,
];

/**
 * Child process execution patterns
 */
const CHILD_PROCESS_PATTERNS = [
  /child_process/,
  /\bexec\s*\(/,
  /\bexecSync\s*\(/,
  /\bexecFile\s*\(/,
  /\bexecFileSync\s*\(/,
  /\bspawn\s*\(/,
  /\bspawnSync\s*\(/,
  /\bfork\s*\(/,
];

/**
 * Node.js network/HTTP patterns (for code scanning)
 * These are used for data exfiltration in attacks like Shai-Hulud 2.0
 */
const NODE_NETWORK_PATTERNS = [
  /\bfetch\s*\(/,
  /\brequire\s*\(\s*['"`]https?['"`]\s*\)/,
  /\bfrom\s+['"`]https?['"`]/,
  /\bhttps?\.request\s*\(/,
  /\bhttps?\.get\s*\(/,
  /\baxios\s*[.(]/,
  /\bgot\s*[.(]/,
  /\bnode-fetch/,
  /\bundici/,
  /\bky\s*[.(]/,
  /\bsuperagent/,
  /\brequest\s*\(/,
  // WebSocket for C2 communication
  /\bWebSocket\s*\(/,
  /\bws\s*[.(]/,
  // DNS exfiltration
  /\bdns\.resolve/,
  /\bdns\.lookup/,
];

/**
 * Environment variable access patterns (potential credential stealing)
 */
const ENV_ACCESS_PATTERNS = [
  /process\.env\s*\[/,
  /process\.env\./,
  // Specific sensitive env vars
  /\b(AWS_SECRET|AWS_ACCESS|GITHUB_TOKEN|NPM_TOKEN|API_KEY|SECRET_KEY|PRIVATE_KEY|PASSWORD|CREDENTIALS?)\b/i,
];

/**
 * File system access to sensitive locations
 */
const SENSITIVE_PATH_PATTERNS = [
  /['"~]\/\.ssh/,
  /['"~]\/\.aws/,
  /['"~]\/\.npmrc/,
  /['"~]\/\.gitconfig/,
  /['"~]\/\.gnupg/,
  /['"~]\/\.config/,
  /['"~]\/\.kube/,
  /['"~]\/\.docker/,
  /\/etc\/passwd/,
  /\/etc\/shadow/,
  /\/etc\/hosts/,
];

/**
 * Obfuscation indicators
 */
const OBFUSCATION_PATTERNS = [
  // Long base64-like strings
  /['"`][A-Za-z0-9+/=]{100,}['"`]/,
  // Hex-encoded strings
  /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){10,}/,
  // Unicode escape sequences
  /\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){10,}/,
  // Array of char codes
  /String\.fromCharCode\([^)]{50,}\)/,
  // Heavily chained array methods (obfuscators love these)
  /\]\s*\[\s*['"`]\w+['"`]\s*\]\s*\[\s*['"`]\w+['"`]\s*\]/,
];

/**
 * Native binary extensions
 */
const NATIVE_EXTENSIONS = ['.node', '.so', '.dll', '.dylib', '.exe'];

/**
 * Git/version control patterns (lower risk but worth noting)
 */
const GIT_PATTERNS = [
  /\bgit\s+clone\b/i,
  /\bgit\s+fetch\b/i,
  /\bgit\s+pull\b/i,
  /\bgh\s+/i,
];

/**
 * Common typosquatting targets
 */
const POPULAR_PACKAGES = [
  'lodash', 'express', 'react', 'axios', 'moment', 'request', 'async',
  'chalk', 'commander', 'debug', 'inquirer', 'yargs', 'glob', 'mkdirp',
  'underscore', 'webpack', 'babel', 'eslint', 'typescript', 'jest',
  'mocha', 'prettier', 'vue', 'angular', 'jquery', 'bootstrap',
  'socket.io', 'mongoose', 'sequelize', 'passport', 'dotenv',
];

// ==================== Analysis Functions ====================

/**
 * Analyze a package for potential supply chain risks
 * @param {Object} pkg - Package object from collector
 * @param {Object} lockIndex - Lock file index
 * @param {Object} config - Configuration options
 * @returns {Object[]} Array of issues found
 */
function analyzePackage(pkg, lockIndex, config = {}) {
  const issues = [];
  const verbose = config.verbose || false;

  // 0. Check for package.json parse errors (potentially malicious or corrupted)
  if (pkg._parseError) {
    const issue = {
      severity: 'high',
      reason: 'corrupted_package_json',
      detail: `Cannot parse package.json: ${pkg._errorMessage}. This could indicate tampering or corruption.`,
      recommendation: 'Investigate why package.json is malformed. Run `npm ci` to reinstall packages.',
    };

    if (verbose) {
      issue.verbose = {
        evidence: {
          errorType: pkg._errorType,
          errorMessage: pkg._errorMessage,
          packagePath: pkg.dir,
        },
        falsePositiveHints: [
          '⚠ Corrupted package.json is unusual and should be investigated',
          'Could be caused by interrupted download or disk corruption',
          'Could be intentional tampering to hide malicious content',
        ],
        riskAssessment: 'HIGH - Package metadata cannot be verified',
      };
    }

    issues.push(issue);
  }

  // 1. Check lockfile integrity (version mismatch, extraneous packages)
  checkLockfileIntegrity(pkg, lockIndex, issues, verbose);

  // 2. Additional structure integrity checks (optional, enabled with --verify-integrity)
  if (config.verifyIntegrity) {
    checkPackageStructureIntegrity(pkg, lockIndex, issues, verbose);
  }

  // 3. Analyze install scripts
  analyzeScripts(pkg, config, issues, verbose);

  // 4. Check for native binaries
  checkNativeBinaries(pkg, issues, verbose);

  // 5. Check for typosquatting
  checkTyposquatting(pkg, issues, verbose);

  // 6. Check metadata anomalies
  checkMetadataAnomalies(pkg, issues, verbose);

  // 7. Optional: Deep code analysis
  if (config.scanCode) {
    analyzeCode(pkg, config, issues, verbose);
  }

  // Add verbose metadata to all issues if verbose mode
  if (verbose) {
    const metadata = getPackageMetadata(pkg);
    const trustIndicators = getTrustIndicators(pkg);
    
    for (const issue of issues) {
      issue.verbose = {
        ...issue.verbose,
        packageMetadata: metadata,
        trustIndicators,
      };
    }
  }

  return issues;
}

/**
 * Check package integrity against lockfile
 */
function checkLockfileIntegrity(pkg, lockIndex, issues, verbose = false) {
  if (!lockIndex.lockPresent) return;

  const lockByPath = lockIndex.indexByPath.get(pkg.relativePath);
  const lockByName = lockIndex.indexByName.get(pkg.name);

  if (!lockByPath && !lockByName) {
    const issue = {
      severity: 'critical',
      reason: 'extraneous_package',
      detail: 'Package exists in node_modules but is missing from lockfile. This could indicate a supply chain attack or compromised node_modules.',
      recommendation: 'Run `npm ci` to reinstall from lockfile, or investigate how this package was added.',
    };
    
    if (verbose) {
      issue.verbose = {
        evidence: {
          installedPath: pkg.dir,
          relativePath: pkg.relativePath,
          installedVersion: pkg.version,
          lockfileChecked: true,
          foundInLockByPath: false,
          foundInLockByName: false,
        },
        falsePositiveHints: [
          'Check if package was manually added via `npm install` without updating lockfile',
          'Check if this is a workspace/monorepo local package',
          'Verify lockfile is up to date with `npm install` or `npm ci`',
        ],
      };
    }
    
    issues.push(issue);
    return;
  }

  const expectedVersion = lockByPath?.version || lockByName?.version;
  if (expectedVersion && expectedVersion !== pkg.version) {
    const issue = {
      severity: 'critical', 
      reason: 'version_mismatch',
      detail: `Installed version ${pkg.version} does not match lockfile version ${expectedVersion}. Package may have been tampered with.`,
      recommendation: 'Run `npm ci` to reinstall correct version. Investigate if this was intentional.',
    };
    
    if (verbose) {
      issue.verbose = {
        evidence: {
          installedVersion: pkg.version,
          expectedVersion: expectedVersion,
          versionDiff: `${expectedVersion} → ${pkg.version}`,
          installedPath: pkg.dir,
        },
        falsePositiveHints: [
          'Check if lockfile was recently regenerated',
          'Verify with `npm ls <package-name>` to see dependency tree',
          'Could be caused by manual edits to node_modules',
        ],
      };
    }
    
    issues.push(issue);
  }
}

/**
 * Perform additional integrity checks on package structure
 * Note: We cannot verify npm's tarball integrity hashes after extraction.
 * Instead, this checks for signs of tampering in package structure.
 */
function checkPackageStructureIntegrity(pkg, lockIndex, issues, verbose = false) {
  if (!lockIndex.lockPresent) return;

  const lockByPath = lockIndex.indexByPath.get(pkg.relativePath);
  const lockByName = lockIndex.indexByName.get(pkg.name);
  const lockEntry = lockByPath || lockByName;

  if (!lockEntry) return; // Already flagged as extraneous in checkLockfileIntegrity

  // Check 1: Package should have a name matching the expected name
  const expectedName = lockByPath ? extractPackageNameFromPath(pkg.relativePath) : pkg.name;
  if (pkg.name && pkg.name !== expectedName && !pkg.name.startsWith('@')) {
    const issue = {
      severity: 'high',
      reason: 'package_name_mismatch',
      detail: `Package at "${pkg.relativePath}" has name "${pkg.name}" but expected "${expectedName}"`,
      recommendation: 'Package may have been swapped or tampered with. Run `npm ci` to reinstall.',
    };

    if (verbose) {
      issue.verbose = {
        evidence: {
          packagePath: pkg.relativePath,
          actualName: pkg.name,
          expectedName: expectedName,
        },
        falsePositiveHints: [
          'This could indicate package substitution attack',
          'Check if package.json was manually modified',
          'Verify with `npm ls` to see expected packages',
        ],
        riskAssessment: 'HIGH - Package identity mismatch',
      };
    }

    issues.push(issue);
  }

  // Check 2: If lockfile has resolved URL, check it's from expected registry
  if (lockEntry.resolved) {
    const resolved = lockEntry.resolved;
    const suspiciousPatterns = [
      /^file:/,  // Local file - unusual for published packages
      /localhost/i,
      /127\.0\.0\.1/,
      /0\.0\.0\.0/,
    ];

    for (const pattern of suspiciousPatterns) {
      if (pattern.test(resolved)) {
        const issue = {
          severity: 'high',
          reason: 'suspicious_resolved_url',
          detail: `Package resolved from suspicious URL: ${resolved.slice(0, 100)}`,
          recommendation: 'Package may be from untrusted source. Verify the resolved URL is intentional.',
        };

        if (verbose) {
          issue.verbose = {
            evidence: {
              resolvedUrl: resolved,
              packageName: pkg.name,
              matchedPattern: pattern.source,
            },
            falsePositiveHints: [
              'Local packages (file:) are normal for monorepos/workspaces',
              'Check if this is an intentional local dependency',
            ],
          };
        }

        issues.push(issue);
        break;
      }
    }
  }
}

/**
 * Extract expected package name from relative path
 */
function extractPackageNameFromPath(relativePath) {
  const parts = relativePath.split('/');
  // Handle scoped packages (@scope/name)
  if (parts[0] && parts[0].startsWith('@') && parts.length >= 2) {
    return `${parts[0]}/${parts[1]}`;
  }
  return parts[0];
}

/**
 * Analyze package scripts for suspicious patterns
 */
function analyzeScripts(pkg, config, issues, verbose = false) {
  const trustedPatterns = config.trustedPatterns || {};
  const trustedPackages = config.trustedPackages || [];

  // Check if package is trusted
  const isTrusted = trustedPackages.some(pattern => {
    if (pattern.includes('*')) {
      const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
      return regex.test(pkg.name);
    }
    return pattern === pkg.name;
  });

  for (const [scriptName, scriptValue] of Object.entries(pkg.scripts)) {
    if (typeof scriptValue !== 'string') continue;
    
    const script = String(scriptValue);
    const isInstallLifecycle = INSTALL_SCRIPT_NAMES.has(scriptName);

    // Check for trusted patterns that reduce severity
    const hasTrustedPattern = Object.keys(trustedPatterns).some(
      pattern => script.includes(pattern)
    );

    if (isInstallLifecycle) {
      // Flag all install scripts (medium baseline)
      const baseSeverity = isTrusted ? 'info' : (hasTrustedPattern ? 'low' : 'medium');
      const issue = {
        severity: baseSeverity,
        reason: 'install_script',
        detail: `Has ${scriptName} script: ${truncate(script, 200)}`,
        recommendation: 'Review the script to ensure it performs only expected operations.',
      };
      
      if (verbose) {
        issue.verbose = {
          evidence: {
            scriptName,
            scriptContent: script,
            isLifecycleScript: true,
            lifecycleType: scriptName,
          },
          scriptFile: path.join(pkg.dir, 'package.json'),
          fullScript: script,
          falsePositiveHints: [
            isTrusted ? '✓ Package is in trusted packages list' : null,
            hasTrustedPattern ? '✓ Script contains trusted pattern' : null,
            'Common install scripts include: node-gyp rebuild, prebuild-install, husky install',
            'Check if script just compiles native addons or sets up git hooks',
          ].filter(Boolean),
        };
      }
      
      issues.push(issue);

      // Check for high-risk patterns in install scripts
      analyzeScriptContent(script, scriptName, true, isTrusted, issues, verbose, pkg);
    } else {
      // Non-install scripts - still check for suspicious patterns but lower severity
      analyzeScriptContent(script, scriptName, false, isTrusted, issues, verbose, pkg);
    }
  }
}

/**
 * Analyze script content for suspicious patterns
 */
function analyzeScriptContent(script, scriptName, isInstall, isTrusted, issues, verbose = false, pkg = null) {
  // script analysis uses regex patterns directly, no need for lowercase

  // Network access
  for (const pattern of NETWORK_PATTERNS) {
    const match = script.match(pattern);
    if (match) {
      const issue = {
        severity: isInstall ? (isTrusted ? 'low' : 'high') : 'medium',
        reason: 'network_access_script',
        detail: `Script "${scriptName}" contains network access pattern: ${truncate(script, 150)}`,
        recommendation: 'Verify that network access is legitimate and from trusted sources.',
      };
      
      if (verbose) {
        issue.verbose = {
          evidence: {
            matchedPattern: pattern.source,
            matchedText: match[0],
            scriptName,
            isInstallScript: isInstall,
          },
          fullScript: script,
          scriptFile: pkg ? path.join(pkg.dir, 'package.json') : null,
          falsePositiveHints: [
            'Legitimate uses: downloading prebuilt binaries (node-gyp, prebuild)',
            'Check if URL points to official package registry or CDN',
            match[0].includes('github.com') ? '⚠ Downloads from GitHub - verify repository' : null,
          ].filter(Boolean),
        };
      }
      
      issues.push(issue);
      break;
    }
  }

  // Shell execution
  for (const pattern of SHELL_EXEC_PATTERNS) {
    const match = script.match(pattern);
    if (match) {
      const issue = {
        severity: isInstall ? 'high' : 'medium',
        reason: 'shell_execution',
        detail: `Script "${scriptName}" executes shell commands: ${truncate(script, 150)}`,
        recommendation: 'Review the shell commands being executed.',
      };
      
      if (verbose) {
        issue.verbose = {
          evidence: {
            matchedPattern: pattern.source,
            matchedText: match[0],
            scriptName,
          },
          fullScript: script,
          scriptFile: pkg ? path.join(pkg.dir, 'package.json') : null,
          falsePositiveHints: [
            'Cross-platform scripts often use shell wrappers',
            'Check what command is being executed after shell invocation',
          ],
        };
      }
      
      issues.push(issue);
      break;
    }
  }

  // Code execution
  for (const pattern of CODE_EXEC_PATTERNS) {
    const match = script.match(pattern);
    if (match) {
      const issue = {
        severity: isInstall ? 'high' : 'medium', 
        reason: 'code_execution',
        detail: `Script "${scriptName}" executes code dynamically: ${truncate(script, 150)}`,
        recommendation: 'Investigate what code is being executed.',
      };
      
      if (verbose) {
        issue.verbose = {
          evidence: {
            matchedPattern: pattern.source,
            matchedText: match[0],
            scriptName,
          },
          fullScript: script,
          scriptFile: pkg ? path.join(pkg.dir, 'package.json') : null,
          falsePositiveHints: [
            'Some build tools use inline code execution',
            'Check what code is being passed to the interpreter',
          ],
        };
      }
      
      issues.push(issue);
      break;
    }
  }

  // Git operations in install (potential for fetching malicious code)
  if (isInstall) {
    for (const pattern of GIT_PATTERNS) {
      const match = script.match(pattern);
      if (match) {
        const issue = {
          severity: 'medium',
          reason: 'git_operation_install',
          detail: `Script "${scriptName}" performs git operations: ${truncate(script, 150)}`,
          recommendation: 'Ensure git operations fetch from trusted repositories.',
        };
        
        if (verbose) {
          issue.verbose = {
            evidence: {
              matchedPattern: pattern.source,
              matchedText: match[0],
              scriptName,
            },
            fullScript: script,
            scriptFile: pkg ? path.join(pkg.dir, 'package.json') : null,
            falsePositiveHints: [
              'Husky and similar tools use git operations legitimately',
              'Check what repository is being cloned/fetched',
            ],
          };
        }
        
        issues.push(issue);
        break;
      }
    }
  }

  // Pipe to shell (extremely dangerous)
  const pipeMatch = script.match(/\|\s*(ba)?sh\b/i) || script.match(/\|\s*node\b/i);
  if (pipeMatch) {
    const issue = {
      severity: 'critical',
      reason: 'pipe_to_shell',
      detail: `Script "${scriptName}" pipes content to shell: ${truncate(script, 150)}`,
      recommendation: 'DANGER: Piping to shell is a common attack vector. Investigate immediately.',
    };
    
    if (verbose) {
      issue.verbose = {
        evidence: {
          matchedPattern: 'pipe to shell (| sh, | bash, | node)',
          matchedText: pipeMatch[0],
          scriptName,
        },
        fullScript: script,
        scriptFile: pkg ? path.join(pkg.dir, 'package.json') : null,
        falsePositiveHints: [
          '⚠ This is almost never legitimate in npm packages',
          'Common attack vector: curl URL | sh downloads and executes remote code',
        ],
        riskAssessment: 'CRITICAL - This pattern is rarely used legitimately',
      };
    }
    
    issues.push(issue);
  }

  // Environment variable exfiltration patterns
  if (isInstall && /process\.env|%\w+%|\$\w+|\$\{\w+\}/.test(script)) {
    const envMatch = script.match(/process\.env|%\w+%|\$\w+|\$\{\w+\}/);
    // Check for patterns that might send env vars somewhere
    const networkMatch = NETWORK_PATTERNS.find(p => p.test(script));
    if (networkMatch) {
      const issue = {
        severity: 'critical',
        reason: 'potential_env_exfiltration',
        detail: `Script "${scriptName}" accesses environment variables and has network access`,
        recommendation: 'This could be exfiltrating secrets. Investigate immediately.',
      };
      
      if (verbose) {
        issue.verbose = {
          evidence: {
            envPattern: envMatch ? envMatch[0] : 'environment variable access',
            networkPattern: networkMatch.source,
            scriptName,
            combinationRisk: 'Environment access + Network = potential data exfiltration',
          },
          fullScript: script,
          scriptFile: pkg ? path.join(pkg.dir, 'package.json') : null,
          falsePositiveHints: [
            '⚠ This combination is typical of credential-stealing malware',
            'Legitimate uses: sending analytics with env-based config',
            'Check if sensitive env vars (API keys, tokens) could be accessed',
          ],
          riskAssessment: 'CRITICAL - Matches Shai-Hulud 2.0 attack pattern',
        };
      }
      
      issues.push(issue);
    }
  }
}

/**
 * Check for native binary artifacts
 */
function checkNativeBinaries(pkg, issues, verbose = false) {
  const found = findNativeArtifacts(pkg.dir, 3);
  
  if (found.length > 0) {
    const listed = found.slice(0, 3).map(p => path.basename(p)).join(', ');
    const issue = {
      severity: 'low',
      reason: 'native_binary',
      detail: `Contains native binaries: ${listed}${found.length > 3 ? `, +${found.length - 3} more` : ''}`,
      recommendation: 'Native binaries are harder to audit. Ensure this is a known native module.',
    };
    
    if (verbose) {
      issue.verbose = {
        evidence: {
          binaryCount: found.length,
          binaryFiles: found.map(f => ({
            path: f,
            relativePath: path.relative(pkg.dir, f),
            filename: path.basename(f),
            extension: path.extname(f),
          })),
        },
        falsePositiveHints: [
          'Common native modules: node-sass, bcrypt, sharp, sqlite3, canvas',
          'Check if package is a known native addon',
          'Native binaries are precompiled for performance-critical operations',
        ],
      };
    }
    
    issues.push(issue);
  }
}

/**
 * Find native artifact files in package
 */
function findNativeArtifacts(pkgDir, maxDepth = 3) {
  const found = [];
  const stack = [{ dir: pkgDir, depth: 0 }];

  while (stack.length > 0) {
    const { dir, depth } = stack.pop();
    if (depth > maxDepth) continue;

    let entries = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      
      if (entry.isDirectory() && !entry.name.startsWith('.')) {
        stack.push({ dir: fullPath, depth: depth + 1 });
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (NATIVE_EXTENSIONS.includes(ext)) {
          found.push(fullPath);
        }
      }
    }
  }

  return found;
}

/**
 * Trusted npm organizations/scopes (official packages, not typosquatting)
 */
const TRUSTED_SCOPES = new Set([
  '@eslint',
  '@babel',
  '@types',
  '@jest',
  '@angular',
  '@vue',
  '@react',
  '@microsoft',
  '@google',
  '@aws-sdk',
  '@swc',
  '@vercel',
  '@nestjs',
  '@prisma',
  '@emotion',
  '@chakra-ui',
  '@mui',
  '@tanstack',
  '@trpc',
  '@octokit',
  '@humanwhocodes', // ESLint ecosystem
  '@nodelib',
]);

/**
 * Known legitimate packages that might trigger false positives
 */
const KNOWN_LEGITIMATE_PACKAGES = new Set([
  'esquery',      // ESLint query language, not related to jquery
  'is-glob',      // Well-known utility
  'is-number',    // Well-known utility
  'has-flag',     // Well-known utility
  'get-stream',   // Well-known utility
  'node-fetch',   // Official fetch polyfill
  'cross-env',    // Well-known utility
  'fast-glob',    // Well-known utility
]);

/**
 * Check for potential typosquatting
 */
function checkTyposquatting(pkg, issues, verbose = false) {
  // Skip trusted scopes
  if (pkg.name.startsWith('@')) {
    const scope = pkg.name.split('/')[0];
    if (TRUSTED_SCOPES.has(scope)) {
      return;
    }
  }

  // Skip known legitimate packages
  if (KNOWN_LEGITIMATE_PACKAGES.has(pkg.name)) {
    return;
  }

  const pkgName = pkg.name.replace(/^@[^/]+\//, ''); // Remove scope for comparison
  
  for (const popular of POPULAR_PACKAGES) {
    if (pkgName === popular) continue;
    
    // Skip if names are too different in length
    const lengthDiff = Math.abs(pkgName.length - popular.length);
    if (lengthDiff > 3) continue;
    
    const distance = levenshteinDistance(pkgName.toLowerCase(), popular.toLowerCase());
    
    // More strict threshold for short names (less than 5 chars need exact match or 1 diff)
    const threshold = pkgName.length < 5 ? 1 : 2;
    
    // Flag if very similar
    if (distance > 0 && distance <= threshold) {
      const issue = {
        severity: 'high',
        reason: 'potential_typosquat',
        detail: `Package name "${pkg.name}" is similar to popular package "${popular}" (edit distance: ${distance})`,
        recommendation: 'Verify this is the intended package and not a typosquatting attack.',
      };
      
      if (verbose) {
        // Calculate character differences
        const differences = [];
        const maxLen = Math.max(pkgName.length, popular.length);
        for (let i = 0; i < maxLen; i++) {
          if (pkgName[i] !== popular[i]) {
            differences.push({
              position: i,
              actual: pkgName[i] || '(missing)',
              expected: popular[i] || '(extra)',
            });
          }
        }
        
        issue.verbose = {
          evidence: {
            packageName: pkg.name,
            similarTo: popular,
            editDistance: distance,
            characterDifferences: differences,
            lengthDiff: pkgName.length - popular.length,
          },
          comparison: {
            actual: pkgName,
            popular: popular,
            diff: differences.map(d => `position ${d.position}: '${d.actual}' vs '${d.expected}'`).join(', '),
          },
          falsePositiveHints: [
            'Check npm page: https://www.npmjs.com/package/' + pkg.name,
            'Compare download counts with the popular package',
            'Check if this package is a legitimate fork or variant',
            'Verify the package author and repository',
          ],
          verificationSteps: [
            `1. Visit https://www.npmjs.com/package/${pkg.name}`,
            `2. Compare with https://www.npmjs.com/package/${popular}`,
            '3. Check weekly downloads, GitHub stars, and maintainers',
            '4. Verify the package was intentionally added to package.json',
          ],
        };
      }
      
      issues.push(issue);
      break;
    }
  }

  // Check for common typosquatting patterns (only for unscoped packages)
  if (!pkg.name.startsWith('@')) {
    checkSuspiciousNamePatterns(pkg, pkgName, issues, verbose);
  }
}

/**
 * Check for suspicious naming patterns that might indicate typosquatting
 */
function checkSuspiciousNamePatterns(pkg, pkgName, issues, verbose = false) {
  const suspiciousPatterns = [
    // Prepending common words to popular package names
    { pattern: /^(get|my|the|fake|real|true|best|free|super|ultra)-?(.+)$/i, group: 2 },
    // Numbers that look like letter substitution (l00dash, r3act)
    { pattern: /[0-9]/, check: 'substitution' },
  ];

  for (const { pattern, group, check } of suspiciousPatterns) {
    if (check === 'substitution') {
      // Check for l33t speak style substitutions
      const normalized = pkgName
        .replace(/0/g, 'o')
        .replace(/1/g, 'l')
        .replace(/3/g, 'e')
        .replace(/4/g, 'a')
        .replace(/5/g, 's')
        .replace(/7/g, 't');
      
      if (normalized !== pkgName && POPULAR_PACKAGES.includes(normalized.toLowerCase())) {
        const issue = {
          severity: 'high',
          reason: 'suspicious_name_pattern',
          detail: `Package name "${pkg.name}" uses character substitution similar to "${normalized}"`,
          recommendation: 'This could be a typosquatting attempt using character substitution.',
        };
        
        if (verbose) {
          const substitutions = [];
          for (let i = 0; i < pkgName.length; i++) {
            if (pkgName[i] !== normalized[i]) {
              substitutions.push({ position: i, original: pkgName[i], normalized: normalized[i] });
            }
          }
          
          issue.verbose = {
            evidence: {
              technique: 'leet speak / character substitution',
              originalName: pkgName,
              normalizedName: normalized,
              substitutions,
              targetPackage: normalized.toLowerCase(),
            },
            falsePositiveHints: [
              'Check if package name predates the popular package',
              'Verify package functionality matches expected behavior',
              'Check author/maintainer reputation',
            ],
          };
        }
        
        issues.push(issue);
        break;
      }
    } else if (pattern.test(pkgName)) {
      const match = pkgName.match(pattern);
      if (match && match[group]) {
        const stripped = match[group].toLowerCase();
        if (POPULAR_PACKAGES.includes(stripped)) {
          const issue = {
            severity: 'medium',
            reason: 'suspicious_name_pattern',
            detail: `Package name "${pkg.name}" might be impersonating "${stripped}"`,
            recommendation: 'Verify this is the intended package.',
          };
          
          if (verbose) {
            issue.verbose = {
              evidence: {
                technique: 'prefix pattern',
                prefix: match[1],
                basePackage: stripped,
                fullName: pkg.name,
              },
              falsePositiveHints: [
                'Some legitimate packages use prefixes (e.g., "my-lodash-plugin")',
                'Check if this is a wrapper, plugin, or extension',
                'Verify package purpose in README and documentation',
              ],
            };
          }
          
          issues.push(issue);
          break;
        }
      }
    }
  }
}

/**
 * Check package metadata for anomalies
 */
function checkMetadataAnomalies(pkg, issues, verbose = false) {
  // Very new package with install scripts and no repository
  const installScripts = Object.keys(pkg.scripts).filter(s => INSTALL_SCRIPT_NAMES.has(s));
  
  if (!pkg.repository && installScripts.length > 0) {
    const issue = {
      severity: 'low',
      reason: 'no_repository',
      detail: 'Package has install scripts but no repository URL',
      recommendation: 'Packages without source repository are harder to audit.',
    };
    
    if (verbose) {
      issue.verbose = {
        evidence: {
          hasRepository: false,
          installScripts: installScripts,
          hasHomepage: !!pkg.homepage,
          hasAuthor: !!pkg.author,
        },
        packageJsonPath: path.join(pkg.dir, 'package.json'),
        falsePositiveHints: [
          'Some private/internal packages may not have public repos',
          'Check if homepage provides source code access',
          'Author information can help verify legitimacy',
        ],
      };
    }
    
    issues.push(issue);
  }

  // Empty or very short description with install scripts
  if ((!pkg.description || pkg.description.length < 10) && installScripts.length > 0) {
    const issue = {
      severity: 'info',
      reason: 'minimal_metadata',
      detail: 'Package has minimal description',
      recommendation: 'Low-quality metadata can indicate hastily published or malicious packages.',
    };
    
    if (verbose) {
      issue.verbose = {
        evidence: {
          description: pkg.description || '(empty)',
          descriptionLength: pkg.description?.length || 0,
          hasReadme: fs.existsSync(path.join(pkg.dir, 'README.md')),
          installScripts: installScripts,
        },
        packageJsonPath: path.join(pkg.dir, 'package.json'),
        falsePositiveHints: [
          'Some utility packages have minimal descriptions',
          'Check README.md for more details',
          'Look at package usage in your codebase',
        ],
      };
    }
    
    issues.push(issue);
  }
}

/**
 * Deep code analysis (optional, slower)
 */
function analyzeCode(pkg, config, issues, verbose = false) {
  const maxFileSize = config.maxFileSizeForCodeScan || 1024 * 1024;
  const maxFiles = config.maxFilesPerPackage || 0; // 0 = unlimited
  const jsFiles = findJsFiles(pkg.dir, 5); // Scan up to 5 levels deep

  // Apply file limit (0 means scan all files)
  const filesToScan = maxFiles > 0 ? jsFiles.slice(0, maxFiles) : jsFiles;

  for (const filePath of filesToScan) {
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > maxFileSize) continue;

      const content = fs.readFileSync(filePath, 'utf8');
      const relativePath = path.relative(pkg.dir, filePath);

      // Check for eval patterns
      for (const pattern of EVAL_PATTERNS) {
        if (pattern.test(content)) {
          const issue = {
            severity: 'high',
            reason: 'eval_usage',
            detail: `File "${relativePath}" uses eval() or similar dynamic code execution`,
            recommendation: 'eval() can execute arbitrary code and is often used in attacks.',
          };
          
          if (verbose) {
            const snippet = extractCodeSnippet(content, pattern, 3);
            const allMatches = findAllMatches(content, pattern, 5);
            
            issue.verbose = {
              evidence: {
                file: filePath,
                relativePath,
                pattern: pattern.source,
                matchCount: allMatches.length,
                matches: allMatches,
              },
              codeSnippet: snippet?.snippet || null,
              lineNumber: snippet?.lineNumber || null,
              matchedText: snippet?.matchedText || null,
              falsePositiveHints: [
                'Some legitimate uses: JSON parsing fallbacks, template engines',
                'Check if eval is used on user-controlled input',
                'vm module usage may be legitimate for sandboxing',
              ],
            };
          }
          
          issues.push(issue);
          break;
        }
      }

      // Check for child_process
      for (const pattern of CHILD_PROCESS_PATTERNS) {
        if (pattern.test(content)) {
          const issue = {
            severity: 'medium',
            reason: 'child_process_usage',
            detail: `File "${relativePath}" uses child_process module`,
            recommendation: 'child_process can execute system commands. Verify usage is legitimate.',
          };
          
          if (verbose) {
            const snippet = extractCodeSnippet(content, pattern, 3);
            const allMatches = findAllMatches(content, pattern, 5);
            
            issue.verbose = {
              evidence: {
                file: filePath,
                relativePath,
                pattern: pattern.source,
                matchCount: allMatches.length,
                matches: allMatches,
              },
              codeSnippet: snippet?.snippet || null,
              lineNumber: snippet?.lineNumber || null,
              matchedText: snippet?.matchedText || null,
              falsePositiveHints: [
                'Build tools commonly use child_process (webpack, babel plugins)',
                'CLI tools often spawn child processes',
                'Check what commands are being executed',
              ],
            };
          }
          
          issues.push(issue);
          break;
        }
      }

      // Check for sensitive path access
      for (const pattern of SENSITIVE_PATH_PATTERNS) {
        if (pattern.test(content)) {
          const issue = {
            severity: 'high',
            reason: 'sensitive_path_access',
            detail: `File "${relativePath}" accesses sensitive paths (${pattern.source})`,
            recommendation: 'Accessing ~/.ssh, ~/.aws, or similar paths can indicate credential theft.',
          };
          
          if (verbose) {
            const snippet = extractCodeSnippet(content, pattern, 3);
            const allMatches = findAllMatches(content, pattern, 5);
            
            issue.verbose = {
              evidence: {
                file: filePath,
                relativePath,
                pattern: pattern.source,
                sensitivePath: pattern.source,
                matchCount: allMatches.length,
                matches: allMatches,
              },
              codeSnippet: snippet?.snippet || null,
              lineNumber: snippet?.lineNumber || null,
              matchedText: snippet?.matchedText || null,
              falsePositiveHints: [
                'SSH/Git tools may legitimately access ~/.ssh',
                'AWS SDK wrappers may check ~/.aws for config',
                'Check if access is read-only or if data is transmitted',
              ],
              riskAssessment: 'HIGH - Verify data is not exfiltrated',
            };
          }
          
          issues.push(issue);
          break;
        }
      }

      // Check for Node.js network patterns (like Shai-Hulud 2.0 attack)
      for (const pattern of NODE_NETWORK_PATTERNS) {
        if (pattern.test(content)) {
          const issue = {
            severity: 'medium',
            reason: 'node_network_access',
            detail: `File "${relativePath}" uses Node.js network APIs (${pattern.source})`,
            recommendation: 'Network access in dependencies should be reviewed for legitimacy.',
          };
          
          if (verbose) {
            const snippet = extractCodeSnippet(content, pattern, 3);
            const allMatches = findAllMatches(content, pattern, 5);
            
            issue.verbose = {
              evidence: {
                file: filePath,
                relativePath,
                pattern: pattern.source,
                matchCount: allMatches.length,
                matches: allMatches,
              },
              codeSnippet: snippet?.snippet || null,
              lineNumber: snippet?.lineNumber || null,
              matchedText: snippet?.matchedText || null,
              falsePositiveHints: [
                'HTTP client libraries (axios, got, fetch) are common',
                'Check what URLs/endpoints are being accessed',
                'Verify network calls match package purpose',
              ],
            };
          }
          
          issues.push(issue);
          break;
        }
      }

      // Check for env var access (in context)
      const envMatch = ENV_ACCESS_PATTERNS.find(p => p.test(content));
      if (envMatch) {
        // Only flag if also has network patterns or child_process
        const networkMatch = NETWORK_PATTERNS.find(p => p.test(content));
        const nodeNetworkMatch = NODE_NETWORK_PATTERNS.find(p => p.test(content));
        const childProcessMatch = CHILD_PROCESS_PATTERNS.find(p => p.test(content));
        
        if (networkMatch || nodeNetworkMatch || childProcessMatch) {
          const issue = {
            severity: 'critical',
            reason: 'env_with_network',
            detail: `File "${relativePath}" accesses environment variables and has network/exec capabilities`,
            recommendation: 'DANGER: This pattern matches credential exfiltration attacks like Shai-Hulud 2.0. Investigate immediately.',
          };
          
          if (verbose) {
            const envSnippet = extractCodeSnippet(content, envMatch, 3);
            const networkSnippet = nodeNetworkMatch 
              ? extractCodeSnippet(content, nodeNetworkMatch, 3)
              : (networkMatch ? extractCodeSnippet(content, networkMatch, 3) : null);
            
            const envMatches = findAllMatches(content, envMatch, 5);
            
            issue.verbose = {
              evidence: {
                file: filePath,
                relativePath,
                envPattern: envMatch.source,
                networkPattern: (nodeNetworkMatch || networkMatch)?.source,
                childProcessPattern: childProcessMatch?.source || null,
                envAccessPoints: envMatches,
              },
              envCodeSnippet: envSnippet?.snippet || null,
              envLineNumber: envSnippet?.lineNumber || null,
              networkCodeSnippet: networkSnippet?.snippet || null,
              networkLineNumber: networkSnippet?.lineNumber || null,
              falsePositiveHints: [
                '⚠ This is a HIGH-RISK pattern matching known attacks',
                'Legitimate uses: reading config from env for API calls',
                'Check what env vars are accessed and where data is sent',
              ],
              riskAssessment: 'CRITICAL - Matches Shai-Hulud 2.0 and similar attack patterns',
              attackPattern: 'Environment variable access combined with network/exec = potential credential exfiltration',
            };
          }
          
          issues.push(issue);
        }
      }

      // Check for obfuscation
      for (const pattern of OBFUSCATION_PATTERNS) {
        if (pattern.test(content)) {
          const issue = {
            severity: 'critical',
            reason: 'obfuscated_code',
            detail: `File "${relativePath}" appears to contain obfuscated code`,
            recommendation: 'DANGER: Obfuscated code is highly suspicious. Investigate immediately.',
          };
          
          if (verbose) {
            const snippet = extractCodeSnippet(content, pattern, 3);
            const match = content.match(pattern);
            
            issue.verbose = {
              evidence: {
                file: filePath,
                relativePath,
                obfuscationType: getObfuscationType(pattern),
                sampleMatch: match ? truncate(match[0], 100) : null,
              },
              codeSnippet: snippet?.snippet || null,
              lineNumber: snippet?.lineNumber || null,
              falsePositiveHints: [
                'Minified code may trigger this - check if it\'s build output',
                'Base64 encoded assets (images, fonts) are usually safe',
                'Check if obfuscation is consistent with package purpose',
              ],
              riskAssessment: 'CRITICAL - Obfuscated code in packages is highly unusual',
            };
          }
          
          issues.push(issue);
          break;
        }
      }

    } catch {
      // Skip files that can't be read
      continue;
    }
  }
}

/**
 * Determine the type of obfuscation based on pattern
 */
function getObfuscationType(pattern) {
  const source = pattern.source;
  if (source.includes('base64') || source.includes('A-Za-z0-9+/=')) {
    return 'base64_encoding';
  }
  if (source.includes('\\\\x')) {
    return 'hex_encoding';
  }
  if (source.includes('\\\\u')) {
    return 'unicode_escape';
  }
  if (source.includes('fromCharCode')) {
    return 'charcode_obfuscation';
  }
  return 'general_obfuscation';
}

/**
 * Find JavaScript files in package
 */
function findJsFiles(dir, maxDepth = 2) {
  const files = [];
  const stack = [{ dir, depth: 0 }];

  while (stack.length > 0) {
    const { dir: currentDir, depth } = stack.pop();
    if (depth > maxDepth) continue;

    let entries = [];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch {
      continue;
    }

    for (const entry of entries) {
      if (entry.name.startsWith('.')) continue;
      if (entry.name === 'node_modules') continue;

      const fullPath = path.join(currentDir, entry.name);

      if (entry.isDirectory()) {
        stack.push({ dir: fullPath, depth: depth + 1 });
      } else if (entry.isFile() && /\.(js|mjs|cjs)$/.test(entry.name)) {
        files.push(fullPath);
      }
    }
  }

  return files;
}

/**
 * Calculate Levenshtein distance between two strings
 */
function levenshteinDistance(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix = [];

  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

/**
 * Truncate string for display
 */
function truncate(str, maxLen) {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 3) + '...';
}

/**
 * Extract code snippet with context around a match
 * @param {string} content - Full file content
 * @param {RegExp} pattern - Pattern to find
 * @param {number} contextLines - Number of lines before/after to include
 * @returns {Object|null} Snippet info with line number, matched text, and context
 */
function extractCodeSnippet(content, pattern, contextLines = 3) {
  const lines = content.split('\n');
  
  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(pattern);
    if (match) {
      const startLine = Math.max(0, i - contextLines);
      const endLine = Math.min(lines.length - 1, i + contextLines);
      
      const snippetLines = [];
      for (let j = startLine; j <= endLine; j++) {
        const lineNum = String(j + 1).padStart(4, ' ');
        const marker = j === i ? '>>>' : '   ';
        snippetLines.push(`${marker} ${lineNum} | ${lines[j]}`);
      }
      
      return {
        lineNumber: i + 1,
        column: match.index + 1,
        matchedText: match[0],
        snippet: snippetLines.join('\n'),
        lineContent: lines[i],
      };
    }
  }
  return null;
}

/**
 * Find all matches of a pattern in content with line info
 * @param {string} content - Full file content
 * @param {RegExp} pattern - Pattern to find
 * @returns {Object[]} Array of match info objects
 */
function findAllMatches(content, pattern, maxMatches = 5) {
  const lines = content.split('\n');
  const matches = [];
  
  for (let i = 0; i < lines.length && matches.length < maxMatches; i++) {
    const match = lines[i].match(pattern);
    if (match) {
      matches.push({
        lineNumber: i + 1,
        column: match.index + 1,
        matchedText: match[0],
        lineContent: lines[i].trim(),
      });
    }
  }
  return matches;
}

/**
 * Get package metadata for verbose output
 * @param {Object} pkg - Package object
 * @returns {Object} Metadata for verbose display
 */
function getPackageMetadata(pkg) {
  return {
    author: pkg.author || null,
    repository: pkg.repository || null,
    license: pkg.license || null,
    homepage: pkg.homepage || null,
    description: pkg.description || null,
    fullPath: pkg.dir,
    hasTypes: !!(pkg.dependencies?.['typescript'] || pkg.name?.startsWith('@types/')),
  };
}

/**
 * Check if package is from a trusted source (for false positive hints)
 * @param {Object} pkg - Package object
 * @returns {Object} Trust indicators
 */
function getTrustIndicators(pkg) {
  const indicators = {
    isScopedPackage: pkg.name?.startsWith('@') || false,
    trustedScope: false,
    hasRepository: !!pkg.repository,
    hasHomepage: !!pkg.homepage,
    hasAuthor: !!pkg.author,
    hasLicense: !!pkg.license,
    knownLegitimate: KNOWN_LEGITIMATE_PACKAGES.has(pkg.name) || false,
  };
  
  if (indicators.isScopedPackage) {
    const scope = pkg.name.split('/')[0];
    indicators.trustedScope = TRUSTED_SCOPES.has(scope);
    indicators.scope = scope;
  }
  
  // Calculate trust score (0-100)
  let trustScore = 0;
  if (indicators.trustedScope) trustScore += 40;
  if (indicators.hasRepository) trustScore += 20;
  if (indicators.hasHomepage) trustScore += 10;
  if (indicators.hasAuthor) trustScore += 10;
  if (indicators.hasLicense) trustScore += 10;
  if (indicators.knownLegitimate) trustScore += 50;
  
  indicators.trustScore = Math.min(100, trustScore);
  indicators.trustLevel = trustScore >= 70 ? 'high' : trustScore >= 40 ? 'medium' : 'low';
  
  return indicators;
}

module.exports = {
  analyzePackage,
  INSTALL_SCRIPT_NAMES,
  POPULAR_PACKAGES,
  extractCodeSnippet,
  findAllMatches,
  getPackageMetadata,
  getTrustIndicators,
};
