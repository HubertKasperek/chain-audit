'use strict';

const fs = require('fs');
const path = require('path');

// ==================== Detection Patterns ====================

/**
 * Install lifecycle scripts that run automatically during package installation
 */
const INSTALL_SCRIPT_NAMES = new Set([
  'preinstall',
  'install', 
  'postinstall',
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
  // Only match actual WebSocket usage, not variable names like ws.length
  /\bWebSocket\s*\(/,
  /\b(?:new\s+)?ws\s*\(/,  // ws() or new ws() - actual WebSocket constructor
  /\brequire\s*\(\s*['"`]ws['"`]\s*\)/,  // require('ws')
  /\bfrom\s+['"`]ws['"`]/,  // from 'ws'
  /\bws\.(?:connect|send|close|on|emit)/,  // ws.connect, ws.send, etc.
  // DNS exfiltration
  /\bdns\.resolve/,
  /\bdns\.lookup/,
];

/**
 * Environment variable access patterns (potential credential stealing)
 * IMPORTANT: Must detect process.env in all forms (with dot, bracket, or standalone)
 */
const ENV_ACCESS_PATTERNS = [
  /process\.env\s*\[/,      // process.env['KEY']
  /process\.env\./,         // process.env.KEY
  /\bprocess\.env\b/,       // process.env (standalone, e.g., JSON.stringify(process.env))
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
  checkLockfileIntegrity(pkg, lockIndex, issues, verbose, config);

  // 2. Additional structure integrity checks (optional, enabled with --verify-integrity)
  if (config.verifyIntegrity) {
    checkPackageStructureIntegrity(pkg, lockIndex, issues, verbose);
  }

  // 3. Analyze install scripts
  analyzeScripts(pkg, config, issues, verbose);

  // 4. Check for native binaries
  checkNativeBinaries(pkg, issues, verbose);

  // 5. Check for typosquatting (optional, enabled with --check-typosquatting)
  if (config.checkTyposquatting) {
    checkTyposquatting(pkg, issues, verbose);
  }

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
function checkLockfileIntegrity(pkg, lockIndex, issues, verbose = false, config = {}) {
  // Skip if lockfile checking is disabled
  if (!config.checkLockfile) return;
  if (!lockIndex.lockPresent) return;

  const lockByPath = lockIndex.indexByPath.get(pkg.relativePath);
  const lockByName = lockIndex.indexByName.get(pkg.name);

  if (!lockByPath && !lockByName) {
    const issue = {
      severity: 'medium',
      reason: 'extraneous_package',
      detail: 'Package exists in node_modules but is missing from lockfile. This is often a false positive (e.g., lockfile not synced after `npm install`). Could also indicate a supply chain attack.',
      recommendation: 'Run `npm ci` to reinstall from lockfile. If this persists, investigate how this package was added.',
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
          '✓ This is often a false positive - most common cause: lockfile not synced after `npm install`',
          '✓ Check if package was manually added via `npm install` without updating lockfile',
          '✓ Check if this is a workspace/monorepo local package',
          '✓ Verify lockfile is up to date: run `npm install` to sync, or `npm ci` to reinstall',
          '⚠ If lockfile is synced and this persists, investigate - could be supply chain attack',
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

  // Check if package is trusted (from config or known legitimate packages)
  const isTrustedFromConfig = trustedPackages.some(pattern => {
    if (pattern.includes('*')) {
      const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
      return regex.test(pkg.name);
    }
    return pattern === pkg.name;
  });
  const isTrusted = isTrustedFromConfig || KNOWN_LEGITIMATE_PACKAGES.has(pkg.name);

  for (const [scriptName, scriptValue] of Object.entries(pkg.scripts)) {
    if (typeof scriptValue !== 'string') continue;
    
    const script = String(scriptValue);
    const isInstallLifecycle = INSTALL_SCRIPT_NAMES.has(scriptName);

    // Check for trusted patterns that reduce severity
    const hasTrustedPattern = Object.keys(trustedPatterns).some(
      pattern => script.includes(pattern)
    );
    
    // Additional context: check if script is just calling npm/node commands (less suspicious)
    const isSimpleNpmCommand = /^(npm|yarn|pnpm|bun)\s+(run|test|start|build|install|ci)/i.test(script.trim());

    if (isInstallLifecycle) {
      // Flag all install scripts (medium baseline)
      // Reduce severity if it's just a simple npm command or has trusted patterns
      let baseSeverity = isTrusted ? 'info' : (hasTrustedPattern ? 'low' : 'medium');
      
      // Check for common legitimate install script patterns
      const isCommonLegitimatePattern = 
        /^(npm|yarn|pnpm|bun)\s+(run|test|start|build|install|ci|audit)/i.test(script.trim()) ||
        /^node\s+install\.js$/i.test(script.trim()) ||
        /^node\s+.*\/install\.js$/i.test(script.trim()) ||
        /^node\s+install\/check$/i.test(script.trim()) || // sharp uses this
        /^(prebuild-install|node-gyp|node-pre-gyp)/i.test(script.trim()) ||
        /^husky\s+install/i.test(script.trim()) ||
        /^patch-package/i.test(script.trim()) ||
        /^node\s+.*\/postinstall/i.test(script.trim()); // Some packages have postinstall scripts
      
      if (isSimpleNpmCommand && !isTrusted && !hasTrustedPattern) {
        baseSeverity = 'low'; // Simple npm commands in install scripts are less suspicious
      } else if (isCommonLegitimatePattern && !isTrusted && !hasTrustedPattern) {
        baseSeverity = 'low'; // Common legitimate patterns are less suspicious
      }
      
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
            isSimpleNpmCommand ? '✓ Script is a simple npm command (less suspicious)' : null,
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

  // Network access - reduce false positives for build/test scripts
  for (const pattern of NETWORK_PATTERNS) {
    const match = script.match(pattern);
    if (match) {
      // Check if it's a build/test script (less suspicious)
      const isBuildOrTestScript = /^(build|test|test:.*|build:.*|compile|transpile|prepublish|prepublishOnly)$/i.test(scriptName);
      
      // Check if it's a release/docs script (often use git fetch legitimately)
      const isReleaseOrDocsScript = /^(release|release:.*|docs|docs:.*|publish|publish:.*)$/i.test(scriptName);
      
      // Check if it's an update script (often use fetch to update data files)
      const isUpdateScript = /^(update|update:.*)$/i.test(scriptName);
      
      // Check if it's a download script (often use curl/wget to fetch data files)
      const isDownloadScript = /^download/i.test(scriptName);
      
      // Check if script contains git fetch/pull/clone (safe in release/docs scripts)
      // Check the full script, not just match[0], because "fetch" might match but we need "git fetch"
      const hasGitOperation = /git\s+(fetch|pull|clone)\b/i.test(script);
      const isGitFetchOnly = hasGitOperation && isReleaseOrDocsScript;
      
      // Check if it's curl/wget to official sources (unicode.org, etc.) in download scripts
      const isOfficialSourceDownload = isDownloadScript && (
        /unicode\.org/i.test(script) ||
        /iana\.org/i.test(script) ||
        /w3\.org/i.test(script) ||
        /ecma-international\.org/i.test(script)
      );
      
      // Only flag build/test scripts if they're install scripts or have suspicious patterns
      if (isBuildOrTestScript && !isInstall) {
        // Skip - build scripts often download dependencies or assets legitimately
        continue;
      }
      
      // Skip update scripts (often use fetch/npm run fetch to update data files)
      // Update scripts are maintenance scripts, not install scripts, so they're less suspicious
      if (isUpdateScript && !isInstall) {
        // Skip - update scripts often fetch updated data files (mime-db, etc.)
        continue;
      }
      
      // Skip git fetch in release/docs scripts (legitimate use)
      // Also skip if the matched pattern is "fetch" but it's part of "git fetch" in a release script
      if (isGitFetchOnly && !isInstall) {
        continue;
      }
      
      // Skip if pattern matched "fetch" but it's actually "git fetch" in a release script
      if (match[0].toLowerCase() === 'fetch' && hasGitOperation && isReleaseOrDocsScript && !isInstall) {
        continue;
      }
      
      // Skip official source downloads in download scripts (legitimate use)
      if (isOfficialSourceDownload && !isInstall) {
        continue;
      }
      
      const severity = isInstall ? (isTrusted ? 'low' : 'high') : (isBuildOrTestScript ? 'low' : 'medium');
      
      const issue = {
        severity,
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
            isBuildOrTestScript,
            isReleaseOrDocsScript,
            isGitFetchOnly,
          },
          fullScript: script,
          scriptFile: pkg ? path.join(pkg.dir, 'package.json') : null,
          falsePositiveHints: [
            isBuildOrTestScript && !isInstall ? '✓ Build/test scripts often download dependencies legitimately' : null,
            isGitFetchOnly && !isInstall ? '✓ Git fetch in release/docs scripts is legitimate' : null,
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

  // Shell execution - reduce false positives for build/test scripts
  for (const pattern of SHELL_EXEC_PATTERNS) {
    const match = script.match(pattern);
    if (match) {
      // Check if it's a build/test script (less suspicious)
      const isBuildOrTestScript = /^(build|test|test:.*|build:.*|compile|transpile|prepublish|prepublishOnly)$/i.test(scriptName);
      
      // Only flag build/test scripts if they're install scripts
      if (isBuildOrTestScript && !isInstall) {
        // Skip - build scripts often use shell wrappers for cross-platform compatibility
        continue;
      }
      
      const severity = isInstall ? 'high' : (isBuildOrTestScript ? 'low' : 'medium');
      
      const issue = {
        severity,
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
            isBuildOrTestScript,
          },
          fullScript: script,
          scriptFile: pkg ? path.join(pkg.dir, 'package.json') : null,
          falsePositiveHints: [
            isBuildOrTestScript && !isInstall ? '✓ Build/test scripts often use shell wrappers for cross-platform compatibility' : null,
            'Cross-platform scripts often use shell wrappers',
            'Check what command is being executed after shell invocation',
          ].filter(Boolean),
        };
      }
      
      issues.push(issue);
      break;
    }
  }

  // Code execution - only flag if suspicious context
  for (const pattern of CODE_EXEC_PATTERNS) {
    const match = script.match(pattern);
    if (match) {
      // Skip false positives: standard npm/node commands that don't execute inline code
      // Examples: "npm run build", "node script.js", "node index.mjs"
      const isStandardCommand = /^(npm\s+(run|test|start|build|install|ci)|node\s+[^-\s]+\.(js|mjs|cjs)|node\s+[^-\s]+$)/i.test(script.trim());
      
      // Check if code is passed inline (more suspicious) vs file execution (less suspicious)
      // Look for quotes after the pattern (e.g., "node -e 'code here'")
      const afterMatch = script.slice(match.index + match[0].length).trim();
      const hasInlineCode = /^['"`]/.test(afterMatch) || /^\s*['"`]/.test(afterMatch);
      
      // Check if it's just a build/test script (less suspicious for non-install scripts)
      const isBuildOrTestScript = /^(build|test|test:.*|build:.*|compile|transpile|lint|format)$/i.test(scriptName);
      
      // Check if it's a version/publish script (often use node -e for simple operations)
      const isVersionScript = /^(pre|post)?(version|publish|pack)$/i.test(scriptName);
      
      // Check if it's any non-install script (less suspicious)
      const isNonInstallScript = !isInstall;
      
      // Whitelist of safe inline code patterns (common legitimate uses)
      const safeInlinePatterns = [
        // Reading package.json version (various formats)
        /console\.log\(require\(['"]\.\/package\.json['"]\)\.version\)/,
        /console\.log\(require\(['"]\.\/package\.json['"]\)\[['"]version['"]\]\)/,
        /process\.env\.npm_package_version/,
        // Simple file operations (copy, read, write simple data)
        /fs\.(copyFileSync|cpSync|readFileSync|writeFileSync)\(/,
        // Simple JSON operations
        /JSON\.(stringify|parse)\(require\(['"]\.\/package\.json['"]\)/,
        // Simple string replacements
        /\.replace\(/,
        // Simple assertions (checking package.json properties)
        /require\(['"]assert['"]\)/,
        /require\(['"]assert['"]\)\(!require\(['"]\.\/package\.json['"]\)\.private\)/,
        // Version checking patterns (common in postversion scripts)
        /^console\.log\(require\(['"]\.\/package\.json['"]\)\.version\)$/,
        // Simple process.exit with version check
        /process\.exit\(process\.version\.startsWith\(/,
        // Safe require patterns: try{require('./file')}catch(e){} - very common in postinstall scripts
        // This pattern just tries to load a file if it exists, otherwise does nothing - completely safe
        /try\s*\{?\s*require\(['"]\.\/[^'"]+['"]\)\s*\}?\s*catch\s*\([^)]+\)\s*\{?\s*\}?/,
        // More flexible: any try/catch with require of local file
        /try\s*\{[^}]*require\(['"]\.\/[^'"]+['"]\)[^}]*\}\s*catch\s*\([^)]+\)\s*\{[^}]*\}/,
      ];
      
      // Check if inline code matches safe patterns
      let isSafeInlineCode = false;
      if (hasInlineCode && match[0].includes('node')) {
        // Extract the code string (between quotes)
        // Handle nested quotes: node -e "code with 'quotes'" or node -e 'code with "quotes"'
        // Try double quotes first, then single, then backticks
        let codeMatch = script.match(/node\s+-e\s+"((?:[^"\\]|\\.)*)"/);
        if (!codeMatch) {
          codeMatch = script.match(/node\s+-e\s+'((?:[^'\\]|\\.)*)'/);
        }
        if (!codeMatch) {
          codeMatch = script.match(/node\s+-e\s+`((?:[^`\\]|\\.)*)`/);
        }
        // Also try with $() shell substitution: "v$(node -e "...")"
        if (!codeMatch) {
          codeMatch = script.match(/\$\(node\s+-e\s+["']((?:[^"'\\]|\\.)*)["']\)/);
        }
        
        if (codeMatch && codeMatch[1]) {
          const inlineCode = codeMatch[1];
          isSafeInlineCode = safeInlinePatterns.some(safePattern => safePattern.test(inlineCode));
          
          // For non-install scripts, also check if code is very simple (only safe operations)
          if (!isSafeInlineCode && isNonInstallScript) {
            // Check if code only contains safe operations (no eval, no network, no file writes)
            const hasUnsafeOps = /eval|Function|child_process|spawn|exec|require\(['"]https?|fetch\(|axios|got|request\(/i.test(inlineCode);
            const hasOnlySafeOps = /^(console\.(log|error|warn)|require\(['"]\.\/package\.json['"]\)|process\.(exit|env|version)|JSON\.(parse|stringify)|fs\.(readFileSync|copyFileSync|cpSync))/.test(inlineCode.trim());
            
            // Check for safe try/catch require patterns (very common in postinstall scripts)
            const isSafeTryRequire = /try\s*\{[^}]*require\(['"]\.\/[^'"]+['"]\)[^}]*\}\s*catch/i.test(inlineCode);
            
            // If it's a simple operation and doesn't have unsafe ops, consider it safe
            // Version/publish scripts are more likely to be safe
            if (!hasUnsafeOps && (hasOnlySafeOps || isSafeTryRequire || (isVersionScript && inlineCode.length < 150))) {
              isSafeInlineCode = true;
            }
          }
          
          // For install scripts, also check for safe try/catch require patterns
          // This is a very common and safe pattern: try{require('./postinstall')}catch(e){}
          if (!isSafeInlineCode && isInstall) {
            const isSafeTryRequire = /try\s*\{[^}]*require\(['"]\.\/[^'"]+['"]\)[^}]*\}\s*catch/i.test(inlineCode);
            if (isSafeTryRequire) {
              // Check that it doesn't have unsafe operations
              const hasUnsafeOps = /eval|Function|child_process|spawn|exec|require\(['"]https?|fetch\(|axios|got|request\(/i.test(inlineCode);
              if (!hasUnsafeOps) {
                isSafeInlineCode = true;
              }
            }
          }
        }
      }
      
      // Skip if it's safe inline code (in both install and non-install scripts)
      if (isSafeInlineCode) {
        continue;
      }
      
      // Only flag if:
      // 1. It's an install script (always suspicious, even if standard command)
      // 2. OR it's not a standard command AND has inline code AND it's not safe
      const shouldFlag = isInstall || (!isStandardCommand && hasInlineCode && !isSafeInlineCode);
      
      if (shouldFlag) {
        // Reduce severity for build/test/version scripts that aren't install scripts
        let severity = isInstall ? 'high' : (hasInlineCode ? 'medium' : 'low');
        if (!isInstall && (isBuildOrTestScript || isVersionScript) && !hasInlineCode) {
          severity = 'low';
        }
        // Further reduce for version scripts with safe inline code
        if (!isInstall && isVersionScript && isSafeInlineCode) {
          severity = 'low';
        }
        
        const issue = {
          severity,
          reason: 'code_execution',
          detail: `Script "${scriptName}" executes code dynamically: ${truncate(script, 150)}`,
          recommendation: hasInlineCode 
            ? 'Inline code execution is risky. Investigate what code is being executed.'
            : 'Investigate what code is being executed.',
        };
        
        if (verbose) {
          issue.verbose = {
            evidence: {
              matchedPattern: pattern.source,
              matchedText: match[0],
              scriptName,
              hasInlineCode,
              isStandardCommand,
              isBuildOrTestScript,
              isVersionScript,
              isSafeInlineCode,
              isInstallScript: isInstall,
            },
            fullScript: script,
            scriptFile: pkg ? path.join(pkg.dir, 'package.json') : null,
            falsePositiveHints: [
              isStandardCommand && !isInstall ? '✓ This appears to be a standard npm/node command' : null,
              isBuildOrTestScript && !isInstall ? '✓ Build/test scripts commonly use code execution' : null,
              isVersionScript && !isInstall ? '✓ Version/publish scripts often use node -e for simple operations' : null,
              isSafeInlineCode && !isInstall ? '✓ Inline code matches safe patterns (reading version, simple file ops)' : null,
              !hasInlineCode ? '✓ Code execution from file is less suspicious than inline' : '⚠ Inline code execution is more suspicious',
              isInstall ? '⚠ Code execution in install scripts is always suspicious' : null,
              'Check what code is being passed to the interpreter',
            ].filter(Boolean),
          };
        }
        
        issues.push(issue);
        break;
      }
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
  // Note: | node is NOT a shell pipe - it's piping to JavaScript interpreter (safe)
  // Only flag | sh, | bash, | zsh, etc. (actual shell interpreters)
  const pipeMatch = script.match(/\|\s*(ba)?sh\b/i) || 
                   script.match(/\|\s*zsh\b/i) ||
                   script.match(/\|\s*fish\b/i) ||
                   script.match(/\|\s*ksh\b/i) ||
                   script.match(/\|\s*csh\b/i);
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
          matchedPattern: 'pipe to shell (| sh, | bash, | zsh, etc.)',
          matchedText: pipeMatch[0],
          scriptName,
        },
        fullScript: script,
        scriptFile: pkg ? path.join(pkg.dir, 'package.json') : null,
        falsePositiveHints: [
          '⚠ This is almost never legitimate in npm packages',
          'Common attack vector: curl URL | sh downloads and executes remote code',
          'Note: | node is NOT flagged (safe - pipes to JS interpreter, not shell)',
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
 * 
 * NOTE: All packages are checked. Users can ignore this rule for specific packages
 * using --ignore-rules native_binary or by configuring ignoredRules in .chainauditrc.json
 */
function checkNativeBinaries(pkg, issues, verbose = false) {
  const found = findNativeArtifacts(pkg.dir, 3);
  
  if (found.length > 0) {
    const listed = found.slice(0, 3).map(p => path.basename(p)).join(', ');
    const issue = {
      severity: 'low',
      reason: 'native_binary',
      detail: `Contains native binaries: ${listed}${found.length > 3 ? `, +${found.length - 3} more` : ''}`,
      recommendation: 'Native binaries are harder to audit. Ensure this is a known native module. Use --ignore-rules native_binary if this is expected.',
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
          'To ignore this check for specific packages, use --ignore-rules native_binary',
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
 * 
 * NOTE: Whitelist cleared - all packages are now checked without exceptions.
 * This ensures that even compromised packages from trusted scopes are detected.
 */
const TRUSTED_SCOPES = new Set([
  // Whitelist cleared for security - all packages are checked
]);

/**
 * Known legitimate packages that might trigger false positives
 * 
 * NOTE: Whitelist cleared - all packages are now checked without exceptions.
 * This ensures that even compromised packages are detected.
 * 
 * If you need to reduce false positives, use the --ignore-rules flag
 * or configure trustedPackages in .chainauditrc.json for specific packages.
 */
const KNOWN_LEGITIMATE_PACKAGES = new Set([
  // Whitelist cleared for security - all packages are checked
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
    // Only check if there are multiple substitutions (more suspicious)
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
      
      // Only flag if:
      // 1. Normalized name matches popular package
      // 2. AND there are at least 2 character substitutions (single number could be version)
      // 3. AND the substitutions are in suspicious positions (not just version numbers at end)
      const substitutionCount = (pkgName.match(/[013457]/g) || []).length;
      const hasVersionSuffix = /[0-9]+$/.test(pkgName);
      const substitutionsInMiddle = pkgName.slice(0, -2).match(/[013457]/g);
      
      if (normalized !== pkgName && 
          POPULAR_PACKAGES.includes(normalized.toLowerCase()) &&
          substitutionCount >= 2 &&
          (!hasVersionSuffix || (substitutionsInMiddle && substitutionsInMiddle.length >= 2))) {
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
        const prefix = match[1]?.toLowerCase();
        
        // Skip common legitimate prefixes
        const legitimatePrefixes = ['my', 'get', 'is', 'has', 'can', 'should', 'will', 'do'];
        
        if (POPULAR_PACKAGES.includes(stripped) && !legitimatePrefixes.includes(prefix)) {
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
 * Check if a match is in a comment, string literal, or regex pattern definition
 * This helps reduce false positives when scanning code that defines detection patterns
 */
function isMatchInNonExecutableContext(content, matchIndex, matchLength) {
  // Get the line containing the match
  const lines = content.split('\n');
  let charCount = 0;
  let lineIndex = 0;
  let lineStart = 0;
  
  for (let i = 0; i < lines.length; i++) {
    const lineEnd = charCount + lines[i].length;
    if (matchIndex >= charCount && matchIndex < lineEnd) {
      lineIndex = i;
      lineStart = charCount;
      break;
    }
    charCount = lineEnd + 1; // +1 for newline
  }
  
  const line = lines[lineIndex];
  const matchInLine = matchIndex - lineStart;
  const lineBeforeMatch = line.slice(0, matchInLine);
  
  // Check if it's in a multi-line comment (need to check entire content, not just line)
  const contentBeforeMatch = content.slice(0, matchIndex);
  const lastCommentStart = contentBeforeMatch.lastIndexOf('/*');
  if (lastCommentStart !== -1) {
    const lastCommentEnd = contentBeforeMatch.lastIndexOf('*/');
    if (lastCommentEnd < lastCommentStart) {
      // Comment started but not closed - match is after comment start
      return true; // In multi-line comment
    }
  }
  
  // Check if it's in a single-line comment
  const singleLineCommentIndex = lineBeforeMatch.lastIndexOf('//');
  if (singleLineCommentIndex !== -1) {
    // Check if there's no newline between comment and match (same line)
    const afterComment = lineBeforeMatch.slice(singleLineCommentIndex + 2);
    if (!afterComment.includes('\n')) {
      // No newline means we're still on the same line as the comment
      // Check if there's an unclosed string (which would mean we're not in comment)
      // But simpler: if // is before match on same line and no newline, we're in comment
      return true; // In comment
    }
  }
  
  // Check if it's in a string literal (single, double, or template string)
  // Need to check entire content before match, not just the line (for multiline strings)
  let inString = false;
  let stringChar = null;
  let escaped = false;
  
  // Check entire content before match for string context
  for (let i = 0; i < contentBeforeMatch.length; i++) {
    const char = contentBeforeMatch[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === '\\') {
      escaped = true;
      continue;
    }
    if ((char === '"' || char === "'" || char === '`') && !inString) {
      inString = true;
      stringChar = char;
    } else if (char === stringChar && inString) {
      inString = false;
      stringChar = null;
    }
  }
  
  // If we're in a string, check if match is also in the string
  if (inString) {
    // CRITICAL: Don't ignore patterns in strings if they're passed to code execution functions
    // Malware often uses: eval("process.env.SECRET"), new Function("return process.env.TOKEN")
    // Check if the string is passed to eval, Function, require, setTimeout, etc.
    const dangerousContexts = [
      /\beval\s*\(/,
      /\bnew\s+Function\s*\(/,
      /\bFunction\s*\(/,
      /\brequire\s*\(/,
      /\bsetTimeout\s*\(/,
      /\bsetInterval\s*\(/,
      /\bvm\.runInContext\s*\(/,
      /\bvm\.runInNewContext\s*\(/,
      /\bvm\.runInThisContext\s*\(/,
      /\bvm\.compileFunction\s*\(/,
    ];
    
    // Find the start of the string by looking backwards from match
    let stringStartIndex = -1;
    let foundQuote = false;
    for (let i = matchInLine - 1; i >= 0; i--) {
      if (lineBeforeMatch[i] === stringChar && (i === 0 || lineBeforeMatch[i - 1] !== '\\')) {
        stringStartIndex = lineStart + i + 1; // +1 to get position after quote
        foundQuote = true;
        break;
      }
    }
    
    if (foundQuote && stringStartIndex !== -1) {
      // Look backwards from string start to find if it's passed to dangerous function
      const beforeString = content.slice(Math.max(0, stringStartIndex - 200), stringStartIndex);
      
      // Check if string is passed to dangerous function
      for (const dangerousPattern of dangerousContexts) {
        const dangerousMatch = beforeString.match(dangerousPattern);
        if (dangerousMatch) {
          // Check if the dangerous function call is before the string (within reasonable distance)
          const dangerousIndex = stringStartIndex - beforeString.length + dangerousMatch.index;
          const distance = stringStartIndex - dangerousIndex;
          // If dangerous function is within 100 chars before string, don't ignore
          if (distance < 100 && distance > 0) {
            return false; // DON'T ignore - this is dangerous!
          }
        }
      }
      
      // Also check for require("https://...") pattern specifically
      if (stringChar === '"' || stringChar === "'") {
        const requireMatch = beforeString.match(/\brequire\s*\(\s*$/);
        if (requireMatch) {
          // String is passed to require() - check if it's a URL
          const afterMatch = content.slice(matchIndex + matchLength, matchIndex + matchLength + 20);
          if (/https?:\/\//.test(afterMatch)) {
            return false; // DON'T ignore - require("https://...") is suspicious!
          }
        }
      }
    }
    
    // If we're in a string and it's not passed to a dangerous function, ignore it
    // Check if string continues after match (for template literals, check more content)
    const contentAfterMatch = content.slice(matchIndex + matchLength, Math.min(content.length, matchIndex + matchLength + 200));
    let afterEscaped = false;
    
    for (let i = 0; i < contentAfterMatch.length; i++) {
      const char = contentAfterMatch[i];
      if (afterEscaped) {
        afterEscaped = false;
        continue;
      }
      if (char === '\\') {
        afterEscaped = true;
        continue;
      }
      if (char === stringChar) {
        break;
      }
      // For non-template strings, stop at newline
      if (char === '\n' && stringChar !== '`') {
        // String might have ended, but we can't be sure without checking the full context
        // If we're in a string and haven't found dangerous context, it's safe to ignore
        break;
      }
    }
    
    // If we're in a string and haven't found it's passed to dangerous function, ignore it
    // This covers cases where string continues or ends - if it's not dangerous, ignore
    return true; // Match is inside string (and not passed to dangerous function)
  }
  
  // Check if it's in a regex pattern definition (e.g., /pattern/ or new RegExp(...))
  // Look backwards from match to find regex literal start
  // (contentBeforeMatch already defined above)
  
  // Find the last unescaped forward slash before the match
  let lastSlashIndex = -1;
  let isEscaped = false;
  for (let i = contentBeforeMatch.length - 1; i >= 0; i--) {
    const char = contentBeforeMatch[i];
    if (isEscaped) {
      isEscaped = false;
      continue;
    }
    if (char === '\\') {
      isEscaped = true;
      continue;
    }
    // Check if this slash starts a regex (not division)
    // Regex starts after: =, (, [, {, ,, ;, :, !, &, |, ?, ~, +, -, *, /, %, ^, <, >, space, tab, newline
    if (char === '/') {
      const beforeSlash = contentBeforeMatch.slice(Math.max(0, i - 10), i);
      const regexStartContext = /[=([{,;:!&|?~+\-*/%^<> \t\n]$/.test(beforeSlash.slice(-1));
      if (regexStartContext || i === 0) {
        lastSlashIndex = i;
        break;
      }
    }
  }
  
  if (lastSlashIndex !== -1) {
    // Check if there's a closing slash with optional flags after the match
    const afterMatch = content.slice(matchIndex + matchLength);
      const regexEndMatch = afterMatch.match(/^[^/\n]*\/[gimuy]*/);
    if (regexEndMatch) {
      // Check if match is between the slashes
      const regexEnd = matchIndex + matchLength + regexEndMatch[0].length;
      const regexStart = lastSlashIndex;
      if (matchIndex >= regexStart && matchIndex < regexEnd) {
        return true; // In regex pattern
      }
    }
  }
  
  // Check for RegExp constructor
  const regExpMatch = contentBeforeMatch.match(/new\s+RegExp\s*\(/);
  if (regExpMatch) {
    // Find the closing parenthesis
    let parenCount = 1;
    let i = regExpMatch.index + regExpMatch[0].length;
    while (i < matchIndex + matchLength && parenCount > 0 && i < content.length) {
      const char = content[i];
      if (char === '(') parenCount++;
      else if (char === ')') parenCount--;
      i++;
    }
    if (parenCount > 0 && matchIndex < i) {
      return true; // In RegExp constructor
    }
  }
  
  // Check if it's in a regex pattern array definition (e.g., const PATTERNS = [/pattern/])
  // Look for array literal with regex patterns
  const arrayPatternMatch = contentBeforeMatch.match(/(?:const|let|var)\s+\w+\s*=\s*\[/);
  if (arrayPatternMatch) {
    // Find the closing bracket
    let bracketCount = 1;
    let i = arrayPatternMatch.index + arrayPatternMatch[0].length;
    while (i < matchIndex + matchLength && bracketCount > 0 && i < content.length) {
      const char = content[i];
      if (char === '[') bracketCount++;
      else if (char === ']') bracketCount--;
      i++;
    }
    if (bracketCount > 0 && matchIndex < i) {
      // Check if match is within a regex literal in the array
      const arrayContent = content.slice(arrayPatternMatch.index + arrayPatternMatch[0].length, i);
      const regexInArray = /\/[^/\n]+\/[gimuy]*/g;
      let regexMatch;
      while ((regexMatch = regexInArray.exec(arrayContent)) !== null) {
        const regexStart = arrayPatternMatch.index + arrayPatternMatch[0].length + regexMatch.index;
        const regexEnd = regexStart + regexMatch[0].length;
        if (matchIndex >= regexStart && matchIndex < regexEnd) {
          return true; // In regex pattern within array definition
        }
      }
    }
  }
  
  return false;
}

/**
 * Deep code analysis (optional, slower)
 */
function analyzeCode(pkg, config, issues, verbose = false) {
  const maxFileSize = config.maxFileSizeForCodeScan || 1024 * 1024;
  const maxFiles = config.maxFilesPerPackage || 0; // 0 = unlimited
  const jsFiles = findJsFiles(pkg.dir, 10); // Scan up to 10 levels deep

  // Apply file limit (0 means scan all files)
  const filesToScan = maxFiles > 0 ? jsFiles.slice(0, maxFiles) : jsFiles;

  for (const filePath of filesToScan) {
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > maxFileSize) continue;

      const content = fs.readFileSync(filePath, 'utf8');
      const relativePath = path.relative(pkg.dir, filePath);

      // Check for eval patterns - reduce false positives
      for (const pattern of EVAL_PATTERNS) {
        const patternMatch = pattern.exec(content);
        if (patternMatch) {
          // Reset regex lastIndex for next use
          pattern.lastIndex = 0;
          
          // Skip if match is in comment, string, or regex definition
          if (isMatchInNonExecutableContext(content, patternMatch.index, patternMatch[0].length)) {
            continue;
          }
          
          // Skip false positives: "eval" in variable/function names (e.g., "unevaluated", "evaluate", "evaluation")
          // Check if "eval" is part of a longer word (not a function call)
          const matchText = patternMatch[0];
          const matchIndex = patternMatch.index;
          const beforeMatch = content.slice(Math.max(0, matchIndex - 20), matchIndex);
          const afterMatch = content.slice(matchIndex + matchText.length, matchIndex + matchText.length + 20);
          
          // Check if it's part of a longer identifier (e.g., "unevaluated", "evaluate", "evaluation")
          // Also check for common false positives like "unevaluatedProperties", "evaluateExpression", etc.
          const isPartOfIdentifier = /[a-zA-Z_$]/.test(beforeMatch.slice(-1)) || /[a-zA-Z0-9_$]/.test(afterMatch.slice(0, 1));
          const isCommonFalsePositive = /\b(unevaluated|evaluate|evaluation|evaluated|evaluator|evaluates)\w*/i.test(beforeMatch + matchText + afterMatch);
          
          if ((isPartOfIdentifier && !matchText.includes('(')) || isCommonFalsePositive) {
            continue; // Skip - it's part of a variable/function name, not eval() call
          }
          
          // Skip if it's in a test directory or test file (tests often use eval for mocking)
          const isTestFile = /(?:^|\/)(?:test|spec|__tests__|__mocks__)(?:\/|$)/i.test(relativePath) ||
                            /(?:^|\/)(?:test|spec)\.(js|mjs|cjs)$/i.test(relativePath);
          
          // Skip minified/bundled files, but NOT main package files or executables
          // IMPORTANT: Don't skip bin/* files (executables) or main package files (index.cjs, main.cjs)
          // These are high-risk entry points that should always be scanned!
          const isMinifiedOrBundled = 
            // Only skip files with .min/.bundle extension in dist/build/lib directories
            (/\.(?:min|bundle)\.(?:js|mjs|cjs)$/i.test(relativePath) &&
             /(?:^|\/)(?:dist|build|lib)\//i.test(relativePath)) ||
            // Skip minified files in dist/build/lib even without extension
            (/(?:^|\/)(?:dist|build|lib)\/.*\.(?:min|bundle)\.(?:js|mjs|cjs)$/i.test(relativePath));
          
          // NEVER skip:
          // - bin/* files (executables - high risk!)
          // - Main package files (index.cjs, main.cjs in root)
          // - Source files (.cjs in src/ or root)
          const isMainPackageFile = /^(index|main)\.(cjs|js|mjs)$/i.test(relativePath);
          const isExecutable = /^bin\//i.test(relativePath);
          const isSourceFile = /^src\//i.test(relativePath);
          
          if (isMainPackageFile || isExecutable || isSourceFile) {
            // Always scan main package files, executables, and source files - these are high-risk!
            // Don't skip even if they match minified patterns
          } else if (isMinifiedOrBundled) {
            // Skip only truly minified files in dist/build/lib
            continue;
          }
          
          // Check if eval/new Function is used for dynamic import (legit use case)
          const contextAroundMatch = content.slice(Math.max(0, matchIndex - 100), Math.min(content.length, matchIndex + matchText.length + 100));
          const isDynamicImport = /(?:dynamicImport|dynamic.*import|import\s*\(|return\s+import)/i.test(contextAroundMatch);
          if (isDynamicImport && (matchText.includes('Function') || matchText.includes('eval'))) {
            continue; // Skip - used for dynamic import, which is a legit use case
          }
          
          // Check for common legitimate Function() constructor patterns
          // These are polyfills and compatibility code, not malicious
          if (matchText.includes('Function')) {
            const functionContext = content.slice(Math.max(0, matchIndex - 50), Math.min(content.length, matchIndex + matchText.length + 150));
            // Function('return this')() - getting global object in strict mode (very common)
            if (/Function\s*\(\s*['"`]return\s+this['"`]\s*\)\s*\(/i.test(functionContext)) {
              continue; // Skip - legitimate pattern for getting global object
            }
            // Function('return async function () {}')() - polyfill for async function detection
            if (/Function\s*\(\s*['"`]return\s+async\s+function/i.test(functionContext)) {
              continue; // Skip - legitimate polyfill pattern
            }
            // Function('return function* () {}')() - polyfill for generator function detection
            if (/Function\s*\(\s*['"`]return\s+function\s*\*/i.test(functionContext)) {
              continue; // Skip - legitimate polyfill pattern
            }
            // Function('"use strict"; return (...).constructor;')() - getting constructor (polyfill)
            if (/Function\s*\(\s*['"`]["']use\s+strict["'];?\s*return\s*\([^)]+\)\.constructor/i.test(functionContext)) {
              continue; // Skip - legitimate polyfill pattern
            }
            // Function('binder', 'return function (...) { return binder.apply(...) }') - function binding polyfill
            if (/Function\s*\(\s*['"`]binder['"`]\s*,\s*['"`]return\s+function/i.test(functionContext)) {
              continue; // Skip - legitimate function binding pattern
            }
          }
          
          // Skip if it's a template engine or known legitimate use case
          const isTemplateEngine = /(?:template|render|compile|parse|eval)/i.test(relativePath) ||
                                  /(?:handlebars|mustache|ejs|pug|jade|nunjucks)/i.test(pkg?.name || '');
          
          // Skip if it's clearly a JSON parser or polyfill
          const isJsonParser = /(?:json|parse|polyfill)/i.test(relativePath) ||
                              /(?:json[_-]?parse|polyfill)/i.test(pkg?.name || '');
          
          // Skip ESLint and related packages (eval is normal for rule evaluation)
          // IMPORTANT: Use exact matches or trusted scopes to avoid missing typosquatting attacks
          const isEslintRelated = pkg && (
            pkg.name === 'eslint' ||
            pkg.name === 'eslint-scope' ||
            pkg.name.startsWith('@eslint/') ||
            pkg.name.startsWith('@humanwhocodes/')
          );
          
          // Check if package is from trusted scope or known legitimate
          const isTrustedPackage = pkg && (
            KNOWN_LEGITIMATE_PACKAGES.has(pkg.name) ||
            (pkg.name.startsWith('@') && TRUSTED_SCOPES.has(pkg.name.split('/')[0]))
          );
          
          // All packages are checked for eval usage
          // Users can configure trustedPackages or use --ignore-rules eval_usage if needed
          
          // Check if it's a compiled/bundled file (common in frameworks)
          const isCompiledFile = /(?:^|\/)(?:dist|build|lib|compiled|cjs|esm|umd|chunk-)(?:\/|$)/i.test(relativePath) ||
                                 /\.(min|bundle|compiled|legacy)\.(js|mjs|cjs)$/i.test(relativePath);
          
          if (isTestFile || isMinifiedOrBundled || isTemplateEngine || isJsonParser || isEslintRelated || isTrustedPackage || isCompiledFile) {
            continue;
          }
          
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
                isTestFile,
                isTemplateEngine,
                isJsonParser,
              },
              codeSnippet: snippet?.snippet || null,
              lineNumber: snippet?.lineNumber || null,
              matchedText: snippet?.matchedText || null,
              falsePositiveHints: [
                isTestFile ? '✓ This appears to be a test file - eval usage for mocking is common' : null,
                isMinifiedOrBundled ? '✓ This appears to be a minified/bundled file - eval patterns may be false positives' : null,
                isEslintRelated ? '✓ ESLint packages use eval for rule evaluation - this is normal' : null,
                isTrustedPackage ? '✓ This is a known legitimate package that uses eval' : null,
                isTemplateEngine ? '✓ This appears to be a template engine - eval usage is expected' : null,
                isJsonParser ? '✓ This appears to be a JSON parser - eval usage for fallback is common' : null,
                'Some legitimate uses: JSON parsing fallbacks, template engines',
                'Check if eval is used on user-controlled input',
                'vm module usage may be legitimate for sandboxing',
              ].filter(Boolean),
            };
          }
          
          issues.push(issue);
          break;
        }
      }

      // Check for child_process - reduce false positives for build tools
      for (const pattern of CHILD_PROCESS_PATTERNS) {
        const patternMatch = pattern.exec(content);
        if (patternMatch) {
          // Reset regex lastIndex for next use
          pattern.lastIndex = 0;
          
          // Skip if match is in comment, string, or regex definition
          if (isMatchInNonExecutableContext(content, patternMatch.index, patternMatch[0].length)) {
            continue;
          }
          
          // Check for false positives: "child_process" in variable names or comments
          const matchText = patternMatch[0];
          const matchIndex = patternMatch.index;
          const beforeMatch = content.slice(Math.max(0, matchIndex - 30), matchIndex);
          const afterMatch = content.slice(matchIndex + matchText.length, matchIndex + matchText.length + 30);
          
          // Check if it's part of a longer identifier or in a comment
          const isPartOfIdentifier = /[a-zA-Z_$]/.test(beforeMatch.slice(-1)) || /[a-zA-Z0-9_$]/.test(afterMatch.slice(0, 1));
          const isInComment = /\/\/.*child_process|\/\*[\s\S]*?child_process/i.test(beforeMatch + matchText);
          
          if (isPartOfIdentifier || isInComment) {
            continue; // Skip - it's part of a variable/function name or in a comment
          }
          
          // Check if it's actually used (not just referenced in a string or comment)
          // For exec/spawn/fork patterns, these are direct function calls and are suspicious even without require nearby
          // For "child_process" string, check if it's actually required/imported
          const isDirectFunctionCall = /^(exec|execSync|execFile|execFileSync|spawn|spawnSync|fork)\s*\(/i.test(matchText);
          
          let hasActualUsage = false;
          if (isDirectFunctionCall) {
            // Direct function calls like exec(), spawn() are suspicious even without require in context
            // Check if child_process is required/imported anywhere in the file
            const actualUsagePattern = /(?:require|import|from)\s*\(?\s*['"`]child_process['"`]/i;
            hasActualUsage = actualUsagePattern.test(content);
          } else {
            // For "child_process" string match, check in context (more likely to be false positive)
            const actualUsagePattern = /(?:require|import|from)\s*\(?\s*['"`]child_process['"`]/i;
            const contextAroundMatch = content.slice(Math.max(0, matchIndex - 100), Math.min(content.length, matchIndex + matchText.length + 100));
            hasActualUsage = actualUsagePattern.test(contextAroundMatch);
          }
          
          if (!hasActualUsage) {
            continue; // Skip - no actual usage found, might be false positive
          }
          
          // Check if it's just checking system info (like ldd --version, uname, arch) - less suspicious
          const contextAroundMatch = content.slice(Math.max(0, matchIndex - 200), Math.min(content.length, matchIndex + matchText.length + 200));
          const isSystemCheck = /(?:ldd\s+--version|uname|arch|platform|os\.platform|process\.platform)/i.test(contextAroundMatch);
          // Also check if it's execSync with simple read-only commands
          if (isSystemCheck && /execSync/i.test(matchText)) {
            // System checks are less suspicious - they're read-only operations
            // But we still flag them with lower severity if they're in suspicious contexts
          }
          
          // Check if package is from trusted scope (only if configured by user)
          const isTrustedPackage = pkg && (
            KNOWN_LEGITIMATE_PACKAGES.has(pkg.name) ||
            (pkg.name.startsWith('@') && TRUSTED_SCOPES.has(pkg.name.split('/')[0]))
          );
          
          // Skip if it's in a build/dist/lib directory or looks like a build tool
          // IMPORTANT: NEVER skip bin/ files (executables) or main package files - these are high-risk!
          // This is a structural check, not a package whitelist
          const isBuildFile = /(?:^|\/)(?:build|dist|lib|scripts?|tools?|cjs|esm|umd)(?:\/|$)/i.test(relativePath) ||
                             /\.(?:config|webpack|rollup|vite|esbuild)\./i.test(relativePath);
          
          // NEVER skip executables or main package files
          const isMainPackageFile = /^(index|main)\.(cjs|js|mjs)$/i.test(relativePath);
          const isExecutable = /^bin\//i.test(relativePath);
          const isSourceFile = /^src\//i.test(relativePath);
          
          // All packages are checked - no hardcoded build tool whitelist
          // Users can configure trustedPackages if needed
          
          // Skip if it's a test file
          const isTestFile = /(?:^|\/)(?:test|spec|__tests__|__mocks__)(?:\/|$)/i.test(relativePath) ||
                            /(?:^|\/)(?:test|spec)\.(js|mjs|cjs)$/i.test(relativePath);
          
          // Always scan executables, main package files, and source files - these are high-risk entry points!
          if (isMainPackageFile || isExecutable || isSourceFile) {
            // Don't skip - these are critical files that should always be scanned
          } else if (isBuildFile || isTrustedPackage || isTestFile) {
            // Build files (based on path structure), user-configured trusted packages, and test files are skipped
            // Users can configure trustedPackages or use --ignore-rules child_process_usage if needed
            continue;
          }
          
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
                isBuildFile,
              },
              codeSnippet: snippet?.snippet || null,
              lineNumber: snippet?.lineNumber || null,
              matchedText: snippet?.matchedText || null,
              falsePositiveHints: [
                isBuildFile ? '✓ This appears to be a build file - child_process usage is common' : null,
                'Build tools commonly use child_process (webpack, babel plugins)',
                'CLI tools often spawn child processes',
                'Check what commands are being executed',
              ].filter(Boolean),
            };
          }
          
          issues.push(issue);
          break;
        }
      }

      // Check for sensitive path access
      for (const pattern of SENSITIVE_PATH_PATTERNS) {
        const patternMatch = pattern.exec(content);
        if (patternMatch) {
          // Reset regex lastIndex for next use
          pattern.lastIndex = 0;
          
          // Skip if match is in comment, string, or regex definition
          if (isMatchInNonExecutableContext(content, patternMatch.index, patternMatch[0].length)) {
            continue;
          }
          
          // Check if package is from trusted scope or known legitimate
          const isTrustedPackage = pkg && (
            KNOWN_LEGITIMATE_PACKAGES.has(pkg.name) ||
            (pkg.name.startsWith('@') && TRUSTED_SCOPES.has(pkg.name.split('/')[0]))
          );
          
          // Check if it's a known diagnostic tool (is-docker, etc.)
          const isDiagnosticTool = /(?:is-docker|is-wsl|is-windows|is-mac|is-linux|platform)/i.test(relativePath) ||
                                  /(?:is-docker|is-wsl|is-windows|is-mac|is-linux|platform)/i.test(pkg?.name || '');
          
          // Check if it's a compiled/bundled file
          const isCompiledFile = /(?:^|\/)(?:dist|build|lib|compiled|cjs|esm|umd)(?:\/|$)/i.test(relativePath) ||
                                 /\.(min|bundle|compiled)\.(js|mjs|cjs)$/i.test(relativePath);
          
          // Skip trusted packages, diagnostic tools, and compiled files
          if (isTrustedPackage || isDiagnosticTool || isCompiledFile) {
            continue;
          }
          
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
      // Skip if package is clearly an HTTP client library or network-related utility
      const isHttpClient = pkg && /^(axios|got|node-fetch|undici|ky|superagent|request|needle|phin|bent|httpie|type-check|xmlhttprequest)/i.test(pkg.name);
      
      // Skip WebSocket-related packages (ws, uri-js for ws:// URLs, etc.)
      const isWebSocketRelated = pkg && (
        /^(ws|websocket|socket\.io|uri-js)/i.test(pkg.name) ||
        /(?:websocket|ws|wss)/i.test(relativePath)
      );
      
      // Check if it's a browser-only package (fetch() is normal in browser packages)
      const isBrowserPackage = pkg && (
        /(?:^|\/)(?:browser|web|client|frontend)(?:\/|$)/i.test(pkg.name) ||
        /(?:^|\/)(?:browser|web|client|frontend)(?:\/|$)/i.test(relativePath) ||
        /\.browser\.(js|mjs|cjs)$/i.test(relativePath)
      );
      
      // Check if package is from trusted scope or known legitimate
      const isTrustedPackage = pkg && (
        KNOWN_LEGITIMATE_PACKAGES.has(pkg.name) ||
        (pkg.name.startsWith('@') && TRUSTED_SCOPES.has(pkg.name.split('/')[0]))
      );
      
      // Check if it's a compiled/bundled file (common in frameworks)
      const isCompiledFile = /(?:^|\/)(?:dist|build|lib|compiled|cjs|esm|umd)(?:\/|$)/i.test(relativePath) ||
                             /\.(min|bundle|compiled)\.(js|mjs|cjs)$/i.test(relativePath);
      
      if (!isHttpClient && !isWebSocketRelated && !isTrustedPackage && !isCompiledFile) {
        for (const pattern of NODE_NETWORK_PATTERNS) {
          const patternMatch = pattern.exec(content);
          if (patternMatch) {
            // Reset regex lastIndex for next use
            pattern.lastIndex = 0;
            
            // Skip if match is in comment, string, or regex definition
            if (isMatchInNonExecutableContext(content, patternMatch.index, patternMatch[0].length)) {
              continue;
            }
            
            // Skip if it's in a test directory (tests often mock network calls)
            const isTestFile = /(?:^|\/)(?:test|spec|__tests__|__mocks__)(?:\/|$)/i.test(relativePath);
            
            if (isTestFile) {
              continue;
            }
            
            // Skip fetch() in browser packages - it's the standard browser API
            if (pattern.source.includes('fetch') && isBrowserPackage) {
              continue;
            }
            
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
                  isTestFile,
                },
                codeSnippet: snippet?.snippet || null,
                lineNumber: snippet?.lineNumber || null,
                matchedText: snippet?.matchedText || null,
                falsePositiveHints: [
                  isTestFile ? '✓ This appears to be a test file - network mocking is common' : null,
                  'HTTP client libraries (axios, got, fetch) are common',
                  'Check what URLs/endpoints are being accessed',
                  'Verify network calls match package purpose',
                ].filter(Boolean),
              };
            }
            
            issues.push(issue);
            break;
          }
        }
      }

      // Check for env var access (in context)
      let envMatch = null;
      let envMatchIndex = -1;
      let envMatchText = null;
      for (const pattern of ENV_ACCESS_PATTERNS) {
        const match = pattern.exec(content);
        if (match) {
          pattern.lastIndex = 0;
          // Skip if match is in comment, string, or regex definition
          if (!isMatchInNonExecutableContext(content, match.index, match[0].length)) {
            envMatch = pattern;
            envMatchIndex = match.index;
            envMatchText = match[0];
            break;
          }
        }
      }
      
      if (envMatch) {
        // Skip known legitimate packages that use env vars (ESLint, config loaders, etc.)
        // IMPORTANT: Use exact matches or trusted scopes to avoid missing typosquatting attacks
        const isKnownLegitimateEnv = pkg && (
          // Only official ESLint packages (exact match or trusted scopes)
          pkg.name === 'eslint' ||
          pkg.name.startsWith('@eslint/') ||
          pkg.name.startsWith('@humanwhocodes/') ||
          // Config/environment utilities (exact matches only)
          pkg.name === 'fs.realpath' || // Old package, likely false positive
          pkg.name === 'dotenv' ||
          pkg.name === 'cross-env' ||
          pkg.name === '@types/node' // Type definitions
        );
        
        // Check if package is from trusted scope or known legitimate
        const isTrustedPackage = pkg && (
          isKnownLegitimateEnv ||
          KNOWN_LEGITIMATE_PACKAGES.has(pkg.name) ||
          (pkg.name.startsWith('@') && TRUSTED_SCOPES.has(pkg.name.split('/')[0]))
        );
        
        // Check if it's a compiled/bundled file (common in frameworks)
        const isCompiledFile = /(?:^|\/)(?:dist|build|lib|compiled|cjs|esm|umd)(?:\/|$)/i.test(relativePath) ||
                               /\.(min|bundle|compiled)\.(js|mjs|cjs)$/i.test(relativePath);
        
        // Check if it's a test file
        const isTestFile = /(?:^|\/)(?:test|spec|__tests__|__mocks__)(?:\/|$)/i.test(relativePath);
        
        // Check if it's a docs/example file (often have network access for demos)
        const isDocsOrExampleFile = /(?:^|\/)(?:docs|example|examples|demo|demos)(?:\/|$)/i.test(relativePath);
        
        // Only flag if also has network patterns or child_process
        // Check for network/child_process patterns, but skip if in comments/strings/regex
        let networkMatch = null;
        for (const pattern of NETWORK_PATTERNS) {
          const match = pattern.exec(content);
          if (match) {
            pattern.lastIndex = 0;
            if (!isMatchInNonExecutableContext(content, match.index, match[0].length)) {
              networkMatch = pattern;
              break;
            }
          }
        }
        
        let nodeNetworkMatch = null;
        for (const pattern of NODE_NETWORK_PATTERNS) {
          const match = pattern.exec(content);
          if (match) {
            pattern.lastIndex = 0;
            if (!isMatchInNonExecutableContext(content, match.index, match[0].length)) {
              nodeNetworkMatch = pattern;
              break;
            }
          }
        }
        
        let childProcessMatch = null;
        let childProcessMatchIndex = -1;
        for (const pattern of CHILD_PROCESS_PATTERNS) {
          const match = pattern.exec(content);
          if (match) {
            pattern.lastIndex = 0;
            if (!isMatchInNonExecutableContext(content, match.index, match[0].length)) {
              // For exec/spawn patterns, verify they're actually function calls, not just the word "exec"
              if (pattern.source.includes('exec') || pattern.source.includes('spawn') || pattern.source.includes('fork')) {
                // Check that it's actually a function call, not part of a variable name
                const beforeMatch = content.slice(Math.max(0, match.index - 20), match.index);
                const afterMatch = content.slice(match.index + match[0].length, match.index + match[0].length + 20);
                // Should be preceded by whitespace, dot, or start of line, and followed by (
                const isActualCall = /(?:^|\s|\.|\(|,|;|:)$/.test(beforeMatch.slice(-1)) && /^\s*\(/.test(afterMatch);
                if (!isActualCall) {
                  continue; // Skip - not an actual function call
                }
              }
              childProcessMatch = pattern;
              childProcessMatchIndex = match.index;
              break;
            }
          }
        }
        
        // Skip if it's a known legitimate package, compiled file, test file, or docs/example
        // Most frameworks use process.env for configuration - this is normal
        if (isTrustedPackage || isCompiledFile || isTestFile || isDocsOrExampleFile) {
          continue;
        }
        
        // Check if it's a simple debug/env check (common and safe)
        // Examples: process.env.DEBUG, process.env.NODE_ENV, process.env.NO_COLOR, process.env.NODE_DEBUG
        const envContext = content.slice(Math.max(0, envMatchIndex - 50), Math.min(content.length, envMatchIndex + 100));
        const simpleEnvCheck = envMatchText && /process\.env\.(NODE_DEBUG|DEBUG|NODE_ENV|NO_COLOR|FORCE_COLOR|CI|TZ|LANG|LC_|HOME|USER|PATH|SHELL|PWD)/i.test(envContext);
        
        // If only safe env vars are accessed (like NODE_DEBUG) and there's no actual exec() call, skip
        // The pattern might match "exec" in comments or variable names
        if (simpleEnvCheck && childProcessMatch) {
          // Verify child_process exec is actually used, not just mentioned
          const childProcessContext = content.slice(Math.max(0, childProcessMatchIndex - 100), Math.min(content.length, childProcessMatchIndex + 200));
          // Check if it's actually calling exec/spawn, not just referencing it
          const hasActualExecCall = /(?:require|import).*child_process|child_process\.(?:exec|spawn|fork)|\.(?:exec|spawn|fork)\s*\(/i.test(childProcessContext);
          // Also check if it's just checking system info (like ldd --version) - less suspicious
          const isSystemCheck = /(?:ldd|uname|arch|platform|os)\s/i.test(childProcessContext);
          if (!hasActualExecCall || isSystemCheck) {
            // Skip if no actual exec call, or if it's just a system check
            continue;
          }
        }
        
        // Only flag if it's NOT a known framework/library pattern
        // Most legitimate packages use process.env for config, not for exfiltration
        // Only flag if there are suspicious patterns (like actual exfiltration attempts)
        if (networkMatch || nodeNetworkMatch || childProcessMatch) {
          // Check if it's an install script (install.js in package root)
          // Install scripts often legitimately use process.env + network for downloading binaries
          // We check the file path, not package name - all packages are treated equally
          const isInstallScriptFile = /^install\.js$/i.test(path.basename(relativePath)) ||
                                     /^install\/[^/]+\.js$/i.test(relativePath);
          
          // If it's just a simple env check (NODE_DEBUG, etc.) and network access, skip
          // These are common and safe patterns
          if (simpleEnvCheck && (nodeNetworkMatch || networkMatch) && !childProcessMatch) {
            // Check if network access is also simple (like in a comment or test)
            const networkMatchObj = nodeNetworkMatch || networkMatch;
            let networkMatchIdx = -1;
            for (const pattern of (nodeNetworkMatch ? NODE_NETWORK_PATTERNS : NETWORK_PATTERNS)) {
              const match = pattern.exec(content);
              if (match && pattern === networkMatchObj) {
                pattern.lastIndex = 0;
                networkMatchIdx = match.index;
                break;
              }
            }
            
            // If network match is also in a non-executable context, skip
            if (networkMatchIdx !== -1 && isMatchInNonExecutableContext(content, networkMatchIdx, 10)) {
              continue; // Both are in comments/strings - skip
            }
            
            // If it's just NODE_DEBUG and fetch/network (common in debug logging), skip
            if (/NODE_DEBUG/i.test(envContext)) {
              continue; // NODE_DEBUG + network is common for debug logging, not exfiltration
            }
          }
          
          // Determine severity based on context
          // Install scripts often legitimately use env + network (downloading binaries)
          // But we still flag them - user should review, but with lower severity
          let severity = 'critical';
          if (isInstallScriptFile) {
            severity = 'medium'; // Install scripts are less suspicious, but still worth reviewing
          }
          
          const issue = {
            severity: severity,
            reason: 'env_with_network',
            detail: `File "${relativePath}" accesses environment variables and has network/exec capabilities`,
            recommendation: isInstallScriptFile 
              ? 'Install scripts often use env vars + network to download binaries. Review to ensure it\'s legitimate.'
              : 'DANGER: This pattern matches credential exfiltration attacks like Shai-Hulud 2.0. Investigate immediately.',
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
                isInstallScriptFile ? '⚠ This appears to be an install script - may legitimately download binaries' : null,
                '⚠ This is a HIGH-RISK pattern matching known attacks',
                'Legitimate uses: reading config from env for API calls, install scripts downloading binaries',
                'Check what env vars are accessed and where data is sent',
              ].filter(Boolean),
              riskAssessment: isInstallScriptFile 
                ? 'MEDIUM - Install scripts often use env + network legitimately, but should be reviewed'
                : 'CRITICAL - Matches Shai-Hulud 2.0 and similar attack patterns',
              attackPattern: 'Environment variable access combined with network/exec = potential credential exfiltration',
            };
          }
          
          issues.push(issue);
        }
      }

      // Check for obfuscation - distinguish between minified and obfuscated
      const isMinifiedFile = /\.min\.(js|mjs|cjs)$/i.test(relativePath) ||
                            /(?:^|\/)(?:dist|build|lib|min|compiled)(?:\/|$)/i.test(relativePath);
      
      // Check if it's a known package that legitimately uses minification/compilation
      const isKnownPackage = pkg && (
        KNOWN_LEGITIMATE_PACKAGES.has(pkg.name) ||
        (pkg.name.startsWith('@') && TRUSTED_SCOPES.has(pkg.name.split('/')[0]))
      );
      
      // Check if file contains data patterns (locale data, regex patterns, etc.) rather than code
      // These files often have long strings that look obfuscated but are just data
      const isDataFile = /(?:locale|data|generated|patterns|regex|emoji|encoding|sbcs|strings)/i.test(relativePath) ||
                        /cdn\.js$/i.test(relativePath) || // CDN locale files
                        /(?:RGI_Emoji|sbcs-data-generated)/i.test(relativePath) ||
                        /strings\.js$/i.test(relativePath); // String data files (e.g., gsap)
      
      // Skip if it's clearly a minified or build output file, known package, or data file
      if (!isMinifiedFile && !isKnownPackage && !isDataFile) {
        for (const pattern of OBFUSCATION_PATTERNS) {
          const patternMatch = pattern.exec(content);
          if (patternMatch) {
            // Reset regex lastIndex for next use
            pattern.lastIndex = 0;
            
            // Skip if match is in comment, string, or regex definition
            // (though obfuscation patterns are less likely to be false positives from this)
            if (isMatchInNonExecutableContext(content, patternMatch.index, patternMatch[0].length)) {
              continue;
            }
            // Distinguish minified from obfuscated:
            // Minified: short variable names, no whitespace, but readable structure (functions, if/else visible)
            // Obfuscated: base64 strings, hex escapes, char codes, unreadable structure
            
            // Check if it's likely minified (has readable structure despite compression)
            const hasReadableStructure = /function\s+\w+|if\s*\(|for\s*\(|while\s*\(|return\s+|const\s+\w+|let\s+\w+|var\s+\w+/.test(content);
            
            // Check for minified patterns: very long single-line files with compressed code
            const lines = content.split('\n');
            const isSingleLineOrFewLines = lines.length <= 20;
            const hasLongCompressedLine = lines.some(line => line.length > 10000 && /[a-zA-Z_$][a-zA-Z0-9_$]{0,2}\s*[=:(]/.test(line));
            
            // Check if it's a compiled/minified file (has function structure but compressed)
            const hasMinifiedStructure = hasReadableStructure && (isSingleLineOrFewLines || hasLongCompressedLine);
            
            // Also check for typical minification patterns: short variable names, compressed but readable
            const hasShortVarNames = /var\s+[a-z]\s*=|const\s+[a-z]\s*=|let\s+[a-z]\s*=/.test(content);
            const isLikelyMinified = hasMinifiedStructure || (hasReadableStructure && hasShortVarNames && content.length < 200000);
            
            if (isLikelyMinified) {
              continue; // Skip minified files (they have readable structure)
            }
            
            // Additional check: very long base64 strings (>500 chars) are more suspicious
            // Short base64 might be assets (images, fonts)
            const longBase64Match = content.match(/['"`][A-Za-z0-9+/=]{500,}['"`]/);
            if (pattern.source.includes('base64') && !longBase64Match) {
              continue; // Skip short base64 (likely assets or data)
            }
            
            // Check if file is mostly data (regex patterns, locale strings, etc.)
            // Data files often have long strings but no actual code structure
            const hasCodeStructure = /(?:function|const|let|var|if|for|while|return|=>|class|export|import)/.test(content);
            const isMostlyData = !hasCodeStructure && content.length > 1000;
            
            if (isMostlyData) {
              continue; // Skip data files (regex patterns, locale data, etc.)
            }
            
            // Skip if it's a test file (tests often have obfuscated test data)
            const isTestFile = /(?:^|\/)(?:test|spec|__tests__|__mocks__)(?:\/|$)/i.test(relativePath);
            if (isTestFile) {
              continue;
            }
            
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
                  isMinifiedFile,
                  isLikelyMinified: isLikelyMinified,
                },
                codeSnippet: snippet?.snippet || null,
                lineNumber: snippet?.lineNumber || null,
                falsePositiveHints: [
                  isMinifiedFile ? '✓ This appears to be a minified file - obfuscation patterns are expected' : null,
                  isLikelyMinified ? '✓ This file appears to be minified - skipping' : null,
                  'Minified code may trigger this - check if it\'s build output',
                  'Base64 encoded assets (images, fonts) are usually safe',
                  'Check if obfuscation is consistent with package purpose',
                ].filter(Boolean),
                riskAssessment: 'CRITICAL - Obfuscated code in packages is highly unusual',
              };
            }
            
            issues.push(issue);
            break;
          }
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
