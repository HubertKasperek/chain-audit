'use strict';

const path = require('path');

const SEVERITY_LEVELS = ['info', 'low', 'medium', 'high', 'critical'];
const severitySet = new Set(SEVERITY_LEVELS);

/**
 * Ensures a flag has a value that doesn't look like another flag
 */
function ensureOptionValue(flag, value) {
  if (!value || value.startsWith('-')) {
    throw new Error(`Flag ${flag} requires a value`);
  }
  return value;
}

/**
 * Normalizes severity level to lowercase, validates it exists
 */
function normalizeSeverity(level) {
  if (!level) return null;
  const lower = String(level).toLowerCase();
  return severitySet.has(lower) ? lower : null;
}

/**
 * Parse severity filter string (comma-separated severity levels)
 * @param {string} value - Comma-separated severity levels (e.g., "critical,high")
 * @returns {string[]} Array of valid severity levels in the order specified
 */
function parseSeverityFilter(value) {
  if (!value) return null;
  const levels = value.split(',').map(s => s.trim().toLowerCase());
  const validLevels = levels.filter(level => severitySet.has(level));
  if (validLevels.length === 0) return null;
  return validLevels;
}

/**
 * Parse comma-separated list of strings
 * @param {string} value - Comma-separated values
 * @returns {string[]} Array of trimmed non-empty strings
 */
function parseCommaSeparatedList(value) {
  if (!value) return null;
  const items = value.split(',').map(s => s.trim()).filter(s => s.length > 0);
  return items.length > 0 ? items : null;
}

/**
 * Parse non-negative integer value
 * @param {string} value - String value to parse
 * @param {string} flag - Flag name for error messages
 * @param {boolean} allowZero - Whether to allow 0 (default: false)
 * @returns {number} Parsed non-negative integer
 */
function parseNonNegativeInt(value, flag, allowZero = false) {
  const num = parseInt(value, 10);
  if (isNaN(num) || num < 0 || (!allowZero && num === 0)) {
    const msg = allowZero ? 'non-negative integer' : 'positive integer';
    throw new Error(`${flag} must be a ${msg}, got "${value}"`);
  }
  return num;
}

/**
 * Calculate Levenshtein distance between two strings
 * @param {string} a - First string
 * @param {string} b - Second string
 * @returns {number} Edit distance
 */
function levenshteinDistance(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array(m + 1)
    .fill(null)
    .map(() => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = Math.min(
          dp[i - 1][j] + 1, // deletion
          dp[i][j - 1] + 1, // insertion
          dp[i - 1][j - 1] + 1 // substitution
        );
      }
    }
  }

  return dp[m][n];
}

/**
 * Get flag requirements description
 * @param {string} flag - Flag name
 * @returns {string|null} Description of what the flag requires, or null if no value needed
 */
function getFlagRequirement(flag) {
  const requirements = {
    '--node-modules': 'path',
    '-n': 'path',
    '--lock': 'lockfile path',
    '-l': 'lockfile path',
    '--config': 'config path',
    '-c': 'config path',
    '--json': null,
    '--sarif': null,
    '--fail-on': 'severity level',
    '--severity': 'severity levels (comma-separated)',
    '-s': 'severity levels (comma-separated)',
    '--scan-code': null,
    '--check-typosquatting': null,
    '--check-lockfile': null,
    '--detailed': null,
    '--verbose': null,
    '-V': null,
    '--help': null,
    '-h': null,
    '--version': null,
    '-v': null,
    '--init': null,
    '--force': null,
    '-f': null,
    '--ignore-packages': 'package list (comma-separated)',
    '-I': 'package list (comma-separated)',
    '--ignore-rules': 'rule IDs (comma-separated)',
    '-R': 'rule IDs (comma-separated)',
    '--trust-packages': 'package list (comma-separated)',
    '-T': 'package list (comma-separated)',
    '--max-file-size': 'bytes',
    '--max-depth': 'depth number',
    '--max-files': 'file count',
    '--verify-integrity': null,
  };
  return requirements[flag] || null;
}

/**
 * Get all valid flags (both long and short forms)
 * @returns {string[]} Array of all valid flag names
 */
function getAllValidFlags() {
  return [
    '--node-modules',
    '-n',
    '--lock',
    '-l',
    '--config',
    '-c',
    '--json',
    '--sarif',
    '--fail-on',
    '--severity',
    '-s',
    '--scan-code',
    '--check-typosquatting',
    '--check-lockfile',
    '--detailed',
    '--verbose',
    '-V',
    '--help',
    '-h',
    '--version',
    '-v',
    '--init',
    '--force',
    '-f',
    '--ignore-packages',
    '-I',
    '--ignore-rules',
    '-R',
    '--trust-packages',
    '-T',
    '--max-file-size',
    '--max-depth',
    '--max-files',
    '--verify-integrity',
  ];
}

/**
 * Find most similar flags to the given unknown flag
 * @param {string} unknownFlag - The unknown flag that was provided
 * @param {number} maxSuggestions - Maximum number of suggestions (default: 2)
 * @returns {Array<{flag: string, requirement: string|null}>} Array of similar flags with their requirements
 */
function findSimilarFlags(unknownFlag, maxSuggestions = 2) {
  const validFlags = getAllValidFlags();
  const similarities = validFlags.map(flag => ({
    flag,
    requirement: getFlagRequirement(flag),
    distance: levenshteinDistance(unknownFlag.toLowerCase(), flag.toLowerCase()),
  }));

  // Sort by distance (lower is better), then by flag length, then alphabetically
  similarities.sort((a, b) => {
    if (a.distance !== b.distance) {
      return a.distance - b.distance;
    }
    if (a.flag.length !== b.flag.length) {
      return a.flag.length - b.flag.length;
    }
    return a.flag.localeCompare(b.flag);
  });

  // Filter out flags that are too different (distance > 50% of longer string length)
  const maxDistance = Math.max(
    Math.floor(unknownFlag.length * 0.5),
    Math.floor(Math.max(...validFlags.map(f => f.length)) * 0.5),
    3
  );

  return similarities
    .filter(item => item.distance <= maxDistance)
    .slice(0, maxSuggestions)
    .map(item => ({ flag: item.flag, requirement: item.requirement }));
}

/**
 * Parse command line arguments
 * @param {string[]} argv - Process arguments (includes node and script path)
 * @returns {Object} Parsed arguments
 */
function parseArgs(argv) {
  const args = {
    nodeModules: path.resolve(process.cwd(), 'node_modules'),
    lockPath: null,
    configPath: null,
    format: 'text',
    failOn: null,
    severityFilter: null,
    help: false,
    showVersion: false,
    scanCode: false,
    checkTyposquatting: false,
    checkLockfile: false,
    verbose: false,
    init: false,
    force: false,
    // New CLI flags for config parity
    ignoredPackages: null,
    ignoredRules: null,
    trustedPackages: null,
    maxFileSize: null,
    maxDepth: null,
    maxFiles: null,
    verifyIntegrity: false,
  };

  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];

    switch (arg) {
      case '--node-modules':
      case '-n': {
        const value = ensureOptionValue(arg, argv[i + 1]);
        args.nodeModules = path.resolve(process.cwd(), value);
        i += 1;
        break;
      }

      case '--lock':
      case '-l': {
        const value = ensureOptionValue(arg, argv[i + 1]);
        args.lockPath = path.resolve(process.cwd(), value);
        i += 1;
        break;
      }

      case '--config':
      case '-c': {
        const value = ensureOptionValue(arg, argv[i + 1]);
        args.configPath = path.resolve(process.cwd(), value);
        i += 1;
        break;
      }

      case '--json':
        args.format = 'json';
        break;

      case '--sarif':
        args.format = 'sarif';
        break;

      case '--fail-on': {
        const value = ensureOptionValue(arg, argv[i + 1]);
        const normalized = normalizeSeverity(value);
        if (!normalized) {
          throw new Error(
            `Invalid --fail-on level "${value}". Valid levels: ${SEVERITY_LEVELS.join(', ')}`
          );
        }
        args.failOn = normalized;
        i += 1;
        break;
      }

      case '--severity':
      case '-s': {
        const value = ensureOptionValue(arg, argv[i + 1]);
        const parsed = parseSeverityFilter(value);
        if (!parsed) {
          throw new Error(
            `Invalid --severity value "${value}". Valid levels: ${SEVERITY_LEVELS.join(', ')}`
          );
        }
        args.severityFilter = parsed;
        i += 1;
        break;
      }

      case '--scan-code':
        args.scanCode = true;
        break;

      case '--check-typosquatting':
        args.checkTyposquatting = true;
        break;

      case '--check-lockfile':
        args.checkLockfile = true;
        break;

      case '--detailed':
      case '--verbose': // Alias for backward compatibility
      case '-V':
        args.verbose = true;
        break;

      case '--help':
      case '-h':
        args.help = true;
        break;

      case '--version':
      case '-v':
        args.showVersion = true;
        break;

      case '--init':
        args.init = true;
        break;

      case '--force':
      case '-f':
        args.force = true;
        break;

      // New flags for config file parity
      case '--ignore-packages':
      case '-I': {
        const value = ensureOptionValue(arg, argv[i + 1]);
        const parsed = parseCommaSeparatedList(value);
        if (!parsed) {
          throw new Error(`${arg} requires at least one package name`);
        }
        args.ignoredPackages = parsed;
        i += 1;
        break;
      }

      case '--ignore-rules':
      case '-R': {
        const value = ensureOptionValue(arg, argv[i + 1]);
        const parsed = parseCommaSeparatedList(value);
        if (!parsed) {
          throw new Error(`${arg} requires at least one rule ID`);
        }
        args.ignoredRules = parsed;
        i += 1;
        break;
      }

      case '--trust-packages':
      case '-T': {
        const value = ensureOptionValue(arg, argv[i + 1]);
        const parsed = parseCommaSeparatedList(value);
        if (!parsed) {
          throw new Error(`${arg} requires at least one package name`);
        }
        args.trustedPackages = parsed;
        i += 1;
        break;
      }

      case '--max-file-size': {
        const value = ensureOptionValue(arg, argv[i + 1]);
        args.maxFileSize = parseNonNegativeInt(value, arg, false);
        i += 1;
        break;
      }

      case '--max-depth': {
        const value = ensureOptionValue(arg, argv[i + 1]);
        args.maxDepth = parseNonNegativeInt(value, arg, false);
        i += 1;
        break;
      }

      case '--max-files': {
        const value = ensureOptionValue(arg, argv[i + 1]);
        args.maxFiles = parseNonNegativeInt(value, arg, true); // 0 = unlimited
        i += 1;
        break;
      }

      case '--verify-integrity':
        args.verifyIntegrity = true;
        break;

      default:
        if (arg.startsWith('-')) {
          const similarFlags = findSimilarFlags(arg);
          let errorMsg = `Unknown flag: "${arg}".\nSee '--help' for available options.`;
          
          if (similarFlags.length > 0) {
            errorMsg += '\n\nThe most similar flag';
            if (similarFlags.length === 1) {
              errorMsg += ' is';
            } else {
              errorMsg += 's are';
            }
            errorMsg += '\n';
            for (const { flag, requirement } of similarFlags) {
              if (requirement) {
                errorMsg += `        ${flag} <${requirement}>\n`;
              } else {
                errorMsg += `        ${flag}\n`;
              }
            }
          }
          
          throw new Error(errorMsg);
        }
        break;
    }
  }

  return args;
}

module.exports = {
  parseArgs,
  SEVERITY_LEVELS,
  normalizeSeverity,
  parseSeverityFilter,
  parseCommaSeparatedList,
  parseNonNegativeInt,
  findSimilarFlags,
  levenshteinDistance,
};
