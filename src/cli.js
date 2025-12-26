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

      case '--verbose':
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
          console.warn(`Warning: Unknown flag "${arg}" - ignoring`);
        }
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
};
