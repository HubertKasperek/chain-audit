'use strict';

/**
 * ANSI color codes
 */
const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
};

/**
 * Determine if colors should be used
 * Respects NO_COLOR env var and TTY detection
 */
function shouldUseColor() {
  // Respect NO_COLOR standard (https://no-color.org/)
  if (process.env.NO_COLOR !== undefined) {
    return false;
  }

  // Force color with FORCE_COLOR
  if (process.env.FORCE_COLOR !== undefined) {
    return process.env.FORCE_COLOR !== '0';
  }

  // Check if stdout is a TTY
  return process.stdout.isTTY === true;
}

const useColor = shouldUseColor();

/**
 * Apply color to text if colors are enabled
 * @param {string} text - Text to colorize
 * @param {string} code - ANSI color code(s)
 * @returns {string} Colorized text or plain text
 */
function color(text, code) {
  if (!useColor) return text;
  return `${code}${text}${colors.reset}`;
}

/**
 * Severity level ordering
 */
const SEVERITY_ORDER = ['info', 'low', 'medium', 'high', 'critical'];

/**
 * Get numeric rank for severity level
 * @param {string} level - Severity level
 * @returns {number} Numeric rank (-1 if invalid)
 */
function rankSeverity(level) {
  const idx = SEVERITY_ORDER.indexOf(level);
  return idx === -1 ? -1 : idx;
}

/**
 * Compare two severity levels
 * @param {string} a - First severity
 * @param {string} b - Second severity
 * @returns {number} Comparison result (-1, 0, or 1)
 */
function compareSeverity(a, b) {
  return rankSeverity(a) - rankSeverity(b);
}

/**
 * Check if severity meets or exceeds threshold
 * @param {string} severity - Severity to check
 * @param {string} threshold - Threshold severity
 * @returns {boolean} True if severity >= threshold
 */
function meetsThreshold(severity, threshold) {
  return rankSeverity(severity) >= rankSeverity(threshold);
}

/**
 * Escape regex special characters in a string.
 * @param {string} text - Raw text to escape
 * @returns {string} Escaped text
 */
function escapeRegExp(text) {
  return String(text).replace(/[|\\{}()[\]^$+?.]/g, '\\$&');
}

/**
 * Convert a simple glob pattern with "*" wildcard to RegExp.
 * @param {string} pattern - Glob pattern (supports only *)
 * @returns {RegExp} Compiled regular expression
 */
function globToRegExp(pattern) {
  const escaped = escapeRegExp(pattern);
  return new RegExp(`^${escaped.replace(/\*/g, '.*')}$`);
}

/**
 * Match value against a simple glob pattern (supports only *).
 * @param {string} pattern - Pattern to match
 * @param {string} value - Value to test
 * @returns {boolean} True when value matches the pattern
 */
function matchesGlobPattern(pattern, value) {
  if (typeof pattern !== 'string' || typeof value !== 'string') {
    return false;
  }
  if (!pattern.includes('*')) {
    return pattern === value;
  }
  return globToRegExp(pattern).test(value);
}

module.exports = {
  colors,
  color,
  useColor,
  SEVERITY_ORDER,
  rankSeverity,
  compareSeverity,
  meetsThreshold,
  escapeRegExp,
  globToRegExp,
  matchesGlobPattern,
};
