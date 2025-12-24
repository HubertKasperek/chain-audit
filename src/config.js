'use strict';

const fs = require('fs');
const path = require('path');

const CONFIG_FILES = [
  '.chainauditrc.json',
  '.chainauditrc',
  'chainaudit.config.json',
];

const DEFAULT_CONFIG = {
  ignoredPackages: [],
  ignoredRules: [],
  scanCode: false,
  failOn: null,
  // Known legitimate packages with install scripts
  trustedPackages: [
    'esbuild',
    'swc',
    '@swc/*',
    'sharp',
    'better-sqlite3',
    'bcrypt',
    'node-sass',
    'puppeteer',
    'playwright',
    '@playwright/*',
    'electron',
    'node-gyp',
  ],
  // Patterns that reduce severity for known legitimate use cases
  trustedPatterns: {
    // node-gyp rebuild is common for native modules
    'node-gyp rebuild': true,
    'prebuild-install': true,
    'node-pre-gyp': true,
  },
  // Maximum file size to scan for code patterns (in bytes)
  maxFileSizeForCodeScan: 1024 * 1024, // 1MB
  // Maximum depth to traverse nested node_modules
  maxNestedDepth: 10,
};

/**
 * Load configuration from file
 * @param {string} configPathOrDir - Path to config file or directory to search
 * @returns {Object} Configuration object
 */
function loadConfig(configPathOrDir) {
  // If it's a direct path to a file
  if (configPathOrDir && fs.existsSync(configPathOrDir)) {
    const stat = fs.statSync(configPathOrDir);
    if (stat.isFile()) {
      return parseConfigFile(configPathOrDir);
    }
  }

  // Search for config files in directory
  const searchDir = configPathOrDir || process.cwd();
  for (const filename of CONFIG_FILES) {
    const configPath = path.join(searchDir, filename);
    if (fs.existsSync(configPath)) {
      return parseConfigFile(configPath);
    }
  }

  return {};
}

/**
 * Parse a configuration file
 * @param {string} configPath - Path to config file
 * @returns {Object} Parsed configuration
 */
function parseConfigFile(configPath) {
  try {
    const content = fs.readFileSync(configPath, 'utf8');
    const config = JSON.parse(content);
    validateConfig(config);
    return config;
  } catch (err) {
    if (err instanceof SyntaxError) {
      throw new Error(`Invalid JSON in config file ${configPath}: ${err.message}`);
    }
    throw new Error(`Cannot read config file ${configPath}: ${err.message}`);
  }
}

/**
 * Validate configuration object
 * @param {Object} config - Configuration to validate
 */
function validateConfig(config) {
  if (config.ignoredPackages && !Array.isArray(config.ignoredPackages)) {
    throw new Error('Config: ignoredPackages must be an array');
  }
  if (config.ignoredRules && !Array.isArray(config.ignoredRules)) {
    throw new Error('Config: ignoredRules must be an array');
  }
  if (config.trustedPackages && !Array.isArray(config.trustedPackages)) {
    throw new Error('Config: trustedPackages must be an array');
  }
  if (config.failOn && !['info', 'low', 'medium', 'high', 'critical'].includes(config.failOn)) {
    throw new Error('Config: failOn must be one of: info, low, medium, high, critical');
  }
  if (config.scanCode !== undefined && typeof config.scanCode !== 'boolean') {
    throw new Error('Config: scanCode must be a boolean');
  }
}

/**
 * Merge configurations with precedence: CLI args > file config > defaults
 * @param {Object} fileConfig - Configuration from file
 * @param {Object} cliArgs - Arguments from command line
 * @returns {Object} Merged configuration
 */
function mergeConfig(fileConfig, cliArgs) {
  const config = { ...DEFAULT_CONFIG };

  // Apply file configuration
  if (fileConfig.ignoredPackages) {
    config.ignoredPackages = [...config.ignoredPackages, ...fileConfig.ignoredPackages];
  }
  if (fileConfig.ignoredRules) {
    config.ignoredRules = fileConfig.ignoredRules;
  }
  if (fileConfig.trustedPackages) {
    config.trustedPackages = [...config.trustedPackages, ...fileConfig.trustedPackages];
  }
  if (fileConfig.trustedPatterns) {
    config.trustedPatterns = { ...config.trustedPatterns, ...fileConfig.trustedPatterns };
  }
  if (fileConfig.failOn) {
    config.failOn = fileConfig.failOn;
  }
  if (fileConfig.scanCode !== undefined) {
    config.scanCode = fileConfig.scanCode;
  }
  if (fileConfig.maxFileSizeForCodeScan) {
    config.maxFileSizeForCodeScan = fileConfig.maxFileSizeForCodeScan;
  }

  // Apply CLI arguments (highest precedence)
  config.nodeModules = cliArgs.nodeModules;
  config.lockPath = cliArgs.lockPath;
  config.format = cliArgs.format;

  if (cliArgs.failOn) {
    config.failOn = cliArgs.failOn;
  }
  if (cliArgs.scanCode) {
    config.scanCode = true;
  }

  return config;
}

module.exports = {
  loadConfig,
  mergeConfig,
  DEFAULT_CONFIG,
};
