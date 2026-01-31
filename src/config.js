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
  checkTyposquatting: false,  // Typosquatting detection (disabled by default due to false positives)
  checkLockfile: false,        // Lockfile integrity checks (disabled by default due to false positives)
  failOn: null,
  severity: null,      // Array of severity levels to show (e.g., ['critical', 'high'])
  format: 'text',      // Output format: 'text', 'json', 'sarif' (sarif is experimental)
  verbose: false,      // Show detailed analysis
  // Known legitimate packages with install scripts
  // NOTE: Whitelist cleared - all packages are now checked without exceptions.
  // Users can still configure trustedPackages in .chainauditrc.json if needed.
  trustedPackages: [],
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
  // Maximum number of JS files to scan per package (0 = unlimited)
  maxFilesPerPackage: 0,
  // Verify integrity hashes from lockfile
  verifyIntegrity: false,
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
  if (config.checkTyposquatting !== undefined && typeof config.checkTyposquatting !== 'boolean') {
    throw new Error('Config: checkTyposquatting must be a boolean');
  }
  if (config.checkLockfile !== undefined && typeof config.checkLockfile !== 'boolean') {
    throw new Error('Config: checkLockfile must be a boolean');
  }
  if (config.severity !== undefined) {
    if (!Array.isArray(config.severity)) {
      throw new Error('Config: severity must be an array of severity levels');
    }
    const validLevels = ['info', 'low', 'medium', 'high', 'critical'];
    for (const level of config.severity) {
      if (!validLevels.includes(level)) {
        throw new Error(`Config: severity contains invalid level "${level}". Valid levels: ${validLevels.join(', ')}`);
      }
    }
  }
  if (config.format !== undefined && !['text', 'json', 'sarif'].includes(config.format)) {
    throw new Error('Config: format must be one of: text, json, sarif');
  }
  if (config.verbose !== undefined && typeof config.verbose !== 'boolean') {
    throw new Error('Config: verbose must be a boolean');
  }
  if (config.maxFileSizeForCodeScan !== undefined) {
    if (typeof config.maxFileSizeForCodeScan !== 'number' || config.maxFileSizeForCodeScan <= 0) {
      throw new Error('Config: maxFileSizeForCodeScan must be a positive number');
    }
  }
  if (config.maxNestedDepth !== undefined) {
    if (typeof config.maxNestedDepth !== 'number' || config.maxNestedDepth <= 0) {
      throw new Error('Config: maxNestedDepth must be a positive number');
    }
  }
  if (config.maxFilesPerPackage !== undefined) {
    if (typeof config.maxFilesPerPackage !== 'number' || config.maxFilesPerPackage < 0) {
      throw new Error('Config: maxFilesPerPackage must be a non-negative number (0 = unlimited)');
    }
  }
  if (config.verifyIntegrity !== undefined && typeof config.verifyIntegrity !== 'boolean') {
    throw new Error('Config: verifyIntegrity must be a boolean');
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
  if (fileConfig.checkTyposquatting !== undefined) {
    config.checkTyposquatting = fileConfig.checkTyposquatting;
  }
  if (fileConfig.checkLockfile !== undefined) {
    config.checkLockfile = fileConfig.checkLockfile;
  }
  if (fileConfig.maxFileSizeForCodeScan !== undefined) {
    config.maxFileSizeForCodeScan = fileConfig.maxFileSizeForCodeScan;
  }
  if (fileConfig.maxNestedDepth !== undefined) {
    config.maxNestedDepth = fileConfig.maxNestedDepth;
  }
  if (fileConfig.maxFilesPerPackage !== undefined) {
    config.maxFilesPerPackage = fileConfig.maxFilesPerPackage;
  }
  if (fileConfig.verifyIntegrity !== undefined) {
    config.verifyIntegrity = fileConfig.verifyIntegrity;
  }
  if (fileConfig.severity) {
    config.severityFilter = fileConfig.severity;
  }
  if (fileConfig.format) {
    config.format = fileConfig.format;
  }
  if (fileConfig.verbose !== undefined) {
    config.verbose = fileConfig.verbose;
  }

  // Apply CLI arguments (highest precedence)
  config.nodeModules = cliArgs.nodeModules;
  config.lockPath = cliArgs.lockPath;

  // CLI format overrides config only if explicitly set (not default 'text')
  if (cliArgs.format && cliArgs.format !== 'text') {
    config.format = cliArgs.format;
  } else if (!fileConfig.format) {
    config.format = cliArgs.format;
  }

  if (cliArgs.failOn) {
    config.failOn = cliArgs.failOn;
  }
  if (cliArgs.scanCode) {
    config.scanCode = true;
  }
  if (cliArgs.checkTyposquatting) {
    config.checkTyposquatting = true;
  }
  if (cliArgs.checkLockfile) {
    config.checkLockfile = true;
  }
  if (cliArgs.severityFilter) {
    config.severityFilter = cliArgs.severityFilter;
  }
  if (cliArgs.verbose) {
    config.verbose = true;
  }

  // New CLI args that override config
  if (cliArgs.ignoredPackages) {
    config.ignoredPackages = [...config.ignoredPackages, ...cliArgs.ignoredPackages];
  }
  if (cliArgs.ignoredRules) {
    config.ignoredRules = [...config.ignoredRules, ...cliArgs.ignoredRules];
  }
  if (cliArgs.trustedPackages) {
    config.trustedPackages = [...config.trustedPackages, ...cliArgs.trustedPackages];
  }
  if (cliArgs.maxFileSize !== undefined && cliArgs.maxFileSize !== null) {
    config.maxFileSizeForCodeScan = cliArgs.maxFileSize;
  }
  if (cliArgs.maxDepth !== undefined && cliArgs.maxDepth !== null) {
    config.maxNestedDepth = cliArgs.maxDepth;
  }
  if (cliArgs.maxFiles !== undefined && cliArgs.maxFiles !== null) {
    config.maxFilesPerPackage = cliArgs.maxFiles;
  }
  if (cliArgs.verifyIntegrity) {
    config.verifyIntegrity = true;
  }

  return config;
}

/**
 * Generate example configuration file content
 * @returns {string} JSON string with example configuration
 */
function generateExampleConfig() {
  const exampleConfig = {
    // Comment-like keys will be stripped in final output, but we use real JSON structure
    ignoredPackages: [
      "example-package-to-ignore",
      "@scope/package-to-ignore",
      "@types/*"
    ],
    ignoredRules: [
      "native_binary"
    ],
    trustedPackages: [
      "my-native-addon",
      "my-build-tool"
    ],
    trustedPatterns: {
      "custom-build-script": true
    },
    scanCode: false,
    checkTyposquatting: false,
    checkLockfile: false,
    failOn: "high",
    severity: ["critical", "high", "medium"],
    format: "text",
    verbose: false,
    maxFileSizeForCodeScan: 1048576,
    maxNestedDepth: 10,
    maxFilesPerPackage: 0,
    verifyIntegrity: false
  };

  return JSON.stringify(exampleConfig, null, 2);
}

/**
 * Initialize a new configuration file in the specified directory
 * @param {string} targetDir - Directory to create config file in
 * @param {Object} options - Options for initialization
 * @param {string} options.filename - Config filename (default: .chainauditrc.json)
 * @param {boolean} options.force - Overwrite existing file
 * @returns {Object} Result with success status and message
 */
function initConfig(targetDir, options = {}) {
  const filename = options.filename || '.chainauditrc.json';
  const force = options.force || false;
  const configPath = path.join(targetDir, filename);

  // Check if file already exists
  if (fs.existsSync(configPath) && !force) {
    return {
      success: false,
      message: `Configuration file already exists at ${configPath}. Use --force to overwrite.`,
      path: configPath,
      exists: true,
    };
  }

  const content = generateExampleConfig();
  
  try {
    fs.writeFileSync(configPath, content, 'utf8');
    return {
      success: true,
      message: `Configuration file created at ${configPath}`,
      path: configPath,
      exists: false,
    };
  } catch (err) {
    return {
      success: false,
      message: `Failed to create configuration file: ${err.message}`,
      path: configPath,
      error: err,
    };
  }
}

module.exports = {
  loadConfig,
  mergeConfig,
  initConfig,
  generateExampleConfig,
  DEFAULT_CONFIG,
  CONFIG_FILES,
};
