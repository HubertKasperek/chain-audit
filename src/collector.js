'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Error types for JSON reading
 */
const JSON_READ_ERROR = {
  FILE_NOT_FOUND: 'FILE_NOT_FOUND',
  PERMISSION_DENIED: 'PERMISSION_DENIED',
  PARSE_ERROR: 'PARSE_ERROR',
  UNKNOWN: 'UNKNOWN',
};

/**
 * Safely read and parse a JSON file with detailed error information
 * @param {string} filePath - Path to JSON file
 * @param {Object} options - Options
 * @param {boolean} options.warnOnError - Whether to log warnings on errors (default: false)
 * @returns {Object} Result object with { data, error, errorType }
 */
function safeReadJSONWithDetails(filePath, options = {}) {
  const warnOnError = options.warnOnError || false;

  try {
    const content = fs.readFileSync(filePath, 'utf8');
    try {
      const data = JSON.parse(content);
      return { data, error: null, errorType: null };
    } catch (parseErr) {
      if (warnOnError) {
        console.warn(`Warning: Invalid JSON in ${filePath}: ${parseErr.message}`);
      }
      return {
        data: null,
        error: parseErr.message,
        errorType: JSON_READ_ERROR.PARSE_ERROR,
        filePath,
      };
    }
  } catch (readErr) {
    if (readErr.code === 'ENOENT') {
      return {
        data: null,
        error: 'File not found',
        errorType: JSON_READ_ERROR.FILE_NOT_FOUND,
        filePath,
      };
    }
    if (readErr.code === 'EACCES' || readErr.code === 'EPERM') {
      if (warnOnError) {
        console.warn(`Warning: Permission denied reading ${filePath}`);
      }
      return {
        data: null,
        error: 'Permission denied',
        errorType: JSON_READ_ERROR.PERMISSION_DENIED,
        filePath,
      };
    }
    if (warnOnError) {
      console.warn(`Warning: Cannot read ${filePath}: ${readErr.message}`);
    }
    return {
      data: null,
      error: readErr.message,
      errorType: JSON_READ_ERROR.UNKNOWN,
      filePath,
    };
  }
}

/**
 * Collect all packages from node_modules recursively
 * @param {string} nodeModulesPath - Path to node_modules
 * @param {number} maxDepth - Maximum nesting depth (default: 10)
 * @returns {Object[]} Array of package objects
 */
function collectPackages(nodeModulesPath, maxDepth = 10) {
  const packages = [];
  const visited = new Set(); // Prevent infinite loops from symlinks
  const stack = [{ dir: nodeModulesPath, relative: '', depth: 0 }];

  while (stack.length > 0) {
    const { dir, relative, depth } = stack.pop();

    if (depth > maxDepth) continue;
    if (!fs.existsSync(dir)) continue;

    // Resolve real path to handle symlinks
    let realDir;
    try {
      realDir = fs.realpathSync(dir);
    } catch {
      continue;
    }

    if (visited.has(realDir)) continue;
    visited.add(realDir);

    let entries = [];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (err) {
      // Permission denied or other read error
      continue;
    }

    for (const entry of entries) {
      // Skip hidden files and .bin directory
      if (entry.name.startsWith('.')) continue;
      if (entry.name === '.bin') continue;

      const entryPath = path.join(dir, entry.name);
      const relPath = relative ? path.join(relative, entry.name) : entry.name;

      if (!entry.isDirectory()) continue;

      if (entry.name.startsWith('@')) {
        // Scoped package - need to go one level deeper
        processScopedPackage(entryPath, relPath, depth, stack, packages);
      } else {
        // Regular package
        processPackage(entryPath, relPath, depth, stack, packages);
      }
    }
  }

  return packages;
}

/**
 * Process a scoped package directory (@scope)
 */
function processScopedPackage(scopeDir, scopeRel, depth, stack, packages) {
  let scopeEntries = [];
  try {
    scopeEntries = fs.readdirSync(scopeDir, { withFileTypes: true });
  } catch {
    return;
  }

  for (const scoped of scopeEntries) {
    if (!scoped.isDirectory()) continue;
    if (scoped.name.startsWith('.')) continue;

    const scopedDir = path.join(scopeDir, scoped.name);
    const scopedRel = path.join(scopeRel, scoped.name);
    
    processPackage(scopedDir, scopedRel, depth, stack, packages);
  }
}

/**
 * Process a single package directory
 */
function processPackage(pkgDir, pkgRel, depth, stack, packages) {
  const pkgJsonPath = path.join(pkgDir, 'package.json');

  if (fs.existsSync(pkgJsonPath)) {
    const pkg = readPackage(pkgDir, pkgRel);
    if (pkg) {
      packages.push(pkg);
    }

    // Check for nested node_modules
    const nestedNodeModules = path.join(pkgDir, 'node_modules');
    if (fs.existsSync(nestedNodeModules)) {
      stack.push({
        dir: nestedNodeModules,
        relative: path.join(pkgRel, 'node_modules'),
        depth: depth + 1,
      });
    }
  } else {
    // Not a package, might be a directory containing packages
    stack.push({ dir: pkgDir, relative: pkgRel, depth });
  }
}

/**
 * Read package.json and extract relevant information
 * @param {string} dir - Package directory
 * @param {string} relativePath - Relative path from node_modules root
 * @returns {Object} Package information with optional parseError flag
 */
function readPackage(dir, relativePath) {
  const pkgJsonPath = path.join(dir, 'package.json');
  const result = safeReadJSONWithDetails(pkgJsonPath, { warnOnError: true });

  // If file not found, return null (directory is not a valid package)
  if (result.errorType === JSON_READ_ERROR.FILE_NOT_FOUND) {
    return null;
  }

  // If there was a parse error or other read error, return a minimal package
  // object with error information so it can still be flagged
  if (result.error) {
    return {
      name: path.basename(dir),
      version: 'unknown',
      description: '',
      scripts: {},
      dependencies: {},
      devDependencies: {},
      peerDependencies: {},
      optionalDependencies: {},
      bin: null,
      main: null,
      module: null,
      exports: null,
      author: null,
      repository: null,
      homepage: null,
      license: null,
      publishConfig: null,
      dir,
      relativePath,
      // Error information for security analysis
      _parseError: true,
      _errorType: result.errorType,
      _errorMessage: result.error,
    };
  }

  const pkg = result.data;

  return {
    name: pkg.name || path.basename(dir),
    version: pkg.version || 'unknown',
    description: pkg.description || '',
    scripts: pkg.scripts || {},
    dependencies: pkg.dependencies || {},
    devDependencies: pkg.devDependencies || {},
    peerDependencies: pkg.peerDependencies || {},
    optionalDependencies: pkg.optionalDependencies || {},
    bin: pkg.bin || null,
    main: pkg.main || null,
    module: pkg.module || null,
    exports: pkg.exports || null,
    // Metadata that might indicate suspicious packages
    author: normalizeAuthor(pkg.author),
    repository: normalizeRepository(pkg.repository),
    homepage: pkg.homepage || null,
    license: pkg.license || null,
    publishConfig: pkg.publishConfig || null,
    // Directory info
    dir,
    relativePath,
  };
}

/**
 * Normalize author field to string
 */
function normalizeAuthor(author) {
  if (!author) return null;
  if (typeof author === 'string') return author;
  if (typeof author === 'object') {
    return [author.name, author.email ? `<${author.email}>` : null]
      .filter(Boolean)
      .join(' ');
  }
  return null;
}

/**
 * Normalize repository field to URL
 */
function normalizeRepository(repo) {
  if (!repo) return null;
  if (typeof repo === 'string') return repo;
  if (typeof repo === 'object' && repo.url) return repo.url;
  return null;
}

module.exports = {
  collectPackages,
  readPackage,
  safeReadJSONWithDetails,
  JSON_READ_ERROR,
};
