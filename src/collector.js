'use strict';

const fs = require('fs');
const path = require('path');

/**
 * Safely read and parse a JSON file
 * @param {string} filePath - Path to JSON file
 * @returns {Object|null} Parsed JSON or null on error
 */
function safeReadJSON(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
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
 * @returns {Object} Package information
 */
function readPackage(dir, relativePath) {
  const pkgJsonPath = path.join(dir, 'package.json');
  const pkg = safeReadJSON(pkgJsonPath);

  if (!pkg) {
    return null;
  }

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
};
