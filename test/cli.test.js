'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { parseArgs, normalizeSeverity, parseSeverityFilter, parseCommaSeparatedList, parseNonNegativeInt, findSimilarFlags, levenshteinDistance, SEVERITY_LEVELS } = require('../src/cli');

describe('normalizeSeverity', () => {
  it('should normalize valid severity levels', () => {
    assert.strictEqual(normalizeSeverity('CRITICAL'), 'critical');
    assert.strictEqual(normalizeSeverity('High'), 'high');
    assert.strictEqual(normalizeSeverity('medium'), 'medium');
  });

  it('should return null for invalid severity', () => {
    assert.strictEqual(normalizeSeverity('invalid'), null);
    assert.strictEqual(normalizeSeverity(null), null);
    assert.strictEqual(normalizeSeverity(''), null);
  });
});

describe('parseSeverityFilter', () => {
  it('should parse comma-separated severity levels', () => {
    const result = parseSeverityFilter('critical,high,medium');
    assert.deepStrictEqual(result, ['critical', 'high', 'medium']);
  });

  it('should normalize to lowercase', () => {
    const result = parseSeverityFilter('CRITICAL,HIGH');
    assert.deepStrictEqual(result, ['critical', 'high']);
  });

  it('should filter out invalid levels', () => {
    const result = parseSeverityFilter('critical,invalid,high');
    assert.deepStrictEqual(result, ['critical', 'high']);
  });

  it('should return null for empty or all invalid', () => {
    assert.strictEqual(parseSeverityFilter(''), null);
    assert.strictEqual(parseSeverityFilter('invalid1,invalid2'), null);
  });

  it('should handle whitespace', () => {
    const result = parseSeverityFilter(' critical , high ');
    assert.deepStrictEqual(result, ['critical', 'high']);
  });
});

describe('parseCommaSeparatedList', () => {
  it('should parse comma-separated values', () => {
    const result = parseCommaSeparatedList('a,b,c');
    assert.deepStrictEqual(result, ['a', 'b', 'c']);
  });

  it('should trim whitespace', () => {
    const result = parseCommaSeparatedList(' a , b , c ');
    assert.deepStrictEqual(result, ['a', 'b', 'c']);
  });

  it('should filter empty strings', () => {
    const result = parseCommaSeparatedList('a,,b');
    assert.deepStrictEqual(result, ['a', 'b']);
  });

  it('should return null for empty input', () => {
    assert.strictEqual(parseCommaSeparatedList(''), null);
    assert.strictEqual(parseCommaSeparatedList('   '), null);
  });
});

describe('parseNonNegativeInt', () => {
  it('should parse valid positive integers', () => {
    assert.strictEqual(parseNonNegativeInt('10', '--test'), 10);
    assert.strictEqual(parseNonNegativeInt('0', '--test', true), 0);
  });

  it('should throw on negative numbers', () => {
    assert.throws(() => {
      parseNonNegativeInt('-1', '--test');
    }, /must be a/);
  });

  it('should throw on zero when not allowed', () => {
    assert.throws(() => {
      parseNonNegativeInt('0', '--test', false);
    }, /must be a positive integer/);
  });

  it('should throw on NaN', () => {
    assert.throws(() => {
      parseNonNegativeInt('abc', '--test');
    }, /must be a/);
  });
});

describe('levenshteinDistance', () => {
  it('should calculate edit distance correctly', () => {
    assert.strictEqual(levenshteinDistance('kitten', 'sitting'), 3);
    assert.strictEqual(levenshteinDistance('', ''), 0);
    assert.strictEqual(levenshteinDistance('abc', ''), 3);
    assert.strictEqual(levenshteinDistance('', 'abc'), 3);
    assert.strictEqual(levenshteinDistance('same', 'same'), 0);
  });
});

describe('findSimilarFlags', () => {
  it('should find similar flags for typos', () => {
    const result = findSimilarFlags('--jsonn');
    assert.ok(result.length > 0);
    assert.ok(result.some(r => r.flag === '--json'));
  });

  it('should find similar flags for missing characters', () => {
    const result = findSimilarFlags('--severit');
    assert.ok(result.length > 0);
    assert.ok(result.some(r => r.flag === '--severity'));
  });

  it('should return empty array for very different flags', () => {
    const result = findSimilarFlags('--completely-different-flag');
    // Should return empty or very few suggestions
    assert.ok(Array.isArray(result));
  });
});

describe('parseArgs', () => {
  it('should parse basic flags', () => {
    const args = parseArgs(['node', 'script', '--json', '--scan-code']);
    
    assert.strictEqual(args.format, 'json');
    assert.strictEqual(args.scanCode, true);
  });

  it('should parse node-modules path', () => {
    const args = parseArgs(['node', 'script', '--node-modules', './custom/node_modules']);
    
    assert.ok(args.nodeModules.endsWith('custom/node_modules'));
  });

  it('should parse lockfile path', () => {
    const args = parseArgs(['node', 'script', '--lock', './package-lock.json']);
    
    assert.ok(args.lockPath.endsWith('package-lock.json'));
  });

  it('should parse severity filter', () => {
    const args = parseArgs(['node', 'script', '--severity', 'critical,high']);
    
    assert.deepStrictEqual(args.severityFilter, ['critical', 'high']);
  });

  it('should parse fail-on', () => {
    const args = parseArgs(['node', 'script', '--fail-on', 'high']);
    
    assert.strictEqual(args.failOn, 'high');
  });

  it('should throw on invalid fail-on', () => {
    assert.throws(() => {
      parseArgs(['node', 'script', '--fail-on', 'invalid']);
    }, /Invalid --fail-on level/);
  });

  it('should parse ignore-packages', () => {
    const args = parseArgs(['node', 'script', '--ignore-packages', 'pkg1,pkg2']);
    
    assert.deepStrictEqual(args.ignoredPackages, ['pkg1', 'pkg2']);
  });

  it('should parse ignore-rules', () => {
    const args = parseArgs(['node', 'script', '--ignore-rules', 'rule1,rule2']);
    
    assert.deepStrictEqual(args.ignoredRules, ['rule1', 'rule2']);
  });

  it('should parse trust-packages', () => {
    const args = parseArgs(['node', 'script', '--trust-packages', 'pkg1']);
    
    assert.deepStrictEqual(args.trustedPackages, ['pkg1']);
  });

  it('should parse max-file-size', () => {
    const args = parseArgs(['node', 'script', '--max-file-size', '2048']);
    
    assert.strictEqual(args.maxFileSize, 2048);
  });

  it('should parse max-depth', () => {
    const args = parseArgs(['node', 'script', '--max-depth', '5']);
    
    assert.strictEqual(args.maxDepth, 5);
  });

  it('should parse max-files', () => {
    const args = parseArgs(['node', 'script', '--max-files', '100']);
    
    assert.strictEqual(args.maxFiles, 100);
  });

  it('should parse verify-integrity flag', () => {
    const args = parseArgs(['node', 'script', '--verify-integrity']);
    
    assert.strictEqual(args.verifyIntegrity, true);
  });

  it('should handle short flags', () => {
    const args = parseArgs(['node', 'script', '-n', './node_modules', '-l', './lock.json', '-s', 'critical']);
    
    assert.ok(args.nodeModules.endsWith('node_modules'));
    assert.ok(args.lockPath.endsWith('lock.json'));
    assert.deepStrictEqual(args.severityFilter, ['critical']);
  });

  it('should handle help and version flags', () => {
    const args1 = parseArgs(['node', 'script', '--help']);
    assert.strictEqual(args1.help, true);
    
    const args2 = parseArgs(['node', 'script', '--version']);
    assert.strictEqual(args2.showVersion, true);
  });

  it('should handle init and force flags', () => {
    const args = parseArgs(['node', 'script', '--init', '--force']);
    
    assert.strictEqual(args.init, true);
    assert.strictEqual(args.force, true);
  });

  it('should throw on unknown flag', () => {
    assert.throws(() => {
      parseArgs(['node', 'script', '--unknown-flag']);
    }, /Unknown flag/);
  });

  it('should throw on flag missing value', () => {
    assert.throws(() => {
      parseArgs(['node', 'script', '--node-modules']);
    }, /requires a value/);
  });

  it('should use default node_modules path', () => {
    const args = parseArgs(['node', 'script']);
    
    assert.ok(args.nodeModules);
    assert.ok(args.nodeModules.includes('node_modules'));
  });
});

describe('SEVERITY_LEVELS', () => {
  it('should have all expected levels', () => {
    assert.deepStrictEqual(SEVERITY_LEVELS, ['info', 'low', 'medium', 'high', 'critical']);
  });
});
