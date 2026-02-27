'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { formatText, formatJson, formatSarif } = require('../src/formatters');

describe('formatText', () => {
  it('should format empty issues list', () => {
    const issues = [];
    const summary = { counts: { info: 0, low: 0, medium: 0, high: 0, critical: 0 }, maxSeverity: null };
    const context = {
      nodeModules: './node_modules',
      lockfile: null,
      lockfileType: null,
      packageCount: 0,
      failLevel: null,
      severityFilter: null,
      version: '1.0.0',
      verbose: false,
    };
    
    const output = formatText(issues, summary, context);
    
    assert.ok(output.includes('No issues detected'));
    assert.ok(output.includes('chain-audit'));
    assert.ok(output.includes('analysis workers:'));
  });

  it('should format issues with severity', () => {
    const issues = [
      {
        severity: 'high',
        reason: 'install_script',
        detail: 'Package has install script',
        recommendation: 'Review script',
        package: 'test-pkg',
        version: '1.0.0',
        path: 'framework-a/node_modules/test-pkg',
      },
    ];
    const summary = { counts: { info: 0, low: 0, medium: 0, high: 1, critical: 0 }, maxSeverity: 'high' };
    const context = {
      nodeModules: './node_modules',
      lockfile: null,
      lockfileType: null,
      packageCount: 1,
      analysisJobs: 3,
      failLevel: null,
      severityFilter: null,
      version: '1.0.0',
      verbose: false,
    };
    
    const output = formatText(issues, summary, context);
    
    assert.ok(output.includes('test-pkg'));
    assert.ok(output.includes('dependency tree:'));
    assert.ok(output.includes('framework-a > test-pkg'));
    assert.ok(output.includes('install_script'));
    assert.ok(output.includes('HIGH'));
  });

  it('should sort issues by severity', () => {
    const issues = [
      { severity: 'low', reason: 'low-issue', detail: 'Low', package: 'low-pkg', version: '1.0.0', path: 'low-pkg' },
      { severity: 'critical', reason: 'critical-issue', detail: 'Critical', package: 'critical-pkg', version: '1.0.0', path: 'critical-pkg' },
      { severity: 'medium', reason: 'medium-issue', detail: 'Medium', package: 'medium-pkg', version: '1.0.0', path: 'medium-pkg' },
    ];
    const summary = { counts: { info: 0, low: 1, medium: 1, high: 0, critical: 1 }, maxSeverity: 'critical' };
    const context = {
      nodeModules: './node_modules',
      lockfile: null,
      lockfileType: null,
      packageCount: 3,
      failLevel: null,
      severityFilter: null,
      version: '1.0.0',
      verbose: false,
    };
    
    const output = formatText(issues, summary, context);
    
    // Critical should appear before medium, which should appear before low
    const criticalIndex = output.indexOf('critical-pkg');
    const mediumIndex = output.indexOf('medium-pkg');
    const lowIndex = output.indexOf('low-pkg');
    
    assert.ok(criticalIndex < mediumIndex);
    assert.ok(mediumIndex < lowIndex);
  });

  it('should handle null severity gracefully', () => {
    const issues = [
      {
        severity: null,
        reason: 'test-issue',
        detail: 'Test issue with null severity',
        package: 'test-pkg',
        version: '1.0.0',
        path: 'test-pkg',
      },
    ];
    const summary = { counts: { info: 0, low: 0, medium: 0, high: 0, critical: 0 }, maxSeverity: null };
    const context = {
      nodeModules: './node_modules',
      lockfile: null,
      lockfileType: null,
      packageCount: 1,
      analysisJobs: 3,
      failLevel: null,
      severityFilter: null,
      version: '1.0.0',
      verbose: false,
    };
    
    // Should not throw error
    assert.doesNotThrow(() => {
      const output = formatText(issues, summary, context);
      assert.ok(output.includes('test-pkg'));
      assert.ok(output.includes('UNKNOWN') || output.includes('null'));
    });
  });
});

describe('formatJson', () => {
  it('should format issues as JSON', () => {
    const issues = [
      {
        severity: 'high',
        reason: 'install_script',
        detail: 'Package has install script',
        recommendation: 'Review script',
        package: 'test-pkg',
        version: '1.0.0',
        path: 'test-pkg',
      },
    ];
    const summary = { counts: { info: 0, low: 0, medium: 0, high: 1, critical: 0 }, maxSeverity: 'high' };
    const context = {
      nodeModules: './node_modules',
      lockfile: null,
      lockfileType: null,
      packageCount: 1,
      analysisJobs: 3,
      failLevel: null,
      severityFilter: null,
      version: '1.0.0',
      verbose: false,
    };
    
    const output = formatJson(issues, summary, context);
    const parsed = JSON.parse(output);
    
    assert.strictEqual(parsed.issues.length, 1);
    assert.strictEqual(parsed.issues[0].package, 'test-pkg');
    assert.strictEqual(parsed.summary.total, 1);
    assert.strictEqual(parsed.summary.maxSeverity, 'high');
    assert.strictEqual(parsed.context.analysisJobs, 3);
    assert.ok(parsed.timestamp);
  });

  it('should include verbose data when verbose is enabled', () => {
    const issues = [
      {
        severity: 'high',
        reason: 'install_script',
        detail: 'Package has install script',
        package: 'test-pkg',
        version: '1.0.0',
        path: 'test-pkg',
        verbose: { codeSnippet: 'test code' },
      },
    ];
    const summary = { counts: { info: 0, low: 0, medium: 0, high: 1, critical: 0 }, maxSeverity: 'high' };
    const context = {
      nodeModules: './node_modules',
      lockfile: null,
      lockfileType: null,
      packageCount: 1,
      failLevel: null,
      severityFilter: null,
      version: '1.0.0',
      verbose: true,
    };
    
    const output = formatJson(issues, summary, context);
    const parsed = JSON.parse(output);
    
    assert.ok(parsed.issues[0].verbose);
    assert.strictEqual(parsed.issues[0].verbose.codeSnippet, 'test code');
  });

  it('should filter summary counts by severity filter', () => {
    const issues = [
      { severity: 'critical', reason: 'test', detail: 'Test', package: 'pkg1', version: '1.0.0', path: 'pkg1' },
      { severity: 'high', reason: 'test', detail: 'Test', package: 'pkg2', version: '1.0.0', path: 'pkg2' },
      { severity: 'low', reason: 'test', detail: 'Test', package: 'pkg3', version: '1.0.0', path: 'pkg3' },
    ];
    const summary = { counts: { info: 0, low: 1, medium: 0, high: 1, critical: 1 }, maxSeverity: 'critical' };
    const context = {
      nodeModules: './node_modules',
      lockfile: null,
      lockfileType: null,
      packageCount: 3,
      failLevel: null,
      severityFilter: ['critical', 'high'],
      version: '1.0.0',
      verbose: false,
    };
    
    const output = formatJson(issues, summary, context);
    const parsed = JSON.parse(output);
    
    // Summary should only include filtered severities
    assert.strictEqual(parsed.summary.critical, 1);
    assert.strictEqual(parsed.summary.high, 1);
    assert.strictEqual(parsed.summary.low, undefined);
  });
});

describe('formatSarif', () => {
  it('should format issues as SARIF', () => {
    const issues = [
      {
        severity: 'high',
        reason: 'install_script',
        detail: 'Package has install script',
        recommendation: 'Review script',
        package: 'test-pkg',
        version: '1.0.0',
        path: 'test-pkg',
      },
    ];
    const summary = { counts: { info: 0, low: 0, medium: 0, high: 1, critical: 0 }, maxSeverity: 'high' };
    const context = {
      nodeModules: './node_modules',
      lockfile: null,
      lockfileType: null,
      packageCount: 1,
      failLevel: null,
      severityFilter: null,
      version: '1.0.0',
      verbose: false,
    };
    
    const output = formatSarif(issues, summary, context);
    const parsed = JSON.parse(output);
    
    assert.strictEqual(parsed.version, '2.1.0');
    assert.strictEqual(parsed.runs.length, 1);
    assert.strictEqual(parsed.runs[0].results.length, 1);
    assert.strictEqual(parsed.runs[0].results[0].ruleId, 'install_script');
    assert.strictEqual(parsed.runs[0].tool.driver.name, 'chain-audit');
  });

  it('should map severity levels correctly', () => {
    const issues = [
      { severity: 'critical', reason: 'test', detail: 'Test', package: 'pkg1', version: '1.0.0', path: 'pkg1' },
      { severity: 'high', reason: 'test', detail: 'Test', package: 'pkg2', version: '1.0.0', path: 'pkg2' },
      { severity: 'medium', reason: 'test', detail: 'Test', package: 'pkg3', version: '1.0.0', path: 'pkg3' },
      { severity: 'low', reason: 'test', detail: 'Test', package: 'pkg4', version: '1.0.0', path: 'pkg4' },
    ];
    const summary = { counts: { info: 0, low: 1, medium: 1, high: 1, critical: 1 }, maxSeverity: 'critical' };
    const context = {
      nodeModules: './node_modules',
      lockfile: null,
      lockfileType: null,
      packageCount: 4,
      failLevel: null,
      severityFilter: null,
      version: '1.0.0',
      verbose: false,
    };
    
    const output = formatSarif(issues, summary, context);
    const parsed = JSON.parse(output);
    
    const results = parsed.runs[0].results;
    assert.strictEqual(results[0].level, 'error'); // critical -> error
    assert.strictEqual(results[1].level, 'error'); // high -> error
    assert.strictEqual(results[2].level, 'warning'); // medium -> warning
    assert.strictEqual(results[3].level, 'note'); // low -> note
  });

  it('should include rule definitions', () => {
    const issues = [];
    const summary = { counts: { info: 0, low: 0, medium: 0, high: 0, critical: 0 }, maxSeverity: null };
    const context = {
      nodeModules: './node_modules',
      lockfile: null,
      lockfileType: null,
      packageCount: 0,
      failLevel: null,
      severityFilter: null,
      version: '1.0.0',
      verbose: false,
    };
    
    const output = formatSarif(issues, summary, context);
    const parsed = JSON.parse(output);
    
    assert.ok(parsed.runs[0].tool.driver.rules);
    assert.ok(parsed.runs[0].tool.driver.rules.length > 0);
    
    const installScriptRule = parsed.runs[0].tool.driver.rules.find(r => r.id === 'install_script');
    assert.ok(installScriptRule);
  });
});
