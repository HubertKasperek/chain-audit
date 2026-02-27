'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { loadConfig, mergeConfig, initConfig, DEFAULT_CONFIG, CONFIG_FILES } = require('../src/config');

describe('parseConfigFile (via loadConfig)', () => {
  it('should parse valid config file', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const configPath = path.join(tempDir, 'config.json');
    
    const configData = {
      ignoredPackages: ['test-pkg'],
      scanCode: true,
      failOn: 'high',
    };
    
    fs.writeFileSync(configPath, JSON.stringify(configData));
    
    try {
      const config = loadConfig(configPath);
      assert.deepStrictEqual(config.ignoredPackages, ['test-pkg']);
      assert.strictEqual(config.scanCode, true);
      assert.strictEqual(config.failOn, 'high');
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  it('should throw on invalid JSON', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const configPath = path.join(tempDir, 'config.json');
    
    fs.writeFileSync(configPath, '{ invalid json }');
    
    try {
      assert.throws(() => {
        loadConfig(configPath);
      }, /Invalid JSON/);
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });
});

describe('validateConfig (via loadConfig)', () => {
  it('should accept valid config', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const configPath = path.join(tempDir, '.chainauditrc.json');
    
    const configData = {
      ignoredPackages: ['test'],
      ignoredRules: ['rule1'],
      trustedPackages: ['trusted'],
      scanCode: true,
      checkTyposquatting: false,
      checkLockfile: true,
      failOn: 'high',
      severity: ['critical', 'high'],
      format: 'json',
      verbose: true,
    };
    
    fs.writeFileSync(configPath, JSON.stringify(configData));
    
    try {
      assert.doesNotThrow(() => loadConfig(tempDir));
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  it('should reject invalid ignoredPackages', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const configPath = path.join(tempDir, '.chainauditrc.json');
    
    fs.writeFileSync(configPath, JSON.stringify({ ignoredPackages: 'not-an-array' }));
    
    try {
      assert.throws(() => {
        loadConfig(configPath);
      }, /ignoredPackages must be an array/);
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  it('should reject invalid ignoredRules', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const configPath = path.join(tempDir, '.chainauditrc.json');
    
    fs.writeFileSync(configPath, JSON.stringify({ ignoredRules: 'not-an-array' }));
    
    try {
      assert.throws(() => {
        loadConfig(configPath);
      }, /ignoredRules must be an array/);
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  it('should reject invalid trustedPackages', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const configPath = path.join(tempDir, '.chainauditrc.json');
    
    fs.writeFileSync(configPath, JSON.stringify({ trustedPackages: 'not-an-array' }));
    
    try {
      assert.throws(() => {
        loadConfig(configPath);
      }, /trustedPackages must be an array/);
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  it('should reject invalid failOn', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const configPath = path.join(tempDir, '.chainauditrc.json');
    
    fs.writeFileSync(configPath, JSON.stringify({ failOn: 'invalid' }));
    
    try {
      assert.throws(() => {
        loadConfig(configPath);
      }, /failOn must be one of/);
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  it('should reject invalid scanCode', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const configPath = path.join(tempDir, '.chainauditrc.json');
    
    fs.writeFileSync(configPath, JSON.stringify({ scanCode: 'not-boolean' }));
    
    try {
      assert.throws(() => {
        loadConfig(configPath);
      }, /scanCode must be a boolean/);
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  it('should reject invalid severity', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const configPath = path.join(tempDir, '.chainauditrc.json');
    
    fs.writeFileSync(configPath, JSON.stringify({ severity: 'not-an-array' }));
    
    try {
      assert.throws(() => {
        loadConfig(configPath);
      }, /severity must be an array/);
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
    
    // Test invalid level - need new temp dir
    const tempDir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const configPath2 = path.join(tempDir2, '.chainauditrc.json');
    fs.writeFileSync(configPath2, JSON.stringify({ severity: ['invalid-level'] }));
    try {
      assert.throws(() => {
        loadConfig(configPath2);
      }, /severity contains invalid level/);
    } finally {
      fs.rmSync(tempDir2, { recursive: true });
    }
  });

  it('should reject invalid format', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const configPath = path.join(tempDir, '.chainauditrc.json');
    
    fs.writeFileSync(configPath, JSON.stringify({ format: 'invalid' }));
    
    try {
      assert.throws(() => {
        loadConfig(configPath);
      }, /format must be one of/);
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  it('should reject invalid maxFileSizeForCodeScan', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const configPath = path.join(tempDir, '.chainauditrc.json');
    
    fs.writeFileSync(configPath, JSON.stringify({ maxFileSizeForCodeScan: -1 }));
    
    try {
      assert.throws(() => {
        loadConfig(configPath);
      }, /maxFileSizeForCodeScan must be a positive number/);
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  it('should reject invalid analysisJobs', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const configPath = path.join(tempDir, '.chainauditrc.json');

    fs.writeFileSync(configPath, JSON.stringify({ analysisJobs: -1 }));

    try {
      assert.throws(() => {
        loadConfig(configPath);
      }, /analysisJobs must be a non-negative integer/);
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });
});

describe('loadConfig', () => {
  it('should load config from file path', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const configPath = path.join(tempDir, 'custom-config.json');
    
    const configData = { scanCode: true, failOn: 'high' };
    fs.writeFileSync(configPath, JSON.stringify(configData));
    
    try {
      const config = loadConfig(configPath);
      assert.strictEqual(config.scanCode, true);
      assert.strictEqual(config.failOn, 'high');
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  it('should search for config files in directory', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const configPath = path.join(tempDir, '.chainauditrc.json');
    
    const configData = { scanCode: true };
    fs.writeFileSync(configPath, JSON.stringify(configData));
    
    try {
      const config = loadConfig(tempDir);
      assert.strictEqual(config.scanCode, true);
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  it('should return empty object if no config found', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    
    try {
      const config = loadConfig(tempDir);
      assert.deepStrictEqual(config, {});
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });
});

describe('mergeConfig', () => {
  it('should merge file config with defaults', () => {
    const fileConfig = {
      scanCode: true,
      ignoredPackages: ['test'],
    };
    
    const cliArgs = {};
    const config = mergeConfig(fileConfig, cliArgs);
    
    assert.strictEqual(config.scanCode, true);
    assert.ok(Array.isArray(config.ignoredPackages));
    assert.ok(config.ignoredPackages.includes('test'));
    assert.strictEqual(config.checkTyposquatting, false); // Default
  });

  it('should prioritize CLI args over file config', () => {
    const fileConfig = {
      scanCode: false,
      failOn: 'medium',
    };
    
    const cliArgs = {
      scanCode: true,
      failOn: 'high',
    };
    
    const config = mergeConfig(fileConfig, cliArgs);
    
    assert.strictEqual(config.scanCode, true); // CLI wins
    assert.strictEqual(config.failOn, 'high'); // CLI wins
  });

  it('should merge arrays correctly', () => {
    const fileConfig = {
      ignoredPackages: ['file-pkg'],
      trustedPackages: ['file-trusted'],
    };
    
    const cliArgs = {
      ignoredPackages: ['cli-pkg'],
      trustedPackages: ['cli-trusted'],
    };
    
    const config = mergeConfig(fileConfig, cliArgs);
    
    assert.ok(config.ignoredPackages.includes('file-pkg'));
    assert.ok(config.ignoredPackages.includes('cli-pkg'));
    assert.ok(config.trustedPackages.includes('file-trusted'));
    assert.ok(config.trustedPackages.includes('cli-trusted'));
  });

  it('should handle CLI format override', () => {
    const fileConfig = { format: 'json' };
    const cliArgs = { format: 'sarif' };
    
    const config = mergeConfig(fileConfig, cliArgs);
    assert.strictEqual(config.format, 'sarif');
  });

  it('should merge analysisJobs from file and override with CLI', () => {
    const fileConfig = { analysisJobs: 2 };
    const cliArgs = { jobs: 4 };

    const config = mergeConfig(fileConfig, cliArgs);
    assert.strictEqual(config.analysisJobs, 4);
  });
});

describe('initConfig', () => {
  it('should create config file', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    
    try {
      const result = initConfig(tempDir);
      
      assert.strictEqual(result.success, true);
      assert.ok(fs.existsSync(result.path));
      
      const content = fs.readFileSync(result.path, 'utf8');
      const config = JSON.parse(content);
      assert.ok(Array.isArray(config.ignoredPackages));
      assert.ok(typeof config.scanCode === 'boolean');
      assert.strictEqual(typeof config.analysisJobs, 'number');
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  it('should not overwrite existing file without force', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const configPath = path.join(tempDir, '.chainauditrc.json');
    
    fs.writeFileSync(configPath, '{}');
    
    try {
      const result = initConfig(tempDir);
      
      assert.strictEqual(result.success, false);
      assert.strictEqual(result.exists, true);
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  it('should overwrite existing file with force', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const configPath = path.join(tempDir, '.chainauditrc.json');
    
    fs.writeFileSync(configPath, '{"old": "data"}');
    
    try {
      const result = initConfig(tempDir, { force: true });
      
      assert.strictEqual(result.success, true);
      
      const content = fs.readFileSync(configPath, 'utf8');
      const config = JSON.parse(content);
      assert.strictEqual(config.old, undefined); // Should be overwritten
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });
});

describe('DEFAULT_CONFIG', () => {
  it('should have all expected default values', () => {
    assert.ok(Array.isArray(DEFAULT_CONFIG.ignoredPackages));
    assert.ok(Array.isArray(DEFAULT_CONFIG.ignoredRules));
    assert.strictEqual(typeof DEFAULT_CONFIG.scanCode, 'boolean');
    assert.strictEqual(typeof DEFAULT_CONFIG.checkTyposquatting, 'boolean');
    assert.strictEqual(typeof DEFAULT_CONFIG.checkLockfile, 'boolean');
    assert.ok(Array.isArray(DEFAULT_CONFIG.trustedPackages));
    assert.ok(typeof DEFAULT_CONFIG.trustedPatterns, 'object');
    assert.strictEqual(typeof DEFAULT_CONFIG.analysisJobs, 'number');
  });
});

describe('CONFIG_FILES', () => {
  it('should have expected config file names', () => {
    assert.ok(Array.isArray(CONFIG_FILES));
    assert.ok(CONFIG_FILES.length > 0);
    assert.ok(CONFIG_FILES.includes('.chainauditrc.json'));
  });
});
