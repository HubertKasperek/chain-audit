'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert');
const { buildLockIndex, LOCKFILE_TYPES } = require('../src/lockfile');
const fs = require('fs');
const path = require('path');
const os = require('os');

describe('buildLockIndex', () => {
  it('should return empty index for non-existent file', () => {
    const result = buildLockIndex('/non/existent/path');
    
    assert.strictEqual(result.lockPresent, false);
    assert.strictEqual(result.indexByPath.size, 0);
    assert.strictEqual(result.indexByName.size, 0);
  });

  it('should return empty index for null path', () => {
    const result = buildLockIndex(null);
    
    assert.strictEqual(result.lockPresent, false);
  });
});

describe('npm lockfile parsing', () => {
  it('should parse npm lockfile v2', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const lockPath = path.join(tempDir, 'package-lock.json');
    
    const lockContent = {
      name: 'test-project',
      lockfileVersion: 2,
      packages: {
        '': { name: 'test-project', version: '1.0.0' },
        'node_modules/lodash': {
          version: '4.17.21',
          resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
          integrity: 'sha512-test',
        },
        'node_modules/@types/node': {
          version: '18.0.0',
          resolved: 'https://registry.npmjs.org/@types/node/-/node-18.0.0.tgz',
        },
      },
    };
    
    fs.writeFileSync(lockPath, JSON.stringify(lockContent));
    
    try {
      const result = buildLockIndex(lockPath);
      
      assert.strictEqual(result.lockPresent, true);
      assert.strictEqual(result.lockType, LOCKFILE_TYPES.NPM_V2);
      assert.strictEqual(result.lockVersion, 2);
      
      assert.ok(result.indexByName.has('lodash'));
      assert.strictEqual(result.indexByName.get('lodash').version, '4.17.21');
      
      assert.ok(result.indexByPath.has('lodash'));
      assert.ok(result.indexByPath.has('@types/node'));
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });

  it('should parse npm lockfile v1', () => {
    const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chain-audit-test-'));
    const lockPath = path.join(tempDir, 'package-lock.json');
    
    const lockContent = {
      name: 'test-project',
      lockfileVersion: 1,
      dependencies: {
        lodash: {
          version: '4.17.21',
          resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz',
        },
        express: {
          version: '4.18.0',
          dependencies: {
            'body-parser': { version: '1.20.0' },
          },
        },
      },
    };
    
    fs.writeFileSync(lockPath, JSON.stringify(lockContent));
    
    try {
      const result = buildLockIndex(lockPath);
      
      assert.strictEqual(result.lockPresent, true);
      assert.strictEqual(result.lockType, LOCKFILE_TYPES.NPM_V1);
      
      assert.ok(result.indexByName.has('lodash'));
      assert.ok(result.indexByName.has('express'));
      assert.ok(result.indexByName.has('body-parser'));
    } finally {
      fs.rmSync(tempDir, { recursive: true });
    }
  });
});

describe('LOCKFILE_TYPES', () => {
  it('should have all lockfile types defined', () => {
    assert.ok(LOCKFILE_TYPES.NPM_V1);
    assert.ok(LOCKFILE_TYPES.NPM_V2);
    assert.ok(LOCKFILE_TYPES.YARN_CLASSIC);
    assert.ok(LOCKFILE_TYPES.YARN_BERRY);
    assert.ok(LOCKFILE_TYPES.PNPM);
    assert.ok(LOCKFILE_TYPES.BUN);
  });
});
