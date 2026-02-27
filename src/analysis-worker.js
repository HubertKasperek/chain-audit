'use strict';

const { parentPort } = require('worker_threads');
const { analyzePackage } = require('./analyzer');

function deserializeLockIndex(payload) {
  return {
    indexByPath: new Map(payload.indexByPath || []),
    indexByName: new Map(payload.indexByName || []),
    lockVersion: payload.lockVersion || null,
    lockPresent: Boolean(payload.lockPresent),
    lockType: payload.lockType || null,
  };
}

let workerState = {
  lockIndex: null,
  config: null,
};

if (!parentPort) {
  process.exit(1);
}

parentPort.on('message', (message) => {
  if (!message || typeof message !== 'object') {
    return;
  }

  if (message.type === 'init') {
    try {
      workerState = {
        lockIndex: deserializeLockIndex(message.lockIndex || {}),
        config: message.config || {},
      };
      parentPort.postMessage({ type: 'ready' });
    } catch (err) {
      parentPort.postMessage({
        type: 'init_error',
        error: {
          message: err.message,
          stack: err.stack,
        },
      });
    }
    return;
  }

  if (message.type === 'analyze') {
    const taskId = message.id;

    try {
      if (!workerState.lockIndex) {
        throw new Error('Worker not initialized');
      }

      const issues = analyzePackage(message.pkg, workerState.lockIndex, workerState.config);
      parentPort.postMessage({
        type: 'result',
        id: taskId,
        issues,
      });
    } catch (err) {
      parentPort.postMessage({
        type: 'task_error',
        id: taskId,
        error: {
          message: err.message,
          stack: err.stack,
        },
      });
    }
  }
});
