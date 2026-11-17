'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { create } = require('./local_flow_counters.js');

test('official-range preflight failure leaves every candidate unscanned and sends zero scanner requests', () => {
  const counters = create(9, 4);
  assert.deepEqual(counters.snapshot(), {
    total: 9, limit: 4, attempted: 0, inFlight: 0, verified: 0, notScanned: 9, unknown: 0
  });
});

test('four concurrent HTTP 503 range rejections never become verified results', () => {
  const counters = create(10, 8);
  for (let index = 0; index < 4; index += 1) assert.equal(counters.begin(index), true);
  assert.deepEqual(counters.snapshot(), {
    total: 10, limit: 8, attempted: 4, inFlight: 4, verified: 0, notScanned: 6, unknown: 0
  });
  for (let index = 0; index < 4; index += 1) assert.equal(counters.notScanned(index), true);
  assert.deepEqual(counters.snapshot(), {
    total: 10, limit: 8, attempted: 4, inFlight: 0, verified: 0, notScanned: 10, unknown: 0
  });
});

test('cancellation during four in-flight requests shows unknown, not false tested results', () => {
  const counters = create(10, 8);
  for (let index = 0; index < 4; index += 1) assert.equal(counters.begin(index), true);
  for (let index = 0; index < 4; index += 1) assert.equal(counters.unknown(index), true);
  assert.deepEqual(counters.snapshot(), {
    total: 10, limit: 8, attempted: 4, inFlight: 0, verified: 0, notScanned: 6, unknown: 4
  });
});

test('only an in-flight candidate can become a verified scanner result', () => {
  const counters = create(3, 3);
  assert.equal(counters.verified(0), false);
  assert.equal(counters.begin(0), true);
  assert.equal(counters.verified(0), true);
  assert.equal(counters.verified(0), false);
  assert.deepEqual(counters.snapshot(), {
    total: 3, limit: 3, attempted: 1, inFlight: 0, verified: 1, notScanned: 2, unknown: 0
  });
});
