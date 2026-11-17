(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.LocalFlowCounters = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  function asCount(value) {
    return Number.isInteger(value) && value > 0 ? value : 0;
  }

  function create(candidateCount, scanLimit) {
    const total = asCount(candidateCount);
    const limit = Math.min(total, asCount(scanLimit));
    const states = Array(total).fill('not-scanned');
    let attempted = 0;

    function transition(index, from, to) {
      if (!Number.isInteger(index) || index < 0 || index >= total || states[index] !== from) return false;
      states[index] = to;
      return true;
    }

    return Object.freeze({
      begin(index) {
        if (index >= limit || !transition(index, 'not-scanned', 'in-flight')) return false;
        attempted += 1;
        return true;
      },
      verified(index) {
        return transition(index, 'in-flight', 'verified');
      },
      notScanned(index) {
        return transition(index, 'in-flight', 'not-scanned');
      },
      unknown(index) {
        return transition(index, 'in-flight', 'unknown');
      },
      snapshot() {
        const counts = { total, limit, attempted, inFlight: 0, verified: 0, notScanned: 0, unknown: 0 };
        for (const state of states) {
          if (state === 'in-flight') counts.inFlight += 1;
          else if (state === 'verified') counts.verified += 1;
          else if (state === 'unknown') counts.unknown += 1;
          else counts.notScanned += 1;
        }
        return counts;
      },
      state(index) {
        return Number.isInteger(index) && index >= 0 && index < total ? states[index] : null;
      }
    });
  }

  return Object.freeze({ create });
});
