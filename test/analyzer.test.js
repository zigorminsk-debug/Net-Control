'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { Analyzer, WINDOW_MS } = require('../src/analyzer');
test('detects patterns in a bounded time window, without declaring infection', () => {
  const a = new Analyzer(); a.setNetworks('10.0.0.0/24'); const now = 1000000;
  const flows = Array.from({length:30}, (_,i) => ({ src:'10.0.0.2', dst:`10.1.0.${i}`, dstPort: i < 10 ? 25 : 3333, protocol:6, bytes:100, packets:1 }));
  a.add(flows,now); const s = a.snapshot(now);
  assert.equal(s.bytes,3000); assert.equal(s.hostCount,1); assert.equal(s.alertCount,3); assert.equal(s.buckets.reduce((a,b)=>a+b,0),30);
  assert.equal(a.snapshot(now+WINDOW_MS+1).flowCount,0);
});
test('caps memory and reports discarded flows', () => { const a = new Analyzer(); const f = {src:'a',dst:'b',bytes:1,packets:1}; a.add(Array(50001).fill(f),1); assert.equal(a.snapshot(1).flowCount,50000); assert.equal(a.snapshot(1).dropped,1); a.clear(); assert.equal(a.snapshot(1).received,0); });
