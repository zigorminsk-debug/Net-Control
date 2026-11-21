'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { History, DAY } = require('../src/history');
const { parseCidrs } = require('../src/direction');
test('history is opt in, bounded by age, persistent, and supports clear', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(),'netcontrol-')); const file = path.join(dir,'history.json');
  try {
    const h = new History(file); const now = Date.now(); const lan = parseCidrs('10.0.0.0/24');
    const f = {src:'10.0.0.1',dst:'8.8.8.8',bytes:100,packets:1};
    h.ingest([f],lan,now); assert.equal(h.summary(now).bucketCount,0);
    h.setEnabled(true);
    for (let day = 1; day <= 3; day++) for (let i=0;i<7;i++) h.ingest([f],lan,now-day*DAY-i*300000);
    assert.ok(h.baselines(now).has('10.0.0.1'));
    h.capture([{type:'test',ip:'10.0.0.1',detail:'x'}],now); h.capture([{type:'test',ip:'10.0.0.1',detail:'x'}],now);
    assert.equal(h.summary(now).eventCount,1); h.flush();
    const h2 = new History(file); h2.load(now); assert.equal(h2.enabled,true); assert.equal(h2.summary(now).eventCount,1); assert.ok(h2.baselines(now).has('10.0.0.1'));
    h2.prune(now+8*DAY); assert.equal(h2.summary(now+8*DAY).eventCount,0); h2.clear(); assert.equal(h2.summary(now).bucketCount,0);
  } finally { fs.rmSync(dir,{recursive:true,force:true}); }
});
test('configurable retention and host daily summary keep existing history opt in', () => {
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'netcontrol-retention-')); try {
  const file=path.join(dir,'h.json'), h=new History(file), now=Date.now(), lan=parseCidrs('10.0.0.0/24');
  h.setEnabled(true); h.setRetentionDays(3); const f={src:'10.0.0.1',dst:'8.8.8.8',bytes:42,packets:1};
  h.ingest([f],lan,now-DAY); h.ingest([f],lan,now); assert.equal(h.hostDays('10.0.0.1',now).days.reduce((n,d)=>n+d.bytes,0),84); h.flush();
  const loaded=new History(file);loaded.load(now);assert.equal(loaded.retentionDays,3);assert.throws(()=>loaded.setRetentionDays(31));loaded.prune(now+4*DAY); assert.equal(loaded.hostDays('10.0.0.1',now+4*DAY).days.length,0);
 } finally {fs.rmSync(dir,{recursive:true,force:true});}
});
