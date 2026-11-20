'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { ReputationStore, parseContent, MAX_AGE } = require('../src/reputation');
const { Analyzer } = require('../src/analyzer');
function content(text) { const buf = Buffer.from(text); return {encoding:'base64',size:buf.length,sha:crypto.createHash('sha1').update(`blob ${buf.length}\0`).update(buf).digest('hex'),content:buf.toString('base64')}; }
test('parses and integrity-checks bounded IP lists', () => {
  const data = content('# source\n8.8.8.8\n1.1.1.1\n8.8.8.8\n');
  assert.deepEqual(parseContent(data).ips,['8.8.8.8','1.1.1.1']);
  assert.throws(() => parseContent({...data,sha:'0'.repeat(40)}),/повреждён/);
  assert.throws(() => parseContent(content('# empty\n')),/пуст/);
});
test('updates two feeds, preserves last good data on failure and disables stale data', async () => {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'reputation-')); const file=path.join(dir,'cache.json'); let fail=false; const urls=[];
  const fetcher=async url => { urls.push(url); if(fail) throw new Error('offline'); return url.includes('/contents/') ? content(`# Source File Date: ${new Date().toUTCString()}\n8.8.8.8\n1.1.1.1\n`) : [{sha:'a'.repeat(40),commit:{committer:{date:new Date().toISOString()}}}]; };
  try {
    const store=new ReputationStore(file,fetcher); await store.refresh(); assert.equal(store.status().feeds.filter(x=>x.active).length,2); assert.equal(store.match('8.8.8.8').length,2);
    assert.equal(urls.length,4); assert.ok(urls.every(url=>url.startsWith('https://api.github.com/repos/'))); assert.ok(urls.every(url=>!url.includes('8.8.8.8')));
    fail=true; await store.refresh(); assert.equal(store.match('8.8.8.8').length,2); assert.ok(store.status().feeds.every(x=>x.error==='offline'));
    assert.equal(store.match('8.8.8.8',Date.now()+MAX_AGE+1000).length,0);
    const loaded=new ReputationStore(file,fetcher); loaded.load(); assert.equal(loaded.match('8.8.8.8').length,2);
    loaded.setEnabled(false); assert.equal(loaded.match('8.8.8.8').length,0); loaded.clear(); assert.equal(loaded.status().feeds[0].count,0);
  } finally { fs.rmSync(dir,{recursive:true,force:true}); }
});
test('matches external addresses locally, groups alerts and shows only matching flows', () => {
  const a=new Analyzer(); a.setNetworks('10.0.0.0/24'); a.reputation={match:ip => ip==='8.8.8.8' ? ['IPsum ≥3'] : []};
  a.add([{src:'10.0.0.1',dst:'8.8.8.8',srcPort:5000,dstPort:443,protocol:6,bytes:100,packets:1}, {src:'10.0.0.1',dst:'1.1.1.1',srcPort:5000,dstPort:443,protocol:6,bytes:500,packets:2}, {src:'8.8.8.8',dst:'10.0.0.2',srcPort:443,dstPort:5000,protocol:6,bytes:200,packets:1}]);
  const snap=a.snapshot(); assert.equal(snap.securityGroups.reputation,2); assert.equal(snap.alerts.filter(x=>x.type==='Совпадение с репутационной базой').length,2);
  const detail=a.securityDetail('reputation'); assert.equal(detail.count,2); assert.equal(detail.bytes,300); assert.equal(detail.hostCount,2); assert.ok(detail.records.every(f=>f.evidence.includes('IPsum')));
  a.setNetworks(''); assert.equal(a.snapshot().securityGroups.reputation,0);
});
test('concurrent refresh callers get status and disabling cancels result application', async () => {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'reputation-race-')); const file=path.join(dir,'cache.json'); let release;
  const gate=new Promise(resolve=>{ release=resolve; });
  const fetcher=async url => { await gate; return url.includes('/contents/') ? content(`# Source File Date: ${new Date().toUTCString()}\n8.8.8.8\n`) : [{sha:'a'.repeat(40),commit:{committer:{date:new Date().toISOString()}}}]; };
  try {
    const store=new ReputationStore(file,fetcher); const first=store.refresh(); const second=store.refresh();
    store.setEnabled(false); release(); const [one,two]=await Promise.all([first,second]);
    assert.equal(one.enabled,false); assert.ok(Array.isArray(two.feeds)); assert.equal(store.match('8.8.8.8').length,0); assert.equal(store.status().feeds[0].count,0);
  } finally { fs.rmSync(dir,{recursive:true,force:true}); }
});

test('outdated upstream mirror date cannot be made fresh by a recent commit', async () => {
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'reputation-age-'));
  try {
    const fetcher=async url => url.includes('/contents/') ? content('# Source File Date: Mon, 01 Jan 2024 00:00:00 GMT\n8.8.8.8\n') : [{sha:'b'.repeat(40),commit:{committer:{date:new Date().toISOString()}}}];
    const store=new ReputationStore(path.join(dir,'cache'),fetcher); await store.refresh();
    assert.equal(store.status().feeds.find(f=>f.id==='blocklistde').active,false);
    assert.deepEqual(store.match('8.8.8.8'),['IPsum ≥3']);
  } finally { fs.rmSync(dir,{recursive:true,force:true}); }
});
