'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { Analyzer } = require('../src/analyzer');
const { analyze, validatePolicy } = require('../src/security');
const { parseCidrs } = require('../src/direction');
const base = {src:'10.0.0.2',dst:'8.8.8.8',srcPort:45000,dstPort:25,protocol:6,bytes:1000000,packets:10000};
const lan = parseCidrs('10.0.0.0/24');
test('security skips external sources and unknown networks, supports exclusions', () => {
  const many = Array.from({length:30},(_,i) => ({...base,dst:`8.8.8.${i+1}`}));
  assert.equal(analyze(many,[],{}).length,0);
  const results = analyze(many,lan,{});
  assert.ok(results.some(a=>a.type==='Сканирование')); assert.ok(results.some(a=>a.type==='Возможный спам'));
  assert.equal(analyze(many,lan,{excluded:'10.0.0.2/32'}).length,0);
  assert.ok(!analyze(many,lan,{mailServers:'10.0.0.2/32'}).some(a=>a.type==='Возможный спам'));
  const external = many.map(f=>({...f,src:'1.1.1.1'})); assert.equal(analyze(external,lan,{}).length,0);
});
test('detects outbound and inbound high volume separately', () => {
  const outbound = [{...base,dstPort:443,packets:100000,bytes:21*1048576}];
  assert.ok(analyze(outbound,lan,{}).some(a=>a.type==='Возможный исходящий DDoS'));
  const inbound = Array.from({length:30},(_,i)=>({...base,src:`8.8.8.${i+1}`,dst:'10.0.0.2',packets:4000}));
  const alerts = analyze(inbound,lan,{});
  assert.ok(alerts.some(a=>a.type==='Возможная входящая атака' && a.ip==='10.0.0.2'));
  assert.ok(!alerts.some(a=>a.type==='Возможный исходящий DDoS'));
});
test('pool list and per-endpoint flow duration are evidence, not infection', () => {
  const f = {...base,dstPort:3333,startTime:1000000,endTime:1600000};
  assert.ok(analyze([f],lan,{}).some(a=>a.type==='Возможный майнинг'));
  const single = {...base,dstPort:443};
  assert.ok(analyze([single],lan,{poolAddresses:'8.8.8.8/32'}).some(a=>a.type==='Возможный майнинг'));
  assert.throws(()=>validatePolicy({ddosPackets:0})); assert.throws(()=>validatePolicy({excluded:'nonsense'}));
});
test('category details include all matching sources and bounded records', () => {
  const a = new Analyzer(); const now=Date.now();
  a.add([{...base,src:'10.0.0.1'}, {...base,src:'10.0.0.2'}, {...base,src:'10.0.0.2',dstPort:443}],now);
  const c = a.categoryDetail('mail',now); assert.equal(c.count,2); assert.equal(c.hostCount,2); assert.equal(c.records.length,2); assert.throws(()=>a.categoryDetail('unknown-category'));
});
