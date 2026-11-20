'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { FlowParser } = require('../src/flow');
function v5() {
  const b = Buffer.alloc(72); b.writeUInt16BE(5, 0); b.writeUInt16BE(1, 2);
  Buffer.from([192,168,1,2, 8,8,8,8]).copy(b,24);
  b.writeUInt32BE(3,40); b.writeUInt32BE(1234,44); b.writeUInt16BE(40000,56); b.writeUInt16BE(443,58); b[62] = 6;
  return b;
}
function packet(version, exporterId = 7) {
  const h = Buffer.alloc(version === 9 ? 20 : 16); h.writeUInt16BE(version, 0); h.writeUInt32BE(exporterId, version === 9 ? 16 : 12); return h;
}
function set(id, payload) { const b = Buffer.alloc(4); b.writeUInt16BE(id,0); b.writeUInt16BE(payload.length + 4,2); return Buffer.concat([b,payload]); }
function template() {
  const b = Buffer.alloc(4 + 7 * 4); b.writeUInt16BE(256,0); b.writeUInt16BE(7,2);
  [[8,4],[12,4],[7,2],[11,2],[4,1],[1,4],[2,4]].forEach(([type,len],i) => { b.writeUInt16BE(type,4+i*4); b.writeUInt16BE(len,6+i*4); }); return b;
}
function record() { const b = Buffer.alloc(21); Buffer.from([10,0,0,1, 1,1,1,1]).copy(b); b.writeUInt16BE(1000,8); b.writeUInt16BE(3333,10); b[12]=6; b.writeUInt32BE(512,13); b.writeUInt32BE(2,17); return b; }
function wrap(version, ...sets) { const h = packet(version); const b = Buffer.concat([h,...sets]); if(version===10) b.writeUInt16BE(b.length,2); return b; }
test('decodes NetFlow v5 and rejects truncated records', () => {
  const p = new FlowParser(); assert.deepEqual(p.parse(v5()), [{src:'192.168.1.2',dst:'8.8.8.8',packets:3,bytes:1234,srcPort:40000,dstPort:443,protocol:6}]); assert.deepEqual(p.parse(v5().subarray(0,71)),[]);
});
for (const version of [9,10]) test(`decodes version ${version} templates and records, scoped to exporter`, () => {
  const p = new FlowParser(); const data = wrap(version,set(256,record()));
  assert.deepEqual(p.parse(data,'router'),[]);
  p.parse(wrap(version,set(version===9 ? 0 : 2,template())),'router');
  assert.deepEqual(p.parse(data,'other'),[]);
  assert.deepEqual(p.parse(data,'router'),[{src:'10.0.0.1',dst:'1.1.1.1',srcPort:1000,dstPort:3333,protocol:6,bytes:512,packets:2}]);
});
test('ignores malformed packets without throwing', () => { const p = new FlowParser(); for(let n=0;n<100;n++) assert.doesNotThrow(() => p.parse(Buffer.alloc(n, 255))); });
test('withdraws IPFIX templates', () => { const p = new FlowParser(); p.parse(wrap(10,set(2,template())),'r'); const withdrawal = Buffer.from([1,0,0,0]); p.parse(wrap(10,set(2,withdrawal)),'r'); assert.deepEqual(p.parse(wrap(10,set(256,record())),'r'),[]); });
test('NetFlow v5 preserves TCP flags, interfaces, sampling and flow timestamps', () => {
  const b = v5(); const nowSeconds = 1700000000; b.writeUInt32BE(100000,4); b.writeUInt32BE(nowSeconds,8); b.writeUInt16BE(0x400a,22);
  b.writeUInt16BE(5,36); b.writeUInt16BE(6,38); b.writeUInt32BE(50000,48); b.writeUInt32BE(90000,52); b[61] = 0x12;
  const f = new FlowParser().parse(b)[0]; assert.equal(f.inputInterface,5); assert.equal(f.outputInterface,6); assert.equal(f.tcpFlags,0x12); assert.equal(f.samplingInterval,10);
  assert.equal(f.startTime, nowSeconds*1000-50000); assert.equal(f.endTime, nowSeconds*1000-10000);
});
test('IPFIX reads optional timestamps, flags and interfaces if supplied', () => {
  const fields = [[8,4],[12,4],[6,1],[10,4],[14,4],[152,8],[153,8]];
  const t = Buffer.alloc(4+fields.length*4); t.writeUInt16BE(256,0); t.writeUInt16BE(fields.length,2);
  fields.forEach(([type,len],i)=>{t.writeUInt16BE(type,4+i*4);t.writeUInt16BE(len,6+i*4);});
  const data=Buffer.alloc(33); Buffer.from([10,0,0,1,8,8,8,8]).copy(data); data[8]=0x12; data.writeUInt32BE(5,9); data.writeUInt32BE(7,13); data.writeBigUInt64BE(1700000000000n,17); data.writeBigUInt64BE(1700000060000n,25);
  const p=new FlowParser(); p.parse(wrap(10,set(2,t)),'r'); const [f]=p.parse(wrap(10,set(256,data)),'r');
  assert.equal(f.startTime,1700000000000); assert.equal(f.endTime,1700000060000); assert.equal(f.tcpFlags,0x12); assert.equal(f.inputInterface,5); assert.equal(f.outputInterface,7);
});
test('NetFlow v9 reconstructs uptime-based timestamps from its export header', () => {
  const fields=[[8,4],[12,4],[22,4],[21,4]]; const t=Buffer.alloc(4+fields.length*4); t.writeUInt16BE(256,0);t.writeUInt16BE(fields.length,2); fields.forEach(([id,len],i)=>{t.writeUInt16BE(id,4+i*4);t.writeUInt16BE(len,6+i*4);});
  const b=Buffer.alloc(16);Buffer.from([10,0,0,1,8,8,8,8]).copy(b);b.writeUInt32BE(50000,8);b.writeUInt32BE(90000,12);
  const p=new FlowParser();p.parse(wrap(9,set(0,t)),'r');const msg=wrap(9,set(256,b));msg.writeUInt32BE(100000,4);msg.writeUInt32BE(1700000000,8);
  const [f]=p.parse(msg,'r');assert.equal(f.startTime,1699999950000);assert.equal(f.endTime,1699999990000);
});
