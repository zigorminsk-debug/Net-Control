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
