'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { classify } = require('../src/traffic-classifier');
const { Analyzer } = require('../src/analyzer');
const { parseCidrs, direction } = require('../src/direction');
const { listLocalAddresses, detectLocalAddress } = require('../src/local-address');
const { buildReport } = require('../src/report');

test('classification is a port hint and supports response traffic', () => {
  for (const [port, proto, expected] of [[25,6,'mail'],[5060,17,'voip'],[554,6,'media'],[6881,6,'p2p'],[443,6,'secureWeb'],[443,17,'secureWeb'],[53,17,'dns']]) {
    assert.equal(classify({dstPort:port, srcPort:53000, protocol:proto}).id, expected);
    assert.equal(classify({srcPort:port, dstPort:53000, protocol:proto}).id, expected);
  }
  assert.equal(classify({srcPort:1,dstPort:25,protocol:17}).id,'other');
  assert.equal(classify({srcPort:0,dstPort:0,protocol:1}).id,'other');
});
test('directions require configured networks; IPv6 stays unknown', () => {
  const networks = parseCidrs('10.0.0.0/8, 192.168.1.0/24');
  assert.equal(direction({src:'10.1.1.1',dst:'8.8.8.8'},networks),'outgoing');
  assert.equal(direction({src:'8.8.8.8',dst:'10.1.1.1'},networks),'incoming');
  assert.equal(direction({src:'192.168.1.2',dst:'10.1.1.1'},networks),'internal');
  assert.equal(direction({src:'8.8.8.8',dst:'1.1.1.1'},networks),'transit');
  assert.equal(direction({src:'2001:db8::1',dst:'10.1.1.1'},networks),'unknown');
  assert.equal(direction({src:'10.1.1.1',dst:'8.8.8.8'},[]),'unknown');
  assert.equal(direction({src:'1.1.1.1',dst:'2.2.2.2'},parseCidrs('0.0.0.0/0')),'internal');
  assert.equal(direction({src:'10.0.0.1',dst:'10.0.0.2'},parseCidrs('10.0.0.1/32')),'outgoing');
  for (const invalid of ['1.2.3.4/33','1.2.3.4','2001:db8::/64','10.0.0.0/-1','1.2.3.4/08']) assert.throws(() => parseCidrs(invalid));
});
test('network interface selection excludes loopback and failed routes return no guess', async () => {
  const interfaces = listLocalAddresses({lo:[{address:'127.0.0.1',family:'IPv4',internal:true}], vpn:[{address:'10.8.0.2',family:'IPv4',internal:false}], v6:[{address:'::1',family:'IPv6',internal:false}]});
  assert.deepEqual(interfaces, [{name:'vpn',address:'10.8.0.2'}]);
  assert.equal((await detectLocalAddress('127.0.0.1')).address, '');
});
test('sorts all sources before limiting and reports host directions', () => {
  const a = new Analyzer(); const now = 1000000;
  const flows = Array.from({length:40}, (_,i) => ({ src:`10.0.0.${i+1}`, dst:'8.8.8.8', srcPort:50000, dstPort:443, protocol:6, bytes:i+1, packets:1 }));
  flows.push({src:'8.8.8.8',dst:'10.0.0.1',srcPort:443,dstPort:50000,protocol:6,bytes:50,packets:1});
  a.setNetworks('10.0.0.0/24'); a.add(flows,now);
  assert.equal(a.snapshot(now,{by:'bytes',direction:'asc'}).hosts[0].ip,'10.0.0.1');
  assert.equal(a.snapshot(now,{by:'bytes',direction:'desc'}).hosts[0].ip,'8.8.8.8');
  const snap = a.snapshot(now,{by:'ip',direction:'asc'});
  assert.equal(snap.directions.outgoing.flows,40); assert.equal(snap.directions.incoming.flows,1); assert.equal(snap.categories[0].flows,41);
  const host = a.hostDetail('10.0.0.1',now);
  assert.equal(host.outgoingBytes,1); assert.equal(host.incomingBytes,50); assert.equal(host.count,2); assert.equal(host.topPeers[0].bytes,51);
  a.setNetworks(''); assert.equal(a.snapshot(now).directions.unknown.flows,41);
});
test('report escapes untrusted fields and includes direction and recommendations', () => {
  const a = new Analyzer(); const now = 1000000;
  a.setNetworks('10.0.0.0/8');
  a.add([{src:'10.0.0.1',dst:'8.8.8.8',srcPort:50000,dstPort:443,protocol:6,bytes:100,packets:1}],now);
  const s = a.snapshot(now); s.alerts.push({type:'<script>x</script>', ip:'10.0.0.1', detail:'& test'});
  const report = buildReport(s,[a.hostDetail('10.0.0.1',now)],now);
  assert.match(report,/Направления трафика/); assert.match(report,/Рекомендации/); assert.match(report,/Исходящий/);
  assert.match(report,/&lt;script&gt;x&lt;\/script&gt;/); assert.doesNotMatch(report,/<script>/);
  assert.match(report,/10\.0\.0\.1/); assert.match(report,/100 Б/);
});
