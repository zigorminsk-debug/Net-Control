'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { testRouter, describeConnectionError } = require('../src/router');
const { portAfterProtocolChange } = require('../src/connection-settings');

test('protocol toggle changes only empty or opposite default ports', () => {
  assert.equal(portAfterProtocolChange('443', false), '80');
  assert.equal(portAfterProtocolChange('80', true), '443');
  assert.equal(portAfterProtocolChange('', false), '80');
  assert.equal(portAfterProtocolChange('8080', true), '8080');
  assert.equal(portAfterProtocolChange('8443', false), '8443');
});
test('connection errors explain the relevant service and defaults', () => {
  assert.match(describeConnectionError({code:'ECONNREFUSED'}, {secure:false, port:443}), /www.*80.*443/);
  assert.match(describeConnectionError({code:'ECONNREFUSED'}, {secure:true, port:443}), /www-ssl.*443/);
  assert.match(describeConnectionError({code:'DEPTH_ZERO_SELF_SIGNED_CERT'}, {secure:true,port:443}), /сертификат/);
  assert.match(describeConnectionError({code:'EPROTO'}, {secure:true,port:443}), /certificate=none/);
});
test('RouterOS check sends Basic auth and reads response', async () => {
  let auth, path;
  const server = http.createServer((req, res) => { auth = req.headers.authorization; path = req.url; res.setHeader('Content-Type','application/json'); res.end(JSON.stringify({version:'7.17', uptime:'1d', 'board-name':'test'})); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const data = await testRouter({ address:'127.0.0.1', port:server.address().port, username:'test', password:'secret', secure:false });
    assert.equal(auth, 'Basic ' + Buffer.from('test:secret').toString('base64')); assert.equal(path, '/rest/system/resource'); assert.equal(data.version, '7.17');
  } finally { await new Promise(resolve => server.close(resolve)); }
});
test('HTTP error codes produce useful messages', async () => {
  const server = http.createServer((_req, res) => { res.writeHead(401); res.end(); });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try { await assert.rejects(testRouter({address:'127.0.0.1',port:server.address().port,username:'u',password:'p',secure:false}), /401.*пароль/); }
  finally { await new Promise(resolve => server.close(resolve)); }
});
test('reads only active DHCP leases, discards ambiguous IPs and uses the read-only REST path', async () => {
  const { readLeases } = require('../src/router'); let requestPath = '';
  const server = http.createServer((req,res) => { requestPath = req.url; res.end(JSON.stringify([
    {status:'bound','active-address':'10.0.0.5','host-name':'desktop','active-mac-address':'AA:BB:CC:DD:EE:FF'},
    {status:'waiting',address:'10.0.0.6'},
    {status:'bound',address:'10.0.0.7'}, {status:'bound',address:'10.0.0.7'}
  ])); });
  await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
  try {
    const leases = await readLeases({address:'127.0.0.1',port:server.address().port,username:'u',password:'p',secure:false});
    assert.equal(requestPath,'/rest/ip/dhcp-server/lease'); assert.deepEqual(leases,[{ip:'10.0.0.5',name:'desktop',mac:'AA:BB:CC:DD:EE:FF'}]);
  } finally { await new Promise(resolve => server.close(resolve)); }
});
test('Traffic Flow preflight only reads configuration and targets', async () => {
  const {inspectTrafficFlow} = require('../src/router'); const requests=[];
  const server=http.createServer((req,res)=>{requests.push([req.method,req.url]);res.setHeader('content-type','application/json');res.end(JSON.stringify(req.url.endsWith('/target') ? [{'dst-address':'10.0.0.2',port:'2055',version:'9',disabled:'false'}] : {enabled:'true',interfaces:'all'}));});
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  try { const result=await inspectTrafficFlow({address:'127.0.0.1',port:server.address().port,username:'u',password:'p',secure:false}); assert.equal(result.enabled,'true');assert.equal(result.targets[0].address,'10.0.0.2');assert.deepEqual(requests.sort(),[['GET','/rest/ip/traffic-flow'],['GET','/rest/ip/traffic-flow/target']].sort()); }
  finally {await new Promise(resolve=>server.close(resolve));}
});
