'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const dgram = require('node:dgram');
const { Collector } = require('../src/collector');
test('validates configuration', async () => { const c = new Collector(); await assert.rejects(c.start('not-an-ip',2055)); await assert.rejects(c.start('127.0.0.1',0)); });
test('receives actual UDP NetFlow from allowed address', async () => {
  const probe = dgram.createSocket('udp4'); await new Promise(r => probe.bind(0,'127.0.0.1',r)); const port = probe.address().port; await new Promise(r => probe.close(r));
  const c = new Collector(); await c.start('127.0.0.1',port);
  try {
    const msg = Buffer.alloc(72); msg.writeUInt16BE(5,0); msg.writeUInt16BE(1,2); Buffer.from([10,0,0,1,8,8,8,8]).copy(msg,24); msg.writeUInt32BE(200,44); msg[62]=6;
    const client = dgram.createSocket('udp4'); await new Promise((resolve,reject) => client.send(msg,port,'127.0.0.1',err => err ? reject(err) : resolve())); client.close();
    await new Promise(resolve => setTimeout(resolve,50)); assert.equal(c.snapshot().flowCount,1); assert.equal(c.snapshot().bytes,200);
  } finally { c.stop(); }
});
