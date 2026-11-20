'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const { JSDOM } = require('jsdom');
const { Analyzer } = require('../src/analyzer');
const html = fs.readFileSync('src/index.html','utf8');
const script = fs.readFileSync('src/renderer.js','utf8');
const settings = fs.readFileSync('src/connection-settings.js','utf8');
const settle = () => new Promise(resolve => setImmediate(resolve));

test('UI detects address, sorts sources, opens alerts and exports report', async () => {
  const a = new Analyzer(); a.setNetworks('10.0.0.0/24');
  a.add(Array.from({length:30}, (_,i) => ({src:'10.0.0.1',dst:`8.8.8.${i+1}`,srcPort:55000,dstPort:443,protocol:6,bytes:100,packets:1})));
  a.add([{src:'8.8.8.1',dst:'10.0.0.1',srcPort:443,dstPort:55000,protocol:6,bytes:50,packets:1}]);
  const calls = []; const dom = new JSDOM(html, {runScripts:'outside-only'}); const win = dom.window;
  win.setInterval = () => 0;
  win.netControl = {
    snapshot: async sort => { calls.push(sort); return {running:true,port:2055,address:'192.168.88.1',lastPacket:null,datagrams:0,error:'',...a.snapshot(Date.now(),sort)}; },
    host: async ip => a.hostDetail(ip),
    localAddress: async () => ({address:'10.0.0.50',interfaceName:'Ethernet',interfaces:[{address:'10.0.0.50',name:'Ethernet'}]}),
    subnets: async () => ['10.0.0.0/24'],
    saveSubnets: async text => ({ok:true,subnets:a.setNetworks(text)}),
    saveReport: async () => ({ok:true,path:'C:\\report.html'})
  };
  try {
    win.eval(settings); win.eval(script); await settle(); await settle();
    const doc = win.document;
    assert.match(doc.getElementById('commands').textContent, /dst-address=10\.0\.0\.50/);
    assert.match(doc.getElementById('directions-list').textContent, /Исходящий/);
    assert.ok(doc.querySelector('#alerts-list button.host-link'));
    doc.querySelector('[data-sort="flows"]').click(); await settle();
    assert.equal(calls.at(-1).by,'flows'); assert.equal(calls.at(-1).direction,'desc');
    doc.querySelector('[data-sort="flows"]').click(); await settle();
    assert.equal(calls.at(-1).direction,'asc');
    assert.equal(doc.querySelector('[data-sort="flows"]').parentElement.getAttribute('aria-sort'),'ascending');
    doc.querySelector('#alerts-list button.host-link').click(); await settle();
    assert.equal(doc.getElementById('host-title').textContent,'10.0.0.1');
    assert.ok(doc.getElementById('host-detail').classList.contains('active-view'));
    assert.match(doc.getElementById('host-in-bytes').textContent,/50 Б/);
    assert.equal(doc.querySelectorAll('#host-records tr').length,31);
    doc.getElementById('back-dashboard').click();
    doc.getElementById('save-report').click(); await settle();
    assert.match(doc.getElementById('report-status').textContent,/Отчёт сохранён/);
    doc.getElementById('subnets').value='192.168.0.0/16'; doc.getElementById('save-subnets').click(); await settle();
    assert.match(doc.getElementById('direction-note').textContent,/192\.168\.0\.0\/16/);
  } finally { win.close(); }
});
