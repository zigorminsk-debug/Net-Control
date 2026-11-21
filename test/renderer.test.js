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
  let savedReview; const calls = []; const dom = new JSDOM(html, {runScripts:'outside-only'}); const win = dom.window;
  win.setInterval = () => 0;
  win.netControl = {
    device: async () => ({name:'',group:'',owner:'',note:''}),
    saveDevice: async () => ({}), review: async () => ({status:'new',note:''}), saveReview: async (type,ip,data) => { savedReview={type,ip,data}; return data; },
    notifications: async () => ({enabled:false,minimum:'medium',supported:true}), saveNotifications: async () => ({}),
    searchFlows: async f => a.search(f), exportFlows: async () => ({ok:true,count:0,path:'export.csv'}),
    hostBindings: async () => ([]),
    hostHistory: async () => ({enabled:false,days:[]}),
    history: async () => ({enabled:false,events:[],eventCount:0,days:[]}),
    reputation: async () => ({enabled:true,feeds:[]}),
    securityDetail: async id => a.securityDetail(id),
    enableReputation: async () => ({ok:true}),
    clearReputation: async () => ({ok:true}),
    refreshReputation: async () => ({ok:true,enabled:true,feeds:[]}),
    policy: async () => a.policy,
    category: async id => a.categoryDetail(id),
    savePolicy: async policy => ({ok:true,policy:a.setPolicy(policy)}),
    setHistoryRetention: async () => ({ok:true}),
    enableHistory: async () => ({ok:true}),
    clearHistory: async () => ({ok:true}),
    updateStatus: async () => ({status:'up-to-date',currentVersion:'1.1.0'}),
    checkUpdates: async () => ({status:'downloaded',currentVersion:'1.1.0',availableVersion:'1.2.0'}),
    installUpdate: async () => ({ok:true}),
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
    assert.equal(doc.querySelectorAll('#volume-chart .bar').length,30);
    assert.ok(doc.querySelector('#top-host-chart button.host-link'));
    doc.querySelector('[data-view=flow-search]').click(); doc.getElementById('search-ip').value='10.0.0.1'; doc.getElementById('search-run').click(); await settle(); assert.match(doc.getElementById('search-status').textContent, /Найдено: 31/); assert.equal(doc.querySelectorAll('#search-results tr').length,31);
    doc.querySelector('[data-view=dashboard]').click();
    a.add(Array.from({length:5},()=>({src:'10.0.0.2',dst:'8.8.4.4',srcPort:55000,dstPort:3333,protocol:6,bytes:100,packets:1})));
    doc.querySelector('[data-threat=miner]').click(); await settle();
    assert.ok(doc.getElementById('threat-detail').classList.contains('active-view'));
    assert.equal(doc.getElementById('threat-host-count').textContent,'1');
    doc.querySelector('#threat-hosts button.text-button').click(); await settle(); doc.getElementById('review-status').value='investigating'; doc.getElementById('review-note').value='checking'; doc.getElementById('review-save').click(); await settle(); assert.deepEqual(JSON.parse(JSON.stringify(savedReview)), {type:'miner',ip:'10.0.0.2',data:{status:'investigating',note:'checking'}});
    doc.getElementById('back-threat').click();
    assert.ok(doc.querySelector('#alerts-list button.host-link'));
    doc.querySelector('#categories-list .category-item').click(); await settle();
    assert.ok(doc.getElementById('category-detail').classList.contains('active-view'));
    assert.ok(doc.querySelector('#category-hosts button.host-link'));
    doc.getElementById('back-category').click();
    doc.querySelector('[data-sort="flows"]').click(); await settle();
    assert.equal(calls.at(-1).by,'flows'); assert.equal(calls.at(-1).direction,'desc');
    doc.querySelector('[data-sort="flows"]').click(); await settle();
    assert.equal(calls.at(-1).direction,'asc');
    assert.equal(doc.querySelector('[data-sort="flows"]').parentElement.getAttribute('aria-sort'),'ascending');
    doc.querySelector('#alerts-list button.host-link').click(); await settle();
    assert.equal(doc.getElementById('host-title').textContent,'10.0.0.1');
    assert.ok(doc.getElementById('host-detail').classList.contains('active-view'));
    assert.match(doc.getElementById('host-in-bytes').textContent,/50 Б/);
    assert.ok(doc.querySelector('#host-graph svg g[role=button]'));
    assert.ok(doc.querySelector('#host-links button.host-link'));
    assert.equal(doc.querySelectorAll('#host-records tr').length,31);
    doc.getElementById('back-dashboard').click();
    doc.querySelector('[data-view=about]').click();
    assert.ok(doc.getElementById('about').classList.contains('active-view'));
    assert.match(doc.getElementById('about-version').textContent,/1\.1\.0/);
    doc.getElementById('check-updates').click(); await settle();
    assert.equal(doc.getElementById('install-update').hidden,false);
    doc.querySelector('[data-view=dashboard]').click();
    doc.getElementById('save-report').click(); await settle();
    assert.match(doc.getElementById('report-status').textContent,/Отчёт сохранён/);
    doc.getElementById('subnets').value='192.168.0.0/16'; doc.getElementById('save-subnets').click(); await settle();
    assert.match(doc.getElementById('direction-note').textContent,/192\.168\.0\.0\/16/);
  } finally { win.close(); }
});
