'use strict';
const test=require('node:test'), assert=require('node:assert/strict'), fs=require('node:fs'), os=require('node:os'), path=require('node:path');
const {Analyzer}=require('../src/analyzer');
const {WorkspaceSettings}=require('../src/workspace-settings');
const {NotificationTracker,SILENCE,COOLDOWN}=require('../src/notifications');
const {toCsv}=require('../src/flow-export');
test('flow filters apply together to all matching flows; export is bounded and CSV safe', () => {
 const a=new Analyzer(); a.setNetworks('10.0.0.0/24 2001:db8::/32'); a.setPolicy({minerRecords:1});
 a.add([{src:'10.0.0.1',dst:'8.8.8.8',srcPort:9,dstPort:3333,protocol:6,bytes:1,packets:1,exporter:'10.0.0.254'}, {src:'2001:db8:0:0:0:0:0:1',dst:'2001:4860::1',srcPort:9,dstPort:443,protocol:6,bytes:2,packets:1,exporter:'10.0.0.253'}]);
 assert.equal(a.search({ip:'10.0.0.1',port:'3333',direction:'outgoing',threat:'miner',exporter:'10.0.0.254'}).total,1);
 assert.equal(a.search({port:'3333',threat:'miner',exporter:'10.0.0.253'}).total,0);
 assert.equal(a.search({ip:'2001:db8::1',category:'secureWeb'}).total,1);
 assert.throws(()=>a.search({port:'70000'})); assert.throws(()=>a.search({exporter:'bad'}));
 assert.match(toCsv([{src:'=cmd',dst:'a"b'}]), /"'=cmd"/); assert.match(toCsv([{dst:'a"b'}]), /"a""b"/);
});
test('workspace notes and settings persist, validate, and can be deleted', () => {
 const dir=fs.mkdtempSync(path.join(os.tmpdir(),'netcontrol-settings-')); try {
  const file=path.join(dir,'x.json'), s=new WorkspaceSettings(file);
  s.saveDevice('10.0.0.1',{name:'PC',group:'office',owner:'A',note:'local'});
  s.saveReview('spam','10.0.0.1',{status:'investigating',note:'check'}); s.setNotifications({enabled:true,minimum:'low'});
  const t=new WorkspaceSettings(file); t.load(); assert.equal(t.device('10.0.0.1').name,'PC'); assert.equal(t.review('spam','10.0.0.1').note,'check'); assert.equal(t.data.notifications.enabled,true);
  assert.throws(()=>t.saveReview('spam','10.0.0.1',{status:'bad',note:''})); assert.throws(()=>t.saveDevice('no',{name:'',group:'',owner:'',note:''}));
  t.saveReview('spam','10.0.0.1',{status:'new',note:''}); assert.deepEqual(t.review('spam','10.0.0.1'),{status:'new',note:''});
 } finally {fs.rmSync(dir,{recursive:true,force:true});}
});
test('notifications group new alerts, apply cooldown and report silence per router', () => {
 const t=new NotificationTracker(), opt={enabled:true,minimum:'low'}, now=Date.now(), source={a:{lastPacket:now},b:{lastPacket:now}};
 const snap={running:true,sources:source,alerts:[{type:'spam',ip:'10.0.0.1',severity:'low'}]};
 assert.equal(t.tick(snap,opt,now).length,1); assert.equal(t.tick(snap,opt,now+1000).length,0);
 t.tick({...snap,alerts:[]},opt,now+2000); assert.equal(t.tick(snap,opt,now+3000).length,0);
 source.a.lastPacket=now+SILENCE+1; const result=t.tick(snap,opt,now+SILENCE+1); assert.equal(result.length,1); assert.match(result[0].body,/b/); assert.doesNotMatch(result[0].body,/a/);
 t.tick({...snap,alerts:[]},opt,now+COOLDOWN+1); assert.equal(t.tick(snap,opt,now+COOLDOWN+2).length,1);
});
