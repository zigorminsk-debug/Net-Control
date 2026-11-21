'use strict';
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const TYPES = new Set(['miner','spam','ddos','reputation']);
const STATUSES = new Set(['new','investigating','false-positive']);
class WorkspaceSettings {
  constructor(file) { this.file=file; this.data={version:1, devices:{}, reviews:{}, notifications:{enabled:false, minimum:'medium'}}; }
  load() {
    try {
      const value=JSON.parse(fs.readFileSync(this.file,'utf8'));
      if (value.version !== 1 || !value.devices || !value.reviews || !value.notifications) throw new Error('Некорректный файл заметок.');
      this.data=value;
    } catch (err) { if (err.code !== 'ENOENT') throw err; }
  }
  save() {
    fs.mkdirSync(path.dirname(this.file),{recursive:true});
    const tmp=this.file+'.tmp'; fs.writeFileSync(tmp, JSON.stringify(this.data), {mode:0o600}); fs.renameSync(tmp,this.file);
  }
  device(ip) { if (!net.isIP(ip)) throw new Error('Некорректный IP.'); return this.data.devices[ip] || {name:'',group:'',owner:'',note:''}; }
  saveDevice(ip, raw) {
    if (!net.isIP(ip) || !raw || typeof raw !== 'object') throw new Error('Некорректные данные устройства.');
    const result={}; for (const key of ['name','group','owner','note']) { if (typeof raw[key] !== 'string' || raw[key].length > (key==='note' ? 1000 : 100)) throw new Error('Слишком длинные или некорректные данные.'); result[key]=raw[key].trim(); }
    if (!this.data.devices[ip] && Object.keys(this.data.devices).length >= 5000) throw new Error('Достигнут лимит устройств.');
    if (Object.values(result).every(v=>!v)) delete this.data.devices[ip]; else this.data.devices[ip]=result;
    this.save(); return result;
  }
  review(type, ip) { if (!TYPES.has(type) || !net.isIP(ip)) throw new Error('Некорректный сигнал.'); return this.data.reviews[`${type}|${ip}`] || {status:'new', note:''}; }
  saveReview(type, ip, raw) {
    this.review(type, ip);
    if (!raw || !STATUSES.has(raw.status) || typeof raw.note !== 'string' || raw.note.length>2000) throw new Error('Некорректный статус или заметка.');
    const key=`${type}|${ip}`, result={status:raw.status, note:raw.note.trim()};
    if (!this.data.reviews[key] && Object.keys(this.data.reviews).length >= 5000) throw new Error('Достигнут лимит заметок.');
    if (result.status==='new' && !result.note) delete this.data.reviews[key]; else this.data.reviews[key]=result;
    this.save(); return result;
  }
  setNotifications(raw) {
    if (!raw || typeof raw.enabled !== 'boolean' || !['low','medium'].includes(raw.minimum)) throw new Error('Некорректные настройки уведомлений.');
    this.data.notifications={enabled:raw.enabled,minimum:raw.minimum}; this.save(); return this.data.notifications;
  }
}
module.exports={WorkspaceSettings};
