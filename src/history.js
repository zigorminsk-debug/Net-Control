'use strict';
const fs = require('node:fs');
const { direction } = require('./direction');
const { classify } = require('./traffic-classifier');
const DAY = 86400000, WINDOW = 300000, MAX_BUCKETS = 100000, MAX_EVENTS = 10000;
class History {
  constructor(path) { this.path = path; this.enabled = false; this.retentionDays = 7; this.buckets = new Map(); this.days = new Map(); this.events = new Map(); this.dirty = false; this.lastPrune = 0; this.baselineCache = null; }
  load(now = Date.now()) {
    try {
      const data = JSON.parse(fs.readFileSync(this.path, 'utf8'));
      if (data.version !== 1) return;
      this.enabled = data.enabled === true;
      if (Number.isInteger(data.retentionDays) && data.retentionDays >= 1 && data.retentionDays <= 30) this.retentionDays = data.retentionDays;
      for (const b of (Array.isArray(data.buckets) ? data.buckets : []).slice(-MAX_BUCKETS)) if (typeof b.ip === 'string' && Number.isFinite(b.time) && Number.isFinite(b.bytes)) this.buckets.set(`${b.time}|${b.ip}`, b);
      for (const d of (Array.isArray(data.days) ? data.days : []).slice(-31)) if (Number.isFinite(d.time)) this.days.set(d.time, d);
      for (const e of (Array.isArray(data.events) ? data.events : []).slice(-MAX_EVENTS)) if (typeof e.key === 'string' && Number.isFinite(e.time)) this.events.set(e.key, e);
      this.prune(now);
    } catch (err) { if (err.code !== 'ENOENT') throw err; }
  }
  setRetentionDays(value) { if (!Number.isInteger(value) || value < 1 || value > 30) throw new Error('Срок хранения должен быть от 1 до 30 дней.'); this.retentionDays=value; this.prune(); this.dirty=true; }
  setEnabled(value) { this.enabled = Boolean(value); this.dirty = true; }
  ingest(flows, networks, now = Date.now()) {
    if (!this.enabled || !flows.length) return;
    const day = Math.floor(now / DAY) * DAY, window = Math.floor(now / WINDOW) * WINDOW;
    let d = this.days.get(day); if (!d) { d = { time: day, bytes: 0, packets: 0, flows: 0 }; this.days.set(day, d); }
    for (const f of flows) {
      d.bytes += f.bytes; d.packets += f.packets; d.flows++;
      if (!d.categories || typeof d.categories !== 'object' || Array.isArray(d.categories)) d.categories={};
      const category=classify(f).id; if (!d.categories[category]) d.categories[category]={bytes:0,flows:0};
      d.categories[category].bytes+=f.bytes; d.categories[category].flows++;
      if (direction(f, networks) !== 'outgoing') continue;
      const key = `${window}|${f.src}`;
      let b = this.buckets.get(key); if (!b) { b = { time: window, ip: f.src, bytes: 0, packets: 0, flows: 0 }; this.buckets.set(key, b); }
      b.bytes += f.bytes; b.packets += f.packets; b.flows++;
    }
    if (now - this.lastPrune >= 60000) { this.prune(now); this.lastPrune = now; }
    while (this.buckets.size > MAX_BUCKETS) this.buckets.delete(this.buckets.keys().next().value);
    this.dirty = true;
  }
  capture(alerts, now = Date.now()) {
    if (!this.enabled) return;
    const bucket = Math.floor(now / WINDOW);
    for (const a of alerts) {
      const key = `${bucket}|${a.type}|${a.ip}`;
      if (!this.events.has(key)) { this.events.set(key, { key, time: now, type: a.type, severity:a.severity, ip: a.ip, detail: a.detail, recommendation: a.recommendation || '', device: a.device || null }); this.dirty = true; }
    }
    while (this.events.size > MAX_EVENTS) this.events.delete(this.events.keys().next().value);
  }
  baselines(now = Date.now()) {
    if (this.baselineCache && now >= this.baselineCache.time && now - this.baselineCache.time < 30000) return this.baselineCache.value;
    const currentWindow = Math.floor(now / WINDOW) * WINDOW; const map = new Map();
    for (const b of this.buckets.values()) {
      if (b.time >= currentWindow || b.time < now - 7 * DAY) continue;
      let h = map.get(b.ip); if (!h) { h = { bytes: 0, windows: 0, days: new Set() }; map.set(b.ip, h); }
      h.bytes += b.bytes; h.windows++; h.days.add(Math.floor(b.time / DAY));
    }
    const result = new Map();
    for (const [ip, h] of map) if (h.windows >= 20 && h.days.size >= 3) result.set(ip, { averageBytes: h.bytes / h.windows, windows: h.windows, days: h.days.size });
    this.baselineCache = { time: now, value: result };
    return result;
  }
  prune(now = Date.now()) {
    const previous = this.buckets.size + this.days.size + this.events.size;
    for (const [key, b] of this.buckets) if (b.time < now - this.retentionDays * DAY) this.buckets.delete(key);
    for (const [key, d] of this.days) if (d.time < now - 30 * DAY) this.days.delete(key);
    for (const [key, e] of this.events) if (e.time < now - this.retentionDays * DAY) this.events.delete(key);
    while (this.buckets.size > MAX_BUCKETS) this.buckets.delete(this.buckets.keys().next().value);
    while (this.events.size > MAX_EVENTS) this.events.delete(this.events.keys().next().value);
    if (previous !== this.buckets.size + this.days.size + this.events.size) { this.dirty = true; this.baselineCache = null; }
  }
  hostDays(ip, now = Date.now()) {
    if (!require('node:net').isIP(ip)) throw new Error('Некорректный IP.');
    this.prune(now); const days = new Map();
    for (const b of this.buckets.values()) {
      if (b.ip !== ip) continue;
      const time=Math.floor(b.time / DAY) * DAY;
      if (!days.has(time)) days.set(time,{time,bytes:0,packets:0,flows:0,windows:0});
      const d=days.get(time); d.bytes+=b.bytes; d.packets+=b.packets; d.flows+=b.flows; d.windows++;
    }
    return {enabled:this.enabled,retentionDays:this.retentionDays,days:[...days.values()].sort((a,b)=>a.time-b.time)};
  }
  summary(now = Date.now()) {
    this.prune(now);
    return { enabled:this.enabled, retentionDays:this.retentionDays, bucketCount:this.buckets.size, days:[...this.days.values()].sort((a,b)=>b.time-a.time), events:[...this.events.values()].sort((a,b)=>b.time-a.time).slice(0, 100), eventCount:this.events.size };
  }
  clear() { this.events.clear(); this.buckets.clear(); this.days.clear(); this.baselineCache = null; this.dirty = true; }
  flush() {
    if (!this.dirty) return;
    this.prune();
    fs.mkdirSync(require('node:path').dirname(this.path), { recursive:true });
    const tmp = `${this.path}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ version:1, enabled:this.enabled, retentionDays:this.retentionDays, buckets:[...this.buckets.values()], days:[...this.days.values()], events:[...this.events.values()] }), { encoding:'utf8', mode:0o600 });
    fs.renameSync(tmp, this.path); this.dirty = false;
  }
}
module.exports = { History, DAY, WINDOW, MAX_BUCKETS, MAX_EVENTS };
