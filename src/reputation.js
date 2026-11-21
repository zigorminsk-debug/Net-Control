'use strict';
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const net = require('node:net');
const crypto = require('node:crypto');
const MAX_RESPONSE = 2 * 1024 * 1024;
const MAX_AGE = 72 * 60 * 60 * 1000;
const FEEDS = [
  { id:'ipsum', name:'IPsum ≥3', repo:'stamparm/ipsum', file:'levels/3.txt', description:'IPsum: совпадение минимум в трёх исходных списках; источники могут пересекаться.', url:'https://github.com/stamparm/ipsum' },
  { id:'blocklistde', name:'Blocklist.de / FireHOL', repo:'firehol/blocklist-ipsets', file:'blocklist_de.ipset', description:'Адреса, замеченные в сообщениях fail2ban; зеркало FireHOL.', url:'https://github.com/firehol/blocklist-ipsets/blob/master/blocklist_de.ipset' }
];
function requestJson(url) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    if (parsed.protocol !== 'https:' || parsed.hostname !== 'api.github.com') return reject(new Error('Недопустимый источник.'));
    const req = https.get(parsed, { timeout:15000, headers:{'User-Agent':'Net-Control-Reputation/1.0', Accept:'application/vnd.github+json'} }, res => {
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`GitHub API HTTP ${res.statusCode}${res.statusCode === 403 ? ' (возможен лимит запросов)' : ''}`)); }
      const chunks = []; let size = 0;
      res.on('data', chunk => { size += chunk.length; if (size > MAX_RESPONSE) req.destroy(new Error('Ответ слишком большой.')); else chunks.push(chunk); });
      res.on('error', reject);
      res.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(new Error('Некорректный ответ GitHub API.')); } });
    });
    req.on('timeout', () => req.destroy(new Error('Время ожидания GitHub истекло.'))); req.on('error', reject);
  });
}
function parseContent(data) {
  if (!data || data.encoding !== 'base64' || typeof data.content !== 'string' || !Number.isInteger(data.size) || data.size < 1 || data.size > 1000000 || !/^[a-f0-9]{40}$/.test(data.sha || '')) throw new Error('Некорректные метаданные списка.');
  const buffer = Buffer.from(data.content.replace(/\s/g,''), 'base64');
  const sha = crypto.createHash('sha1').update(`blob ${buffer.length}\0`).update(buffer).digest('hex');
  if (buffer.length !== data.size || sha !== data.sha) throw new Error('Файл списка повреждён или неполон.');
  const text = buffer.toString('utf8');
  const sourceDate = /^#\s*Source File Date:\s*(.+)$/im.exec(text);
  const sourceFileDate = sourceDate ? Date.parse(sourceDate[1].trim()) : NaN;
  const ips = new Set(); let invalid = 0;
  for (const line of text.split(/\r?\n/)) {
    const value = line.trim(); if (!value || value.startsWith('#')) continue;
    if (net.isIP(value) !== 4) { invalid++; continue; }
    ips.add(value); if (ips.size > 150000) throw new Error('Список превышает лимит записей.');
  }
  if (!ips.size || invalid > Math.max(10, ips.size / 100)) throw new Error('Формат списка не поддерживается или список пуст.');
  return { ips:[...ips], sha, invalid, sourceFileDate };
}
class ReputationStore {
  constructor(file, fetchJson = requestJson) {
    this.file = file; this.fetchJson = fetchJson; this.enabled = true; this.entries = new Map(); this.lastAttempt = 0; this.inFlight = null; this.generation = 0;
  }
  load() {
    try {
      const data = JSON.parse(fs.readFileSync(this.file,'utf8')); if (data.version !== 1) throw new Error('Неизвестный формат кэша.');
      this.enabled = data.enabled !== false; this.lastAttempt = Number(data.lastAttempt) || 0;
      for (const feed of FEEDS) {
        const entry = data.feeds?.[feed.id];
        if (!entry || !Array.isArray(entry.ips) || entry.ips.length > 150000) continue;
        const ips = new Set(entry.ips.filter(ip => net.isIP(ip) === 4));
        this.entries.set(feed.id, { ips, sha:String(entry.sha || ''), fetchedAt:Number(entry.fetchedAt) || 0, sourceUpdatedAt:Number(entry.sourceUpdatedAt) || 0, error:String(entry.error || '').slice(0,300) });
      }
    } catch (err) { if (err.code !== 'ENOENT') throw err; }
  }
  save() {
    fs.mkdirSync(path.dirname(this.file), {recursive:true});
    const feeds = {};
    for (const [id, e] of this.entries) feeds[id] = { ...e, ips:[...e.ips] };
    const tmp = `${this.file}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({version:1,enabled:this.enabled,lastAttempt:this.lastAttempt,feeds}), {encoding:'utf8',mode:0o600});
    fs.renameSync(tmp,this.file);
  }
  isFresh(entry, now = Date.now()) { return !!(entry && entry.ips.size && entry.fetchedAt > 0 && entry.sourceUpdatedAt > 0 && entry.fetchedAt <= now + 300000 && entry.sourceUpdatedAt <= now + 300000 && now - entry.fetchedAt <= MAX_AGE && now - entry.sourceUpdatedAt <= MAX_AGE); }
  match(ip, now = Date.now()) {
    if (!this.enabled || net.isIP(ip) !== 4) return [];
    return FEEDS.filter(feed => { const e = this.entries.get(feed.id); return this.isFresh(e,now) && e.ips.has(ip); }).map(feed => feed.name);
  }
  status(now = Date.now()) {
    return { enabled:this.enabled, refreshing:!!this.inFlight, lastAttempt:this.lastAttempt, feeds:FEEDS.map(feed => { const e = this.entries.get(feed.id); return { ...feed, count:e?.ips.size || 0, fetchedAt:e?.fetchedAt || 0, sourceUpdatedAt:e?.sourceUpdatedAt || 0, sha:e?.sha || '', active:this.enabled && this.isFresh(e,now), error:e?.error || '' }; }) };
  }
  setEnabled(enabled) { if (typeof enabled !== 'boolean') throw new Error('Некорректная настройка.'); this.enabled = enabled; this.generation++; this.save(); }
  clear() { this.generation++; this.entries.clear(); this.lastAttempt = 0; this.save(); }
  async refresh() {
    if (!this.enabled) return this.status();
    if (this.inFlight) { await this.inFlight; return this.status(); }
    this.lastAttempt = Date.now();
    const generation = this.generation;
    this.inFlight = (async () => {
      for (const feed of FEEDS) {
        if (!this.enabled || generation !== this.generation) break;
        try {
          const commitsUrl = `https://api.github.com/repos/${feed.repo}/commits?path=${encodeURIComponent(feed.file)}&per_page=1`;
          const commits = await this.fetchJson(commitsUrl);
          const revision = commits?.[0]?.sha;
          const commitDate = Date.parse(commits?.[0]?.commit?.committer?.date || '');
          if (!/^[a-f0-9]{40}$/.test(revision || '') || !Number.isFinite(commitDate)) throw new Error('Не удалось определить версию и дату файла.');
          const contentUrl = `https://api.github.com/repos/${feed.repo}/contents/${feed.file}?ref=${revision}`;
          const parsed = parseContent(await this.fetchJson(contentUrl));
          if (feed.id === 'blocklistde' && !Number.isFinite(parsed.sourceFileDate)) throw new Error('Дата оригинального списка Blocklist.de неизвестна.');
          // For the mirror use the older of the upstream file date and its GitHub change date.
          // IPsum's level file has no upstream date; the GitHub file change date is only a proxy.
          const sourceUpdatedAt = feed.id === 'blocklistde' ? Math.min(commitDate, parsed.sourceFileDate) : commitDate;
          if (!this.enabled || generation !== this.generation) break;
          this.entries.set(feed.id, { ips:new Set(parsed.ips), sha:parsed.sha, fetchedAt:Date.now(), sourceUpdatedAt, error:'' });
        } catch (err) {
          if (!this.enabled || generation !== this.generation) break;
          const old = this.entries.get(feed.id) || { ips:new Set(), sha:'', fetchedAt:0, sourceUpdatedAt:0 };
          this.entries.set(feed.id, { ...old, error:String(err.message || err).slice(0,300) });
        }
      }
      if (generation === this.generation) this.save();
    })();
    try { await this.inFlight; } finally { this.inFlight = null; }
    return this.status();
  }
  async refreshIfDue(now = Date.now()) {
    const incomplete = FEEDS.some(feed => !this.isFresh(this.entries.get(feed.id), now));
    const interval = incomplete ? 60 * 60 * 1000 : 24 * 60 * 60 * 1000;
    if (this.enabled && (!this.lastAttempt || now - this.lastAttempt >= interval)) return this.refresh();
    return this.status();
  }
}
module.exports = { FEEDS, MAX_AGE, ReputationStore, parseContent, requestJson };
