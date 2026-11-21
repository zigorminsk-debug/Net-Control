'use strict';
const { addCategory, categoryList, classify, CATEGORIES } = require('./traffic-classifier');
const { parseCidrs, direction, emptyDirections, ipv6Number } = require('./direction');
const { analyze, validatePolicy, isMailFlow, isMinerFlow } = require('./security');
const WINDOW_MS = 5 * 60 * 1000;
const MAX_FLOWS = 50000;
class Analyzer {
  constructor() { this.flows = []; this.received = 0; this.dropped = 0; this.networks = []; this.policy = validatePolicy(); this.baselines = new Map(); this.reputation = null; }
  setPolicy(policy) { this.policy = validatePolicy(policy); return { ...this.policy }; }
  setNetworks(text) { this.networks = parseCidrs(text); return this.networks.map(n => n.cidr); }
  add(flows, now = Date.now()) {
    for (const flow of flows) {
      if (!flow.src || !flow.dst) continue;
      this.flows.push({ ...flow, time: now }); this.received++;
    }
    this.prune(now);
  }
  prune(now) {
    let i = 0;
    while (i < this.flows.length && this.flows[i].time < now - WINDOW_MS) i++;
    if (i) this.flows.splice(0, i);
    if (this.flows.length > MAX_FLOWS) {
      const excess = this.flows.length - MAX_FLOWS;
      this.flows.splice(0, excess); this.dropped += excess;
    }
  }
  snapshot(now = Date.now(), sort = {}) {
    this.prune(now);
    const hosts = new Map(); const categories = new Map(); const directions = emptyDirections(); const buckets = Array(30).fill(0); const byteBuckets = Array(30).fill(0); const packetBuckets = Array(30).fill(0); let bytes = 0; let packets = 0;
    for (const f of this.flows) {
      bytes += f.bytes; packets += f.packets; addCategory(categories, f);
      const dir = directions[direction(f, this.networks)]; dir.flows++; dir.bytes += f.bytes;
      const bucket = Math.max(0, Math.min(29, Math.floor((f.time - (now - WINDOW_MS)) / 10000))); buckets[bucket]++; byteBuckets[bucket] += f.bytes; packetBuckets[bucket] += f.packets;
      if (!hosts.has(f.src)) hosts.set(f.src, { ip: f.src, bytes: 0, flows: 0, destinations: new Set() });
      const h = hosts.get(f.src); h.bytes += f.bytes; h.flows++; h.destinations.add(f.dst);
    }
    const alerts = analyze(this.flows, this.networks, this.policy, this.baselines, this.reputation);
    const securityGroups = this.groupSummary(alerts);
    const key = ['ip', 'destinations', 'flows', 'bytes'].includes(sort?.by) ? sort.by : 'bytes';
    const sortDirection = sort?.direction === 'asc' ? 1 : -1;
    const hostRows = [...hosts.values()].map(h => ({ ip: h.ip, bytes: h.bytes, flows: h.flows, destinations: h.destinations.size }));
    const collator = new Intl.Collator('en', { numeric: true });
    const topTraffic = [...hostRows].sort((a,b) => b.bytes-a.bytes).slice(0,8);
    hostRows.sort((a, b) => sortDirection * (key === 'ip' ? collator.compare(a.ip, b.ip) : a[key] - b[key]) || collator.compare(a.ip, b.ip));
    return { bytes, packets, buckets, byteBuckets, packetBuckets, topTraffic, directions, networks: this.networks.map(n => n.cidr), categories: categoryList(categories), hostCount: hosts.size, securityGroups, alertCount: alerts.length, flowCount: this.flows.length, received: this.received, dropped: this.dropped, hosts: hostRows.slice(0, 30), alerts: alerts.slice(0, 100), recent: this.flows.slice(-50).reverse() };
  }
  groupSummary(alerts) {
    const groups = { miner: new Set(), spam: new Set(), ddos: new Set(), reputation: new Set() };
    for (const alert of alerts) {
      const id = alert.type === 'Возможный майнинг' ? 'miner' : alert.type === 'Возможный спам' ? 'spam' : ['Возможный исходящий DDoS', 'Возможная входящая атака'].includes(alert.type) ? 'ddos' : alert.type === 'Совпадение с репутационной базой' ? 'reputation' : '';
      if (id) groups[id].add(alert.ip);
    }
    return Object.fromEntries(Object.entries(groups).map(([key, ips]) => [key, ips.size]));
  }
  securityDetail(id, now = Date.now(), limit = 200) {
    const types = { miner:['Возможный майнинг'], spam:['Возможный спам'], ddos:['Возможный исходящий DDoS','Возможная входящая атака'], reputation:['Совпадение с репутационной базой'] };
    if (!Object.hasOwn(types, id)) throw new Error('Неизвестный тип сигнала.');
    this.prune(now);
    const alerts = analyze(this.flows, this.networks, this.policy, this.baselines, this.reputation).filter(a => types[id].includes(a.type));
    const byHost = new Map();
    for (const alert of alerts) {
      if (!byHost.has(alert.ip)) byHost.set(alert.ip, { ip:alert.ip, alerts:[], bytes:0, flows:0, peers:new Set() });
      byHost.get(alert.ip).alerts.push(alert);
    }
    const pools = parseCidrs(this.policy.poolAddresses), records = [];
    let totalBytes = 0, count = 0;
    for (const f of this.flows) {
      const dir = direction(f, this.networks);
      const ip = dir === 'outgoing' ? f.src : dir === 'incoming' ? f.dst : '';
      const host = byHost.get(ip); if (!host) continue;
      let include = false;
      if (id === 'miner') include = dir === 'outgoing' && isMinerFlow(f, pools);
      else if (id === 'spam') include = dir === 'outgoing' && isMailFlow(f);
      else if (id === 'ddos') include = host.alerts.some(a => (a.type === 'Возможный исходящий DDoS' && dir === 'outgoing') || (a.type === 'Возможная входящая атака' && dir === 'incoming'));
      else if (id === 'reputation' && this.reputation) include = this.reputation.match(dir === 'outgoing' ? f.dst : f.src).length > 0;
      if (!include) continue;
      count++; totalBytes += f.bytes; host.bytes += f.bytes; host.flows++; host.peers.add(dir === 'outgoing' ? f.dst : f.src);
      records.push({ ...f, localHost:ip, direction:dir, evidence: id === 'reputation' && this.reputation ? this.reputation.match(dir === 'outgoing' ? f.dst : f.src).join(', ') : '' });
    }
    return { id, hostCount:byHost.size, count, bytes:totalBytes, hosts:[...byHost.values()].sort((a,b)=>b.bytes-a.bytes).slice(0,100).map(h => ({ip:h.ip, bytes:h.bytes, flows:h.flows, peers:h.peers.size, alerts:h.alerts})), records:records.slice(-limit).reverse() };
  }
  search(raw = {}, now = Date.now(), limit = 200) {
    this.prune(now);
    if (!raw || typeof raw !== 'object') throw new Error('Некорректный фильтр.');
    const ip = String(raw.ip || '').trim(), port = String(raw.port || '').trim();
    const exporter = String(raw.exporter || '').trim();
    const protocol = String(raw.protocol || ''), dir = String(raw.direction || ''), category = String(raw.category || ''), threat = String(raw.threat || '');
    if (exporter && require('node:net').isIP(exporter) !== 4) throw new Error('Укажите корректный IPv4 экспортёра.');
    if (ip && (!require('node:net').isIP(ip) || (require('node:net').isIP(ip) === 6 && ipv6Number(ip) === null))) throw new Error('Укажите корректный IP-адрес.');
    if (port && (!/^\d{1,5}$/.test(port) || Number(port) > 65535)) throw new Error('Укажите порт от 0 до 65535.');
    if (protocol && !['6','17','1','58'].includes(protocol)) throw new Error('Неизвестный протокол.');
    if (dir && !['incoming','outgoing','internal','transit','unknown'].includes(dir)) throw new Error('Неизвестное направление.');
    if (category && !Object.hasOwn(CATEGORIES, category)) throw new Error('Неизвестная категория.');
    if (threat && !['miner','spam','ddos','reputation'].includes(threat)) throw new Error('Неизвестный сигнал.');
    const source = threat ? this.securityDetail(threat, now, MAX_FLOWS).records : [...this.flows].reverse();
    const matches = [];
    for (const f of source) {
      const d = direction(f, this.networks), c = classify(f);
      if (exporter && f.exporter !== exporter) continue;
      if (ip && f.src !== ip && f.dst !== ip && !(require('node:net').isIP(ip) === 6 && (ipv6Number(f.src) === ipv6Number(ip) || ipv6Number(f.dst) === ipv6Number(ip)))) continue;
      if (port && f.srcPort !== Number(port) && f.dstPort !== Number(port)) continue;
      if (protocol && f.protocol !== Number(protocol)) continue;
      if (dir && d !== dir) continue;
      if (category && c.id !== category) continue;
      matches.push({ ...f, direction:d, category:c.label, categoryId:c.id });
    }
    return { total:matches.length, records:matches.slice(0, Math.max(0, Math.min(MAX_FLOWS, limit))) };
  }
  categoryDetail(id, now = Date.now()) {
    if (!Object.hasOwn(CATEGORIES, id)) throw new Error('Неизвестный тип трафика.');
    this.prune(now);
    const hosts = new Map(); const records = []; let bytes = 0, count = 0;
    for (const f of this.flows) {
      const c = classify(f); if (c.id !== id) continue;
      count++; bytes += f.bytes;
      if (!hosts.has(f.src)) hosts.set(f.src, { ip: f.src, bytes: 0, flows: 0, targets: new Set() });
      const h = hosts.get(f.src); h.bytes += f.bytes; h.flows++; h.targets.add(f.dst);
      records.push({ ...f, evidence: c.evidence });
    }
    return { id, label: CATEGORIES[id], bytes, count, hostCount: hosts.size, hosts: [...hosts.values()].sort((a,b) => b.bytes - a.bytes).slice(0, 100).map(h => ({ip:h.ip, bytes:h.bytes, flows:h.flows, targets:h.targets.size})), records: records.slice(-200).reverse() };
  }
  hostDetail(ip, now = Date.now()) {
    this.prune(now);
    const categories = new Map(); const peers = new Map(); const records = [];
    let bytes = 0, packets = 0, outgoing = 0, incoming = 0, outgoingBytes = 0, incomingBytes = 0, count = 0;
    for (const f of this.flows) {
      if (f.src !== ip && f.dst !== ip) continue;
      count++; bytes += f.bytes; packets += f.packets;
      if (f.src === ip) { outgoing++; outgoingBytes += f.bytes; }
      if (f.dst === ip) { incoming++; incomingBytes += f.bytes; }
      const peer = f.src === ip ? f.dst : f.src;
      if (!peers.has(peer)) peers.set(peer, { ip: peer, bytes: 0, flows: 0 });
      const counterpart = peers.get(peer); counterpart.bytes += f.bytes; counterpart.flows++;
      const category = addCategory(categories, f);
      records.push({ ...f, category: category.label, evidence: category.evidence });
    }
    return { ip, bytes, packets, outgoing, incoming, outgoingBytes, incomingBytes, count, peers: peers.size, topPeers: [...peers.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 10), categories: categoryList(categories), records: records.slice(-200).reverse() };
  }
  clear() { this.flows = []; this.received = 0; this.dropped = 0; }
}
module.exports = { Analyzer, WINDOW_MS };
