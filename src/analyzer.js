'use strict';
const WINDOW_MS = 5 * 60 * 1000;
const MAX_FLOWS = 50000;
const MINER_PORTS = new Set([3333, 4444, 5555, 7777, 14444, 14433]);
const MAIL_PORTS = new Set([25, 465, 587]);
class Analyzer {
  constructor() { this.flows = []; this.received = 0; this.dropped = 0; }
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
  snapshot(now = Date.now()) {
    this.prune(now);
    const hosts = new Map(); const buckets = Array(30).fill(0); let bytes = 0; let packets = 0;
    for (const f of this.flows) {
      bytes += f.bytes; packets += f.packets;
      const bucket = Math.max(0, Math.min(29, Math.floor((f.time - (now - WINDOW_MS)) / 10000))); buckets[bucket]++;
      if (!hosts.has(f.src)) hosts.set(f.src, { ip: f.src, bytes: 0, flows: 0, destinations: new Set(), mail: new Set(), miner: 0 });
      const h = hosts.get(f.src); h.bytes += f.bytes; h.flows++; h.destinations.add(f.dst);
      if (f.protocol === 6 && MAIL_PORTS.has(f.dstPort)) h.mail.add(f.dst);
      if (f.protocol === 6 && MINER_PORTS.has(f.dstPort)) h.miner++;
    }
    const alerts = [];
    for (const h of hosts.values()) {
      if (h.destinations.size >= 30) alerts.push({ type: 'Сканирование', severity: 'high', ip: h.ip, detail: `${h.destinations.size} адресов назначения за 5 минут` });
      if (h.mail.size >= 10) alerts.push({ type: 'Возможный спам', severity: 'medium', ip: h.ip, detail: `SMTP к ${h.mail.size} адресам за 5 минут` });
      if (h.miner >= 5) alerts.push({ type: 'Возможный майнинг', severity: 'medium', ip: h.ip, detail: `${h.miner} потоков на порты, часто используемые пулами` });
    }
    alerts.sort ( (a, b) => (a.severity === 'high' ? 0 : 1) - (b.severity === 'high' ? 0 : 1));
    return { bytes, packets, buckets, hostCount: hosts.size, alertCount: alerts.length, flowCount: this.flows.length, received: this.received, dropped: this.dropped, hosts: [...hosts.values()].sort((a, b) => b.bytes - a.bytes).slice(0, 30).map(h => ({ ip: h.ip, bytes: h.bytes, flows: h.flows, destinations: h.destinations.size })), alerts: alerts.slice(0, 100), recent: this.flows.slice(-50).reverse() };
  }
  clear() { this.flows = []; this.received = 0; this.dropped = 0; }
}
module.exports = { Analyzer, WINDOW_MS };
