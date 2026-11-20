'use strict';
const { parseCidrs, direction, ipNumber } = require('./direction');
const MINER_PORTS = new Set([3333, 4444, 5555, 7777, 14433, 14444]);
const SMTP_PORTS = new Set([25, 465, 587]);
const DEFAULTS = Object.freeze({ scanDestinations: 30, smtpDestinations: 10, minerRecords: 5, minerMinutes: 5, ddosPackets: 100000, ddosBytesMB: 20, ddosSources: 30, excluded: '', mailServers: '', poolAddresses: '' });
const LIMITS = { scanDestinations: [2, 100000], smtpDestinations: [2, 100000], minerRecords: [1, 50000], minerMinutes: [1, 10080], ddosPackets: [1, 100000000000], ddosBytesMB: [1, 1000000], ddosSources: [2, 50000] };
function validatePolicy(input = {}) {
  const result = { ...DEFAULTS };
  for (const [key, [min, max]] of Object.entries(LIMITS)) {
    const v = input[key] === undefined ? DEFAULTS[key] : Number(input[key]);
    if (!Number.isSafeInteger(v) || v < min || v > max) throw new Error(`Некорректный порог ${key}: допустимо ${min}–${max}.`);
    result[key] = v;
  }
  for (const key of ['excluded', 'mailServers', 'poolAddresses']) {
    if (input[key] !== undefined && typeof input[key] !== 'string') throw new Error('Списки сетей должны быть текстом в формате CIDR.');
    result[key] = parseCidrs(input[key] || '').map(n => n.cidr).join('\n');
  }
  return result;
}
function contains(ip, networks) {
  const n = ipNumber(ip);
  return n !== null && networks.some(cidr => ((n & cidr.mask) >>> 0) === cidr.network);
}
function isMailFlow(f) { return f.protocol === 6 && SMTP_PORTS.has(f.dstPort); }
function isMinerFlow(f, pools) { return f.protocol === 6 && (MINER_PORTS.has(f.dstPort) || contains(f.dst, pools)); }
function analyze(flows, networks, rawPolicy, baselines = new Map(), reputation = null) {
  const policy = validatePolicy(rawPolicy);
  const excluded = parseCidrs(policy.excluded), mailServers = parseCidrs(policy.mailServers), pools = parseCidrs(policy.poolAddresses);
  const outbound = new Map(), inbound = new Map(), reputationHits = new Map();
  for (const f of flows) {
    const dir = direction(f, networks);
    const localIp = dir === 'outgoing' ? f.src : dir === 'incoming' ? f.dst : '';
    const remoteIp = dir === 'outgoing' ? f.dst : dir === 'incoming' ? f.src : '';
    if (localIp && !contains(localIp, excluded) && reputation) {
      const matches = reputation.match(remoteIp);
      if (matches.length) {
        let entry = reputationHits.get(localIp);
        if (!entry) { entry = { peers: new Set(), sources: new Set(), flows: 0 }; reputationHits.set(localIp, entry); }
        entry.peers.add(remoteIp); for (const match of matches) entry.sources.add(match); entry.flows++;
      }
    }
    if (dir === 'outgoing' && !contains(f.src, excluded)) {
      let h = outbound.get(f.src);
      if (!h) { h = { targets: new Set(), smtp: new Set(), miners: 0, pools: new Set(), intervals: new Map(), bytes: 0, packets: 0 }; outbound.set(f.src, h); }
      h.targets.add(f.dst); h.bytes += f.bytes; h.packets += f.packets;
      if (isMailFlow(f)) h.smtp.add(f.dst);
      if (isMinerFlow(f, pools)) {
        h.miners++;
        if (contains(f.dst, pools)) h.pools.add(f.dst);
        if (Number.isFinite(f.startTime) && Number.isFinite(f.endTime) && f.endTime >= f.startTime) {
          const key = `${f.dst}:${f.dstPort}`;
          const interval = h.intervals.get(key) || { start: f.startTime, end: f.endTime };
          interval.start = Math.min(interval.start, f.startTime); interval.end = Math.max(interval.end, f.endTime); h.intervals.set(key, interval);
        }
      }
    } else if (dir === 'incoming' && !contains(f.dst, excluded)) {
      let h = inbound.get(f.dst);
      if (!h) { h = { sources: new Set(), bytes: 0, packets: 0 }; inbound.set(f.dst, h); }
      h.sources.add(f.src); h.bytes += f.bytes; h.packets += f.packets;
    }
  }
  const alerts = [];
  for (const [ip, h] of outbound) {
    if (h.targets.size >= policy.scanDestinations) alerts.push({ type:'Сканирование', severity:h.targets.size >= policy.scanDestinations * 2 ? 'medium' : 'low', ip, detail:`${h.targets.size} внешних IP назначения за окно экспорта.`, recommendation:'Проверьте назначение устройства, журналы firewall и легитимные сканеры.' });
    if (!contains(ip, mailServers) && h.smtp.size >= policy.smtpDestinations) alerts.push({ type:'Возможный спам', severity:h.smtp.size >= policy.smtpDestinations * 2 ? 'medium' : 'low', ip, detail:`SMTP к ${h.smtp.size} внешним адресам; это не содержание писем и не число доставок.`, recommendation:'Проверьте почтовые журналы и процессы; разрешённые почтовые серверы внесите в исключение.' });
    const duration = Math.max(0, ...[...h.intervals.values()].map(value => Math.floor((value.end - value.start) / 60000)));
    if (h.miners && (h.miners >= policy.minerRecords || duration >= policy.minerMinutes || h.pools.size > 0)) alerts.push({ type:'Возможный майнинг', severity:h.pools.size && (duration >= policy.minerMinutes || h.miners >= policy.minerRecords) ? 'medium' : 'low', ip, detail:`${h.miners} записей на характерные порты или заданные адреса пулов${duration ? `; интервал по времени потоков ${duration} мин` : ''}${h.pools.size ? `; совпадений с заданными адресами: ${h.pools.size}` : ''}.`, recommendation:'Проверьте процессы и DNS/назначение на устройстве. Порт и адрес сами по себе не доказывают майнинг.' });
    const baseline = baselines.get(ip);
    const baselineNote = baseline ? ` Среднее по ${baseline.windows} наблюдаемым пятиминутным окнам за ${baseline.days} дней: ${Math.round(baseline.averageBytes / 1048576)} МБ${baseline.averageBytes && h.bytes >= baseline.averageBytes * 3 ? '; текущее окно превышает среднее более чем в 3 раза' : ''}.` : ' История для сравнения недостаточна или выключена.';
    if (h.packets >= policy.ddosPackets && h.bytes >= policy.ddosBytesMB * 1024 * 1024) alerts.push({ type:'Возможный исходящий DDoS', severity:baseline && baseline.averageBytes > 0 && h.bytes >= baseline.averageBytes * 3 ? 'medium' : 'low', ip, detail:`${h.packets} экспортированных пакетов и ${Math.round(h.bytes / 1048576)} МБ к ${h.targets.size} внешним адресам за окно получения записей.${baselineNote}`, recommendation:'Сравните с обычной нагрузкой, проверьте назначения и процессы, подтвердите по firewall/IDS.' });
  }
  for (const [ip, h] of inbound) {
    if (h.sources.size >= policy.ddosSources && h.packets >= policy.ddosPackets) alerts.push({ type:'Возможная входящая атака', severity:h.sources.size >= policy.ddosSources * 2 && h.packets >= policy.ddosPackets * 2 ? 'medium' : 'low', ip, detail:`${h.sources.size} внешних источников и ${h.packets} экспортированных пакетов к внутреннему узлу за окно получения записей.`, recommendation:'Проверьте легитимность нагрузки, firewall и журналы сервиса; при подтверждении обратитесь к провайдеру.' });
  }
  for (const [ip, hit] of reputationHits) {
    alerts.push({ type:'Совпадение с репутационной базой', severity:'low', ip, detail:`${hit.flows} записей с ${hit.peers.size} внешними IP; источники: ${[...hit.sources].join(', ')}. Примеры IP: ${[...hit.peers].slice(0, 5).join(', ')}.`, recommendation:'Проверьте адрес и время по журналам. IP может быть общим, устаревшим или ошибочно включённым; совпадение не доказывает компрометацию.' });
  }
  alerts.sort((a, b) => (a.severity === 'medium' ? 0 : 1) - (b.severity === 'medium' ? 0 : 1));
  return alerts;
}
module.exports = { DEFAULTS, validatePolicy, analyze, contains, isMailFlow, isMinerFlow };
