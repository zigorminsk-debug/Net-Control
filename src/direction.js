'use strict';
const net = require('node:net');
const LABELS = { outgoing: 'Исходящий', incoming: 'Входящий', internal: 'Внутренний', transit: 'Транзитный', unknown: 'Не определён' };
function ipNumber(ip) {
  if (typeof ip !== 'string' || net.isIP(ip) !== 4) return null;
  return ip.split('.').reduce((n, octet) => (n * 256 + Number(octet)) >>> 0, 0);
}
function parseCidrs(text) {
  if (typeof text !== 'string' || text.length > 4096) throw new Error('Введите не более 4096 символов подсетей.');
  const values = text.split(/[\s,;]+/).filter(Boolean);
  if (values.length > 64) throw new Error('Укажите не более 64 подсетей.');
  return [...new Set(values)].map(cidr => {
    const parts = cidr.split('/');
    const ip = parts.length === 2 ? ipNumber(parts[0]) : null;
    if (ip === null || !/^(0|[1-9]\d?)$/.test(parts[1]) || Number(parts[1]) > 32) throw new Error(`Неверная IPv4-подсеть: ${cidr}. Пример: 192.168.88.0/24`);
    const prefix = Number(parts[1]);
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return { cidr, mask, network: (ip & mask) >>> 0 };
  });
}
function direction(flow, networks) {
  const src = ipNumber(flow.src), dst = ipNumber(flow.dst);
  if (!networks.length || src === null || dst === null) return 'unknown';
  const isLocal = ip => networks.some(n => ((ip & n.mask) >>> 0) === n.network);
  const source = isLocal(src), destination = isLocal(dst);
  return source ? (destination ? 'internal' : 'outgoing') : (destination ? 'incoming' : 'transit');
}
function emptyDirections() { return Object.fromEntries(Object.entries(LABELS).map(([key, label]) => [key, { label, flows: 0, bytes: 0 }])); }
module.exports = { parseCidrs, direction, emptyDirections, ipNumber };
