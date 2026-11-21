'use strict';
const net = require('node:net');
const LABELS = { outgoing: 'Исходящий', incoming: 'Входящий', internal: 'Внутренний', transit: 'Транзитный', unknown: 'Не определён' };
function ipNumber(ip) {
  if (typeof ip !== 'string' || net.isIP(ip) !== 4) return null;
  return ip.split('.').reduce((n, octet) => (n * 256 + Number(octet)) >>> 0, 0);
}
function ipv6Number(ip) {
  if (typeof ip !== 'string' || net.isIP(ip) !== 6 || ip.includes('%')) return null;
  // URL canonicalizes compressed and IPv4-embedded addresses to hexadecimal.
  const canonical = new URL(`http://[${ip}]/`).hostname.slice(1, -1);
  const sides = canonical.split('::');
  const left = sides[0] ? sides[0].split(':') : [];
  const right = sides.length > 1 && sides[1] ? sides[1].split(':') : [];
  const parts = sides.length > 1 ? [...left, ...Array(8-left.length-right.length).fill('0'), ...right] : left;
  if (parts.length !== 8) return null;
  return parts.reduce((n, part) => (n << 16n) | BigInt(parseInt(part,16)), 0n);
}
function parseCidrs(text) {
  if (typeof text !== 'string' || text.length > 4096) throw new Error('Введите не более 4096 символов подсетей.');
  const values = text.split(/[\s,;]+/).filter(Boolean);
  if (values.length > 64) throw new Error('Укажите не более 64 подсетей.');
  return [...new Set(values)].map(cidr => {
    const parts = cidr.split('/'), family = parts.length === 2 ? net.isIP(parts[0]) : 0;
    if (!family || !/^(0|[1-9]\d{0,2})$/.test(parts[1]) || Number(parts[1]) > (family === 4 ? 32 : 128)) throw new Error(`Неверная IP-подсеть: ${cidr}. Пример: 192.168.88.0/24 или 2001:db8::/64`);
    const prefix = Number(parts[1]);
    if (family === 4) {
      const ip = ipNumber(parts[0]), mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
      return { cidr, family, mask, network: (ip & mask) >>> 0 };
    }
    const ip = ipv6Number(parts[0]);
    if (ip === null) throw new Error(`Неверная IPv6-подсеть: ${cidr}`);
    const mask = prefix === 0 ? 0n : ((1n << BigInt(prefix)) - 1n) << BigInt(128-prefix);
    return { cidr, family, mask, network: ip & mask };
  });
}
function containsIp(ip, networks) {
  const family = net.isIP(ip);
  if (family === 4) { const n = ipNumber(ip); return networks.some(cidr => cidr.family === 4 && ((n & cidr.mask) >>> 0) === cidr.network); }
  if (family === 6) { const n = ipv6Number(ip); return n !== null && networks.some(cidr => cidr.family === 6 && (n & cidr.mask) === cidr.network); }
  return false;
}
function direction(flow, networks) {
  const family = net.isIP(flow.src);
  if (!family || family !== net.isIP(flow.dst) || !networks.some(n => n.family === family) || (family === 6 && (ipv6Number(flow.src) === null || ipv6Number(flow.dst) === null))) return 'unknown';
  const source = containsIp(flow.src, networks), destination = containsIp(flow.dst, networks);
  return source ? (destination ? 'internal' : 'outgoing') : (destination ? 'incoming' : 'transit');
}
function emptyDirections() { return Object.fromEntries(Object.entries(LABELS).map(([key, label]) => [key, { label, flows: 0, bytes: 0 }])); }
module.exports = { parseCidrs, direction, emptyDirections, ipNumber, ipv6Number, containsIp };
