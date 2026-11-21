'use strict';

// NetFlow v5 and template-based NetFlow v9 / IPFIX (RFC 3954 / RFC 7011).
// Templates are scoped to an exporter and observation domain. Unknown templates
// and fields are ignored rather than guessing a record layout.
const MAX_TEMPLATES = 1024;
const TEMPLATE_TTL = 30 * 60 * 1000;
const MAX_RECORDS = 10000;

function uint(buf) {
  if (!buf.length || buf.length > 8) return 0;
  let n = 0;
  for (const b of buf) n = n * 256 + b;
  return Math.min(n, Number.MAX_SAFE_INTEGER);
}
function ipv4(buf) { return buf.length === 4 ? Array.from(buf).join('.') : ''; }
function ipv6(buf) {
  if (buf.length !== 16) return '';
  const parts = [];
  for (let i = 0; i < 16; i += 2) parts.push(buf.readUInt16BE(i).toString(16));
  return parts.join(':');
}
function decode(fields, record, clock) {
  const flow = { src: '', dst: '', srcPort: 0, dstPort: 0, protocol: 0, packets: 0, bytes: 0 };
  let p = 0; let startSys, endSys, startMs, endMs;
  for (const f of fields) {
    let length = f.length;
    if (length === 65535) {
      if (p >= record.length) return null;
      length = record[p++];
      if (length === 255) { if (p + 2 > record.length) return null; length = record.readUInt16BE(p); p += 2; }
    }
    if (p + length > record.length) return null;
    const value = record.subarray(p, p + length); p += length;
    if (f.enterprise) continue;
    switch (f.type) {
      case 1: flow.bytes = uint(value); break;
      case 2: flow.packets = uint(value); break;
      case 4: flow.protocol = uint(value); break;
      case 6: flow.tcpFlags = uint(value); break;
      case 10: flow.inputInterface = uint(value); break;
      case 14: flow.outputInterface = uint(value); break;
      case 22: startSys = uint(value); break;
      case 21: endSys = uint(value); break;
      case 150: startMs ??= uint(value) * 1000; break;
      case 151: endMs ??= uint(value) * 1000; break;
      case 152: startMs = uint(value); break;
      case 153: endMs = uint(value); break;
      case 7: flow.srcPort = uint(value); break;
      case 8: flow.src = ipv4(value); break;
      case 11: flow.dstPort = uint(value); break;
      case 12: flow.dst = ipv4(value); break;
      case 27: flow.src = ipv6(value); break;
      case 28: flow.dst = ipv6(value); break;
    }
  }
  if (clock && startMs == null && startSys != null) startMs = clock.exportMs - ((clock.uptime - startSys) >>> 0);
  if (clock && endMs == null && endSys != null) endMs = clock.exportMs - ((clock.uptime - endSys) >>> 0);
  if (Number.isFinite(startMs) && startMs >= 946684800000 && startMs <= Date.now() + 86400000) flow.startTime = startMs;
  if (Number.isFinite(endMs) && endMs >= 946684800000 && endMs <= Date.now() + 86400000) flow.endTime = endMs;
  return { flow, consumed: p };
}
class FlowParser {
  constructor() { this.templates = new Map(); this.stats = { versions: {5:0,9:0,10:0}, unsupported:0, malformed:0, unknownTemplates:0 }; }
  parse(buf, exporter = '') {
    if (!Buffer.isBuffer(buf) || buf.length < 2) { this.stats.malformed++; return []; }
    const version = buf.readUInt16BE(0);
    if (version === 5 || version === 9 || version === 10) this.stats.versions[version]++;
    else { this.stats.unsupported++; return []; }
    if (version === 5) return this.v5(buf);
    if (version === 9 || version === 10) return this.templated(buf, exporter, version);
    return [];
  }
  v5(buf) {
    if (buf.length < 24) { this.stats.malformed++; return []; }
    const count = buf.readUInt16BE(2);
    if (count > 30 || buf.length < 24 + count * 48) { this.stats.malformed++; return []; }
    const records = [];
    for (let i = 0; i < count; i++) {
      const p = 24 + i * 48;
      const flow = { src: ipv4(buf.subarray(p, p + 4)), dst: ipv4(buf.subarray(p + 4, p + 8)), packets: buf.readUInt32BE(p + 16), bytes: buf.readUInt32BE(p + 20), srcPort: buf.readUInt16BE(p + 32), dstPort: buf.readUInt16BE(p + 34), protocol: buf[p + 38] };
      if (buf[p + 37]) flow.tcpFlags = buf[p + 37];
      if (buf.readUInt16BE(p + 12)) flow.inputInterface = buf.readUInt16BE(p + 12);
      if (buf.readUInt16BE(p + 14)) flow.outputInterface = buf.readUInt16BE(p + 14);
      const sample = buf.readUInt16BE(22); if ((sample >> 14) && (sample & 0x3fff) > 1) flow.samplingInterval = sample & 0x3fff;
      const uptime = buf.readUInt32BE(4), exportMs = buf.readUInt32BE(8) * 1000 + Math.floor(buf.readUInt32BE(12) / 1000000);
      for (const [key, offset] of [['startTime', 24], ['endTime', 28]]) {
        const ticks = buf.readUInt32BE(p + offset); const timestamp = exportMs - ((uptime - ticks) >>> 0);
        if (ticks && timestamp >= 946684800000 && timestamp <= Date.now() + 86400000) flow[key] = timestamp;
      }
      records.push(flow);
    }
    return records;
  }
  templated(buf, exporter, version) {
    const header = version === 9 ? 20 : 16;
    if (buf.length < header) { this.stats.malformed++; return []; }
    const end = version === 10 ? buf.readUInt16BE(2) : buf.length;
    if (end < header || end > buf.length) { this.stats.malformed++; return []; }
    const domain = buf.readUInt32BE(version === 9 ? 16 : 12);
    const clock = version === 9 ? { uptime: buf.readUInt32BE(4), exportMs: buf.readUInt32BE(8) * 1000 } : null;
    const prefix = `${exporter}|${version}|${domain}|`;
    const now = Date.now();
    for (const [key, template] of this.templates) if (now - template.at > TEMPLATE_TTL) this.templates.delete(key);
    const records = [];
    for (let pos = header; pos + 4 <= end;) {
      const id = buf.readUInt16BE(pos), length = buf.readUInt16BE(pos + 2);
      if (length < 4 || pos + length > end) { this.stats.malformed++; break; }
      let p = pos + 4; const setEnd = pos + length;
      const isTemplate = id === (version === 9 ? 0 : 2);
      if (isTemplate) {
        while (p + 4 <= setEnd) {
          const templateId = buf.readUInt16BE(p), count = buf.readUInt16BE(p + 2); p += 4;
          if (templateId < 256) break;
          // IPFIX template withdrawal.
          if (count === 0 && version === 10) { this.templates.delete(prefix + templateId); continue; }
          if (!count || count > 256) break;
          const fields = []; let valid = true;
          for (let i = 0; i < count; i++) {
            if (p + 4 > setEnd) { valid = false; break; }
            let type = buf.readUInt16BE(p); const fieldLength = buf.readUInt16BE(p + 2); p += 4;
            let enterprise = false;
            if (version === 10 && (type & 0x8000)) {
              type &= 0x7fff; enterprise = true;
              if (p + 4 > setEnd) { valid = false; break; }
              p += 4;
            }
            if (!fieldLength) { valid = false; break; }
            fields.push({ type, length: fieldLength, enterprise });
          }
          if (!valid) break;
          if (this.templates.size >= MAX_TEMPLATES && !this.templates.has(prefix + templateId)) this.templates.delete(this.templates.keys().next().value);
          this.templates.set(prefix + templateId, { fields, at: now });
        }
      } else if (id >= 256) {
        const template = this.templates.get(prefix + id);
        if (!template) this.stats.unknownTemplates++;
        if (template) {
          while (p < setEnd && records.length < MAX_RECORDS) {
            const result = decode(template.fields, buf.subarray(p, setEnd), clock);
            if (!result || !result.consumed) break;
            p += result.consumed;
            if (result.flow.src && result.flow.dst) records.push(result.flow);
          }
        }
      }
      pos += length;
    }
    return records;
  }
}
module.exports = { FlowParser };
