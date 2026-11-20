'use strict';
// A port hint is not an application or service identity. HTTPS/QUIC remain
// generic because flow metadata does not reveal the encrypted application.
const CATEGORIES = {
  mail: 'Почта', voip: 'IP-телефония', media: 'Медиа', p2p: 'P2P',
  dns: 'DNS', web: 'Веб', secureWeb: 'HTTPS / QUIC', vpn: 'VPN',
  files: 'Файлы / SSH', other: 'Не определено'
};
const RULES = [
  { id: 'mail', protocols: [6], ports: [25, 110, 143, 465, 587, 993, 995] },
  { id: 'voip', protocols: [6, 17], ports: [5060, 5061, 4569, 1720] },
  { id: 'media', protocols: [6, 17], ports: [554, 1935, 5004, 5005, 8554] },
  { id: 'p2p', protocols: [6, 17], ports: [4662, 4672, 6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889, 51413] },
  { id: 'dns', protocols: [6, 17], ports: [53, 853] },
  { id: 'web', protocols: [6], ports: [80, 8000, 8080] },
  { id: 'secureWeb', protocols: [6, 17], ports: [443, 8443] },
  { id: 'vpn', protocols: [6, 17], ports: [1194, 1701, 1723, 51820] },
  { id: 'vpn', protocols: [17], ports: [500, 4500] },
  { id: 'files', protocols: [6], ports: [20, 21, 22, 445, 2049] }
];
function classify(flow) {
  // Destination is preferred. Source is used for reverse-direction records.
  for (const side of ['dstPort', 'srcPort']) {
    const port = Number(flow[side]);
    for (const rule of RULES) {
      if (rule.protocols.includes(flow.protocol) && rule.ports.includes(port)) {
        const protocol = flow.protocol === 6 ? 'TCP' : 'UDP';
        return { id: rule.id, label: CATEGORIES[rule.id], evidence: `${protocol} ${port} (${side === 'dstPort' ? 'назначение' : 'источник'})` };
      }
    }
  }
  return { id: 'other', label: CATEGORIES.other, evidence: 'Нет совпадения по порту' };
}
function addCategory(map, flow) {
  const category = classify(flow);
  if (!map.has(category.id)) map.set(category.id, { id: category.id, label: category.label, bytes: 0, flows: 0 });
  const item = map.get(category.id); item.bytes += flow.bytes; item.flows++;
  return category;
}
function categoryList(map) { return [...map.values()].sort((a, b) => b.bytes - a.bytes || b.flows - a.flows); }
module.exports = { classify, addCategory, categoryList, CATEGORIES };
