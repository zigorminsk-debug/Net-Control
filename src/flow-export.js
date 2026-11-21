'use strict';
// Quote every cell and neutralize spreadsheet formulas, including leading whitespace.
function cell(value) {
  let text = String(value ?? '');
  if (/^[\s]*[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}
function toCsv(records) {
  const fields = ['time','exporter','src','srcPort','dst','dstPort','protocol','direction','category','bytes','packets'];
  return '\ufeff' + [fields.map(cell).join(','), ...records.map(row => fields.map(key => cell(row[key])).join(','))].join('\r\n') + '\r\n';
}
module.exports = { toCsv };
