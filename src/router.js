'use strict';
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
function validateAddress(address) { return net.isIP(address) === 4; }
function testRouter({ address, port, username, password, secure, allowSelfSigned }) {
  return new Promise((resolve, reject) => {
    if (!validateAddress(address) || !Number.isInteger(port) || port < 1 || port > 65535 || !username || typeof password !== 'string') return reject(new Error('Проверьте IPv4-адрес, порт и имя пользователя.'));
    const transport = secure ? https : http;
    const req = transport.request({ hostname: address, port, path: '/rest/system/resource', method: 'GET', timeout: 8000, headers: { Authorization: 'Basic ' + Buffer.from(`${username}:${password}`).toString('base64'), Accept: 'application/json' }, ...(secure ? { rejectUnauthorized: !allowSelfSigned } : {}) }, res => {
      let body = '';
      res.on('data', chunk => { body += chunk; if (body.length > 65536) req.destroy(new Error('Слишком большой ответ роутера.')); });
      res.on('end', () => {
        if (res.statusCode !== 200) return reject(new Error(`RouterOS вернул HTTP ${res.statusCode}. Проверьте доступ и учётные данные.`));
        try {
          const data = JSON.parse(body);
          resolve({ version: String(data.version || 'неизвестно'), uptime: String(data.uptime || 'неизвестно'), board: String(data['board-name'] || 'MikroTik') });
        } catch { reject(new Error('Ответ не похож на RouterOS REST API.')); }
      });
    });
    req.on('timeout', () => req.destroy(new Error('Время ожидания подключения истекло.')));
    req.on('error', reject); req.end();
  });
}
module.exports = { validateAddress, testRouter };
