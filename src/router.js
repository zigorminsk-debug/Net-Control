'use strict';
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
function validateAddress(address) { return net.isIP(address) === 4; }
function describeConnectionError(err, { secure, port }) {
  const service = secure ? 'www-ssl' : 'www';
  const hint = secure ? 'HTTPS обычно использует порт 443.' : 'HTTP обычно использует порт 80; порт 443 обычно предназначен для HTTPS.';
  if (err.code === 'ECONNREFUSED') return `Соединение отклонено (ECONNREFUSED). Проверьте IP, порт ${port}, доступность службы ${service} и правила firewall на роутере. ${hint}`;
  if (err.code === 'ROUTER_TIMEOUT' || err.code === 'ETIMEDOUT') return `Время ожидания истекло. Проверьте маршрутизацию, IP, порт ${port}, службу ${service} и правила firewall.`;
  if (['ENETUNREACH', 'EHOSTUNREACH'].includes(err.code)) return 'Роутер недоступен по сети. Проверьте IP-адрес и маршрут до него.';
  if (['DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'ERR_TLS_CERT_ALTNAME_INVALID'].includes(err.code)) return 'Ошибка проверки сертификата HTTPS. Проверьте сертификат и его соответствие адресу роутера. Доверие самоподписанному сертификату отключает проверку и небезопасно.';
  if (err.code && (err.code.startsWith('ERR_SSL_') || err.code.startsWith('ERR_TLS_') || err.code === 'EPROTO')) return `Ошибка TLS. Проверьте HTTPS, порт ${port} и службу www-ssl с назначенным сертификатом. Если certificate=none, назначьте сертификат на роутере; флажок доверия не создаёт его.`;
  return `Ошибка подключения: ${err.message}`;
}
function testRouter({ address, port, username, password, secure, allowSelfSigned }) {
  return new Promise((resolve, reject) => {
    if (!validateAddress(address) || !Number.isInteger(port) || port < 1 || port > 65535 || !username || typeof password !== 'string') return reject(new Error('Проверьте IPv4-адрес, порт и имя пользователя.'));
    const transport = secure ? https : http;
    const req = transport.request({ hostname: address, port, path: '/rest/system/resource', method: 'GET', timeout: 8000, headers: { Authorization: 'Basic ' + Buffer.from(`${username}:${password}`).toString('base64'), Accept: 'application/json' }, ...(secure ? { rejectUnauthorized: !allowSelfSigned } : {}) }, res => {
      let body = '';
      res.on('data', chunk => { body += chunk; if (body.length > 65536) req.destroy(new Error('Слишком большой ответ роутера.')); });
      res.on('error', err => reject(new Error(describeConnectionError(err, { secure, port }))));
      res.on('end', () => {
        if (res.statusCode === 401 || res.statusCode === 403) return reject(new Error(`RouterOS вернул HTTP ${res.statusCode}. Проверьте имя пользователя, пароль и права доступа.`));
        if (res.statusCode === 404) return reject(new Error('RouterOS вернул HTTP 404. REST API доступен в RouterOS 7; проверьте адрес, порт и службу www/www-ssl.'));
        if (res.statusCode !== 200) return reject(new Error(`RouterOS вернул HTTP ${res.statusCode}. Проверьте доступ и настройки службы.`));
        try {
          const data = JSON.parse(body);
          resolve({ version: String(data.version || 'неизвестно'), uptime: String(data.uptime || 'неизвестно'), board: String(data['board-name'] || 'MikroTik') });
        } catch { reject(new Error('Ответ не похож на RouterOS REST API.')); }
      });
    });
    req.on('timeout', () => req.destroy(Object.assign(new Error('Время ожидания подключения истекло.'), { code: 'ROUTER_TIMEOUT' })));
    req.on('error', err => reject(new Error(describeConnectionError(err, { secure, port })))); req.end();
  });
}
module.exports = { validateAddress, testRouter, describeConnectionError };
