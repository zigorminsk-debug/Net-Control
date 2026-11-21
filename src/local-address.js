'use strict';
const os = require('node:os');
const dgram = require('node:dgram');
const net = require('node:net');
function isUsableAddress(address) {
  if (net.isIP(address) !== 4) return false;
  const octets = address.split('.').map(Number);
  return octets[0] !== 0 && octets[0] !== 127 && octets[0] < 224 && address !== '255.255.255.255';
}
function listLocalAddresses(networks = os.networkInterfaces()) {
  const result = [];
  for (const [name, entries] of Object.entries(networks)) {
    for (const entry of entries || []) {
      if ((entry.family === 'IPv4' || entry.family === 4) && !entry.internal && isUsableAddress(entry.address)) result.push({ name, address: entry.address });
    }
  }
  return result;
}
function routeAddress(router) {
  return new Promise((resolve, reject) => {
    if (!isUsableAddress(router)) return reject(new Error('Укажите IPv4-адрес роутера, отличный от localhost.'));
    const socket = dgram.createSocket('udp4');
    // connect() selects an OS route and local source address; no datagram is sent.
    socket.once('error', err => { try { socket.close(); } catch {} reject(err); });
    socket.connect(9, router, () => {
      try { const address = socket.address().address; socket.close(); resolve(address); }
      catch (err) { try { socket.close(); } catch {} reject(err); }
    });
  });
}
async function detectLocalAddress(router) {
  const interfaces = listLocalAddresses();
  try {
    const address = await routeAddress(router);
    const match = interfaces.find(item => item.address === address);
    if (!match) throw new Error('Адрес выбранного маршрута не найден среди сетевых интерфейсов.');
    return { address, interfaceName: match.name, interfaces };
  } catch (err) { return { address: '', interfaces, error: err.message }; }
}
module.exports = { isUsableAddress, listLocalAddresses, routeAddress, detectLocalAddress };
