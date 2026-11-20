'use strict';
const dgram = require('node:dgram');
const { FlowParser } = require('./flow');
const { Analyzer } = require('./analyzer');
const { validateAddress } = require('./router');
class Collector {
  constructor() { this.socket = null; this.parser = new FlowParser(); this.analyzer = new Analyzer(); this.state = { running: false, address: '', port: 2055, datagrams: 0, lastPacket: null, error: '' }; }
  async start(address, port) {
    if (!validateAddress(address) || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Укажите IPv4 роутера и UDP-порт от 1 до 65535.');
    this.stop(); this.parser = new FlowParser(); this.analyzer.clear();
    this.state = { running: false, address, port, datagrams: 0, lastPacket: null, error: '' };
    const socket = dgram.createSocket('udp4'); this.socket = socket;
    socket.on('message', (msg, remote) => {
      if (remote.address !== address) return;
      this.state.datagrams++; this.state.lastPacket = Date.now();
      try { this.analyzer.add(this.parser.parse(msg, remote.address)); } catch { /* malformed UDP packet */ }
    });
    socket.on('error', err => { this.state.error = err.message; this.state.running = false; if (this.socket === socket) { this.socket = null; try { socket.close(); } catch {} } });
    await new Promise((resolve, reject) => {
      const onError = err => reject(err);
      socket.once('error', onError);
      socket.bind(port, '0.0.0.0', () => { socket.removeListener('error', onError); this.state.running = true; resolve(); });
    });
    return this.snapshot();
  }
  stop() { if (this.socket) { const socket = this.socket; this.socket = null; try { socket.close(); } catch {} } this.state.running = false; }
  snapshot() { return { ...this.state, ...this.analyzer.snapshot() }; }
}
module.exports = { Collector };
