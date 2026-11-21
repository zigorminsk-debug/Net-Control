'use strict';
const dgram = require('node:dgram');
const { FlowParser } = require('./flow');
const { Analyzer } = require('./analyzer');
const { validateAddress } = require('./router');
class Collector {
  constructor() { this.onFlows = null; this.socket = null; this.parser = new FlowParser(); this.analyzer = new Analyzer(); this.state = { running: false, address: '', port: 2055, datagrams: 0, lastPacket: null, rejected: 0, parseErrors: 0, error: '' }; }
  async start(address, port, extraExporters = []) {
    if (!validateAddress(address) || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Укажите IPv4 роутера и UDP-порт от 1 до 65535.');
    if (!Array.isArray(extraExporters) || extraExporters.length > 15 || extraExporters.some(ip => !validateAddress(ip))) throw new Error('Укажите до 15 дополнительных IPv4-адресов роутеров.');
    const exporters = [...new Set([address, ...extraExporters])];
    this.stop(); this.parser = new FlowParser(); this.analyzer.clear();
    this.state = { running: false, address, port, datagrams: 0, lastPacket: null, rejected: 0, parseErrors: 0, error: '' };
    this.state.startedAt = Date.now();
    this.state.sources = Object.fromEntries(exporters.map(ip => [ip, {datagrams:0, lastPacket:null, flows:0}]));
    const socket = dgram.createSocket('udp4'); this.socket = socket;
    socket.on('message', (msg, remote) => {
      if (!Object.hasOwn(this.state.sources, remote.address)) { this.state.rejected++; return; }
      this.state.datagrams++; this.state.lastPacket = Date.now();
      const source = this.state.sources[remote.address]; source.datagrams++; source.lastPacket = this.state.lastPacket;
      try { const now = Date.now(); const flows = this.parser.parse(msg, remote.address).map(flow => ({...flow, exporter:remote.address})); source.flows += flows.length; this.analyzer.add(flows, now); if (this.onFlows) this.onFlows(flows, now); } catch { this.state.parseErrors++; }
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
  snapshot(sort) { return { ...this.state, diagnostics: { ...this.parser.stats, templates: this.parser.templates.size }, ...this.analyzer.snapshot(Date.now(), sort) }; }
}
module.exports = { Collector };
