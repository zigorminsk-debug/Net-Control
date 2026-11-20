'use strict';
const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const fs = require('node:fs/promises');
const path = require('node:path');
const { Collector } = require('./collector');
const { testRouter } = require('./router');
const { detectLocalAddress } = require('./local-address');
const { buildReport } = require('./report');
const { parseCidrs } = require('./direction');
const net = require('node:net');
const collector = new Collector();
function createWindow() {
  const window = new BrowserWindow({ width: 1440, height: 920, minWidth: 1000, minHeight: 700, backgroundColor: '#0b1015', title: 'Net Control', webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true } });
  window.loadFile(path.join(__dirname, 'index.html'));
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.webContents.on('will-navigate', event => event.preventDefault());
}
ipcMain.handle('collector:start', (_event, options) => collector.start(options.address, Number(options.port)));
ipcMain.handle('collector:stop', () => { collector.stop(); return collector.snapshot(); });
ipcMain.handle('collector:snapshot', (_event, sort) => collector.snapshot(sort));
ipcMain.handle('collector:host', (_event, ip) => {
  if (typeof ip !== 'string' || !net.isIP(ip)) throw new Error('Некорректный IP-адрес хоста.');
  return collector.analyzer.hostDetail(ip);
});
ipcMain.handle('network:local-address', (_event, router) => detectLocalAddress(router));
ipcMain.handle('network:subnets', () => collector.analyzer.networks.map(n => n.cidr));
ipcMain.handle('network:save-subnets', async (_event, text) => {
  try {
    const entries = parseCidrs(text).map(n => n.cidr);
    await fs.mkdir(app.getPath('userData'), { recursive: true });
    await fs.writeFile(path.join(app.getPath('userData'), 'networks.json'), JSON.stringify({ subnets: entries }), 'utf8');
    collector.analyzer.setNetworks(entries.join('\n'));
    return { ok: true, subnets: entries };
  } catch (err) { return { ok: false, error: err.message }; }
});
ipcMain.handle('collector:clear', () => { collector.analyzer.clear(); return collector.snapshot(); });
ipcMain.handle('report:save', async event => {
  const owner = BrowserWindow.fromWebContents(event.sender);
  if (!owner) return { ok: false, error: 'Окно приложения не найдено.' };
  const result = await dialog.showSaveDialog(owner, { title: 'Сохранить отчёт', defaultPath: `net-control-report-${new Date().toISOString().slice(0, 10)}.html`, filters: [{ name: 'HTML', extensions: ['html'] }] });
  if (result.canceled || !result.filePath) return { ok: false, canceled: true };
  try {
    const now = Date.now();
    const snapshot = { ...collector.state, ...collector.analyzer.snapshot(now) };
    const details = snapshot.hosts.slice(0, 20).map(host => collector.analyzer.hostDetail(host.ip, now));
    await fs.writeFile(result.filePath, buildReport(snapshot, details, now), 'utf8');
    return { ok: true, path: result.filePath };
  } catch (err) { return { ok: false, error: err.message }; }
});
ipcMain.handle('router:test', async (_event, options) => {
  try { return { ok: true, data: await testRouter({ ...options, port: Number(options.port) }) }; }
  catch (err) { return { ok: false, error: err.message }; }
});
app.whenReady().then(async () => {
  try {
    const config = JSON.parse(await fs.readFile(path.join(app.getPath('userData'), 'networks.json'), 'utf8'));
    if (Array.isArray(config.subnets) && config.subnets.every(s => typeof s === 'string')) collector.analyzer.setNetworks(config.subnets.join('\n'));
  } catch (err) { if (err.code !== 'ENOENT') console.error('Cannot load local subnets:', err.message); }
  createWindow();
});
app.on('window-all-closed', () => { collector.stop(); if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
