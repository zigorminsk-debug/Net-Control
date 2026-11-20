'use strict';
const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const fs = require('node:fs/promises');
const path = require('node:path');
const { Collector } = require('./collector');
const { testRouter } = require('./router');
const { detectLocalAddress } = require('./local-address');
const { buildReport } = require('./report');
const { parseCidrs } = require('./direction');
const { createUpdateController } = require('./updater');
const net = require('node:net');
const collector = new Collector();
let updates;
function createWindow() {
  const window = new BrowserWindow({ width: 1440, height: 920, minWidth: 1000, minHeight: 700, backgroundColor: '#0b1015', title: 'Net Control', webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true } });
  window.loadFile(path.join(__dirname, 'index.html'));
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.webContents.on('will-navigate', event => event.preventDefault());
}
ipcMain.handle('updates:status', () => updates.status());
ipcMain.handle('updates:check', () => updates.check());
ipcMain.handle('updates:install', async event => {
  const state = updates.status();
  if (state.status !== 'downloaded') return { ok: false, error: 'Обновление ещё не загружено.' };
  const owner = BrowserWindow.fromWebContents(event.sender);
  if (!owner) return { ok: false, error: 'Окно приложения не найдено.' };
  const result = await dialog.showMessageBox(owner, {
    type: 'warning', title: 'Установка обновления', buttons: ['Отмена', 'Установить'], defaultId: 0, cancelId: 0,
    message: `Установить Net Control ${state.availableVersion}?`,
    detail: 'Приложение закроется и перезапустится. Текущие потоки из памяти будут потеряны. Установщик не подписан цифровой подписью: устанавливайте обновление только если доверяете этому GitHub-репозиторию.'
  });
  if (result.response !== 1) return { ok: false, canceled: true };
  try { return updates.install() ? { ok: true } : { ok: false, error: 'Обновление больше не готово к установке.' }; }
  catch (err) { return { ok: false, error: err.message }; }
});
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
  const { autoUpdater } = require('electron-updater');
  updates = createUpdateController({ updater: autoUpdater, packaged: app.isPackaged, platform: process.platform, version: app.getVersion() });
  createWindow();
  if (app.isPackaged && process.platform === 'win32') {
    setTimeout(() => updates.check(), 10000);
    setInterval(() => updates.check(), 6 * 60 * 60 * 1000);
  }
});
app.on('window-all-closed', () => { collector.stop(); if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
