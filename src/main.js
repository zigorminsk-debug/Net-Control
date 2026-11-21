'use strict';
const { app, BrowserWindow, ipcMain, dialog, Notification, Menu } = require('electron');
const fs = require('node:fs/promises');
const path = require('node:path');
const { Collector } = require('./collector');
const { testRouter, readLeases, inspectTrafficFlow } = require('./router');
const { detectLocalAddress } = require('./local-address');
const { buildReport } = require('./report');
const { parseCidrs } = require('./direction');
const { createUpdateController } = require('./updater');
const { History } = require('./history');
const { validatePolicy } = require('./security');
const { ReputationStore } = require('./reputation');
const { WorkspaceSettings } = require('./workspace-settings');
const { NotificationTracker } = require('./notifications');
const { createMenuTemplate } = require('./application-menu');
const net = require('node:net');
const collector = new Collector();
let updates;
let history;
let reputation;
let workspaceSettings;
const notificationTracker = new NotificationTracker();
let reputationError = '';
let historyError = '';
let leases = new Map();
let leasesFetchedAt = 0;
let leasesRouter = '';
function deviceFor(ip, now = Date.now()) {
  if (Object.keys(collector.state.sources || {}).length > 1 || !leasesFetchedAt || leasesRouter !== collector.state.address || now - leasesFetchedAt > 5 * 60000) return null;
  const entry = leases.get(ip); return entry ? { ...entry, observedAt: leasesFetchedAt } : null;
}
let mainWindow = null;
function sendMenuAction(action) {
  const window = mainWindow;
  if (!window || window.isDestroyed()) return;
  const send = () => { if (!window.isDestroyed()) window.webContents.send('menu:action', action); };
  // A menu item can be clicked while the renderer is loading.
  if (window.webContents.isLoadingMainFrame()) window.webContents.once('did-finish-load', send);
  else send();
}
function createWindow() {
  const window = new BrowserWindow({ width: 1440, height: 920, minWidth: 1000, minHeight: 700, backgroundColor: '#0b1015', title: 'Net Control', webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true } });
  mainWindow = window;
  window.on('closed', () => { if (mainWindow === window) mainWindow = null; });
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
ipcMain.handle('collector:start', (_event, options) => collector.start(options.address, Number(options.port), options.exporters || []));
ipcMain.handle('collector:stop', () => { collector.stop(); return collector.snapshot(); });
ipcMain.handle('collector:snapshot', (_event, sort) => {
  collector.analyzer.baselines = history.enabled ? history.baselines() : new Map();
  const snapshot = collector.snapshot(sort);
  for (const alert of snapshot.alerts) alert.device = deviceFor(alert.ip);
  if (snapshot.running) history.capture(snapshot.alerts);
  return snapshot;
});
ipcMain.handle('collector:security-detail', (_event, id) => collector.analyzer.securityDetail(id));
ipcMain.handle('collector:search', (_event, filter) => collector.analyzer.search(filter));
ipcMain.handle('collector:export', async (event, filter, format) => {
  if (!['csv','json'].includes(format)) return { ok:false, error:'Неизвестный формат.' };
  const owner = BrowserWindow.fromWebContents(event.sender);
  if (!owner) return { ok:false, error:'Окно приложения не найдено.' };
  try {
    const result = collector.analyzer.search(filter, Date.now(), 50000);
    const dialogResult = await dialog.showSaveDialog(owner, { title:'Экспорт отфильтрованных потоков', defaultPath:`net-control-flows.${format}`, filters:[{name:format.toUpperCase(), extensions:[format]}] });
    if (dialogResult.canceled || !dialogResult.filePath) return { ok:false, canceled:true };
    const data = format === 'json' ? JSON.stringify({ exportedAt:new Date().toISOString(), window:'5 minutes; reception time', filter, total:result.total, records:result.records }, null, 2) : require('./flow-export').toCsv(result.records);
    await fs.writeFile(dialogResult.filePath, data, 'utf8');
    return { ok:true, count:result.total, path:dialogResult.filePath };
  } catch (err) { return { ok:false, error:err.message }; }
});
ipcMain.handle('collector:category', (_event, id) => collector.analyzer.categoryDetail(id));
ipcMain.handle('collector:host', (_event, ip) => {
  if (typeof ip !== 'string' || !net.isIP(ip)) throw new Error('Некорректный IP-адрес хоста.');
  return { ...collector.analyzer.hostDetail(ip), device: deviceFor(ip) };
});
ipcMain.handle('workspace:device', (_event, ip) => workspaceSettings.device(ip));
ipcMain.handle('workspace:save-device', (_event, ip, data) => workspaceSettings.saveDevice(ip, data));
ipcMain.handle('workspace:review', (_event, type, ip) => workspaceSettings.review(type, ip));
ipcMain.handle('workspace:save-review', (_event, type, ip, data) => workspaceSettings.saveReview(type, ip, data));
ipcMain.handle('workspace:notifications', () => ({...workspaceSettings.data.notifications, supported:Notification.isSupported()}));
ipcMain.handle('workspace:save-notifications', (_event, data) => workspaceSettings.setNotifications(data));
ipcMain.handle('network:local-address', (_event, router) => detectLocalAddress(router));
ipcMain.handle('reputation:status', () => ({ ...reputation.status(), error:reputationError }));
ipcMain.handle('reputation:refresh', async () => {
  try { const result = await reputation.refresh(); reputationError = ''; return {ok:true, ...result}; }
  catch (err) { reputationError = err.message; return {ok:false, error:err.message}; }
});
ipcMain.handle('reputation:enabled', (_event, enabled) => {
  try { reputation.setEnabled(enabled); reputationError = ''; if (enabled) void reputation.refreshIfDue().catch(err => { reputationError = err.message; }); return {ok:true}; }
  catch (err) { reputationError = err.message; return {ok:false, error:err.message}; }
});
ipcMain.handle('reputation:clear', () => {
  try { reputation.clear(); reputationError = ''; return {ok:true}; }
  catch (err) { reputationError = err.message; return {ok:false, error:err.message}; }
});
ipcMain.handle('security:policy', () => ({ ...collector.analyzer.policy }));
ipcMain.handle('security:save-policy', async (_event, raw) => {
  try {
    const policy = validatePolicy(raw);
    await fs.writeFile(path.join(app.getPath('userData'), 'security-policy.json'), JSON.stringify(policy), 'utf8');
    collector.analyzer.setPolicy(policy);
    return { ok:true, policy };
  } catch (err) { return { ok:false, error:err.message }; }
});
ipcMain.handle('history:host-bindings', (_event, ip) => history.hostBindings(ip));
ipcMain.handle('history:host-days', (_event, ip) => history.hostDays(ip));
ipcMain.handle('history:summary', () => ({ ...history.summary(), error:historyError }));
ipcMain.handle('history:retention', (_event, days) => {
  try { history.setRetentionDays(Number(days)); history.flush(); historyError=''; return {ok:true}; } catch (err) { historyError=err.message; return {ok:false,error:err.message}; }
});
ipcMain.handle('history:enabled', (_event, enabled) => {
  try { if (typeof enabled !== 'boolean') throw new Error('Некорректный параметр.'); history.setEnabled(enabled); history.flush(); historyError = ''; return {ok:true}; }
  catch (err) { historyError = err.message; return {ok:false, error:err.message}; }
});
ipcMain.handle('history:clear', () => {
  try { history.clear(); history.flush(); historyError = ''; return {ok:true}; }
  catch (err) { historyError = err.message; return {ok:false, error:err.message}; }
});
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
    collector.analyzer.baselines = history.enabled ? history.baselines(now) : new Map();
    const snapshot = { ...collector.state, ...collector.analyzer.snapshot(now), history: history.summary(now), reputation: reputation.status(now) };
    const details = snapshot.hosts.slice(0, 20).map(host => collector.analyzer.hostDetail(host.ip, now));
    await fs.writeFile(result.filePath, buildReport(snapshot, details, now), 'utf8');
    return { ok: true, path: result.filePath };
  } catch (err) { return { ok: false, error: err.message }; }
});
ipcMain.handle('router:leases', async (_event, options) => {
  leases = new Map(); leasesFetchedAt = 0; leasesRouter = '';
  try {
    const items = await readLeases({ ...options, port: Number(options.port) });
    leases = new Map(items.map(item => [item.ip, item])); leasesFetchedAt = Date.now(); leasesRouter = options.address;
    history.captureLeases(options.address, items, leasesFetchedAt);
    return { ok:true, count:items.length, observedAt:leasesFetchedAt };
  } catch (err) { return { ok:false, error:err.message }; }
});
ipcMain.handle('router:inspect-flow', async (_event, options) => {
  try { return {ok:true, data:await inspectTrafficFlow({...options, port:Number(options.port)})}; }
  catch (err) { return {ok:false, error:err.message}; }
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
  try {
    const policy = JSON.parse(await fs.readFile(path.join(app.getPath('userData'), 'security-policy.json'), 'utf8'));
    collector.analyzer.setPolicy(policy);
  } catch (err) { if (err.code !== 'ENOENT') console.error('Cannot load security policy:', err.message); }
  workspaceSettings = new WorkspaceSettings(path.join(app.getPath('userData'), 'workspace-settings.json'));
  try { workspaceSettings.load(); } catch (err) { console.error('Cannot load workspace settings:', err.message); }
  setInterval(() => {
    try {
      const options = workspaceSettings.data.notifications;
      if (!options.enabled || !Notification.isSupported()) { notificationTracker.tick({running:false},options); return; }
      for (const msg of notificationTracker.tick(collector.snapshot(),options)) new Notification(msg).show();
    } catch (err) { console.error('Notification error:', err.message); }
  }, 10000);
  reputation = new ReputationStore(path.join(app.getPath('userData'), 'reputation-cache.json'));
  try { reputation.load(); } catch (err) { reputationError = `Не удалось прочитать кэш: ${err.message}`; }
  collector.analyzer.reputation = reputation;
  const refreshReputation = async () => { try { await reputation.refreshIfDue(); } catch (err) { reputationError = `Не удалось сохранить базу: ${err.message}`; } };
  setTimeout(refreshReputation, 15000); setInterval(refreshReputation, 60 * 60 * 1000);
  history = new History(path.join(app.getPath('userData'), 'security-history.json'));
  try { history.load(); } catch (err) { historyError = `Не удалось прочитать историю: ${err.message}`; }
  collector.onFlows = (flows, now) => { try { history.ingest(flows, collector.analyzer.networks, now); } catch (err) { historyError = `Не удалось обработать историю: ${err.message}`; } };
  setInterval(() => { try { history.prune(); if (history.dirty) { history.flush(); historyError = ''; } } catch (err) { historyError = `Не удалось сохранить историю: ${err.message}`; } }, 30000);
  const { autoUpdater } = require('electron-updater');
  updates = createUpdateController({ updater: autoUpdater, packaged: app.isPackaged, platform: process.platform, version: app.getVersion() });
  Menu.setApplicationMenu(Menu.buildFromTemplate(createMenuTemplate(sendMenuAction, () => {
    if (!mainWindow || mainWindow.isDestroyed()) return;
    if (mainWindow.isMaximized()) mainWindow.unmaximize(); else mainWindow.maximize();
  })));
  createWindow();
  if (app.isPackaged && process.platform === 'win32') {
    setTimeout(() => updates.check(), 10000);
    setInterval(() => updates.check(), 6 * 60 * 60 * 1000);
  }
});
app.on('before-quit', () => { if (history) { try { history.flush(); } catch (err) { console.error('Cannot save history:', err.message); } } });
app.on('window-all-closed', () => { collector.stop(); if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
