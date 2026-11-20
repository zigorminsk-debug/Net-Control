'use strict';
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('node:path');
const { Collector } = require('./collector');
const { testRouter } = require('./router');
const collector = new Collector();
function createWindow() {
  const window = new BrowserWindow({ width: 1440, height: 920, minWidth: 1000, minHeight: 700, backgroundColor: '#0b1015', title: 'Net Control', webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true } });
  window.loadFile(path.join(__dirname, 'index.html'));
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.webContents.on('will-navigate', event => event.preventDefault());
}
ipcMain.handle('collector:start', (_event, options) => collector.start(options.address, Number(options.port)));
ipcMain.handle('collector:stop', () => { collector.stop(); return collector.snapshot(); });
ipcMain.handle('collector:snapshot', () => collector.snapshot());
ipcMain.handle('collector:clear', () => { collector.analyzer.clear(); return collector.snapshot(); });
ipcMain.handle('router:test', async (_event, options) => {
  try { return { ok: true, data: await testRouter({ ...options, port: Number(options.port) }) }; }
  catch (err) { return { ok: false, error: err.message }; }
});
app.whenReady().then(createWindow);
app.on('window-all-closed', () => { collector.stop(); if (process.platform !== 'darwin') app.quit(); });
app.on('activate', () => { if (BrowserWindow.getAllWindows().length === 0) createWindow(); });
