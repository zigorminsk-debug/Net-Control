'use strict';
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('netControl', {
  start: options => ipcRenderer.invoke('collector:start', options),
  stop: () => ipcRenderer.invoke('collector:stop'),
  snapshot: () => ipcRenderer.invoke('collector:snapshot'),
  clear: () => ipcRenderer.invoke('collector:clear'),
  testRouter: options => ipcRenderer.invoke('router:test', options)
});
