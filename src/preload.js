'use strict';
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('netControl', {
  start: options => ipcRenderer.invoke('collector:start', options),
  stop: () => ipcRenderer.invoke('collector:stop'),
  snapshot: sort => ipcRenderer.invoke('collector:snapshot', sort),
  saveReport: () => ipcRenderer.invoke('report:save'),
  host: ip => ipcRenderer.invoke('collector:host', ip),
  localAddress: router => ipcRenderer.invoke('network:local-address', router),
  subnets: () => ipcRenderer.invoke('network:subnets'),
  saveSubnets: text => ipcRenderer.invoke('network:save-subnets', text),
  clear: () => ipcRenderer.invoke('collector:clear'),
  testRouter: options => ipcRenderer.invoke('router:test', options)
});
