'use strict';
const { contextBridge, ipcRenderer } = require('electron');
contextBridge.exposeInMainWorld('netControl', {
  updateStatus: () => ipcRenderer.invoke('updates:status'),
  checkUpdates: () => ipcRenderer.invoke('updates:check'),
  installUpdate: () => ipcRenderer.invoke('updates:install'),
  start: options => ipcRenderer.invoke('collector:start', options),
  stop: () => ipcRenderer.invoke('collector:stop'),
  snapshot: sort => ipcRenderer.invoke('collector:snapshot', sort),
  saveReport: () => ipcRenderer.invoke('report:save'),
  reputation: () => ipcRenderer.invoke('reputation:status'),
  refreshReputation: () => ipcRenderer.invoke('reputation:refresh'),
  enableReputation: enabled => ipcRenderer.invoke('reputation:enabled', enabled),
  clearReputation: () => ipcRenderer.invoke('reputation:clear'),
  securityDetail: id => ipcRenderer.invoke('collector:security-detail', id),
  history: () => ipcRenderer.invoke('history:summary'),
  enableHistory: enabled => ipcRenderer.invoke('history:enabled', enabled),
  clearHistory: () => ipcRenderer.invoke('history:clear'),
  category: id => ipcRenderer.invoke('collector:category', id),
  policy: () => ipcRenderer.invoke('security:policy'),
  savePolicy: policy => ipcRenderer.invoke('security:save-policy', policy),
  host: ip => ipcRenderer.invoke('collector:host', ip),
  localAddress: router => ipcRenderer.invoke('network:local-address', router),
  subnets: () => ipcRenderer.invoke('network:subnets'),
  saveSubnets: text => ipcRenderer.invoke('network:save-subnets', text),
  clear: () => ipcRenderer.invoke('collector:clear'),
  readLeases: options => ipcRenderer.invoke('router:leases', options),
  testRouter: options => ipcRenderer.invoke('router:test', options)
});
