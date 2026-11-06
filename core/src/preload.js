const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('argusUpdater', {
  // Core updater functions
  getAutoUpdateServices: () => ipcRenderer.invoke('updater:getAutoUpdateServices'),
  runAutomaticUpdates: () => ipcRenderer.invoke('updater:runAutomaticUpdates'),
  runManualUpdate: (service) => ipcRenderer.invoke('updater:runManualUpdate', service),
  updateAll: () => ipcRenderer.invoke('updater:updateAll'),

  // Optional: listen for live progress logs
  onUpdateLog: (callback) => {
    ipcRenderer.on('updater:log', (_event, message) => callback(message));
  },
});
