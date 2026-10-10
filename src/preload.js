const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('mcpGuard', {
  version: process.versions.electron,
  onUpdateStatus: (callback) => {
    const listener = (_event, status) => callback(status);
    ipcRenderer.on('update:status', listener);
    return () => ipcRenderer.removeListener('update:status', listener);
  },
  listDevices: () => ipcRenderer.invoke('adb:list-devices'),
  getDeviceInfo: (serial) => ipcRenderer.invoke('adb:device-info', serial),
  scanDevice: (serial, device) => ipcRenderer.invoke('scan:run', serial, device),
  uninstallPackages: (serial, packages) =>
    ipcRenderer.invoke('adb:uninstall-many', serial, packages),
  onUninstallProgress: (callback) => {
    const listener = (_event, entry) => callback(entry);
    ipcRenderer.on('uninstall:progress', listener);
    return () => ipcRenderer.removeListener('uninstall:progress', listener);
  },
  getConfig: () => ipcRenderer.invoke('config:get'),
  setConfig: (patch) => ipcRenderer.invoke('config:set', patch),
  checkBackend: () => ipcRenderer.invoke('backend:check'),
  pairBackend: (code) => ipcRenderer.invoke('backend:pair', code),
  tidyFind: (serial, userPackages) => ipcRenderer.invoke('tidy:find', serial, userPackages),
  tidyApply: (serial, items) => ipcRenderer.invoke('tidy:apply', serial, items),
  tidyJournal: () => ipcRenderer.invoke('tidy:journal'),
  tidyUndo: (serial, ts) => ipcRenderer.invoke('tidy:undo', serial, ts),
  rulesInfo: () => ipcRenderer.invoke('rules:info'),
  onScanProgress: (callback) => {
    const listener = (_event, progress) => callback(progress);
    ipcRenderer.on('scan:progress', listener);
    return () => ipcRenderer.removeListener('scan:progress', listener);
  },
});
