// src/preload.js
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
    triggerUpdateCheck: (isAutoUpdateEnabled) => ipcRenderer.send('check-updates', isAutoUpdateEnabled),
    setNetworkPolicy: (isAirGapped) => ipcRenderer.send('set-network-policy', isAirGapped),
    getAppVersion: () => ipcRenderer.invoke('get-app-version'),
    getPlatform: () => process.platform,
    selectFolder: () => ipcRenderer.invoke('dialog:openDirectory'),
    selectMbtiles: () => ipcRenderer.invoke('dialog:openMbtiles')
});
