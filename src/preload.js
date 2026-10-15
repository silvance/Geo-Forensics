// src/preload.js
const { contextBridge, ipcRenderer } = require('electron');

// The per-launch local API token, fetched synchronously so it is available
// to the very first page script. It never leaves the renderer except as a
// credential on requests to the app's own loopback server.
const apiToken = ipcRenderer.sendSync('get-api-token');

contextBridge.exposeInMainWorld('electronAPI', {
    getApiToken: () => apiToken,
    triggerUpdateCheck: (isAutoUpdateEnabled) => ipcRenderer.send('check-updates', isAutoUpdateEnabled),
    setNetworkPolicy: (isAirGapped) => ipcRenderer.send('set-network-policy', isAirGapped),
    getAppVersion: () => ipcRenderer.invoke('get-app-version'),
    getPlatform: () => process.platform,
    selectFolder: () => ipcRenderer.invoke('dialog:openDirectory'),
    selectMbtiles: () => ipcRenderer.invoke('dialog:openMbtiles')
});
