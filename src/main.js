/* Refloow Geo Forensics
 * Copyright (C) 2026  Veljko Vuckovic (Refloow) <legal@refloow.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

const { app, BrowserWindow, ipcMain, dialog, session } = require('electron');
const { autoUpdater } = require('electron-updater');
const path = require('path');
const { startServer } = require('./src/server.js');
const { exiftool } = require('exiftool-vendored');

// Prevent automatic downloads
autoUpdater.autoDownload = false

// --- Air-Gapped Mode network policy ---
// The application is built for offline / air-gapped forensic workstations, so
// it starts locked down: no outbound network is permitted until the renderer
// (which owns the persisted setting) explicitly turns Air-Gapped Mode off.
// This is a hard guarantee enforced at the Electron session layer, on top of
// the renderer simply not adding online map layers or requesting updates.
let airGapped = true;

// Requests to the app's own loopback server and to local resources must always
// be allowed — the UI is served from http://localhost:<port> and the bundled
// Leaflet/tiles come through it. Everything else is blocked while air-gapped.
function isLocalRequest(url) {
    if (/^(devtools|file|blob|data|chrome-extension):/i.test(url)) return true;
    try {
        const host = new URL(url).hostname;
        return host === 'localhost' || host === '127.0.0.1' || host === '[::1]' || host === '::1';
    } catch (err) {
        // A URL we can't parse is not a recognizable local request; block it
        return false;
    }
}

function installNetworkGuard() {
    // Blocks any non-local http(s)/ws request whenever Air-Gapped Mode is on.
    // Prevents accidental outbound traffic rather than letting it fail later.
    session.defaultSession.webRequest.onBeforeRequest((details, callback) => {
        if (airGapped && !isLocalRequest(details.url)) {
            console.warn(`[air-gap] blocked outbound request: ${details.url}`);
            return callback({ cancel: true });
        }
        callback({ cancel: false });
    });
}

let mainWindow;
let splashWindow;
let activePort;


// Splash screen
function createWindow() {
    splashWindow = new BrowserWindow({
        width: 450,
        height: 350,
        frame: false,
        backgroundColor: '#121212', 
        center: true,
        show: false, // Don't show until ready to prevent flickering
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
        }
    });

    // Aggressive Always-On-Top for Linux
    splashWindow.setAlwaysOnTop(true, 'screen-saver'); 
    splashWindow.setVisibleOnAllWorkspaces(true);
    splashWindow.loadFile(path.join(__dirname, 'public', 'splash.html'));

    // Show splash screen smoothly once it has loaded the HTML
    splashWindow.once('ready-to-show', () => {
        splashWindow.show();
    });

    // main window
    mainWindow = new BrowserWindow({
        width: 1280,
        height: 800,
        titleBarStyle: 'hidden',
        titleBarOverlay: {
            color: '#181818', 
            symbolColor: '#d0d0d0',
            height: 35 
        },
        title: "GeoForensics",
        show: false,
        backgroundColor: '#121212',
        webPreferences: {
            nodeIntegration: false,
            contextIsolation: true,
            preload: path.join(__dirname, 'preload.js')
        }
    });

    mainWindow.setMenuBarVisibility(false);

    // Intercept target="_blank" links and open them in the user's default browser
    mainWindow.webContents.setWindowOpenHandler(({ url }) => {
        require('electron').shell.openExternal(url);
        return { action: 'deny' };
    });

    mainWindow.loadURL(`http://localhost:${activePort}`);

    mainWindow.webContents.on('did-finish-load', () => {
        setTimeout(() => {
            if (splashWindow && !splashWindow.isDestroyed()) {
                splashWindow.close();
            }
            mainWindow.show();
            mainWindow.focus(); // Focusing main window after splash dissapears
        }, 1200); 
    });
}

// The renderer owns the persisted Air-Gapped Mode setting and pushes it here.
// Until it does, the guard stays on (fail-closed).
ipcMain.on('set-network-policy', (event, isAirGapped) => {
    airGapped = (isAirGapped !== false);
    console.log(`[air-gap] network guard ${airGapped ? 'ARMED (offline)' : 'disarmed (online allowed)'}`);
});

// Listen for the frontend telling us to check for updates
ipcMain.on('check-updates', (event, autoUpdateEnabled) => {
    // Abort the update process if running as a Microsoft Store AppX
    if (process.windowsStore) {
        console.log("Running as a Microsoft Store app. Auto-updates disabled.");
        return;
    }

    // Air-Gapped Mode suppresses update checks entirely, regardless of the
    // separate auto-update setting. The app must never contact GitHub while
    // air-gapped, and must not surface a "couldn't reach GitHub" error for it.
    if (airGapped) {
        console.log("Air-Gapped Mode is on; update checks are suppressed.");
        return;
    }

    if (autoUpdateEnabled === 'true') {
        autoUpdater.checkForUpdates().catch(err => {
            dialog.showErrorBox("Check Promise Error", err.toString());
        });
    }
});

ipcMain.handle('get-app-version', () => {
    return app.getVersion();
});

// Native OS Folder Picker Handler
ipcMain.handle('dialog:openDirectory', async () => {
    const { canceled, filePaths } = await dialog.showOpenDialog({
        title: 'Select Evidence Folder',
        properties: ['openDirectory'] // Restrict to selecting folders
    });
    
    if (canceled) {
        return null; // User clicked "Cancel"
    } else {
        return filePaths[0]; // Returns the path of the selected folder
    }
});

// Native OS file picker for an offline map package (.mbtiles)
ipcMain.handle('dialog:openMbtiles', async () => {
    const { canceled, filePaths } = await dialog.showOpenDialog({
        title: 'Import Offline Map Package',
        properties: ['openFile'],
        filters: [{ name: 'Offline Map (MBTiles)', extensions: ['mbtiles'] }]
    });

    if (canceled || filePaths.length === 0) return null;
    return filePaths[0];
});

/*
// Tells if GitHub was checked but no update was found
autoUpdater.on('update-not-available', (info) => {
    dialog.showMessageBox({ 
        type: 'info', 
        title: 'Debug: No Update Found', 
        message: `GitHub was checked, but no update was found. Local version: ${app.getVersion()}. Cloud version: ${info.version}` 
    });
});
*/

// Tells if there is a hash mismatch or network failure. Never shown while
// air-gapped: an offline machine cannot reach GitHub by design, and that is
// not an error the examiner should see.
autoUpdater.on('error', (err) => {
    if (airGapped) return;
    dialog.showErrorBox("Updater Error", "An error occurred:\n" + err.toString());
});

// ---------------------------

// Update Available - Ask User to Upgrade
autoUpdater.on('update-available', async (info) => {
    const { response } = await dialog.showMessageBox({
        type: 'info',
        title: 'Update Available',
        message: `Version ${info.version} of GeoForensics is available. Would you like to download and install it?`,
        buttons: ['Yes, Upgrade', 'No, Cancel']
    });

    if (response === 0) { // User clicked 'Yes'
        autoUpdater.downloadUpdate();
    }
});

// Update Downloaded - Ask User to Restart
autoUpdater.on('update-downloaded', async () => {
    const { response } = await dialog.showMessageBox({
        type: 'info',
        title: 'Update Ready',
        message: 'The update has been downloaded. Restart the application to apply the changes?',
        buttons: ['Restart Now', 'Later']
    });

    if (response === 0) {
        // Parameter 1: isSilent = true (Runs the installer in the background without the wizard)
        // Parameter 2: isForceRunAfter = true (Automatically re-opens the app when finished)
        autoUpdater.quitAndInstall(true, true);
    }
});
app.whenReady().then(async () => {
    try {
        installNetworkGuard(); // Arm the air-gap guard before any window can load
        activePort = await startServer(3000);
        createWindow();
    } catch (error) {
        console.error("Failed to start GeoForensics server:", error);
    }

    app.on('activate', function () {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

app.on('window-all-closed', function () {
    if (process.platform !== 'darwin') app.quit();
});

// THE KILL SWITCH: Before the app fully quits, safely terminate the ExifTool background process
app.on('before-quit', async () => {
    try {
        await exiftool.end();
        console.log("ExifTool background process terminated securely.");
    } catch (err) {
        console.error("Error shutting down ExifTool:", err);
    }
});

/* Refloow Geo Forensics
 * Copyright (C) 2026  Veljko Vuckovic (Refloow) <legal@refloow.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.

 */

