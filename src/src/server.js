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


const express = require('express');
const path = require('path');
const apiRoutes = require('./routes/api');
const { countFiles } = require('../src/utils/scanner');

const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// Serve Leaflet from the bundled npm package instead of a CDN, so the UI
// loads with no internet connection (evidence work is often offline)
app.use('/vendor/leaflet', express.static(path.join(__dirname, '../node_modules/leaflet/dist')));

app.use('/api', apiRoutes);

app.post('/api/estimate', async (req, res) => {
    try {
        const { folderPath } = req.body;
        if (!folderPath) {
            return res.status(400).json({ success: false, error: 'No path provided' });
        }
        
        const count = await countFiles(folderPath);
        res.json({ success: true, count });
    } catch (error) {
        res.status(500).json({ success: false, error: error.message });
    }
});

// start the server dynamically
function startServer(port = 3000) {
    return new Promise((resolve, reject) => {
        // Bind to loopback only: this API can list evidence folders and serve
        // scanned files, so it must never be reachable from other machines
        const server = app.listen(port, '127.0.0.1');

        server.once('listening', () => {
            // server.address() is only set once the bind truly succeeded,
            // which keeps a failed bind from resolving with the wrong port
            const address = server.address();
            if (!address) return;

            console.log(`=========================================`);
            console.log(`GeoForensics has started!`);
            console.log(`Open in browser: http://localhost:${address.port}`);
            console.log(`=========================================`);
            resolve(address.port); // Returning successful port
        });

        // Listen for errors (ports already in use)
        server.once('error', (err) => {
            if (err.code === 'EADDRINUSE') {
                console.log(`Port ${port} is in use, trying ${port + 1}...`);
                // Waiting for the next port check to resolve and pass that port up
                resolve(startServer(port + 1));
            } else {
                reject(err);
            }
        });
    });
}

// app is exported so the test suite can bind it to an ephemeral port
module.exports = { startServer, app };

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
