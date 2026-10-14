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
const crypto = require('crypto');
const apiRoutes = require('./routes/api');
const { countFiles } = require('../src/utils/scanner');

const app = express();
const PORT = 3000;

// --- Local API token ---
// The server only ever binds to loopback, but loopback is shared with every
// other process on the workstation. When the desktop app starts it generates
// a random per-launch token, hands it to its own renderer through the preload
// bridge, and configures it here; from then on every /api request must carry
// it (Authorization: Bearer <token>, or ?token= for <img>, EventSource and
// map tiles, which cannot set headers). Another local process or browser tab
// cannot obtain the token, so it cannot trigger scans or read evidence files.
// With no token configured (plain `node src/server.js` for development, and
// the test suite) the API behaves as before.
let apiToken = null;

function setApiToken(token) {
    apiToken = typeof token === 'string' && token.length > 0 ? token : null;
}

function tokenMatches(presented) {
    if (typeof presented !== 'string') return false;
    const a = Buffer.from(presented);
    const b = Buffer.from(apiToken);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function requireApiToken(req, res, next) {
    if (!apiToken) return next();
    const header = req.get('authorization') || '';
    const bearer = header.startsWith('Bearer ') ? header.slice(7) : null;
    const presented = bearer != null ? bearer : (typeof req.query.token === 'string' ? req.query.token : null);
    if (presented != null && tokenMatches(presented)) return next();
    res.status(401).json({ success: false, error: 'Missing or invalid local API token' });
}

// --- Security headers ---
// Content Security Policy for the app's own pages: scripts, styles, media and
// API calls only from the loopback origin; images additionally from the six
// known online basemap hosts (which Air-Gapped Mode blocks at the network
// layer anyway). This is defence in depth: even if an injected metadata
// string ever escaped HTML escaping, it could not load or send anything to an
// arbitrary host. 'unsafe-inline' is required by the current single-file UI.
const CONTENT_SECURITY_POLICY = [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: https://*.basemaps.cartocdn.com https://server.arcgisonline.com https://*.tile.opentopomap.org https://*.tile.openstreetmap.fr https://tile.openstreetmap.org",
    "media-src 'self'",
    "connect-src 'self'",
    "font-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
].join('; ');

app.use((req, res, next) => {
    res.set('Content-Security-Policy', CONTENT_SECURITY_POLICY);
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Referrer-Policy', 'no-referrer');
    res.set('Cache-Control', 'no-store');
    next();
});

app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// Serve Leaflet from the bundled npm package instead of a CDN, so the UI
// loads with no internet connection (evidence work is often offline)
app.use('/vendor/leaflet', express.static(path.join(__dirname, '../node_modules/leaflet/dist')));

app.use('/api', requireApiToken);
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

// start the server dynamically. options.apiToken: the per-launch token the
// desktop app requires on every /api request (see setApiToken above).
function startServer(port = 3000, options = {}) {
    if (options.apiToken) setApiToken(options.apiToken);
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
                resolve(startServer(port + 1, options));
            } else {
                reject(err);
            }
        });
    });
}

// app is exported so the test suite can bind it to an ephemeral port
module.exports = { startServer, app, setApiToken, CONTENT_SECURITY_POLICY };

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
