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

const fs = require('fs');
const path = require('path');
const express = require('express');
const router = express.Router();
const { scanDirectory, isServableFile } = require('../utils/scanner');
const mbtiles = require('../utils/mbtiles');


router.post('/scan', async (req, res) => {
    const { folderPath } = req.body;

    console.log(`[ANALYZE] Request for folder: ${folderPath}`);

    try {
        const { results, stats } = await scanDirectory(folderPath);
        res.json({ success: true, data: results, stats: stats });
    } catch (error) {
        console.error("Error:", error.message);
        res.status(400).json({ success: false, error: error.message });
    }
});

// Scans currently streaming over /scan-stream, keyed by the client-generated
// id, so /scan-cancel can abort them mid-flight
const activeScans = new Map();

// Streaming variant of /scan: emits live "progress" events over Server-Sent
// Events while the scan runs, then a final "done" (or "scan-error") event
router.get('/scan-stream', async (req, res) => {
    const folderPath = req.query.path;
    const scanId = req.query.id;

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    const send = (event, payload) => {
        res.write(`event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`);
    };

    if (typeof folderPath !== 'string' || folderPath.trim() === '') {
        send('scan-error', { error: 'No path provided' });
        res.end();
        return;
    }

    console.log(`[ANALYZE] Streaming scan for folder: ${folderPath}`);

    const controller = new AbortController();
    if (typeof scanId === 'string' && scanId) activeScans.set(scanId, controller);

    // Abort the scan if the app window disappears mid-scan
    req.on('close', () => controller.abort());

    try {
        // Progress events are throttled so huge folders don't flood the stream
        let lastSent = 0;
        const { results, stats } = await scanDirectory(folderPath, {
            signal: controller.signal,
            onProgress: (processed, total) => {
                const now = Date.now();
                if (processed === total || now - lastSent >= 100) {
                    lastSent = now;
                    send('progress', { processed, total });
                }
            }
        });
        send('done', { data: results, stats: stats });
    } catch (error) {
        console.error("Error:", error.message);
        send('scan-error', { error: error.message });
    } finally {
        if (typeof scanId === 'string' && scanId) activeScans.delete(scanId);
        res.end();
    }
});

// Cancels a running streaming scan; its partial results still arrive
// through the open event stream, flagged with stats.aborted
router.post('/scan-cancel', (req, res) => {
    const { scanId } = req.body;
    const controller = scanId ? activeScans.get(scanId) : undefined;

    if (controller) {
        controller.abort();
        res.json({ success: true });
    } else {
        res.status(404).json({ success: false, error: 'No active scan with that id' });
    }
});

// Endpoint to safely serve local images to the frontend
router.get('/image', (req, res) => {
    const imagePath = req.query.path;

    // Only serve files discovered by the current scan, so this endpoint
    // can never be used to read arbitrary files from disk
    if (typeof imagePath === 'string' && isServableFile(imagePath) && fs.existsSync(imagePath)) {
        res.sendFile(path.resolve(imagePath));
    } else {
        res.status(404).send('Image not found');
    }
});

// --- Offline map (MBTiles) endpoints ---
// All tile serving happens here on the loopback server; the renderer never
// reads the .mbtiles file directly.

// Import / activate an offline map by path. The path comes from the native
// file picker in the desktop app. The file is validated (read-only) before use.
router.post('/offline-map', (req, res) => {
    const { path: mapPath } = req.body || {};
    try {
        const meta = mbtiles.setActiveMap(mapPath);
        res.json({ success: true, meta });
    } catch (error) {
        res.status(400).json({ success: false, error: error.message });
    }
});

// Current active offline map metadata, or null.
router.get('/offline-map', (req, res) => {
    res.json({ success: true, meta: mbtiles.getActiveMap() });
});

// Deactivate the offline map.
router.delete('/offline-map', (req, res) => {
    mbtiles.clearActiveMap();
    res.json({ success: true });
});

// Serve one raster tile. z/x/y are parsed as integers and validated in
// mbtiles.getTile (which rejects anything non-integer or out of range);
// missing tiles return 404. The trailing extension, if any, is ignored.
router.get('/tiles/:z/:x/:y', (req, res) => {
    const z = parseInt(req.params.z, 10);
    const x = parseInt(req.params.x, 10);
    const y = parseInt(String(req.params.y).replace(/\.\w+$/, ''), 10); // strip .png etc.
    const tile = mbtiles.getTile(z, x, y);
    if (!tile) {
        return res.status(404).send('Tile not found');
    }
    res.set('Content-Type', tile.contentType);
    res.set('Cache-Control', 'no-store');
    res.send(tile.data);
});

module.exports = router;

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
