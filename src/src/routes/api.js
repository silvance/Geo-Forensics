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
