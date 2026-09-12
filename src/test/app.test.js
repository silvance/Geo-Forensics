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

// End-to-end tests for the scanning engine and the local HTTP API.
// Run with: npm test  (uses the Node.js built-in test runner, no extra deps)

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const { exiftool } = require('exiftool-vendored');
const { scanDirectory, countFiles, isServableFile } = require('../src/utils/scanner');
const mbtiles = require('../src/utils/mbtiles');
const { app } = require('../src/server');

// A 1x1 red PNG used to fill test map tiles
const RED_PNG = Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64');

// Writes a small valid raster MBTiles (bounds ~19-21E/44-46N, zoom 0-4) with a
// tile at XYZ z2/x2/y1 (stored TMS-flipped) for tile-serving tests.
function writeTestMbtiles(filePath) {
    const db = new DatabaseSync(filePath);
    db.exec('CREATE TABLE metadata (name text, value text); CREATE TABLE tiles (zoom_level integer, tile_column integer, tile_row integer, tile_data blob);');
    for (const [k, v] of [['name', 'Test Region'], ['format', 'png'], ['bounds', '19.0,44.0,21.0,46.0'], ['minzoom', '0'], ['maxzoom', '4']]) {
        db.prepare('INSERT INTO metadata VALUES (?, ?)').run(k, v);
    }
    // XYZ y=1 at z=2 -> TMS row = (2^2 - 1) - 1 = 2
    db.prepare('INSERT INTO tiles VALUES (?, ?, ?, ?)').run(2, 2, 2, RED_PNG);
    db.close();
}

// Minimal valid 1x1 JPEG used as the base for all fixtures
const TINY_JPEG = Buffer.from(
    '/9j/4AAQSkZJRgABAQEAYABgAAD/2wBDAAgGBgcGBQgHBwcJCQgKDBQNDAsLDBkSEw8UHRofHh0a' +
    'HBwgJC4nICIsIxwcKDcpLDAxNDQ0Hyc5PTgyPC4zNDL/wAALCAABAAEBAREA/8QAFAABAAAAAAAA' +
    'AAAAAAAAAAAACf/EABQQAQAAAAAAAAAAAAAAAAAAAAD/2gAIAQEAAD8AVN//2Q==', 'base64');

let tmpDir;        // Evidence folder with fixtures
let subDir;        // Nested folder inside it
let gpsFile;       // JPEG with GPS + timestamp + device + altitude
let nestedGpsFile; // JPEG with GPS inside the nested folder
let equatorFile;   // JPEG at latitude 0 (valid coordinate, must not be dropped)
let plainFile;     // JPEG with no GPS data
let mbtilesDir;    // Temp dir holding the MBTiles fixture (outside the scan)
let mbtilesPath;   // Valid MBTiles map package
let server;        // HTTP server bound to an ephemeral port
let baseUrl;

async function writeFixture(filePath, tags) {
    fs.writeFileSync(filePath, TINY_JPEG);
    if (tags) {
        await exiftool.write(filePath, tags);
        // ExifTool leaves a "<name>_original" backup next to the file
        fs.rmSync(filePath + '_original', { force: true });
    }
}

before(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'geo-forensics-test-'));
    subDir = path.join(tmpDir, 'subdir');
    fs.mkdirSync(subDir);

    gpsFile = path.join(tmpDir, 'belgrade.jpg');
    nestedGpsFile = path.join(subDir, 'nested.jpg');
    equatorFile = path.join(tmpDir, 'equator.jpg');
    plainFile = path.join(tmpDir, 'plain.jpg');

    await writeFixture(gpsFile, {
        GPSLatitude: 44.8125, GPSLongitude: 20.4612,
        GPSLatitudeRef: 'N', GPSLongitudeRef: 'E',
        GPSAltitude: 117.3,
        GPSImgDirection: 247.5, GPSImgDirectionRef: 'T',
        GPSSpeed: 30, GPSSpeedRef: 'M',
        LensModel: 'Test back camera 6.81mm f/1.68',
        Software: 'Adobe Photoshop 25.0',
        Make: 'TestMake',
        DateTimeOriginal: '2026:01:15 10:30:00',
        OffsetTimeOriginal: '+01:00',
        Model: 'TestCam <img src=x onerror=alert(1)>'
    });
    await writeFixture(nestedGpsFile, {
        GPSLatitude: 45.2671, GPSLongitude: 19.8335,
        GPSLatitudeRef: 'N', GPSLongitudeRef: 'E',
        DateTimeOriginal: '2026:01:16 12:00:00'
    });
    await writeFixture(equatorFile, {
        GPSLatitude: 0, GPSLongitude: 9.45,
        GPSLatitudeRef: 'N', GPSLongitudeRef: 'E'
    });
    await writeFixture(plainFile, null);

    // A text file: readable by ExifTool but carries no location data
    fs.writeFileSync(path.join(tmpDir, 'notes.txt'), 'case notes');

    // A valid MBTiles map package for offline-map tests. Kept OUTSIDE the
    // scanned evidence folder so it does not affect file counts.
    mbtilesDir = fs.mkdtempSync(path.join(os.tmpdir(), 'geo-forensics-map-'));
    mbtilesPath = path.join(mbtilesDir, 'region.mbtiles');
    writeTestMbtiles(mbtilesPath);

    // Symlink loop back to the root; the walker must not recurse forever.
    // Skipped on filesystems that don't allow symlink creation.
    try {
        fs.symlinkSync(tmpDir, path.join(subDir, 'loop'), 'dir');
    } catch (err) {
        // ignore
    }

    server = await new Promise((resolve) => {
        const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
    server.closeAllConnections?.();
    await new Promise((resolve) => server.close(resolve));
    mbtiles.clearActiveMap();
    await exiftool.end();
    fs.rmSync(tmpDir, { recursive: true, force: true });
    if (mbtilesDir) fs.rmSync(mbtilesDir, { recursive: true, force: true });
});

test('countFiles walks nested folders and survives symlink loops', async () => {
    const count = await countFiles(tmpDir);
    assert.equal(count, 5); // 4 jpg + 1 txt, the loop symlink is not a file
});

test('countFiles rejects a path that does not exist', async () => {
    await assert.rejects(() => countFiles(path.join(tmpDir, 'no-such-dir')));
});

test('scanDirectory finds GPS evidence recursively and reports stats', async () => {
    const { results, stats } = await scanDirectory(tmpDir);

    assert.equal(results.length, 3);
    const names = results.map((r) => r.name).sort();
    assert.deepEqual(names, ['belgrade.jpg', 'equator.jpg', 'nested.jpg']);

    assert.equal(stats.totalFiles, 5);
    assert.equal(stats.withLocation, 3);
    assert.equal(stats.noLocation, 2); // plain.jpg + notes.txt
    assert.equal(stats.unreadable, 0);
});

test('scanDirectory keeps latitude 0 (equator is a valid coordinate)', async () => {
    const { results } = await scanDirectory(tmpDir);
    const equator = results.find((r) => r.name === 'equator.jpg');
    assert.ok(equator, 'equator file missing from results');
    assert.equal(equator.lat, 0);
    assert.equal(equator.lon, 9.45);
});

test('scanDirectory extracts time, device and altitude', async () => {
    const { results } = await scanDirectory(tmpDir);
    const belgrade = results.find((r) => r.name === 'belgrade.jpg');
    // The timeline value is the raw EXIF string, including a genuine offset
    assert.equal(belgrade.time, '2026:01:15 10:30:00+01:00');
    assert.ok(belgrade.camera.startsWith('TestCam'));
    assert.equal(belgrade.alt, 117.3);
    const nested = results.find((r) => r.name === 'nested.jpg');
    assert.equal(nested.alt, null);
});

test('scanDirectory extracts heading, speed, lens and software', async () => {
    const { results } = await scanDirectory(tmpDir);
    const belgrade = results.find((r) => r.name === 'belgrade.jpg');
    assert.equal(belgrade.heading, 247.5);
    // 30 mph, normalized to km/h
    assert.ok(Math.abs(belgrade.speedKmh - 48.28032) < 0.001, `speedKmh was ${belgrade.speedKmh}`);
    assert.equal(belgrade.lens, 'Test back camera 6.81mm f/1.68');
    assert.equal(belgrade.software, 'Adobe Photoshop 25.0');

    // Files without these tags report null, not undefined or 0
    const nested = results.find((r) => r.name === 'nested.jpg');
    assert.equal(nested.heading, null);
    assert.equal(nested.speedKmh, null);
    assert.equal(nested.lens, null);
    assert.equal(nested.software, null);
});

test('isServableFile only allows files discovered by the scan', async () => {
    await scanDirectory(tmpDir);
    assert.equal(isServableFile(gpsFile), true);
    assert.equal(isServableFile(plainFile), false); // exists, but no GPS -> never served
    assert.equal(isServableFile('/etc/passwd'), false);
});

test('POST /api/scan returns evidence and stats', async () => {
    const res = await fetch(`${baseUrl}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ folderPath: tmpDir })
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.data.length, 3);
    assert.equal(body.stats.totalFiles, 5);
});

test('POST /api/scan rejects an invalid path', async () => {
    const res = await fetch(`${baseUrl}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ folderPath: path.join(tmpDir, 'missing') })
    });
    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.success, false);
});

test('POST /api/estimate counts files', async () => {
    const res = await fetch(`${baseUrl}/api/estimate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ folderPath: tmpDir })
    });
    const body = await res.json();
    assert.equal(body.success, true);
    assert.equal(body.count, 5);
});

test('GET /api/image serves scanned files and nothing else', async () => {
    await fetch(`${baseUrl}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ folderPath: tmpDir })
    });

    const ok = await fetch(`${baseUrl}/api/image?path=${encodeURIComponent(gpsFile)}`);
    assert.equal(ok.status, 200);

    // Existing files that were not part of the scan must never be served
    const secret = await fetch(`${baseUrl}/api/image?path=${encodeURIComponent(__filename)}`);
    assert.equal(secret.status, 404);

    const missing = await fetch(`${baseUrl}/api/image?path=${encodeURIComponent('/no/such/file.jpg')}`);
    assert.equal(missing.status, 404);
});

test('scanDirectory reports progress for every file', async () => {
    const calls = [];
    const { stats } = await scanDirectory(tmpDir, {
        onProgress: (processed, total) => calls.push([processed, total])
    });
    assert.equal(calls.length, 5);
    assert.deepEqual(calls[calls.length - 1], [5, 5]);
    assert.equal(stats.processed, 5);
    assert.equal(stats.aborted, false);
});

test('scanDirectory stops early when the signal is already aborted', async () => {
    const controller = new AbortController();
    controller.abort();
    const { results, stats } = await scanDirectory(tmpDir, { signal: controller.signal });
    assert.equal(results.length, 0);
    assert.equal(stats.processed, 0);
    assert.equal(stats.aborted, true);
    assert.equal(stats.totalFiles, 5); // Discovery still ran; examination did not
});

test('GET /api/scan-stream emits progress and done events', async () => {
    const res = await fetch(`${baseUrl}/api/scan-stream?path=${encodeURIComponent(tmpDir)}&id=test-stream-1`);
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type'), /text\/event-stream/);

    const body = await res.text(); // The server ends the stream after "done"
    assert.ok(body.includes('event: progress'), 'expected at least one progress event');
    assert.ok(body.includes('event: done'), 'expected a done event');

    // Parse the payload of the done event
    const doneData = body.split('event: done\n')[1].split('\n')[0].replace('data: ', '');
    const payload = JSON.parse(doneData);
    assert.equal(payload.data.length, 3);
    assert.equal(payload.stats.totalFiles, 5);
    assert.equal(payload.stats.aborted, false);
});

test('GET /api/scan-stream reports an invalid path as a scan-error event', async () => {
    const res = await fetch(`${baseUrl}/api/scan-stream?path=${encodeURIComponent(path.join(tmpDir, 'missing'))}&id=test-stream-2`);
    const body = await res.text();
    assert.ok(body.includes('event: scan-error'), 'expected a scan-error event');
    assert.ok(!body.includes('event: done'));
});

test('POST /api/scan-cancel rejects unknown scan ids', async () => {
    const res = await fetch(`${baseUrl}/api/scan-cancel`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scanId: 'no-such-scan' })
    });
    assert.equal(res.status, 404);
});

test('GET /vendor/leaflet serves the bundled Leaflet build', async () => {
    const js = await fetch(`${baseUrl}/vendor/leaflet/leaflet.js`);
    assert.equal(js.status, 200);
    const css = await fetch(`${baseUrl}/vendor/leaflet/leaflet.css`);
    assert.equal(css.status, 200);
});

// --- SHA-256 hashing ---

test('scanDirectory hashes every evidence file with SHA-256', async () => {
    const { results, stats } = await scanDirectory(tmpDir);
    const belgrade = results.find((r) => r.name === 'belgrade.jpg');
    const expected = crypto.createHash('sha256').update(fs.readFileSync(gpsFile)).digest('hex');
    assert.equal(belgrade.sha256, expected);
    assert.equal(belgrade.hashError, null);
    assert.equal(stats.hashFailures, 0);
    // Every located file carries a 64-hex-char digest
    for (const r of results) assert.match(r.sha256, /^[0-9a-f]{64}$/);
});

// --- Timestamp forensics ---

test('scanDirectory preserves raw timestamps and the timeline field', async () => {
    const { results } = await scanDirectory(tmpDir);
    const belgrade = results.find((r) => r.name === 'belgrade.jpg');
    assert.equal(belgrade.timelineField, 'DateTimeOriginal');
    assert.equal(belgrade.timestamps.dateTimeOriginal, '2026:01:15 10:30:00+01:00');
    assert.equal(belgrade.timestamps.offsetTimeOriginal, '+01:00');
    assert.equal(belgrade.make, 'TestMake');
    assert.equal(belgrade.model.startsWith('TestCam'), true);
});

test('a genuine EXIF offset is reported as timezone-known', async () => {
    const { results } = await scanDirectory(tmpDir);
    const belgrade = results.find((r) => r.name === 'belgrade.jpg');
    assert.equal(belgrade.timezoneKnown, true);
    assert.equal(belgrade.timezoneOffset, '+01:00');
});

test('a timestamp without an offset is timezone-unknown, never inferred from GPS', async () => {
    const { results } = await scanDirectory(tmpDir);
    // nested.jpg has GPS but no OffsetTime*; exiftool can infer a zone from the
    // coordinates, but that inference must NOT be presented as a known offset.
    const nested = results.find((r) => r.name === 'nested.jpg');
    assert.equal(nested.timezoneKnown, false);
    assert.equal(nested.timezoneOffset, null);
});

// --- /api/versions provenance ---

test('GET /api/versions returns app and ExifTool versions', async () => {
    const body = await (await fetch(`${baseUrl}/api/versions`)).json();
    assert.equal(body.success, true);
    assert.ok(body.appVersion);
    assert.match(String(body.exiftoolVersion), /^\d+\.\d+/);
});

// --- Offline MBTiles: module ---

test('mbtiles opens a valid package and reads metadata', () => {
    const meta = mbtiles.setActiveMap(mbtilesPath);
    assert.equal(meta.name, 'Test Region');
    assert.equal(meta.format, 'png');
    assert.deepEqual(meta.bounds, [19, 44, 21, 46]);
    assert.equal(meta.minzoom, 0);
    assert.equal(meta.maxzoom, 4);
    mbtiles.clearActiveMap();
});

test('mbtiles serves a tile with correct TMS Y-flip and 404s otherwise', () => {
    mbtiles.setActiveMap(mbtilesPath);
    // The tile stored at XYZ z2/x2/y1
    const tile = mbtiles.getTile(2, 2, 1);
    assert.ok(tile && tile.data.length > 0);
    assert.equal(tile.contentType, 'image/png');
    // A different tile is absent
    assert.equal(mbtiles.getTile(2, 0, 0), null);
    // Out of range and non-integer inputs are rejected
    assert.equal(mbtiles.getTile(2, 99, 99), null);
    assert.equal(mbtiles.getTile(2, 'x', 1), null);
    assert.equal(mbtiles.getTile(-1, 0, 0), null);
    mbtiles.clearActiveMap();
});

test('mbtiles rejects a missing or non-MBTiles file', () => {
    assert.throws(() => mbtiles.openMbtiles(path.join(tmpDir, 'nope.mbtiles')));
    const junk = path.join(tmpDir, 'junk.mbtiles');
    fs.writeFileSync(junk, 'not a database');
    assert.throws(() => mbtiles.openMbtiles(junk));
});

// --- Offline MBTiles: API ---

test('offline-map endpoints import, report, serve tiles and clear', async () => {
    // Import
    const imp = await (await fetch(`${baseUrl}/api/offline-map`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: mbtilesPath })
    })).json();
    assert.equal(imp.success, true);
    assert.equal(imp.meta.name, 'Test Region');

    // Current map
    const cur = await (await fetch(`${baseUrl}/api/offline-map`)).json();
    assert.equal(cur.meta.name, 'Test Region');

    // Tile served from localhost
    const tile = await fetch(`${baseUrl}/api/tiles/2/2/1`);
    assert.equal(tile.status, 200);
    assert.match(tile.headers.get('content-type'), /image\/png/);

    // Missing tile -> 404
    const miss = await fetch(`${baseUrl}/api/tiles/2/0/0`);
    assert.equal(miss.status, 404);

    // Clear
    await fetch(`${baseUrl}/api/offline-map`, { method: 'DELETE' });
    const after = await (await fetch(`${baseUrl}/api/offline-map`)).json();
    assert.equal(after.meta, null);
    const gone = await fetch(`${baseUrl}/api/tiles/2/2/1`);
    assert.equal(gone.status, 404);
});

test('offline-map import rejects an invalid path', async () => {
    const res = await fetch(`${baseUrl}/api/offline-map`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: path.join(tmpDir, 'does-not-exist.mbtiles') })
    });
    assert.equal(res.status, 400);
    const body = await res.json();
    assert.equal(body.success, false);
});

// --- Air-gap network safety (server layer) ---

test('scanning and serving make no outbound network connection', async () => {
    // Trip on any attempt to open a non-loopback socket during a full scan +
    // API round-trip. ExifTool uses a child process, not sockets, so this
    // asserts the scan/serve path itself never reaches the network.
    const net = require('node:net');
    const realConnect = net.Socket.prototype.connect;
    const offending = [];
    net.Socket.prototype.connect = function (...args) {
        const opts = typeof args[0] === 'object' ? args[0] : { port: args[0], host: args[1] };
        const host = String(opts.host || opts.path || '');
        if (host && !/^(127\.0\.0\.1|::1|localhost)$/.test(host) && !opts.path) {
            offending.push(host);
        }
        return realConnect.apply(this, args);
    };
    try {
        await scanDirectory(tmpDir);
        await fetch(`${baseUrl}/api/versions`);
        await fetch(`${baseUrl}/api/offline-map`);
    } finally {
        net.Socket.prototype.connect = realConnect;
    }
    assert.deepEqual(offending, []);
});
