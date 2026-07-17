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

const { exiftool } = require('exiftool-vendored');
const { scanDirectory, countFiles, isServableFile } = require('../src/utils/scanner');
const { app } = require('../src/server');

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
        DateTimeOriginal: '2026:01:15 10:30:00',
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
    await exiftool.end();
    fs.rmSync(tmpDir, { recursive: true, force: true });
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
    assert.equal(belgrade.time, '2026:01:15 10:30:00');
    assert.ok(belgrade.camera.startsWith('TestCam'));
    assert.equal(belgrade.alt, 117.3);
    const nested = results.find((r) => r.name === 'nested.jpg');
    assert.equal(nested.alt, null);
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

test('GET /vendor/leaflet serves the bundled Leaflet build', async () => {
    const js = await fetch(`${baseUrl}/vendor/leaflet/leaflet.js`);
    assert.equal(js.status, 200);
    const css = await fetch(`${baseUrl}/vendor/leaflet/leaflet.css`);
    assert.equal(css.status, 200);
});
