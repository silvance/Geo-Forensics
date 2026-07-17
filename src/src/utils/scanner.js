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
const { exiftool } = require('exiftool-vendored');

// How many files are handed to ExifTool at once. exiftool-vendored keeps a
// pool of background processes, so reading files one by one leaves most of
// that pool idle during large batch scans.
const SCAN_CONCURRENCY = 4;

// Files discovered by the most recent scan. The /api/image endpoint only
// serves paths present in this set, so the local HTTP server can never be
// used to read arbitrary files from disk.
const servableFiles = new Set();

// Normalize the path for the current OS (Linux/Windows) and validate it
function resolveScanRoot(dirPath) {
    const normalizedPath = path.resolve(dirPath.trim());

    if (!fs.existsSync(normalizedPath)) {
        throw new Error("Folder doesnt exist or path is not valid");
    }

    return normalizedPath;
}

// Shared recursive directory walker used by both the scanner and the file
// count estimator. Tracks resolved directories so symlink loops can't
// recurse forever, and silently skips unreadable or restricted entries.
async function collectFiles(rootPath) {
    const files = [];
    const visited = new Set();

    async function walk(dir) {
        let realDir;
        try {
            realDir = await fs.promises.realpath(dir);
        } catch (err) {
            return; // Broken link or restricted access
        }

        // Symlink loop protection: never enter the same real directory twice
        if (visited.has(realDir)) return;
        visited.add(realDir);

        let entries;
        try {
            entries = await fs.promises.readdir(dir, { withFileTypes: true });
        } catch (err) {
            return; // Restricted access folder
        }

        for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            try {
                if (entry.isDirectory()) {
                    await walk(fullPath); // Recurse into subdirectories
                } else if (entry.isFile()) {
                    files.push({ name: entry.name, fullPath });
                } else if (entry.isSymbolicLink()) {
                    // Follow links to files and folders; the visited set
                    // above guards against circular links
                    const stat = await fs.promises.stat(fullPath);
                    if (stat.isDirectory()) {
                        await walk(fullPath);
                    } else if (stat.isFile()) {
                        files.push({ name: entry.name, fullPath });
                    }
                }
            } catch (err) {
                // Silently skip unreadable files or restricted access folders
            }
        }
    }

    await walk(rootPath);
    return files;
}

// options.onProgress: called as (processedCount, totalFiles) after every file
// options.signal: an AbortSignal; aborting stops the scan early and the
// partial results are returned with stats.aborted = true
async function scanDirectory(dirPath, options = {}) {
    const { onProgress, signal } = options;

    const files = await collectFiles(resolveScanRoot(dirPath));

    // A new scan resets the UI, so files from the previous scan no longer
    // need to stay servable to the frontend
    servableFiles.clear();

    // Fill results by index so output keeps directory order no matter
    // which ExifTool read finishes first
    const results = new Array(files.length).fill(null);
    let nextIndex = 0;

    // Completeness counters: an investigator needs to know how much of the
    // evidence set was actually examined, not just what matched
    let processed = 0;
    let noLocation = 0;
    let unreadable = 0;

    async function worker() {
        while (nextIndex < files.length) {
            // Stop claiming new files once the scan has been cancelled;
            // reads already in flight are allowed to finish
            if (signal && signal.aborted) return;

            const index = nextIndex++;
            const file = files[index];

            try {
                // Let ExifTool read the file (works for JPG, CR3, MP4, MOV, HEIC, etc.)
                const tags = await exiftool.read(file.fullPath);

                // ExifTool reports fatal problems (empty file, unknown
                // format) as an Error tag instead of throwing
                if (tags.Error) {
                    unreadable++;

                // Check if GPS data exists. 0 is a valid coordinate on the
                // equator / prime meridian, so only reject missing values
                } else if (tags.GPSLatitude != null && tags.GPSLongitude != null) {

                    // Format the Time natively
                    let formattedTime = "Unknown Time";
                    const rawDate = tags.DateTimeOriginal || tags.CreateDate || tags.ModifyDate;

                    if (rawDate) {
                        formattedTime = rawDate.rawValue || rawDate.toString();
                    }

                    servableFiles.add(file.fullPath);
                    results[index] = {
                        name: file.name,
                        fullPath: file.fullPath,
                        lat: tags.GPSLatitude,
                        lon: tags.GPSLongitude,
                        alt: typeof tags.GPSAltitude === 'number' ? tags.GPSAltitude : null,
                        time: formattedTime,
                        camera: tags.Model || tags.Make || "Unknown device"
                    };
                } else {
                    noLocation++;
                }
            } catch (err) {
                // Count files ExifTool can't parse instead of hiding them
                unreadable++;
            }

            processed++;
            if (onProgress) onProgress(processed, files.length);
        }
    }

    // Run a small pool of workers so ExifTool processes files in parallel
    const workers = [];
    for (let i = 0; i < Math.min(SCAN_CONCURRENCY, files.length); i++) {
        workers.push(worker());
    }
    await Promise.all(workers);

    const found = results.filter(Boolean);

    return {
        results: found,
        stats: {
            totalFiles: files.length,
            processed: processed,
            withLocation: found.length,
            noLocation: noLocation,
            unreadable: unreadable,
            aborted: !!(signal && signal.aborted)
        }
    };
}

async function countFiles(dirPath) {
    const files = await collectFiles(resolveScanRoot(dirPath));
    return files.length;
}

// Used by the /api/image endpoint to make sure only files discovered by
// the current scan can ever be served over HTTP
function isServableFile(filePath) {
    return servableFiles.has(path.resolve(filePath));
}

module.exports = { scanDirectory, countFiles, isServableFile };

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
