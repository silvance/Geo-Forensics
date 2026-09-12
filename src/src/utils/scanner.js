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
const crypto = require('crypto');
const { exiftool } = require('exiftool-vendored');

// Streams a file through SHA-256, returning { sha256, error }. The file is read
// read-only and never modified. Streaming keeps memory flat regardless of file
// size, so large videos don't blow up a batch scan. A read failure is reported
// (never silently dropped) so an examiner sees which files could not be hashed.
function hashFile(filePath) {
    return new Promise((resolve) => {
        const hash = crypto.createHash('sha256');
        const stream = fs.createReadStream(filePath);
        stream.on('error', (err) => resolve({ sha256: null, error: err.code || err.message }));
        stream.on('data', (chunk) => hash.update(chunk));
        stream.on('end', () => resolve({ sha256: hash.digest('hex'), error: null }));
    });
}

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

// EXIF speed is km/h unless the ref tag says otherwise (mph or knots);
// exiftool expands the ref to a human-readable string
function toKmh(speed, ref) {
    const unit = String(ref || '').toLowerCase();
    if (unit.includes('mph')) return speed * 1.609344;
    if (unit.includes('knot')) return speed * 1.852;
    return speed;
}

// exiftool-vendored returns date tags as ExifDateTime objects; this returns
// the raw EXIF string exactly as stored (never a reformatted/normalized value).
function rawDateString(v) {
    if (v == null) return null;
    if (typeof v === 'string') return v;
    return v.rawValue || v.toString();
}

// Determines the UTC offset for a timestamp field without ever guessing.
// EXIF timestamps frequently carry no timezone; we only report an offset when
// one is GENUINELY RECORDED in the file — embedded in the timestamp value or in
// the paired EXIF Offset* tag. Crucially, we do NOT trust exiftool's inferred
// zone (it derives one from GPS coordinates, which is an inference, not a fact
// in the file); reporting that as a known offset would misrepresent evidence.
// Returns { known, offset } where offset is e.g. "+02:00" or null.
function resolveOffset(dateValue, offsetTagValue) {
    // An offset embedded in the raw timestamp value itself is definitive
    const raw = rawDateString(dateValue);
    if (raw) {
        const m = raw.match(/([+-]\d{2}:?\d{2}|Z)$/);
        if (m) {
            const off = m[1] === 'Z' ? '+00:00' : m[1].replace(/^([+-]\d{2})(\d{2})$/, '$1:$2');
            return { known: true, offset: off };
        }
    }
    // The paired EXIF Offset* tag, when the timestamp itself had none
    if (offsetTagValue) {
        return { known: true, offset: String(offsetTagValue) };
    }
    // No recorded offset — timezone is genuinely unknown. Never inferred.
    return { known: false, offset: null };
}

// Builds the full timestamp picture for a file. All three raw EXIF timestamps
// and their offset tags are preserved; the timeline field is chosen as
// DateTimeOriginal -> CreateDate -> ModifyDate (unchanged), but which field was
// used and whether its timezone is known are made explicit.
function extractTimestamps(tags) {
    const dateTimeOriginal = rawDateString(tags.DateTimeOriginal);
    const createDate = rawDateString(tags.CreateDate);
    const modifyDate = rawDateString(tags.ModifyDate);

    const timestamps = {
        dateTimeOriginal,
        createDate,
        modifyDate,
        offsetTimeOriginal: tags.OffsetTimeOriginal ? String(tags.OffsetTimeOriginal) : null,
        offsetTimeDigitized: tags.OffsetTimeDigitized ? String(tags.OffsetTimeDigitized) : null,
        offsetTime: tags.OffsetTime ? String(tags.OffsetTime) : null,
    };

    // Timeline selection with EXIF-correct offset pairing:
    //   DateTimeOriginal <- OffsetTimeOriginal
    //   CreateDate       <- OffsetTimeDigitized
    //   ModifyDate       <- OffsetTime
    let timelineField = null;
    let selectedValue = null;
    let tz = { known: false, offset: null };
    if (tags.DateTimeOriginal != null) {
        timelineField = 'DateTimeOriginal';
        selectedValue = tags.DateTimeOriginal;
        tz = resolveOffset(tags.DateTimeOriginal, tags.OffsetTimeOriginal);
    } else if (tags.CreateDate != null) {
        timelineField = 'CreateDate';
        selectedValue = tags.CreateDate;
        tz = resolveOffset(tags.CreateDate, tags.OffsetTimeDigitized);
    } else if (tags.ModifyDate != null) {
        timelineField = 'ModifyDate';
        selectedValue = tags.ModifyDate;
        tz = resolveOffset(tags.ModifyDate, tags.OffsetTime);
    }

    return {
        timestamps,
        timelineField,
        time: selectedValue != null ? rawDateString(selectedValue) : 'Unknown Time',
        timezoneKnown: tz.known,
        timezoneOffset: tz.offset,
    };
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
    let hashFailures = 0;

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

                    // Preserve all three raw EXIF timestamps and their offsets,
                    // and record which field drives the timeline plus whether
                    // its timezone is actually known
                    const ts = extractTimestamps(tags);

                    // Reproducible identifier for the file (original bytes)
                    const hash = await hashFile(file.fullPath);
                    if (hash.error) hashFailures++;

                    servableFiles.add(file.fullPath);
                    results[index] = {
                        name: file.name,
                        fullPath: file.fullPath,
                        sha256: hash.sha256,
                        hashError: hash.error,
                        lat: tags.GPSLatitude,
                        lon: tags.GPSLongitude,
                        alt: typeof tags.GPSAltitude === 'number' ? tags.GPSAltitude : null,
                        time: ts.time,                       // raw string of the timeline field (display + sort)
                        timelineField: ts.timelineField,     // which EXIF field the timeline used
                        timezoneKnown: ts.timezoneKnown,     // false = ambiguous local time, do not assume UTC/local
                        timezoneOffset: ts.timezoneOffset,   // e.g. "+02:00" when known
                        timestamps: ts.timestamps,           // all raw timestamps + offset tags
                        camera: tags.Model || tags.Make || "Unknown device",
                        make: tags.Make || null,
                        model: tags.Model || null,
                        // Extra forensic context, null when the file lacks it
                        heading: typeof tags.GPSImgDirection === 'number' ? tags.GPSImgDirection : null,
                        speedKmh: typeof tags.GPSSpeed === 'number' ? toKmh(tags.GPSSpeed, tags.GPSSpeedRef) : null,
                        lens: tags.LensModel || null,
                        // Editing software is a tamper indicator worth surfacing
                        software: tags.Software || null
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
            hashFailures: hashFailures,
            aborted: !!(signal && signal.aborted)
        }
    };
}

async function countFiles(dirPath) {
    const files = await collectFiles(resolveScanRoot(dirPath));
    return files.length;
}

// Version of the bundled ExifTool, for report/manifest provenance.
async function getExiftoolVersion() {
    try {
        return await exiftool.version();
    } catch (err) {
        return null;
    }
}

// Used by the /api/image endpoint to make sure only files discovered by
// the current scan can ever be served over HTTP
function isServableFile(filePath) {
    return servableFiles.has(path.resolve(filePath));
}

module.exports = { scanDirectory, countFiles, isServableFile, getExiftoolVersion };

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
