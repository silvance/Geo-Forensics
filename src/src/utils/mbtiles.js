/* GeoForensics
 * Copyright (C) 2026  GeoForensics contributors
 * Based on Refloow Geo Forensics (C) 2026 Veljko Vuckovic, AGPL-3.0.
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

// Offline raster basemap support backed by MBTiles files.
//
// MBTiles is a single SQLite database of map tiles (https://github.com/mapbox/mbtiles-spec).
// We read it with Node's built-in node:sqlite so the portable Windows build
// needs no native module to compile — the exact packaging risk that rules out
// better-sqlite3 for an offline forensic tool. The database is opened READ-ONLY
// and every query is a parameterized prepared statement with numeric inputs, so
// an imported file can never mutate itself and no SQL is ever built from input.

const fs = require('fs');
const { DatabaseSync } = require('node:sqlite');

// Content type per MBTiles `format` metadata value (raster formats only)
const RASTER_CONTENT_TYPES = {
    png: 'image/png',
    jpg: 'image/jpeg',
    jpeg: 'image/jpeg',
    webp: 'image/webp',
};

// The single active offline map: { db, meta, path }. Only one at a time.
let active = null;

// Parse "west,south,east,north" into a numeric [w, s, e, n], or null.
function parseBounds(value) {
    if (!value) return null;
    const parts = String(value).split(',').map((n) => parseFloat(n.trim()));
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return null;
    return parts;
}

// Opens and validates an MBTiles file, returning { db, meta }. Throws an Error
// with a human-readable message if the file is missing or not a usable raster
// MBTiles. Does not touch module state.
function openMbtiles(mapPath) {
    if (typeof mapPath !== 'string' || mapPath.trim() === '') {
        throw new Error('No map path provided');
    }
    if (!fs.existsSync(mapPath)) {
        throw new Error('Map package not found at that path');
    }

    let db;
    try {
        db = new DatabaseSync(mapPath, { readOnly: true });
    } catch (err) {
        throw new Error('File is not a readable SQLite/MBTiles database');
    }

    try {
        // Require the MBTiles schema: a `tiles` table/view and a `metadata` table.
        const objects = db.prepare(
            "SELECT name FROM sqlite_master WHERE type IN ('table','view')"
        ).all().map((r) => r.name);
        if (!objects.includes('tiles') || !objects.includes('metadata')) {
            throw new Error('File is not a valid MBTiles map package (missing tiles/metadata)');
        }

        // Confirm the tiles carry the expected columns and at least one tile.
        const sample = db.prepare(
            'SELECT zoom_level, tile_column, tile_row, tile_data FROM tiles LIMIT 1'
        ).get();
        if (!sample) {
            throw new Error('Map package contains no tiles');
        }

        // Read the metadata table into a plain object.
        const metaRows = db.prepare('SELECT name, value FROM metadata').all();
        const metaMap = {};
        for (const row of metaRows) metaMap[row.name] = row.value;

        const format = (metaMap.format || 'png').toLowerCase();
        if (!RASTER_CONTENT_TYPES[format]) {
            // Vector tiles (pbf) are not supported by this raster Leaflet layer.
            throw new Error(`Unsupported tile format "${format}" (only raster png/jpg/webp are supported)`);
        }

        // Zoom range: prefer metadata, fall back to the actual tile range.
        let minzoom = metaMap.minzoom != null ? parseInt(metaMap.minzoom, 10) : null;
        let maxzoom = metaMap.maxzoom != null ? parseInt(metaMap.maxzoom, 10) : null;
        if (minzoom == null || maxzoom == null || Number.isNaN(minzoom) || Number.isNaN(maxzoom)) {
            const z = db.prepare('SELECT MIN(zoom_level) AS lo, MAX(zoom_level) AS hi FROM tiles').get();
            if (minzoom == null || Number.isNaN(minzoom)) minzoom = z.lo;
            if (maxzoom == null || Number.isNaN(maxzoom)) maxzoom = z.hi;
        }

        const meta = {
            name: metaMap.name || null,
            format,
            contentType: RASTER_CONTENT_TYPES[format],
            bounds: parseBounds(metaMap.bounds),
            minzoom,
            maxzoom,
        };

        return { db, meta };
    } catch (err) {
        try { db.close(); } catch (e) { /* ignore */ }
        throw err;
    }
}

// Makes an MBTiles file the active offline map. Returns the public metadata
// (no db handle). Closes any previously active map first.
function setActiveMap(mapPath) {
    const { db, meta } = openMbtiles(mapPath);
    clearActiveMap();
    active = { db, meta, path: mapPath };
    return publicMeta();
}

function clearActiveMap() {
    if (active) {
        try { active.db.close(); } catch (err) { /* ignore */ }
        active = null;
    }
}

// Metadata safe to hand to the client (no internal handles).
function publicMeta() {
    if (!active) return null;
    return {
        name: active.meta.name,
        format: active.meta.format,
        bounds: active.meta.bounds,
        minzoom: active.meta.minzoom,
        maxzoom: active.meta.maxzoom,
        path: active.path,
    };
}

// Returns { data: Buffer, contentType } for an XYZ tile, or null if absent.
// Leaflet uses XYZ (origin top-left); MBTiles stores TMS (origin bottom-left),
// so the row is flipped: tmsRow = 2^z - 1 - y.
function getTile(z, x, y) {
    if (!active) return null;

    // Only accept non-negative integers; reject anything else outright.
    z = Number(z); x = Number(x); y = Number(y);
    if (![z, x, y].every((n) => Number.isInteger(n) && n >= 0)) return null;

    const max = Math.pow(2, z) - 1;
    if (z < 0 || x > max || y > max) return null; // outside this zoom's grid
    const tmsRow = max - y;

    const row = active.db.prepare(
        'SELECT tile_data FROM tiles WHERE zoom_level = ? AND tile_column = ? AND tile_row = ?'
    ).get(z, x, tmsRow);

    if (!row || !row.tile_data) return null;
    return { data: Buffer.from(row.tile_data), contentType: active.meta.contentType };
}

module.exports = { openMbtiles, setActiveMap, clearActiveMap, getActiveMap: publicMeta, getTile };
