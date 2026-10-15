# Changelog

All notable changes to GeoForensics are recorded here, newest first. The
project follows semantic versioning; a version is cut by tagging `vX.Y.Z`,
which builds the Windows installer and portable exe and attaches them to a
draft GitHub release whose notes are taken from the matching section below.

## 1.6.0 — 2026-10-14

Forensic depth and local hardening. No change to the export data model:
the Forensic Manifest stays at `manifestVersion: 1` (new fields are additive).

### Forensic correctness

- **Every file is hashed.** SHA-256 now covers every file in the evidence
  folder, located or not. The scan returns an inventory of unlocated and
  unreadable files, each hashed, and the Forensic Manifest lists them under
  `otherFiles`, so the manifest attests to the whole folder.
- **Duplicate detection.** Byte-identical files are detected across the
  whole inventory. Later copies carry `duplicateOf` (the first occurrence's
  path) and a `duplicate` flag; the status line, exports and report count
  them. Directory entries are walked in sorted order so "first occurrence"
  is reproducible across machines.
- **GPS time as a timezone anchor.** `GPSDateStamp`/`GPSTimeStamp` (UTC by
  definition) are read as `gpsUtcTime`. When a timestamp has no embedded
  offset, the offset implied by GPS time is reported as `derivedOffset`,
  labelled *derived* everywhere; `timezoneKnown` stays false. When an offset
  is embedded, `clockDriftSeconds` reports the camera clock against GPS
  time as a consistency check.
- **Coordinate sanity flags.** Exactly 0,0 is flagged `null-island` and
  values outside the valid range `out-of-range`; both stay plotted.
- **Fixed: 0,0 positions were invisible.** The ExifTool wrapper's default
  read options silently drop a 0,0 position, so such files were counted as
  "no location". The scanner now reads them.

### Security

- **Per-launch local API token.** The desktop app generates a random token
  at start, hands it only to its own renderer, and the loopback server
  requires it on every `/api` request. Other local processes or browser
  tabs can no longer trigger scans or read evidence files.
- **Content Security Policy** and hardening headers on every response
  (self-only scripts, styles, media and API calls; images from self plus the
  known basemap hosts; `nosniff`, `no-referrer`, `no-store`).
- **No online links in the HTML case report.** The per-row OpenStreetMap
  link column is replaced by a Flags column.

### Engineering

- Linux, macOS and Snap build workflows moved to Node 22 with `npm ci`, so
  every platform build includes offline-map support (`node:sqlite`).
- Tagged releases take their notes from this changelog.
- `SECURITY.md` describes the threat model and how to report an issue.
- Tests: 39 (11 new) covering the inventory, GPS anchor, flags, duplicates,
  token enforcement and security headers.

## 1.5.0 — 2026-09-12

The air-gap release. GeoForensics became an air-gap-native forensic tool
rather than one that "mostly works offline".

- **Air-Gapped Mode** (default on): every non-loopback request is cancelled
  in the main process, fail-closed; Chromium background networking,
  component updates and the auto-updater are disabled while it is on.
- **Offline basemaps** from raster MBTiles packages, read through Node's
  built-in SQLite (read-only, parameterized integer queries, no native
  module), with a coverage warning when evidence falls outside the map.
- **SHA-256** of every located file, streamed; hash failures are counted.
- **Honest timestamps**: all raw EXIF timestamps and offset tags preserved,
  the timeline field made explicit, a timezone claimed only from an embedded
  offset (the ExifTool GPS-inferred zone is deliberately ignored).
- **Provenance** on every export: app and ExifTool version, scan folder,
  start/end, completeness counts, filter state, partial-scan flag, air-gap
  state and offline map in use.
- **Forensic Manifest** export (`manifestVersion: 1`) and tool versions
  endpoint.
- **Windows release bundle**: NSIS installer and single-file portable exe,
  built by a tag-triggered workflow with ExifTool unpacked from the asar.
- In-app help on AXIOM exports, timezones and offline use; project
  rebranded as GeoForensics with the upstream AGPL attribution kept.

## 1.4.0 and earlier

Upstream history as Refloow Geo Forensics by Veljko Vuckovic, plus the first
fork rounds: evidence export (CSV, GeoJSON, KML), scan completeness stats,
bundled Leaflet, streamed scan progress with cancel, device and date
filtering, HTML case report with optional thumbnails, richer metadata
(heading, speed, lens, software) and camera-direction cones, a loopback-only
API with an image allowlist, metadata HTML escaping, and parallel ExifTool
reads.
