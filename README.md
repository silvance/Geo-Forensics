# 📍 GeoForensics

### **Open-Source Batch Image & Video Geolocation Forensics**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D%2022-brightgreen)](https://nodejs.org/)
[![Tests](https://github.com/silvance/Geo-Forensics/actions/workflows/tests.yml/badge.svg)](https://github.com/silvance/Geo-Forensics/actions/workflows/tests.yml)

**GeoForensics** is a free, open-source digital forensics tool for investigators, OSINT practitioners, and security analysts. Point it at a folder of images or videos and it extracts EXIF metadata in bulk, plots every GPS coordinate on an interactive map, and reconstructs a chronological timeline of events — entirely on your own machine. No uploads, no accounts, no telemetry.

It is built for **offline / air-gapped forensic workstations**: with Air-Gapped Mode on (the default), no data of any kind leaves the machine.

---

## 🚀 Features

* **Batch EXIF extraction** — processes entire directory trees concurrently using [ExifTool](https://exiftool.org/), supporting virtually every image and video format (JPG, HEIC, CR3, MP4, MOV, …).
* **Air-Gapped Mode (default ON)** — a hard block on all outbound network requests, enforced in the Electron process: no update checks, no online map tiles, nothing leaves the workstation. A header badge always shows the current state.
* **Offline basemaps** — import a local **MBTiles** raster map package (Settings → Offline Maps) to plot evidence on a real basemap with no connection. Evidence outside the map's coverage is flagged.
* **SHA-256 hashing** — every located file is hashed (original bytes, read-only) for a reproducible identifier, included in every export.
* **Forensic timestamps** — all raw EXIF timestamps and their offset tags are preserved; the timeline field used is recorded, and timezone-less timestamps are clearly marked *unknown* (never silently assumed UTC or local).
* **Interactive mapping** — evidence plotted with clustered pins, chronological numbering, a movement path, and camera-direction cones. Six online basemaps are available when Air-Gapped Mode is off.
* **Live progress & cancel** — scans stream real progress and can be cancelled mid-flight; partial results are clearly flagged.
* **Filtering** — narrow results by device or date range without rescanning; evidence numbering stays stable.
* **Evidence export** — **CSV**, **GeoJSON**, **KML**, a self-contained **HTML case report** (with full scan provenance and an optional embedded thumbnail per image), and a **Forensic Manifest (JSON, `manifestVersion: 1`)** — all including SHA-256, coordinates, altitude, raw timestamps, timezone status, device/lens/software, heading and speed.
* **Scan completeness reporting** — discovered / examined / located / unreadable / hash-failure counts, surfaced in the UI and baked into reports.
* **Dark & light mode**, media previews, precision zoom, and cross-platform support (Windows, Linux, macOS).

## 🔒 Privacy & offline guarantee

All processing happens locally. The embedded web server binds to `127.0.0.1` only and serves only files discovered by the current scan (and imported offline-map tiles). With Air-Gapped Mode on, the Electron process cancels any non-loopback request before it leaves the machine. See [PRIVACY.md](.github/PRIVACY.md).

## 🧭 Working with forensic exports (Magnet AXIOM & others)

GeoForensics analyzes the metadata **embedded in the files you supply**. When exporting evidence from a forensic suite such as Magnet AXIOM, export the **original / native file** whenever possible. Location information that exists only in a separate case artifact or database — not inside the media file itself — cannot be recovered from an exported image that does not contain that metadata. GeoForensics does not parse AXIOM case files; it reads the exported originals.

## 💻 Requirements

* **OS:** Windows 10/11, macOS (Intel/Apple Silicon), or Linux
* **Runtime (development only):** [Node.js](https://nodejs.org/) **v22 or newer** (the offline-map reader uses Node's built-in SQLite). Packaged builds bundle their own runtime — end users need nothing installed.
* **Stack:** Electron, Express, `exiftool-vendored`, Leaflet, `node:sqlite` (built-in)

| Component | Minimum | Recommended |
| :--- | :--- | :--- |
| **Storage** | ~350 MB | 500 MB+ |
| **RAM** | 2 GB | 4 GB+ for large batches |
| **CPU** | Dual-core 2.0 GHz | Quad-core+ for faster parsing |

## 🛠️ Getting Started

```bash
git clone https://github.com/silvance/Geo-Forensics.git
cd Geo-Forensics/src
npm install
npm start
```

### Running the tests

```bash
npm test
```

The test suite covers the scanning engine (recursive walking, symlink-loop protection, GPS/altitude extraction, completeness stats, abort semantics) and the local HTTP API (scan, streaming progress, cancel, image allowlist). Tests run automatically on every push and pull request via GitHub Actions.

### Packaging

```bash
npm run package          # Windows (NSIS installer + portable single-file exe)
npm run package:mac      # macOS (dmg + zip)
npm run package:linux    # Linux (AppImage, deb, snap)
```

Windows builds bundle everything — Electron, the local server, ExifTool, and Leaflet — so nothing needs to be installed separately. The **portable exe** runs directly from a single file (USB-stick friendly); the **installer** adds shortcuts and auto-update support. The `Windows Release` GitHub Actions workflow builds both automatically: run it from the Actions tab, or push a `v*` tag to build and attach them to a draft GitHub release.

## 📖 Usage

1. **Import** — click *Browse Folder* (or paste a path) to select an evidence folder.
2. **Analyze** — the scanner walks the tree and extracts GPS, timestamps, device, and altitude from every readable file, with live progress. Cancel anytime; partials are flagged.
3. **Investigate** — explore the map, follow the numbered timeline, filter by device or date, and preview media.
4. **Export** — hand off results as CSV, GeoJSON, or KML.

## 🤝 Contributing

Bug reports, feature requests, and pull requests are welcome — see [CONTRIBUTING.md](.github/CONTRIBUTING.md) and the [issue tracker](https://github.com/silvance/Geo-Forensics/issues).

## 📜 License

Licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)** — see [LICENSE](LICENSE). Any distributed modifications must remain open source under the same license.

## 🙏 Acknowledgments

* **GeoForensics is a fork of [Refloow Geo Forensics](https://github.com/Refloow/Refloow-Geo-Forensics)** by Veljko Vuckovic, used under AGPL-3.0. Original copyright notices are preserved in the source files. This project is independent of and not affiliated with or endorsed by Refloow.
* **[ExifTool](https://exiftool.org/)** by Phil Harvey — the metadata extraction engine, via [`exiftool-vendored`](https://www.npmjs.com/package/exiftool-vendored).
* **[Leaflet](https://leafletjs.com/)** — interactive maps.
* **[Express](https://expressjs.com/)** — the local API server.
