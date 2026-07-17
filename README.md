# 📍 GeoForensics

### **Open-Source Batch Image & Video Geolocation Forensics**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D%2020.10.0-brightgreen)](https://nodejs.org/)
[![Tests](https://github.com/silvance/Geo-Forensics/actions/workflows/tests.yml/badge.svg)](https://github.com/silvance/Geo-Forensics/actions/workflows/tests.yml)

**GeoForensics** is a free, open-source digital forensics tool for investigators, OSINT practitioners, and security analysts. Point it at a folder of images or videos and it extracts EXIF metadata in bulk, plots every GPS coordinate on an interactive map, and reconstructs a chronological timeline of events — entirely on your own machine. No uploads, no accounts, no telemetry.

---

## 🚀 Features

* **Batch EXIF extraction** — processes entire directory trees concurrently using [ExifTool](https://exiftool.org/), supporting virtually every image and video format (JPG, HEIC, CR3, MP4, MOV, …).
* **Interactive mapping** — evidence plotted on six switchable map layers (dark, light, satellite, topographic, humanitarian, street), with clustered pins for co-located files.
* **Timeline reconstruction** — results are sorted chronologically, numbered on the map, and connected with a movement path to track motion or verify alibis.
* **Live progress & cancel** — scans stream real progress ("Scanning 4,812 / 20,000 files…") and can be cancelled mid-flight; partial results are clearly flagged so they can't be mistaken for a complete scan.
* **Filtering** — narrow large result sets by device or date range without rescanning; evidence numbering stays stable so references never shift.
* **Evidence export** — download any scan (or filtered subset) as **CSV** (spreadsheets/reports), **GeoJSON** (QGIS, ArcGIS), or **KML** (Google Earth), including coordinates, altitude, timestamps, and device info.
* **Scan completeness reporting** — the status line tells you how many files were examined and how many were unreadable, so nothing is silently skipped.
* **Media previews** — optional thumbnails in the sidebar and map popups (toggle off for maximum performance on huge sets).
* **Offline-capable** — the app runs fully locally and its UI loads without an internet connection; only map tiles require network access.
* **Dark & light mode**, altitude display, precision zoom, and cross-platform support (Windows, Linux, macOS).

## 🔒 Privacy

All processing happens locally. The embedded web server binds to `127.0.0.1` only, serves only files discovered by the current scan, and nothing is ever transmitted anywhere. See [PRIVACY.md](.github/PRIVACY.md).

## 💻 Requirements

* **OS:** Windows 10/11, macOS (Intel/Apple Silicon), or Linux
* **Runtime:** [Node.js](https://nodejs.org/) v20.10.0 or newer (development)
* **Stack:** Electron, Express, `exiftool-vendored`, Leaflet

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
npm run package          # Windows (NSIS installer)
npm run package:mac      # macOS (dmg + zip)
npm run package:linux    # Linux (AppImage, deb, snap)
```

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
