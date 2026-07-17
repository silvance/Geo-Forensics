# Contributing to GeoForensics

Thanks for your interest in improving GeoForensics! Bug reports, feature requests, and pull requests are all welcome.

## 🛠️ Local Development Setup

1. **Prerequisites:** [Node.js](https://nodejs.org/) v20.10.0 or newer.
2. **Clone your fork:** `git clone https://github.com/<your-username>/Geo-Forensics.git`
3. **Navigate to the app directory:** `cd Geo-Forensics/src`
4. **Install dependencies:** `npm install`
5. **Run the application:** `npm start`
6. **Run the tests:** `npm test`

## 💻 Code Standards & Expectations

* **Tests:** The scanning engine and local API are covered by the test suite in `src/test/`. Please keep `npm test` green and add tests for new backend behavior. Tests run automatically on every pull request.
* **UI/UX consistency:** Any new buttons, modals, or controls must fully support both **dark mode** and **light mode** (see the `body.light-theme` rules in `styles.css`).
* **Non-blocking logic:** The scanning backend must remain asynchronous. Do not introduce synchronous file reads that could freeze the app during large directory scans.
* **Security:** The embedded server must stay bound to `127.0.0.1`, and endpoints that touch the filesystem must never serve paths outside the current scan's allowlist. Escape all metadata (it comes from untrusted files) before inserting it into the DOM.
* **Comments:** Explain the *why* behind non-obvious logic, especially around EXIF handling and map rendering.

## 🚀 How to Contribute

1. **Fork the repository** and create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-improvement
   ```
2. **Make your changes** and commit with a clear, descriptive message.
3. **Push** the branch to your fork and **open a pull request** against `main`, describing:
   - **What** you changed
   - **Why** the change is needed
   - **How** to test it
4. **Engage in review** — respond to comments and update the PR as needed.

## 📜 Licensing of Contributions

GeoForensics is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**. By submitting a pull request you agree that your contribution is licensed under AGPL-3.0. You retain the copyright to your work — there is no copyright assignment or CLA.

GeoForensics is a fork of [Refloow Geo Forensics](https://github.com/Refloow/Refloow-Geo-Forensics) by Veljko Vuckovic; the original copyright notices in the source files must be preserved.
