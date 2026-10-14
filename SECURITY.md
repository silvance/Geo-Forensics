# Security

GeoForensics is built for offline, single-examiner forensic workstations.
This page states what it protects against and how to report a problem.

## Threat model

- **Evidence must never leave the machine.** Air-Gapped Mode (default on)
  cancels every non-loopback request in the Electron main process and
  disables Chromium background networking and the auto-updater. The local
  HTTP server binds to 127.0.0.1 only.
- **Other local processes must not reach the evidence API.** The desktop
  app generates a random token at launch and requires it on every `/api`
  request; only the app's own renderer receives it. `/api/image` serves only
  files discovered by the current scan.
- **File metadata is untrusted input.** Every value read from a file is
  HTML-escaped before display, a Content Security Policy restricts the UI to
  the loopback origin, and offline map packages are opened read-only with
  parameterized, integer-only SQL.
- **Evidence is never modified.** Files are read-only; hashes are computed on
  the original bytes.

Out of scope: a compromised operating system, a malicious examiner on the
same account, and tampering with the ExifTool binary shipped in the bundle.

## Reporting a vulnerability

Open a private security advisory on GitHub
(Security → Report a vulnerability) or, if that is unavailable, an issue
with no exploit details asking for a contact. Please include the version
(Settings shows it), the platform and steps to reproduce. You should hear
back within a week.
