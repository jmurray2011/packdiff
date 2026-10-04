# Changelog

All notable changes are documented here, following [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.1] - 2026-10-04

### Fixed
- RPMs that record a size for directories, as nFPM and GoReleaser write them, lost their directory entries, and their RPM 6 form failed to read. Directory permission and owner changes in such packages are now reported.

## [0.1.0] - 2026-10-04

### Added
- Static comparison of two release artifacts (RPM including RPM 6, DEB, WAR, JAR, EAR, ZIP including self-executing jars, and tar plain or compressed with gzip, xz, zstd, or bzip2), reporting changes in config, outbound reach, crypto, schema, host footprint, dependencies, and file contents.
- First-party JavaScript scanned through source maps that embed their sources.
- JSON result, terminal summary, and a self-contained HTML report.
- Suppression and pattern rules, with built-in suppression of namespace URIs, documentation links, loopback addresses, and build metadata.
- Memory limits on nested archives and kept content.
- Static Linux, macOS, and Windows binaries with SHA-256 checksums, cosign bundles, build provenance, per-binary SBOMs, and Apache-2.0 licensing.
