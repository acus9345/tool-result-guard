# Changelog

All notable changes to this project are documented here. This project follows [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-29

### Added

- `createGuard(options)` with `check()`, `value()`, `wrapTool()`, `tools()`, `mcpResult()` and `mcpClient()`.
- Policy per risk level with the actions `pass`, `flag`, `sanitize`, `redact`, `wrap` and `block`. Default: pass clean text, sanitize low, wrap medium, block high.
- `onDetect` hook, custom `blockMessage`, `throwOnBlock` with `GuardBlockedError`, and injection-scan options via `scan`.
- `guardText()` and `redact()` helpers.

[0.1.0]: https://github.com/acus9345/tool-result-guard/releases/tag/v0.1.0
