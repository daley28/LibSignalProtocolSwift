# Changelog

## Unreleased

### Patch

- Fixed SwiftPM CommonCrypto linkage on macOS by removing the invalid explicit `CommonCrypto` library link.
- Made the global crypto provider storage concurrency-safe while preserving the existing `SignalCrypto.provider` getter and setter API.
- Added strict-concurrency verification to the maintainer workflow.
- Added package maintainer documentation for local verification and protocol buffer regeneration.
