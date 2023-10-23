# firmware-manifest-validator

Offline, read-only validation of a firmware manifest against a local target policy. When a local artifact basename is supplied, its byte length and SHA-256 digest are verified. This tool never signs, publishes, or flashes firmware.

## Run

Node.js 22+; no package dependencies or network calls.

```sh
node bin/firmware-manifest-validator.mjs --root examples/pass --policy policy.json --manifest manifest.json
node bin/firmware-manifest-validator.mjs --root examples/fail --policy policy.json --manifest manifest.json
npm run check
```

One JSON report goes to stdout: exit 0=`pass`, 1=`fail`, 2=`incomplete` or invalid configuration. Invalid options, root, or policy leave stdout empty. Unreadable or malformed manifest/artifact emits an incomplete report. JSON and firmware file paths are resolved by realpath beneath `--root`; duplicate decoded JSON keys and invalid UTF-8 JSON are rejected. No files are written.

## Policy and manifest

Policy: `{"schemaVersion":"1","targetHardware":"board-a","currentVersion":"1.2.3","bootloaderVersion":"2.0.0","maxBytes":1024,"fileVerification":"required"}`. `fileVerification` is `required` or `optional`. The maximum cannot exceed 16,777,216 bytes. Optional top-level `metadata` is non-semantic.

Manifest: `{"schemaVersion":"1","complete":true,"targetHardware":"board-a","version":"1.3.0","sizeBytes":19,"digestSha256":"<64 hex digits>","compatibleFrom":["1.2.3"],"minBootloaderVersion":"1.0.0","rollback":{"supported":true,"version":"1.2.3"},"file":"firmware.bin"}`. The `file` field, when present, is a basename under the root. The manifest version must advance the installed SemVer version; current firmware must be listed as compatible; the bootloader must meet the minimum; rollback must explicitly support the current version. Missing rollback is incomplete; `{"supported":false}` fails even without a version, while `supported:true` needs a valid current version. Wrong target, incompatible base/bootloader, excessive size, and mismatched local bytes or digest fail. If file verification is optional and no file is named, `digestVerification` is `not-supplied`, never `verified`. Findings use fixed messages and logical pointers, never raw hardware identifiers, versions, paths, or digest values. Signatures and authenticity are outside scope.

## Limits

Policy and manifest each ≤65,536 bytes; firmware ≤16,777,216 bytes; ≤100 compatible base versions; JSON depth ≤16; evaluation deadline 5,000 ms using an injected monotonic clock. Each declared bound accepts N and rejects N+1.
