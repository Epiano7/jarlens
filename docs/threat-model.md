# Threat Model

JarLens assumes scanned jars may be hostile.

## Default safety boundaries

- Do not execute scanned jars.
- Do not load jar classes into the JarLens process.
- Do not upload jar contents.
- Do not make network requests during normal scans.
- Treat nested jars as additional payloads requiring review.

## In scope

- Discord token loggers.
- Minecraft session/account stealers.
- IP grabbers.
- Browser credential path access.
- Runtime loaders and reflection-heavy payload staging.
- Suspicious process execution.
- Common encoding/crypto helpers used for obfuscation.

## Out of scope for the MVP

- Full Java decompilation.
- Behavioral sandboxing.
- Guaranteeing a clean verdict.
- Detecting every obfuscated malware family.
- Cloud reputation lookups.
