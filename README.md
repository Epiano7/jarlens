# JarLens

Portable static malware triage for Minecraft jars and Java plugins.

JarLens is built for quick, explainable review of suspicious `.jar` files before anyone runs them. It unpacks the archive, extracts metadata and printable class strings, checks a readable rule catalog, and produces a risk report with evidence for every finding.

## Trust promise

- JarLens does not execute jars.
- JarLens does not upload jars.
- JarLens makes no network requests during scanning.
- JarLens only contacts GitHub when you click **Check updates**.
- JarLens is a static triage tool, not a guarantee that a jar is safe.

## Current features

- Portable Windows WPF app with drag-and-drop jar scanning.
- CLI scanner for scripts and CI.
- SHA-256 fingerprinting.
- Manifest, Bukkit/Paper `plugin.yml`, Forge/Fabric metadata extraction.
- Nested jar detection.
- Rule-based detection for token loggers, Minecraft session stealers, credential paths, IP grabbers, loaders, process execution, and obfuscation helpers.
- Human-readable findings with category, severity, explanation, and evidence.
- Manual GitHub Releases update check.

## Updates

JarLens compares its built-in app version to the latest GitHub Release only when you click **Check updates**. It does not upload scanned jars or send scan results.

Portable app updates are release-based, not commit-based. Normal users should install tagged releases such as `v1.0.0`, not arbitrary commits.

## Build

```powershell
dotnet build JarLens.sln -c Release
```

## Run the CLI

```powershell
dotnet run --project src/JarLens.Cli -- "C:\path\to\file.jar"
```

To scan with the editable catalog in `rules/`:

```powershell
dotnet run --project src/JarLens.Cli -- "C:\path\to\file.jar" rules
```

## Portable release

```powershell
dotnet publish src/JarLens.App -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true -p:EnableCompressionInSingleFile=true
```

The output exe is written under:

```text
src/JarLens.App/bin/Release/net9.0-windows/win-x64/publish/
```

## Rule catalog

Rules are stored as JSON files in `rules/`. See [docs/rule-format.md](docs/rule-format.md).

## Important limitation

Static analysis catches many common stealers and loaders, but it cannot prove a jar is safe. Obfuscated or staged malware may require manual reverse engineering or sandbox execution in an isolated VM.
