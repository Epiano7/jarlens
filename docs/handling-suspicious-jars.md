# Handling Suspicious Jars

Treat unknown jars like untrusted executable files.

## Safer handling

- Do not double-click or run suspicious jars.
- Do not open them with Java, Minecraft, a mod loader, or a server.
- Store samples in a clearly labeled quarantine folder.
- Prefer a disposable VM or test machine with no Discord, browser, Minecraft, or password-manager sessions.
- Keep samples zipped if you need to move them around.
- Do not share live malware publicly in the repository.

## Lower risk does not mean no risk

An unopened jar sitting on disk is much lower risk than an executed jar, but accidents happen: file association mistakes, previews, antivirus actions, or accidental drag/drop into a mod folder. Keep suspicious files away from normal downloads and game folders.

## JarLens behavior

JarLens statically inspects jars as archives. It does not execute jars, load jar classes, or upload scanned files.
