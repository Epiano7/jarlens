# Release Process

Use a real Markdown notes file for release bodies. Do not pass notes with escaped
`\n` sequences on the command line, because GitHub will render those as literal
text.

Keep public release notes user-facing. Mention shipped features, fixes, and
behavior changes, but keep local verification details, private sample names, and
work-in-progress context out of public changelogs.

## Manual release notes

Create a temporary notes file:

```powershell
@'
JarLens v1.0.6 short summary.

- First change.
- Second change.
- Verification note.
'@ | Set-Content -LiteralPath release-notes.md -Encoding UTF8
```

Create or update the GitHub release with `--notes-file`:

```powershell
gh release create v1.0.6 artifacts/JarLens-win-x64.zip artifacts/JarLens-win-x64.zip.sha256 artifacts/JarLens-win-x64/SHA256SUMS.txt --title "JarLens v1.0.6" --notes-file release-notes.md
```

For an existing release:

```powershell
gh release edit v1.0.6 --notes-file release-notes.md
```
