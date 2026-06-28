# Rule Format

JarLens rules are JSON objects grouped in arrays. The scanner loads every `*.json` file from a rules directory.

```json
{
  "id": "discord_webhook",
  "label": "Discord webhook endpoint",
  "category": "Token Logger / Exfiltration",
  "severity": "High",
  "explanation": "Why this indicator matters.",
  "patterns": [
    { "value": "discord.com/api/webhooks" },
    { "value": "java/net/HttpURLConnection" }
  ]
}
```

## Fields

- `id`: Stable machine-readable identifier.
- `label`: Short finding title shown in reports.
- `category`: Human-readable family such as `Token Logger`, `IP Grabber`, or `Loader / Obfuscation`.
- `severity`: `Info`, `Low`, `Medium`, `High`, or `Critical`.
- `explanation`: Plain-English reason this matters.
- `patterns`: Strings or regexes to search for in jar metadata and extracted class strings.

## Pattern kinds

```json
{ "value": "discord.com/api/webhooks", "kind": "Contains" }
{ "value": "mfa\\.[A-Za-z0-9_-]{20,}", "kind": "Regex" }
```

`Contains` is the default.
