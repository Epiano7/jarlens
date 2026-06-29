using System.Text.Json;
using System.Text.Json.Serialization;

namespace JarLens.Scanner;

public static class RuleCatalog
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public static IReadOnlyList<IndicatorRule> LoadDirectory(string directory)
    {
        if (!Directory.Exists(directory))
        {
            return DefaultRules;
        }

        var rules = new List<IndicatorRule>();
        foreach (var file in Directory.EnumerateFiles(directory, "*.json").Order())
        {
            var parsed = JsonSerializer.Deserialize<List<IndicatorRule>>(File.ReadAllText(file), JsonOptions);
            if (parsed is not null)
            {
                rules.AddRange(parsed);
            }
        }

        return rules.Count == 0 ? DefaultRules : rules;
    }

    public static IReadOnlyList<IndicatorRule> DefaultRules { get; } =
    [
        new()
        {
            Id = "discord_webhook",
            Label = "Discord webhook endpoint",
            Category = "Token Logger / Exfiltration",
            Severity = Severity.High,
            Explanation = "Discord webhooks are commonly used by jar stealers to send tokens, IPs, screenshots, or system data to an attacker-controlled channel.",
            Patterns =
            [
                new() { Value = "discord.com/api/webhooks" },
                new() { Value = "discordapp.com/api/webhooks" }
            ]
        },
        new()
        {
            Id = "discord_token_regex",
            Label = "Discord token-looking string",
            Category = "Token Logger / Credential Artifact",
            Severity = Severity.High,
            Explanation = "The jar contains a string shaped like a Discord token. This may be a hardcoded test token, stolen token, or token-pattern handling code.",
            Patterns =
            [
                new() { Value = @"mfa\.[A-Za-z0-9_-]{20,}", Kind = PatternKind.Regex },
                new() { Value = @"[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{20,}", Kind = PatternKind.Regex }
            ]
        },
        new()
        {
            Id = "discord_token_storage",
            Label = "Discord token storage access",
            Category = "Token Logger",
            Severity = Severity.High,
            Explanation = "References to Discord LevelDB or Local State paths can indicate token harvesting from local Discord clients.",
            FalsePositiveHint = "Discord rich presence or IPC integrations may mention Discord client names without reading token storage. Stronger evidence is a combination of Local State, leveldb, and exfiltration.",
            Patterns =
            [
                new() { Value = "Local State" },
                new() { Value = "leveldb" }
            ]
        },
        new()
        {
            Id = "telegram_bot_api",
            Label = "Telegram bot API endpoint",
            Category = "Exfiltration",
            Severity = Severity.High,
            Explanation = "Telegram bot endpoints are often used by stealers to send data out of a victim machine.",
            Patterns =
            [
                new() { Value = @"api\.telegram\.org/bot[A-Za-z0-9:_-]+/send", Kind = PatternKind.Regex },
                new() { Value = "api.telegram.org/bot" }
            ]
        },
        new()
        {
            Id = "common_exfil_endpoint",
            Label = "Common exfiltration endpoint",
            Category = "Exfiltration",
            Severity = Severity.Medium,
            Explanation = "The jar references a service commonly used to receive or stage stolen data.",
            Patterns =
            [
                new() { Value = "webhook.site", AppliesTo = ".class" },
                new() { Value = "pastebin.com/api", AppliesTo = ".class" },
                new() { Value = "hastebin", AppliesTo = ".class" },
                new() { Value = "requestbin", AppliesTo = ".class" },
                new() { Value = "ngrok-free.app", AppliesTo = ".class" },
                new() { Value = "trycloudflare.com", AppliesTo = ".class" }
            ]
        },
        new()
        {
            Id = "public_ip_lookup",
            Label = "Public IP lookup service",
            Category = "IP Grabber",
            Severity = Severity.Medium,
            Explanation = "Public IP lookup APIs are commonly used to identify and exfiltrate a user's external IP address.",
            Patterns =
            [
                new() { Value = "api.ipify.org" },
                new() { Value = "ifconfig.me" },
                new() { Value = "icanhazip.com" },
                new() { Value = "ipinfo.io" },
                new() { Value = "checkip.amazonaws.com" }
            ]
        },
        new()
        {
            Id = "minecraft_auth_files",
            Label = "Minecraft account/session file access",
            Category = "Minecraft Session Stealer",
            Severity = Severity.High,
            Explanation = "Minecraft launcher auth files may contain account/session material useful to steal accounts or sessions.",
            FalsePositiveHint = "Generic .minecraft mentions are common in legitimate mods, so this rule only looks for account/session file names and token strings.",
            Patterns =
            [
                new() { Value = "launcher_accounts.json" },
                new() { Value = "accounts.json" },
                new() { Value = "accessToken" },
                new() { Value = "clientToken" }
            ]
        },
        new()
        {
            Id = "browser_secret_paths",
            Label = "Browser credential storage access",
            Category = "Credential Stealer",
            Severity = Severity.High,
            Explanation = "Browser cookie, password, and key database paths are often used by credential stealers.",
            FalsePositiveHint = "Generic cookie classes are common in HTTP libraries, so this rule avoids matching the standalone word Cookies.",
            Patterns =
            [
                new() { Value = "Login Data" },
                new() { Value = "Network\\Cookies" },
                new() { Value = "AppData\\Local\\Google\\Chrome" },
                new() { Value = "Microsoft\\Edge\\User Data" },
                new() { Value = "BraveSoftware\\Brave-Browser\\User Data" }
            ]
        },
        new()
        {
            Id = "persistence_paths",
            Label = "Persistence/startup path",
            Category = "Persistence",
            Severity = Severity.High,
            Explanation = "References to startup folders, Run registry keys, or scheduled tasks may indicate an attempt to persist after reboot.",
            Patterns =
            [
                new() { Value = @"Microsoft\\Windows\\Start Menu\\Programs\\Startup" },
                new() { Value = @"Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
                new() { Value = "schtasks" },
                new() { Value = "Task Scheduler" }
            ]
        },
        new()
        {
            Id = "process_execution",
            Label = "Process or shell execution",
            Category = "Remote Access / Persistence",
            Severity = Severity.Medium,
            Explanation = "Launching external processes from a Minecraft jar is unusual and can be used for persistence, downloaders, or system changes.",
            FalsePositiveHint = "Runtime metadata appears in normal class files, so this rule focuses on actual process execution APIs and shell names.",
            Patterns =
            [
                new() { Value = "java/lang/ProcessBuilder" },
                new() { Value = "Runtime.exec" },
                new() { Value = "powershell" },
                new() { Value = "cmd.exe" }
            ]
        },
        new()
        {
            Id = "networking_api",
            Label = "Networking APIs",
            Category = "Network Activity",
            Severity = Severity.Low,
            Explanation = "Network APIs are not malicious on their own, but unexpected outbound traffic from a mod/plugin deserves review.",
            Patterns =
            [
                new() { Value = "java/net/URL", AppliesTo = ".class" },
                new() { Value = "java/net/HttpURLConnection", AppliesTo = ".class" },
                new() { Value = "java/net/Socket", AppliesTo = ".class" },
                new() { Value = "java/net/http/HttpClient", AppliesTo = ".class" },
                new() { Value = "http://", AppliesTo = ".class" },
                new() { Value = "https://", AppliesTo = ".class" }
            ]
        },
        new()
        {
            Id = "runtime_loader",
            Label = "Runtime class loading",
            Category = "Loader / Obfuscation",
            Severity = Severity.Medium,
            Explanation = "Dynamic class loading can be legitimate, but it is also used to hide or download payloads.",
            FalsePositiveHint = "Plain ClassLoader references are common in libraries, so this rule focuses on URLClassLoader, defineClass, or reflective class lookup.",
            Patterns =
            [
                new() { Value = "java/net/URLClassLoader" },
                new() { Value = "defineClass" },
                new() { Value = "Class.forName" }
            ]
        },
        new()
        {
            Id = "crypto_encoding",
            Label = "Crypto or encoded payload helpers",
            Category = "Obfuscation / Evasion",
            Severity = Severity.Low,
            Explanation = "Base64 and crypto APIs are common in benign software too, but in small jars they can indicate hidden strings or payloads.",
            Patterns =
            [
                new() { Value = "java/util/Base64" },
                new() { Value = "javax/crypto/Cipher" },
                new() { Value = "AES" },
                new() { Value = "GZIPInputStream" }
            ]
        }
    ];
}
