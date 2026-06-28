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
            Id = "discord_token_storage",
            Label = "Discord token storage access",
            Category = "Token Logger",
            Severity = Severity.High,
            Explanation = "References to Discord LevelDB or Local State paths can indicate token harvesting from local Discord clients.",
            Patterns =
            [
                new() { Value = "Local State" },
                new() { Value = "leveldb" },
                new() { Value = "discordcanary" },
                new() { Value = "discordptb" }
            ]
        },
        new()
        {
            Id = "minecraft_auth_files",
            Label = "Minecraft account/session file access",
            Category = "Minecraft Session Stealer",
            Severity = Severity.High,
            Explanation = "Minecraft launcher auth files may contain account/session material useful to steal accounts or sessions.",
            Patterns =
            [
                new() { Value = ".minecraft" },
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
            Patterns =
            [
                new() { Value = "Login Data" },
                new() { Value = "Cookies" },
                new() { Value = "User Data" },
                new() { Value = "AppData\\Local\\Google\\Chrome" },
                new() { Value = "Microsoft\\Edge\\User Data" }
            ]
        },
        new()
        {
            Id = "process_execution",
            Label = "Process or shell execution",
            Category = "Remote Access / Persistence",
            Severity = Severity.Medium,
            Explanation = "Launching external processes from a Minecraft jar is unusual and can be used for persistence, downloaders, or system changes.",
            Patterns =
            [
                new() { Value = "java/lang/Runtime" },
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
            Patterns =
            [
                new() { Value = "java/net/URLClassLoader" },
                new() { Value = "java/lang/ClassLoader" },
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
