using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace JarLens.Scanner;

public sealed class JarScanner
{
    private const int MaxEvidencePerRule = 10;

    public ScanResult Scan(string jarPath, IReadOnlyList<IndicatorRule>? rules = null)
    {
        if (!File.Exists(jarPath))
        {
            throw new FileNotFoundException("Jar file was not found.", jarPath);
        }

        var file = new FileInfo(jarPath);
        var documents = new List<ScanDocument>();
        var metadata = new List<string>();
        var entryCount = 0;
        var classCount = 0;
        var nestedJarCount = 0;
        var embeddedExecutables = new List<Evidence>();

        using var archive = ZipFile.OpenRead(jarPath);
        foreach (var entry in archive.Entries)
        {
            if (string.IsNullOrEmpty(entry.Name))
            {
                continue;
            }

            entryCount++;
            var name = entry.FullName.Replace('\\', '/');
            if (name.EndsWith(".class", StringComparison.OrdinalIgnoreCase))
            {
                classCount++;
            }
            else if (name.EndsWith(".jar", StringComparison.OrdinalIgnoreCase))
            {
                nestedJarCount++;
                documents.Add(new ScanDocument(name, "nested jar"));
            }
            else if (IsExecutableOrScript(name))
            {
                embeddedExecutables.Add(new Evidence { Source = name, Match = Path.GetExtension(name) });
                documents.Add(new ScanDocument(name, "embedded executable or script"));
            }

            var bytes = ReadEntryBytes(entry);
            if (bytes.Length == 0)
            {
                continue;
            }

            if (IsMetadataFile(name))
            {
                var text = DecodeText(bytes);
                metadata.Add($"{name}:{Environment.NewLine}{TrimForReport(text, 1200)}");
                documents.Add(new ScanDocument(name, text));
            }

            var strings = ExtractPrintableStrings(bytes);
            if (strings.Count > 0)
            {
                documents.Add(new ScanDocument(name, string.Join('\n', strings)));
            }
        }

        if (nestedJarCount > 0)
        {
            documents.Add(new ScanDocument("archive", $"{nestedJarCount} nested jar file(s)"));
        }

        var activeRules = rules is { Count: > 0 } ? rules : RuleCatalog.DefaultRules;
        var findings = MatchRules(activeRules, documents);
        findings.AddRange(BuildCompositeFindings(findings));
        if (nestedJarCount > 0)
        {
            findings.Add(new Finding
            {
                RuleId = "nested_jars",
                Label = "Nested jar payloads",
                Category = "Loader / Packaging",
                Severity = Severity.Low,
                Explanation = "Nested jars are common in shaded mods/plugins, but they can also hide secondary payloads. Review them when other suspicious indicators are present.",
                Evidence = [new Evidence { Source = "archive", Match = $"{nestedJarCount} nested jar file(s)" }]
            });
        }
        if (embeddedExecutables.Count > 0)
        {
            findings.Add(new Finding
            {
                RuleId = "embedded_executable_or_script",
                Label = "Embedded executable or script",
                Category = "Payload / Dropper",
                Severity = Severity.Medium,
                Explanation = "Jars can contain resources, but embedded executables or scripts are unusual for normal Minecraft mods/plugins and may be dropped or launched later.",
                Evidence = embeddedExecutables.Take(MaxEvidencePerRule).ToList()
            });
        }

        return new ScanResult
        {
            FileName = file.Name,
            FilePath = file.FullName,
            Sha256 = ComputeSha256(jarPath),
            SizeBytes = file.Length,
            EntryCount = entryCount,
            ClassCount = classCount,
            NestedJarCount = nestedJarCount,
            EmbeddedExecutableCount = embeddedExecutables.Count,
            Metadata = metadata,
            Findings = findings.OrderByDescending(f => f.Severity).ThenBy(f => f.Category).ToList(),
            Risk = Score(findings)
        };
    }

    private static List<Finding> MatchRules(IReadOnlyList<IndicatorRule> rules, IReadOnlyList<ScanDocument> documents)
    {
        var findings = new List<Finding>();

        foreach (var rule in rules)
        {
            var evidence = new List<Evidence>();
            foreach (var pattern in rule.Patterns)
            {
                foreach (var document in documents)
                {
                    if (pattern.AppliesTo is not null &&
                        !document.Source.Contains(pattern.AppliesTo, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    if (IsMatch(document.Text, pattern))
                    {
                        evidence.Add(new Evidence
                        {
                            Source = document.Source,
                            Match = pattern.Value
                        });
                    }

                    if (evidence.Count >= MaxEvidencePerRule)
                    {
                        break;
                    }
                }

                if (evidence.Count >= MaxEvidencePerRule)
                {
                    break;
                }
            }

            if (evidence.Count > 0)
            {
                var explanation = string.IsNullOrWhiteSpace(rule.FalsePositiveHint)
                    ? rule.Explanation
                    : rule.Explanation + " False-positive note: " + rule.FalsePositiveHint;

                findings.Add(new Finding
                {
                    RuleId = rule.Id,
                    Label = rule.Label,
                    Category = rule.Category,
                    Severity = rule.Severity,
                    Explanation = explanation,
                    Evidence = evidence.DistinctBy(e => $"{e.Source}|{e.Match}").ToList()
                });
            }
        }

        return findings;
    }

    private static List<Finding> BuildCompositeFindings(IReadOnlyList<Finding> findings)
    {
        var byId = findings.ToDictionary(f => f.RuleId, StringComparer.OrdinalIgnoreCase);
        var composites = new List<Finding>();
        byId.TryGetValue("discord_webhook", out var discordWebhook);
        byId.TryGetValue("telegram_bot_api", out var telegramApi);
        byId.TryGetValue("common_exfil_endpoint", out var exfilEndpoint);

        if (byId.TryGetValue("discord_token_storage", out var discordStorage) &&
            (discordWebhook is not null || telegramApi is not null || exfilEndpoint is not null))
        {
            composites.Add(new Finding
            {
                RuleId = "combo_token_access_and_exfil",
                Label = "Token storage access with exfiltration path",
                Category = "Token Logger",
                Severity = Severity.Critical,
                Explanation = "The jar contains both local token-storage indicators and a likely outbound exfiltration path. This combination is much stronger than either signal alone.",
                Evidence = CombineEvidence(discordStorage, discordWebhook, telegramApi, exfilEndpoint)
            });
        }

        if (byId.TryGetValue("minecraft_auth_files", out var minecraftAuth) &&
            (discordWebhook is not null || telegramApi is not null || exfilEndpoint is not null))
        {
            composites.Add(new Finding
            {
                RuleId = "combo_minecraft_auth_and_exfil",
                Label = "Minecraft auth access with exfiltration path",
                Category = "Minecraft Session Stealer",
                Severity = Severity.Critical,
                Explanation = "The jar contains Minecraft account/session indicators plus a likely outbound exfiltration path.",
                Evidence = CombineEvidence(minecraftAuth, discordWebhook, telegramApi, exfilEndpoint)
            });
        }

        if (byId.TryGetValue("runtime_loader", out var loader) &&
            byId.TryGetValue("networking_api", out var network))
        {
            composites.Add(new Finding
            {
                RuleId = "combo_network_loader",
                Label = "Network-capable runtime loader",
                Category = "Loader / Downloader",
                Severity = Severity.High,
                Explanation = "The jar contains networking APIs and runtime class-loading indicators. This can be benign, but it is also a common downloader/loader pattern.",
                Evidence = CombineEvidence(loader, network)
            });
        }

        return composites;
    }

    private static IReadOnlyList<Evidence> CombineEvidence(params Finding?[] findings) =>
        findings
            .Where(f => f is not null)
            .SelectMany(f => f!.Evidence)
            .DistinctBy(e => $"{e.Source}|{e.Match}")
            .Take(MaxEvidencePerRule)
            .ToList();

    private static bool IsMatch(string text, RulePattern pattern) =>
        pattern.Kind switch
        {
            PatternKind.Regex => Regex.IsMatch(text, pattern.Value, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(250)),
            _ => text.Contains(pattern.Value, StringComparison.OrdinalIgnoreCase)
        };

    private static RiskSummary Score(IReadOnlyList<Finding> findings)
    {
        var score = findings.Sum(f => f.Severity switch
        {
            Severity.Critical => 60,
            Severity.High => 35,
            Severity.Medium => 15,
            Severity.Low => 5,
            _ => 0
        });

        var highestSeverity = findings.Count == 0 ? Severity.Info : findings.Max(f => f.Severity);
        var level = score switch
        {
            _ when highestSeverity >= Severity.High => "High",
            >= 30 => "Medium",
            >= 1 => "Low",
            _ => "No indicators"
        };

        var verdict = level switch
        {
            "High" => "High-risk indicators were found. Treat this jar as unsafe until manually reviewed.",
            "Medium" => "Suspicious indicators were found. Review the evidence before running this jar.",
            "Low" => "Only low-confidence indicators were found. This does not prove the jar is safe.",
            _ => "No known malicious indicators were found by the current static rule catalog."
        };

        return new RiskSummary { Level = level, Score = score, Verdict = verdict };
    }

    private static byte[] ReadEntryBytes(ZipArchiveEntry entry)
    {
        using var source = entry.Open();
        using var memory = new MemoryStream();
        source.CopyTo(memory);
        return memory.ToArray();
    }

    private static bool IsMetadataFile(string name) =>
        name.Equals("META-INF/MANIFEST.MF", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("plugin.yml", StringComparison.OrdinalIgnoreCase) ||
        name.EndsWith("mods.toml", StringComparison.OrdinalIgnoreCase) ||
        name.EndsWith("fabric.mod.json", StringComparison.OrdinalIgnoreCase) ||
        name.EndsWith("quilt.mod.json", StringComparison.OrdinalIgnoreCase) ||
        name.EndsWith("pom.xml", StringComparison.OrdinalIgnoreCase) ||
        name.EndsWith("pom.properties", StringComparison.OrdinalIgnoreCase);

    private static bool IsExecutableOrScript(string name)
    {
        var extension = Path.GetExtension(name);
        return extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".scr", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".ps1", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".bat", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".cmd", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".vbs", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".js", StringComparison.OrdinalIgnoreCase);
    }

    private static string DecodeText(byte[] bytes)
    {
        try
        {
            return Encoding.UTF8.GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            return Encoding.Latin1.GetString(bytes);
        }
    }

    private static IReadOnlyList<string> ExtractPrintableStrings(byte[] bytes)
    {
        var strings = new List<string>();
        var builder = new StringBuilder();

        foreach (var value in bytes)
        {
            if (value is >= 32 and <= 126)
            {
                builder.Append((char)value);
            }
            else
            {
                FlushString(builder, strings);
            }
        }

        FlushString(builder, strings);
        return strings;
    }

    private static void FlushString(StringBuilder builder, List<string> strings)
    {
        if (builder.Length >= 4)
        {
            strings.Add(builder.ToString());
        }

        builder.Clear();
    }

    private static string ComputeSha256(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static string TrimForReport(string value, int maxLength) =>
        value.Length <= maxLength ? value : value[..maxLength] + "\n...";

    private sealed record ScanDocument(string Source, string Text);
}
