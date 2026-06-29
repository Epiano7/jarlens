using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace JarLens.Scanner;

public sealed class JarScanner
{
    private const int MaxEvidencePerRule = 10;
    private const int MaxNestedDepth = 4;

    public ScanResult Scan(string jarPath, IReadOnlyList<IndicatorRule>? rules = null)
    {
        if (!File.Exists(jarPath))
        {
            throw new FileNotFoundException("Jar file was not found.", jarPath);
        }

        var file = new FileInfo(jarPath);
        var documents = new List<ScanDocument>();
        var metadata = new List<string>();
        var stats = new ScanStats();
        var embeddedExecutables = new List<Evidence>();

        using var archive = ZipFile.OpenRead(jarPath);
        ProcessArchive(archive, file.Name, 0, documents, metadata, embeddedExecutables, stats);

        if (stats.NestedJarCount > 0)
        {
            documents.Add(new ScanDocument("archive", $"{stats.NestedJarCount} nested jar file(s) recursively inspected"));
        }

        var activeRules = rules is { Count: > 0 } ? rules : RuleCatalog.DefaultRules;
        var findings = MatchRules(activeRules, documents);
        findings.AddRange(BuildMetadataFindings(file.Name, documents));
        if (stats.NestedJarCount > 0)
        {
            findings.Add(new Finding
            {
                RuleId = "nested_jars",
                Label = "Nested jar payloads",
                Category = "Loader / Packaging",
                Severity = Severity.Low,
                Explanation = "Nested jars are common in shaded mods/plugins, but they can also hide secondary payloads. Review them when other suspicious indicators are present.",
                Evidence = [new Evidence { Source = "archive", Match = $"{stats.NestedJarCount} nested jar file(s) recursively inspected" }]
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
        findings.AddRange(BuildCompositeFindings(findings));

        return new ScanResult
        {
            FileName = file.Name,
            FilePath = file.FullName,
            Sha256 = ComputeSha256(jarPath),
            SizeBytes = file.Length,
            EntryCount = stats.EntryCount,
            ClassCount = stats.ClassCount,
            NestedJarCount = stats.NestedJarCount,
            EmbeddedExecutableCount = embeddedExecutables.Count,
            Metadata = metadata,
            Findings = findings.OrderByDescending(f => f.Severity).ThenBy(f => f.Category).ToList(),
            Risk = Score(findings)
        };
    }

    private static void ProcessArchive(
        ZipArchive archive,
        string sourcePrefix,
        int depth,
        List<ScanDocument> documents,
        List<string> metadata,
        List<Evidence> embeddedExecutables,
        ScanStats stats)
    {
        foreach (var entry in archive.Entries)
        {
            if (string.IsNullOrEmpty(entry.Name))
            {
                continue;
            }

            stats.EntryCount++;
            var name = entry.FullName.Replace('\\', '/');
            var sourceName = sourcePrefix + "!/" + name;
            var bytes = ReadEntryBytes(entry);

            if (name.EndsWith(".class", StringComparison.OrdinalIgnoreCase))
            {
                stats.ClassCount++;
            }
            else if (name.EndsWith(".jar", StringComparison.OrdinalIgnoreCase))
            {
                stats.NestedJarCount++;
                documents.Add(new ScanDocument(sourceName, "nested jar"));

                if (depth < MaxNestedDepth && bytes.Length > 0)
                {
                    TryProcessNestedJar(bytes, sourceName, depth + 1, documents, metadata, embeddedExecutables, stats);
                }
            }
            else if (IsExecutableOrScript(name))
            {
                embeddedExecutables.Add(new Evidence { Source = sourceName, Match = Path.GetExtension(name) });
                documents.Add(new ScanDocument(sourceName, "embedded executable or script"));
            }

            if (bytes.Length == 0)
            {
                continue;
            }

            if (IsMetadataFile(name))
            {
                var text = DecodeText(bytes);
                metadata.Add($"{sourceName}:{Environment.NewLine}{TrimForReport(text, 1200)}");
                documents.Add(new ScanDocument(sourceName, text));
            }

            if (IsExecutableOrScript(name))
            {
                continue;
            }

            var strings = ExtractPrintableStrings(bytes);
            if (strings.Count > 0)
            {
                documents.Add(new ScanDocument(sourceName, string.Join('\n', strings)));
            }
        }
    }

    private static void TryProcessNestedJar(
        byte[] bytes,
        string sourceName,
        int depth,
        List<ScanDocument> documents,
        List<string> metadata,
        List<Evidence> embeddedExecutables,
        ScanStats stats)
    {
        try
        {
            using var memory = new MemoryStream(bytes);
            using var nestedArchive = new ZipArchive(memory, ZipArchiveMode.Read, leaveOpen: false);
            ProcessArchive(nestedArchive, sourceName, depth, documents, metadata, embeddedExecutables, stats);
        }
        catch (InvalidDataException)
        {
            documents.Add(new ScanDocument(sourceName, "nested jar could not be opened"));
        }
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

                    if (TryMatch(document.Text, pattern, out var matchedValue))
                    {
                        evidence.Add(new Evidence
                        {
                            Source = document.Source,
                            Match = matchedValue
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
            var overlap = FindSourceOverlap(loader, network);
            if (overlap.Count > 0)
            {
                composites.Add(new Finding
                {
                    RuleId = "combo_network_loader",
                    Label = "Network-capable runtime loader",
                    Category = "Loader / Downloader",
                    Severity = Severity.Medium,
                    Explanation = "The same class contains networking APIs and runtime class-loading indicators. This can be benign in mod loaders, but it is also a downloader/loader pattern worth reviewing.",
                    Evidence = overlap
                });
            }
        }

        if (byId.TryGetValue("process_execution", out var process) &&
            byId.TryGetValue("networking_api", out var networking) &&
            byId.TryGetValue("crypto_encoding", out var crypto))
        {
            var overlap = FindSourceOverlap(process, networking, crypto);
            if (overlap.Count > 0)
            {
                composites.Add(new Finding
                {
                    RuleId = "combo_process_network_crypto_same_class",
                    Label = "Process execution, networking, and crypto in same class",
                    Category = "RAT / Loader",
                    Severity = Severity.Critical,
                    Explanation = "The same class contains process-launch, network, and encoding/crypto indicators. This is a strong malware pattern for launchers, stealers, and remote-access payloads.",
                    Evidence = overlap
                });
            }
        }

        if (byId.TryGetValue("metadata_identity_mismatch", out var identityMismatch) &&
            byId.TryGetValue("nested_jars", out var nestedJars) &&
            byId.TryGetValue("networking_api", out var metadataNetworking) &&
            byId.TryGetValue("crypto_encoding", out var metadataCrypto))
        {
            composites.Add(new Finding
            {
                RuleId = "combo_impersonation_nested_network_code",
                Label = "Possible repackaged mod with nested network-capable code",
                Category = "Impersonation / Loader",
                Severity = Severity.High,
                Explanation = "The jar filename/branding does not match its declared mod identity, and the package also contains nested jars with network and encoding helpers. This combination is common in repackaged malware even when each low-level API is individually explainable.",
                Evidence = CombineEvidence(identityMismatch, nestedJars, metadataNetworking, metadataCrypto)
            });
        }

        return composites;
    }

    private static List<Finding> BuildMetadataFindings(string fileName, IReadOnlyList<ScanDocument> documents)
    {
        var findings = new List<Finding>();
        foreach (var metadata in documents
            .Where(d => d.Source.EndsWith("fabric.mod.json", StringComparison.OrdinalIgnoreCase))
            .DistinctBy(d => d.Source, StringComparer.OrdinalIgnoreCase))
        {
            var suspiciousEntrypoints = Regex.Matches(metadata.Text, "\"com\\.github\\.[A-Za-z0-9_$]+\"")
                .Select(match => new Evidence { Source = metadata.Source, Match = match.Value.Trim('"') })
                .DistinctBy(e => $"{e.Source}|{e.Match}")
                .Take(MaxEvidencePerRule)
                .ToList();

            if (suspiciousEntrypoints.Count > 0)
            {
                findings.Add(new Finding
                {
                    RuleId = "suspicious_fabric_entrypoint",
                    Label = "Suspicious Fabric entrypoint",
                    Category = "Impersonation / Loader",
                    Severity = Severity.High,
                    Explanation = "The Fabric metadata registers an entrypoint under a generic com.github package. In mod impersonation cases, extra entrypoints can be used to launch hidden payload code alongside a legitimate-looking mod.",
                    Evidence = suspiciousEntrypoints
                });
            }

            if (IsRootMetadata(fileName, metadata.Source) &&
                TryBuildIdentityMismatchEvidence(fileName, metadata, out var mismatchEvidence))
            {
                findings.Add(new Finding
                {
                    RuleId = "metadata_identity_mismatch",
                    Label = "Jar filename does not match declared mod identity",
                    Category = "Impersonation / Loader",
                    Severity = Severity.Medium,
                    Explanation = "The outer jar name appears unrelated to the Fabric mod id/name declared inside the jar. This can happen with harmless renames, but it is also a common sign of repackaged or impersonated mods.",
                    Evidence = [mismatchEvidence]
                });
            }
        }

        foreach (var manifest in documents
            .Where(d => d.Source.EndsWith("META-INF/MANIFEST.MF", StringComparison.OrdinalIgnoreCase))
            .DistinctBy(d => d.Source, StringComparer.OrdinalIgnoreCase))
        {
            var mainClass = Regex.Match(manifest.Text, @"(?m)^Main-Class:\s*(com\.github\.[A-Za-z0-9_.$-]+)\s*$");
            if (mainClass.Success)
            {
                findings.Add(new Finding
                {
                    RuleId = "suspicious_manifest_main_class",
                    Label = "Suspicious manifest main class",
                    Category = "Impersonation / Loader",
                    Severity = Severity.Medium,
                    Explanation = "The jar manifest defines a generic com.github Main-Class. Minecraft mods usually load through mod metadata; an unrelated main class can be a sign of repackaging or a hidden launcher.",
                    Evidence = [new Evidence { Source = manifest.Source, Match = mainClass.Groups[1].Value }]
                });
            }
        }

        return findings;
    }

    private static bool IsRootMetadata(string fileName, string source) =>
        source.Equals(fileName + "!/fabric.mod.json", StringComparison.OrdinalIgnoreCase) ||
        source.Equals(fileName + "!/quilt.mod.json", StringComparison.OrdinalIgnoreCase);

    private static bool TryBuildIdentityMismatchEvidence(string fileName, ScanDocument metadata, out Evidence evidence)
    {
        evidence = new Evidence { Source = metadata.Source, Match = string.Empty };
        var fileTokens = ExtractIdentityTokens(Path.GetFileNameWithoutExtension(fileName));
        if (fileTokens.Count == 0)
        {
            return false;
        }

        var id = FirstJsonStringValue(metadata.Text, "id");
        var name = FirstJsonStringValue(metadata.Text, "name");
        var sources = FirstJsonStringValue(metadata.Text, "sources");
        var homepage = FirstJsonStringValue(metadata.Text, "homepage");
        var identityText = string.Join(' ', new[] { id, name, sources, homepage }.Where(value => !string.IsNullOrWhiteSpace(value)));
        var identityTokens = ExtractIdentityTokens(identityText);
        if (identityTokens.Count == 0)
        {
            return false;
        }

        var hasOverlap = fileTokens.Overlaps(identityTokens);
        if (hasOverlap)
        {
            return false;
        }

        evidence = new Evidence
        {
            Source = metadata.Source,
            Match = $"file '{Path.GetFileNameWithoutExtension(fileName)}' vs declared id/name '{id ?? "unknown"}' / '{name ?? "unknown"}'"
        };
        return true;
    }

    private static string? FirstJsonStringValue(string text, string propertyName)
    {
        var escapedName = Regex.Escape(propertyName);
        var match = Regex.Match(text, $"\"{escapedName}\"\\s*:\\s*\"([^\"]+)\"", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        return match.Success ? match.Groups[1].Value : null;
    }

    private static HashSet<string> ExtractIdentityTokens(string value)
    {
        var ignored = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "fabric", "forge", "quilt", "neoforge", "minecraft", "client", "server", "mod", "mods",
            "mc", "snapshot", "release", "beta", "alpha", "build", "final", "official"
        };

        return Regex.Matches(value, "[a-zA-Z][a-zA-Z0-9]+")
            .SelectMany(match => ExpandIdentityToken(match.Value))
            .Where(token => token.Length >= 5)
            .Where(token => !ignored.Contains(token))
            .Where(token => !Regex.IsMatch(token, @"^\d+$"))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    private static IEnumerable<string> ExpandIdentityToken(string value)
    {
        var normalized = value.ToLowerInvariant();
        yield return normalized;
        if (normalized.EndsWith('s') && normalized.Length > 5)
        {
            yield return normalized[..^1];
        }

        foreach (Match part in Regex.Matches(value, @"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)|\d+"))
        {
            var token = part.Value.ToLowerInvariant();
            yield return token;
            if (token.EndsWith('s') && token.Length > 5)
            {
                yield return token[..^1];
            }
        }
    }

    private static IReadOnlyList<Evidence> CombineEvidence(params Finding?[] findings) =>
        findings
            .Where(f => f is not null)
            .SelectMany(f => f!.Evidence)
            .DistinctBy(e => $"{e.Source}|{e.Match}")
            .Take(MaxEvidencePerRule)
            .ToList();

    private static IReadOnlyList<Evidence> FindSourceOverlap(params Finding[] findings)
    {
        var commonSources = findings
            .Select(f => f.Evidence.Select(e => e.Source).ToHashSet(StringComparer.OrdinalIgnoreCase))
            .Aggregate((left, right) =>
            {
                left.IntersectWith(right);
                return left;
            });

        return findings
            .SelectMany(f => f.Evidence)
            .Where(e => commonSources.Contains(e.Source))
            .DistinctBy(e => $"{e.Source}|{e.Match}")
            .Take(MaxEvidencePerRule)
            .ToList();
    }

    private static bool TryMatch(string text, RulePattern pattern, out string matchedValue)
    {
        matchedValue = pattern.Value;
        if (pattern.Kind == PatternKind.Regex)
        {
            var match = Regex.Match(text, pattern.Value, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, TimeSpan.FromMilliseconds(250));
            if (!match.Success)
            {
                return false;
            }

            matchedValue = match.Value;
            return true;
        }

        return text.Contains(pattern.Value, StringComparison.OrdinalIgnoreCase);
    }

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
               extension.Equals(".js", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".so", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".dylib", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".jnilib", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".node", StringComparison.OrdinalIgnoreCase);
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

    private sealed class ScanStats
    {
        public int EntryCount { get; set; }
        public int ClassCount { get; set; }
        public int NestedJarCount { get; set; }
    }
}
