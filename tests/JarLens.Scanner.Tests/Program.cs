using JarLens.Scanner;
using System.IO.Compression;
using System.Text;

var tempJar = Path.Combine(Path.GetTempPath(), $"jarlens-test-{Guid.NewGuid():N}.jar");
var falsePositiveJar = Path.Combine(Path.GetTempPath(), $"jarlens-fp-test-{Guid.NewGuid():N}.jar");
var comboJar = Path.Combine(Path.GetTempPath(), $"jarlens-combo-test-{Guid.NewGuid():N}.jar");
var nestedComboJar = Path.Combine(Path.GetTempPath(), $"jarlens-nested-combo-test-{Guid.NewGuid():N}.jar");
var ratPatternJar = Path.Combine(Path.GetTempPath(), $"jarlens-rat-pattern-test-{Guid.NewGuid():N}.jar");
var impersonatedJar = Path.Combine(Path.GetTempPath(), $"Krypton-1.21.11+5.1.1-{Guid.NewGuid():N}.jar");
try
{
    using (var archive = ZipFile.Open(tempJar, ZipArchiveMode.Create))
    {
        var manifest = archive.CreateEntry("META-INF/MANIFEST.MF");
        await using (var stream = manifest.Open())
        {
            await stream.WriteAsync(Encoding.UTF8.GetBytes("Manifest-Version: 1.0\n"));
        }

        var suspicious = archive.CreateEntry("demo/Suspicious.class");
        await using (var stream = suspicious.Open())
        {
            await stream.WriteAsync(Encoding.UTF8.GetBytes("discord.com/api/webhooks java/net/URL"));
        }
    }

    var result = new JarScanner().Scan(tempJar);
    Assert(result.Findings.Any(f => f.RuleId == "discord_webhook"), "Expected Discord webhook finding.");
    Assert(result.Findings.Any(f => f.RuleId == "networking_api"), "Expected networking API finding.");
    Assert(result.Entries.Any(e => e.Path.EndsWith("demo/Suspicious.class") && e.Type == "class" && e.Sha256.Length == 64), "Expected safe entry inventory with class hash.");
    Assert(result.Risk.Level is "High", "Expected high risk.");

    using (var archive = ZipFile.Open(falsePositiveJar, ZipArchiveMode.Create))
    {
        var libraryClass = archive.CreateEntry("org/apache/http/client/CookieStore.class");
        await using (var stream = libraryClass.Open())
        {
            await stream.WriteAsync(Encoding.UTF8.GetBytes("Cookies .minecraft discordcanary java/lang/Runtime java/lang/ClassLoader"));
        }
    }

    var falsePositiveResult = new JarScanner().Scan(falsePositiveJar);
    Assert(falsePositiveResult.Findings.All(f => f.Severity < Severity.High), "Generic library strings should not create high-risk findings.");

    using (var archive = ZipFile.Open(comboJar, ZipArchiveMode.Create))
    {
        var stealerClass = archive.CreateEntry("demo/Combo.class");
        await using (var stream = stealerClass.Open())
        {
            await stream.WriteAsync(Encoding.UTF8.GetBytes("Local State leveldb discord.com/api/webhooks"));
        }
    }

    var comboResult = new JarScanner().Scan(comboJar);
    Assert(comboResult.Findings.Any(f => f.RuleId == "combo_token_access_and_exfil" && f.Severity == Severity.Critical), "Expected critical combo token/exfil finding.");

    using (var nestedPayload = new MemoryStream())
    {
        using (var nestedArchive = new ZipArchive(nestedPayload, ZipArchiveMode.Create, leaveOpen: true))
        {
            var stealerClass = nestedArchive.CreateEntry("payload/Hidden.class");
            await using var stream = stealerClass.Open();
            await stream.WriteAsync(Encoding.UTF8.GetBytes("Local State leveldb discord.com/api/webhooks"));
        }

        nestedPayload.Position = 0;
        using var outerArchive = ZipFile.Open(nestedComboJar, ZipArchiveMode.Create);
        var nestedEntry = outerArchive.CreateEntry("META-INF/jars/hidden.jar");
        await using var nestedEntryStream = nestedEntry.Open();
        await nestedPayload.CopyToAsync(nestedEntryStream);
    }

    var nestedComboResult = new JarScanner().Scan(nestedComboJar);
    Assert(nestedComboResult.NestedJarCount == 1, "Expected nested jar count.");
    Assert(nestedComboResult.Findings.Any(f => f.RuleId == "combo_token_access_and_exfil" && f.Severity == Severity.Critical), "Expected critical combo token/exfil finding inside nested jar.");

    using (var archive = ZipFile.Open(ratPatternJar, ZipArchiveMode.Create))
    {
        var manifest = archive.CreateEntry("META-INF/MANIFEST.MF");
        await using (var stream = manifest.Open())
        {
            await stream.WriteAsync(Encoding.UTF8.GetBytes("Manifest-Version: 1.0\nMain-Class: com.github.du_npiq_zf\n"));
        }

        var modJson = archive.CreateEntry("fabric.mod.json");
        await using (var stream = modJson.Open())
        {
            await stream.WriteAsync(Encoding.UTF8.GetBytes("""
                {
                  "schemaVersion": 1,
                  "id": "voicechat",
                  "name": "Simple Voice Chat",
                  "entrypoints": {
                    "main": [
                      "de.maxhenkel.voicechat.FabricVoicechatMod",
                      "com.github.fjiqlt4"
                    ]
                  }
                }
                """));
        }

        var ratClass = archive.CreateEntry("com/github/fjiqlt4.class");
        await using (var stream = ratClass.Open())
        {
            await stream.WriteAsync(Encoding.UTF8.GetBytes("java/lang/ProcessBuilder java/net/URL java/util/Base64"));
        }
    }

    var ratPatternResult = new JarScanner().Scan(ratPatternJar);
    Assert(ratPatternResult.Findings.Any(f => f.RuleId == "combo_process_network_crypto_same_class" && f.Severity == Severity.Critical), "Expected critical process/network/crypto same-class finding.");
    Assert(ratPatternResult.Findings.Any(f => f.RuleId == "suspicious_fabric_entrypoint" && f.Severity == Severity.High), "Expected suspicious Fabric entrypoint finding.");
    Assert(ratPatternResult.Findings.Any(f => f.RuleId == "suspicious_manifest_main_class"), "Expected suspicious manifest main class finding.");

    using (var archive = ZipFile.Open(impersonatedJar, ZipArchiveMode.Create))
    {
        var modJson = archive.CreateEntry("fabric.mod.json");
        await using (var stream = modJson.Open())
        {
            await stream.WriteAsync(Encoding.UTF8.GetBytes("""
                {
                  "schemaVersion": 1,
                  "id": "notenoughanimations",
                  "name": "NotEnoughAnimations",
                  "contact": {
                    "homepage": "https://modrinth.com/mod/not-enough-animations",
                    "sources": "https://github.com/tr7zw/NotEnoughAnimations"
                  },
                  "jars": [
                    { "file": "META-INF/jars/TRansition.jar" }
                  ]
                }
                """));
        }

        using var nestedPayload = new MemoryStream();
        using (var nestedArchive = new ZipArchive(nestedPayload, ZipArchiveMode.Create, leaveOpen: true))
        {
            var libraryClass = nestedArchive.CreateEntry("dev/tr7zw/libsentry/HttpConnection.class");
            await using var stream = libraryClass.Open();
            await stream.WriteAsync(Encoding.UTF8.GetBytes("java/net/URL java/util/Base64"));
        }

        nestedPayload.Position = 0;
        var nestedEntry = archive.CreateEntry("META-INF/jars/TRansition.jar");
        await using var nestedEntryStream = nestedEntry.Open();
        await nestedPayload.CopyToAsync(nestedEntryStream);
    }

    var impersonatedResult = new JarScanner().Scan(impersonatedJar);
    Assert(impersonatedResult.Findings.Any(f => f.RuleId == "metadata_identity_mismatch" && f.Severity == Severity.Medium), "Expected metadata identity mismatch finding.");
    Assert(impersonatedResult.Findings.Any(f => f.RuleId == "combo_impersonation_nested_network_code" && f.Severity == Severity.High), "Expected high-risk impersonation plus nested network-code finding.");
    Assert(impersonatedResult.Risk.Level is "High", "Expected impersonated nested network-capable jar to be high risk.");
    Console.WriteLine("JarLens.Scanner.Tests passed.");
    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"JarLens.Scanner.Tests failed: {ex.Message}");
    return 1;
}
finally
{
    if (File.Exists(tempJar))
    {
        File.Delete(tempJar);
    }

    if (File.Exists(falsePositiveJar))
    {
        File.Delete(falsePositiveJar);
    }

    if (File.Exists(comboJar))
    {
        File.Delete(comboJar);
    }

    if (File.Exists(nestedComboJar))
    {
        File.Delete(nestedComboJar);
    }

    if (File.Exists(ratPatternJar))
    {
        File.Delete(ratPatternJar);
    }

    if (File.Exists(impersonatedJar))
    {
        File.Delete(impersonatedJar);
    }
}

static void Assert(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}
