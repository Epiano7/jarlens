using JarLens.Scanner;
using System.IO.Compression;
using System.Text;

var tempJar = Path.Combine(Path.GetTempPath(), $"jarlens-test-{Guid.NewGuid():N}.jar");
var falsePositiveJar = Path.Combine(Path.GetTempPath(), $"jarlens-fp-test-{Guid.NewGuid():N}.jar");
var comboJar = Path.Combine(Path.GetTempPath(), $"jarlens-combo-test-{Guid.NewGuid():N}.jar");
var nestedComboJar = Path.Combine(Path.GetTempPath(), $"jarlens-nested-combo-test-{Guid.NewGuid():N}.jar");
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
}

static void Assert(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}
