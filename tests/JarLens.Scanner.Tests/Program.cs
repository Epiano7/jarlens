using JarLens.Scanner;
using System.IO.Compression;
using System.Text;

var tempJar = Path.Combine(Path.GetTempPath(), $"jarlens-test-{Guid.NewGuid():N}.jar");
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
}

static void Assert(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}
