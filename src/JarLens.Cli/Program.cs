using JarLens.Scanner;

if (args.Length == 0)
{
    Console.WriteLine("Usage:");
    Console.WriteLine("  jarlens <path-to-jar> [rules-directory]");
    Console.WriteLine("  jarlens <folder-with-jars> [rules-directory]");
    return 2;
}

var targetPath = args[0];
var rules = args.Length > 1 ? RuleCatalog.LoadDirectory(args[1]) : RuleCatalog.DefaultRules;
var scanner = new JarScanner();

if (Directory.Exists(targetPath))
{
    return ScanDirectory(targetPath, rules, scanner);
}

var result = scanner.Scan(targetPath, rules);
PrintDetailedReport(result);
return result.Risk.Level == "High" ? 1 : 0;

static int ScanDirectory(string directory, IReadOnlyList<IndicatorRule> rules, JarScanner scanner)
{
    var jarFiles = Directory.EnumerateFiles(directory, "*.jar", SearchOption.AllDirectories).Order().ToList();
    if (jarFiles.Count == 0)
    {
        Console.WriteLine("No .jar files found.");
        return 0;
    }

    var results = new List<ScanResult>();
    foreach (var jar in jarFiles)
    {
        try
        {
            results.Add(scanner.Scan(jar, rules));
        }
        catch (Exception ex)
        {
            Console.WriteLine($"ERROR scanning {jar}: {ex.Message}");
        }
    }

    Console.WriteLine($"Scanned {results.Count} jar(s). Ranked by risk:");
    Console.WriteLine();
    Console.WriteLine("{0,-12} {1,5} {2,8} {3,8} {4,-45} {5}", "Risk", "Score", "Findings", "Classes", "File", "Top findings");
    Console.WriteLine(new string('-', 120));

    foreach (var scan in results.OrderByDescending(r => RiskRank(r.Risk.Level)).ThenByDescending(r => r.Risk.Score).ThenBy(r => r.FileName))
    {
        var topFindings = scan.Findings.Count == 0
            ? "-"
            : string.Join("; ", scan.Findings.Take(3).Select(f => $"{f.Label} ({f.Severity})"));

        Console.WriteLine("{0,-12} {1,5} {2,8} {3,8} {4,-45} {5}",
            scan.Risk.Level,
            scan.Risk.Score,
            scan.Findings.Count,
            scan.ClassCount,
            Trim(scan.FileName, 45),
            topFindings);
    }

    Console.WriteLine();
    Console.WriteLine("Use the CLI on a single jar path to print full evidence for that file.");
    return results.Any(r => r.Risk.Level == "High") ? 1 : 0;
}

static void PrintDetailedReport(ScanResult result)
{
    Console.WriteLine($"JarLens report for {result.FileName}");
    Console.WriteLine($"Risk: {result.Risk.Level} ({result.Risk.Score})");
    Console.WriteLine(result.Risk.Verdict);
    Console.WriteLine();
    Console.WriteLine($"SHA256: {result.Sha256}");
    Console.WriteLine($"Size: {result.SizeBytes:N0} bytes");
    Console.WriteLine($"Entries: {result.EntryCount}, classes: {result.ClassCount}, nested jars: {result.NestedJarCount}, embedded executables/scripts: {result.EmbeddedExecutableCount}");
    Console.WriteLine("Score guide: 0 no indicators, 1-29 low, 30+ medium, any high-severity rule high.");
    Console.WriteLine();

    if (result.Findings.Count == 0)
    {
        Console.WriteLine("No findings.");
        return;
    }

    foreach (var finding in result.Findings)
    {
        Console.WriteLine($"[{finding.Severity}, +{ScoreContribution(finding.Severity)}] {finding.Label} ({finding.Category})");
        Console.WriteLine($"  {finding.Explanation}");
        Console.WriteLine($"  Evidence ({finding.Evidence.Count}):");
        foreach (var evidence in finding.Evidence)
        {
            Console.WriteLine($"    - {evidence.Source}: {evidence.Match}");
        }

        Console.WriteLine();
    }
}

static int ScoreContribution(Severity severity) => severity switch
{
    Severity.Critical => 60,
    Severity.High => 35,
    Severity.Medium => 15,
    Severity.Low => 5,
    _ => 0
};

static int RiskRank(string level) => level switch
{
    "High" => 3,
    "Medium" => 2,
    "Low" => 1,
    _ => 0
};

static string Trim(string value, int maxLength) =>
    value.Length <= maxLength ? value : value[..Math.Max(0, maxLength - 3)] + "...";
