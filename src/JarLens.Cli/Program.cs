using JarLens.Scanner;

if (args.Length == 0)
{
    Console.WriteLine("Usage: jarlens <path-to-jar> [rules-directory]");
    return 2;
}

var jarPath = args[0];
var rules = args.Length > 1 ? RuleCatalog.LoadDirectory(args[1]) : RuleCatalog.DefaultRules;
var scanner = new JarScanner();
var result = scanner.Scan(jarPath, rules);

Console.WriteLine($"JarLens report for {result.FileName}");
Console.WriteLine($"Risk: {result.Risk.Level} ({result.Risk.Score})");
Console.WriteLine(result.Risk.Verdict);
Console.WriteLine();
Console.WriteLine($"SHA256: {result.Sha256}");
Console.WriteLine($"Size: {result.SizeBytes:N0} bytes");
Console.WriteLine($"Entries: {result.EntryCount}, classes: {result.ClassCount}, nested jars: {result.NestedJarCount}");
Console.WriteLine("Score guide: 0 no indicators, 1-29 low, 30+ medium, any high-severity rule high.");
Console.WriteLine();

if (result.Findings.Count == 0)
{
    Console.WriteLine("No findings.");
    return 0;
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

return result.Risk.Level == "High" ? 1 : 0;

static int ScoreContribution(Severity severity) => severity switch
{
    Severity.Critical => 60,
    Severity.High => 35,
    Severity.Medium => 15,
    Severity.Low => 5,
    _ => 0
};
