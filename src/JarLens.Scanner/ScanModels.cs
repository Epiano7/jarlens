namespace JarLens.Scanner;

public sealed record ScanResult
{
    public required string FileName { get; init; }
    public required string FilePath { get; init; }
    public required string Sha256 { get; init; }
    public long SizeBytes { get; init; }
    public int EntryCount { get; init; }
    public int ClassCount { get; init; }
    public int NestedJarCount { get; init; }
    public int EmbeddedExecutableCount { get; init; }
    public IReadOnlyList<JarEntryInfo> Entries { get; init; } = [];
    public IReadOnlyList<string> Metadata { get; init; } = [];
    public IReadOnlyList<Finding> Findings { get; init; } = [];
    public required RiskSummary Risk { get; init; }
}

public sealed record JarEntryInfo
{
    public required string Path { get; init; }
    public required string Type { get; init; }
    public long SizeBytes { get; init; }
    public required string Sha256 { get; init; }
}

public sealed record Finding
{
    public required string RuleId { get; init; }
    public required string Label { get; init; }
    public required string Category { get; init; }
    public Severity Severity { get; init; }
    public required string Explanation { get; init; }
    public IReadOnlyList<Evidence> Evidence { get; init; } = [];
}

public sealed record Evidence
{
    public required string Source { get; init; }
    public required string Match { get; init; }
}

public sealed record RiskSummary
{
    public required string Level { get; init; }
    public int Score { get; init; }
    public required string Verdict { get; init; }
}
