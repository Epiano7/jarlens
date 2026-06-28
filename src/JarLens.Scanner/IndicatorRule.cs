using System.Text.Json.Serialization;

namespace JarLens.Scanner;

public sealed record IndicatorRule
{
    public required string Id { get; init; }
    public required string Label { get; init; }
    public required string Category { get; init; }
    public Severity Severity { get; init; } = Severity.Low;
    public string Explanation { get; init; } = "";
    public List<RulePattern> Patterns { get; init; } = [];
}

public sealed record RulePattern
{
    public required string Value { get; init; }
    public PatternKind Kind { get; init; } = PatternKind.Contains;
    public string? AppliesTo { get; init; }
}

[JsonConverter(typeof(JsonStringEnumConverter<PatternKind>))]
public enum PatternKind
{
    Contains,
    Regex
}
