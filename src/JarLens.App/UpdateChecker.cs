using System.Diagnostics;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace JarLens.App;

public sealed record UpdateCheckResult(
    Version CurrentVersion,
    Version? LatestVersion,
    string? LatestTag,
    string? ReleaseUrl,
    bool IsUpdateAvailable,
    string Message);

public static class UpdateChecker
{
    private const string LatestReleaseUrl = "https://api.github.com/repos/Epiano7/jarlens/releases/latest";
    private static readonly HttpClient Client = new();

    static UpdateChecker()
    {
        Client.DefaultRequestHeaders.UserAgent.ParseAdd("JarLens");
    }

    public static async Task<UpdateCheckResult> CheckLatestReleaseAsync(CancellationToken cancellationToken = default)
    {
        var current = Assembly.GetExecutingAssembly().GetName().Version ?? new Version(0, 0, 0);
        using var response = await Client.GetAsync(LatestReleaseUrl, cancellationToken);
        response.EnsureSuccessStatusCode();

        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        var release = await JsonSerializer.DeserializeAsync<GitHubRelease>(stream, cancellationToken: cancellationToken);
        var latest = ParseTag(release?.TagName);

        if (latest is null)
        {
            return new UpdateCheckResult(current, null, release?.TagName, release?.HtmlUrl, false, "GitHub returned a release, but JarLens could not parse its version tag.");
        }

        var isNewer = latest > new Version(current.Major, current.Minor, current.Build < 0 ? 0 : current.Build);
        var message = isNewer
            ? $"JarLens {release!.TagName} is available. The GitHub release page will show the portable zip and checksums."
            : $"JarLens is up to date. Current version: {current.Major}.{current.Minor}.{Math.Max(current.Build, 0)}.";

        return new UpdateCheckResult(current, latest, release?.TagName, release?.HtmlUrl, isNewer, message);
    }

    public static void OpenReleasePage(string url)
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = url,
            UseShellExecute = true
        });
    }

    private static Version? ParseTag(string? tag)
    {
        if (string.IsNullOrWhiteSpace(tag))
        {
            return null;
        }

        var normalized = tag.Trim();
        if (normalized.StartsWith('v') || normalized.StartsWith('V'))
        {
            normalized = normalized[1..];
        }

        return Version.TryParse(normalized, out var version) ? version : null;
    }

    private sealed record GitHubRelease(
        [property: JsonPropertyName("tag_name")] string? TagName,
        [property: JsonPropertyName("html_url")] string? HtmlUrl);
}
