using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace JarLens.App;

public sealed record UpdateCheckResult(
    Version CurrentVersion,
    Version? LatestVersion,
    string? LatestTag,
    string? ReleaseUrl,
    string? ZipAssetUrl,
    string? ChecksumAssetUrl,
    bool IsUpdateAvailable,
    string Message);

public sealed record PreparedUpdate(string ZipPath, string UpdaterPath, string InstallDirectory, string AppExe);

public static class UpdateChecker
{
    private const string LatestReleaseUrl = "https://api.github.com/repos/Epiano7/jarlens/releases/latest";
    private const string ZipAssetName = "JarLens-win-x64.zip";
    private const string ChecksumAssetName = "JarLens-win-x64.zip.sha256";
    private const string UpdaterExeName = "JarLens.Updater.exe";
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
            return new UpdateCheckResult(current, null, release?.TagName, release?.HtmlUrl, null, null, false, "GitHub returned a release, but JarLens could not parse its version tag.");
        }

        var currentComparable = new Version(current.Major, current.Minor, current.Build < 0 ? 0 : current.Build);
        var isNewer = latest > currentComparable;
        var zipAsset = release?.Assets.FirstOrDefault(asset => asset.Name.Equals(ZipAssetName, StringComparison.OrdinalIgnoreCase));
        var checksumAsset = release?.Assets.FirstOrDefault(asset => asset.Name.Equals(ChecksumAssetName, StringComparison.OrdinalIgnoreCase));
        var message = isNewer
            ? $"JarLens {release!.TagName} is available. JarLens can download, verify, install, and restart automatically."
            : $"JarLens is up to date. Current version: {currentComparable}.";

        return new UpdateCheckResult(current, latest, release?.TagName, release?.HtmlUrl, zipAsset?.BrowserDownloadUrl, checksumAsset?.BrowserDownloadUrl, isNewer, message);
    }

    public static async Task<PreparedUpdate> DownloadAndPrepareUpdateAsync(UpdateCheckResult update, IProgress<string>? progress = null, CancellationToken cancellationToken = default)
    {
        if (update.ZipAssetUrl is null || update.ChecksumAssetUrl is null)
        {
            throw new InvalidOperationException("The release is missing the portable zip or checksum asset.");
        }

        var updateDirectory = Path.Combine(Path.GetTempPath(), "JarLens-update-download-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(updateDirectory);

        var zipPath = Path.Combine(updateDirectory, ZipAssetName);
        var checksumPath = Path.Combine(updateDirectory, ChecksumAssetName);

        progress?.Report("Downloading release zip...");
        await DownloadFileAsync(update.ZipAssetUrl, zipPath, cancellationToken);

        progress?.Report("Downloading checksum...");
        await DownloadFileAsync(update.ChecksumAssetUrl, checksumPath, cancellationToken);

        progress?.Report("Verifying SHA-256...");
        VerifyChecksum(zipPath, checksumPath);

        var installDirectory = AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var installedUpdater = Path.Combine(installDirectory, UpdaterExeName);
        if (!File.Exists(installedUpdater))
        {
            throw new FileNotFoundException("JarLens updater was not found beside JarLens.exe.", installedUpdater);
        }

        var tempUpdater = Path.Combine(updateDirectory, UpdaterExeName);
        File.Copy(installedUpdater, tempUpdater, overwrite: true);

        return new PreparedUpdate(zipPath, tempUpdater, installDirectory, "JarLens.exe");
    }

    public static void StartUpdaterAndExit(PreparedUpdate preparedUpdate)
    {
        var currentProcess = Process.GetCurrentProcess();
        Process.Start(new ProcessStartInfo
        {
            FileName = preparedUpdate.UpdaterPath,
            UseShellExecute = true,
            Arguments = Quote(preparedUpdate.InstallDirectory) + " " +
                        Quote(preparedUpdate.ZipPath) + " " +
                        Quote(preparedUpdate.AppExe) + " " +
                        currentProcess.Id
        });
    }

    public static void OpenReleasePage(string url)
    {
        Process.Start(new ProcessStartInfo
        {
            FileName = url,
            UseShellExecute = true
        });
    }

    private static async Task DownloadFileAsync(string url, string destination, CancellationToken cancellationToken)
    {
        using var response = await Client.GetAsync(url, cancellationToken);
        response.EnsureSuccessStatusCode();
        await using var source = await response.Content.ReadAsStreamAsync(cancellationToken);
        await using var target = File.Create(destination);
        await source.CopyToAsync(target, cancellationToken);
    }

    private static void VerifyChecksum(string zipPath, string checksumPath)
    {
        var checksumLine = File.ReadLines(checksumPath).FirstOrDefault(line => line.Contains(ZipAssetName, StringComparison.OrdinalIgnoreCase));
        if (checksumLine is null)
        {
            throw new InvalidOperationException("Checksum file does not contain an entry for the release zip.");
        }

        var expected = checksumLine.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        if (string.IsNullOrWhiteSpace(expected))
        {
            throw new InvalidOperationException("Checksum file does not contain a readable SHA-256 hash.");
        }

        using var stream = File.OpenRead(zipPath);
        var actual = Convert.ToHexString(SHA256.HashData(stream));
        if (!actual.Equals(expected, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Downloaded zip checksum did not match the release checksum.");
        }
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

    private static string Quote(string value) => "\"" + value.Replace("\"", "\\\"") + "\"";

    private sealed record GitHubRelease(
        [property: JsonPropertyName("tag_name")] string? TagName,
        [property: JsonPropertyName("html_url")] string? HtmlUrl,
        [property: JsonPropertyName("assets")] List<GitHubAsset> Assets);

    private sealed record GitHubAsset(
        [property: JsonPropertyName("name")] string Name,
        [property: JsonPropertyName("browser_download_url")] string BrowserDownloadUrl);
}
