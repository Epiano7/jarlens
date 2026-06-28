using System.Diagnostics;
using System.IO.Compression;

if (args.Length < 4)
{
    Console.Error.WriteLine("Usage: JarLens.Updater <install-dir> <zip-path> <app-exe> <pid>");
    return 2;
}

var installDirectory = Path.GetFullPath(args[0]);
var zipPath = Path.GetFullPath(args[1]);
var appExe = args[2];
var processId = int.TryParse(args[3], out var parsedPid) ? parsedPid : 0;
var extractDirectory = Path.Combine(Path.GetTempPath(), "JarLens-update-" + Guid.NewGuid().ToString("N"));

try
{
    if (processId > 0)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            process.WaitForExit(30000);
        }
        catch (ArgumentException)
        {
            // JarLens already exited.
        }
    }

    Directory.CreateDirectory(extractDirectory);
    ZipFile.ExtractToDirectory(zipPath, extractDirectory, overwriteFiles: true);
    CopyDirectory(extractDirectory, installDirectory);

    var appPath = Path.Combine(installDirectory, appExe);
    if (File.Exists(appPath))
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = appPath,
                WorkingDirectory = installDirectory,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("JarLens was updated, but relaunch failed: " + ex.Message);
        }
    }

    return 0;
}
catch (Exception ex)
{
    Console.Error.WriteLine("JarLens update failed: " + ex.Message);
    Console.Error.WriteLine("Install directory: " + installDirectory);
    Console.Error.WriteLine("Zip path: " + zipPath);
    return 1;
}
finally
{
    TryDelete(extractDirectory);
}

static void CopyDirectory(string sourceDirectory, string targetDirectory)
{
    Directory.CreateDirectory(targetDirectory);

    foreach (var directory in Directory.EnumerateDirectories(sourceDirectory, "*", SearchOption.AllDirectories))
    {
        var relative = Path.GetRelativePath(sourceDirectory, directory);
        Directory.CreateDirectory(Path.Combine(targetDirectory, relative));
    }

    foreach (var file in Directory.EnumerateFiles(sourceDirectory, "*", SearchOption.AllDirectories))
    {
        var relative = Path.GetRelativePath(sourceDirectory, file);
        var target = Path.Combine(targetDirectory, relative);
        Directory.CreateDirectory(Path.GetDirectoryName(target)!);
        File.Copy(file, target, overwrite: true);
    }
}

static void TryDelete(string path)
{
    try
    {
        if (Directory.Exists(path))
        {
            Directory.Delete(path, recursive: true);
        }
    }
    catch
    {
        // Best effort cleanup.
    }
}
