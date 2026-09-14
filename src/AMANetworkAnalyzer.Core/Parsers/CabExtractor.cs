namespace AMANetworkAnalyzer.Parsers;

using System.Diagnostics;

/// <summary>
/// Extracts .etl files from Windows .cab archives produced by netsh trace.
/// Uses the built-in Windows expand.exe — no third-party dependencies.
/// </summary>
public static class CabExtractor
{
    private static readonly TimeSpan ExtractionTimeout = TimeSpan.FromMinutes(5);

    /// <summary>
    /// expand.exe resolved from the real system directory. Launching it by bare name would
    /// search the working directory and PATH first, both of which an attacker may control.
    /// </summary>
    private static string ExpandExecutablePath =>
        Path.Combine(Environment.SystemDirectory, "expand.exe");

    /// <summary>
    /// Extracts a .cab file and returns the path to the first .etl file found inside.
    /// The caller is responsible for cleaning up the temp directory.
    /// </summary>
    public static async Task<(string? EtlPath, string? TempDir, string? Error)> ExtractEtlFromCabAsync(
        string cabPath, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(cabPath);

        string tempDir = Path.Combine(Path.GetTempPath(), $"ama_cab_{Guid.NewGuid():N}");

        try
        {
            if (!File.Exists(ExpandExecutablePath))
                return (null, null, "expand.exe was not found in the Windows system directory.");

            Directory.CreateDirectory(tempDir);

            var startInfo = new ProcessStartInfo
            {
                FileName = ExpandExecutablePath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = tempDir
            };
            startInfo.ArgumentList.Add(cabPath);
            startInfo.ArgumentList.Add("-F:*");
            startInfo.ArgumentList.Add(tempDir);

            using var process = Process.Start(startInfo);
            if (process is null)
                return (null, tempDir, "Failed to start expand.exe.");

            var (exitCode, standardError) = await EtlConverter
                .RunToCompletionAsync(process, ExtractionTimeout, cancellationToken)
                .ConfigureAwait(false);

            if (exitCode != 0)
                return (null, tempDir, $"expand.exe failed (exit {exitCode}): {standardError}".Trim());

            string? etlPath = FindContainedEtl(tempDir);
            if (etlPath is null)
                return (null, tempDir, "No .etl file was found inside the .cab archive. It may not be a network trace.");

            return (etlPath, tempDir, null);
        }
        catch (OperationCanceledException)
        {
            CleanupTempDir(tempDir);
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return (null, tempDir, $"CAB extraction error: {ex.Message}");
        }
    }

    /// <summary>
    /// Returns the first .etl file that genuinely resides under <paramref name="tempDir"/>.
    /// A malicious archive can carry traversal entries or links, so every candidate is
    /// re-checked against the extraction root after path resolution (CWE-22).
    /// </summary>
    private static string? FindContainedEtl(string tempDir)
    {
        string root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(tempDir))
                      + Path.DirectorySeparatorChar;

        foreach (string candidate in Directory.EnumerateFiles(tempDir, "*.etl", SearchOption.AllDirectories))
        {
            var info = new FileInfo(candidate);

            // Reparse points can redirect outside the root even when the path looks contained.
            if (info.Attributes.HasFlag(FileAttributes.ReparsePoint))
                continue;

            string resolved = Path.GetFullPath(info.LinkTarget ?? info.FullName);
            if (resolved.StartsWith(root, StringComparison.OrdinalIgnoreCase))
                return resolved;
        }

        return null;
    }

    /// <summary>Clean up the temporary extraction directory.</summary>
    public static void CleanupTempDir(string? tempDir)
    {
        if (string.IsNullOrEmpty(tempDir)) return;

        try
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
        catch (IOException) { /* best effort */ }
        catch (UnauthorizedAccessException) { /* best effort */ }
    }
}
