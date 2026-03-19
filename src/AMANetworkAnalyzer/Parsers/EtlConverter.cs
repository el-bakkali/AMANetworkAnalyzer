namespace AMANetworkAnalyzer.Parsers;

using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography;

/// <summary>
/// Converts Microsoft ETL (Event Trace Log) network captures to pcapng format
/// using Microsoft's open-source etl2pcapng tool (MIT license).
/// Auto-downloads v1.11.0 from GitHub with SHA-256 integrity verification.
/// Source: https://github.com/microsoft/etl2pcapng
/// </summary>
public static class EtlConverter
{
    // Pinned to v1.11.0 — update these three values together when upgrading
    private const string PinnedVersion = "v1.11.0";
    private const string DownloadUrl = "https://github.com/microsoft/etl2pcapng/releases/download/v1.11.0/etl2pcapng.exe";
    private const string ExpectedSha256 = "C2D03AAC43EA0F5626FC8D909E6688393FEAF71BD6FACD39AAF8A637382D9043";
    private const long ExpectedSizeBytes = 163872;
    private const long MaxDownloadSizeBytes = 10 * 1024 * 1024; // 10 MB safety ceiling

    private static string ToolsDir => Path.Combine(AppContext.BaseDirectory, "tools");
    private static string ToolsExePath => Path.Combine(ToolsDir, "etl2pcapng.exe");

    private static readonly string[] SearchPaths =
    [
        "etl2pcapng.exe",
        Path.Combine(AppContext.BaseDirectory, "etl2pcapng.exe"),
        ToolsExePath,
    ];

    /// <summary>Checks if etl2pcapng.exe is available locally.</summary>
    public static bool IsAvailable() => FindExecutable() is not null;

    /// <summary>
    /// Ensures etl2pcapng.exe is available, downloading it if necessary.
    /// Downloads from a pinned GitHub release URL and verifies SHA-256 integrity.
    /// Returns (true, null) on success, or (false, errorMessage) on failure.
    /// </summary>
    public static async Task<(bool Success, string? Error)> EnsureAvailableAsync(
        Action<string>? onStatus = null, CancellationToken ct = default)
    {
        if (IsAvailable())
            return (true, null);

        onStatus?.Invoke($"Downloading etl2pcapng {PinnedVersion} from GitHub…");

        try
        {
            Directory.CreateDirectory(ToolsDir);

            // Download to a temp file first, verify, then move into place
            string tempPath = Path.Combine(ToolsDir, $"etl2pcapng_{Guid.NewGuid():N}.tmp");

            try
            {
                using var http = new HttpClient();
                http.DefaultRequestHeaders.UserAgent.ParseAdd("AMANetworkAnalyzer/1.0");
                http.Timeout = TimeSpan.FromSeconds(60);

                using var response = await http.GetAsync(DownloadUrl, HttpCompletionOption.ResponseHeadersRead, ct);
                response.EnsureSuccessStatusCode();

                // Validate content length before downloading
                if (response.Content.Headers.ContentLength > MaxDownloadSizeBytes)
                    return (false, "Download rejected: file exceeds size safety limit.");

                using (var fs = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                {
                    await response.Content.CopyToAsync(fs, ct);
                    fs.Flush();

                    if (fs.Length > MaxDownloadSizeBytes)
                        return (false, "Download rejected: file exceeds size safety limit.");
                }

                onStatus?.Invoke("Verifying SHA-256 integrity…");

                // SHA-256 verification — this is the critical security check
                string actualHash = ComputeSha256(tempPath);
                if (!actualHash.Equals(ExpectedSha256, StringComparison.OrdinalIgnoreCase))
                {
                    try { File.Delete(tempPath); } catch { }
                    return (false,
                        $"SHA-256 verification FAILED.\n\n" +
                        $"Expected: {ExpectedSha256}\n" +
                        $"Actual:   {actualHash}\n\n" +
                        "The downloaded file does not match the known-good binary. " +
                        "This could indicate tampering or a network interception.\n\n" +
                        $"Download manually from:\nhttps://github.com/microsoft/etl2pcapng/releases/tag/{PinnedVersion}");
                }

                // Verification passed — move into place
                File.Move(tempPath, ToolsExePath, overwrite: true);
            }
            finally
            {
                // Clean up temp file if it still exists (e.g. on error)
                try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }
            }

            if (!File.Exists(ToolsExePath))
                return (false, "Download completed but etl2pcapng.exe was not found.");

            onStatus?.Invoke($"etl2pcapng {PinnedVersion} ready (SHA-256 verified).");
            return (true, null);
        }
        catch (OperationCanceledException)
        {
            return (false, "Download was cancelled.");
        }
        catch (Exception ex)
        {
            return (false, $"Auto-download failed: {ex.Message}\n\nDownload manually from:\nhttps://github.com/microsoft/etl2pcapng/releases/tag/{PinnedVersion}");
        }
    }

    private static string ComputeSha256(string filePath)
    {
        using var sha = SHA256.Create();
        using var fs = File.OpenRead(filePath);
        byte[] hash = sha.ComputeHash(fs);
        return Convert.ToHexString(hash);
    }

    /// <summary>
    /// Converts an ETL file to a temporary pcapng file.
    /// Returns the path to the pcapng file, or null if conversion failed.
    /// The caller is responsible for deleting the temp file.
    /// </summary>
    public static async Task<(string? PcapngPath, string? Error)> ConvertAsync(string etlPath, CancellationToken ct = default)
    {
        string? exe = FindExecutable();
        if (exe is null)
            return (null, "etl2pcapng.exe not found. Download it from https://github.com/microsoft/etl2pcapng/releases and place it next to the analyzer or in the 'tools' subfolder.");

        // Use random filename to prevent predictable temp file attacks
        string outputPath = Path.Combine(Path.GetTempPath(), $"ama_analyzer_{Guid.NewGuid():N}.pcapng");

        try
        {
            // Use ArgumentList to prevent command injection via filenames
            var psi = new ProcessStartInfo
            {
                FileName = exe,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            psi.ArgumentList.Add(etlPath);
            psi.ArgumentList.Add(outputPath);

            using var proc = Process.Start(psi);
            if (proc is null)
                return (null, "Failed to start etl2pcapng process.");

            string stdout = await proc.StandardOutput.ReadToEndAsync(ct);
            string stderr = await proc.StandardError.ReadToEndAsync(ct);

            await proc.WaitForExitAsync(ct);

            if (proc.ExitCode != 0)
                return (null, $"etl2pcapng failed (exit {proc.ExitCode}): {stderr}".Trim());

            if (!File.Exists(outputPath))
                return (null, "etl2pcapng completed but output file was not created.");

            return (outputPath, null);
        }
        catch (Exception ex)
        {
            return (null, $"ETL conversion error: {ex.Message}");
        }
    }

    private static string? FindExecutable()
    {
        foreach (var path in SearchPaths)
        {
            if (File.Exists(path))
                return Path.GetFullPath(path);
        }

        // Check PATH
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "where.exe",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
            };
            psi.ArgumentList.Add("etl2pcapng.exe");
            using var proc = Process.Start(psi);
            if (proc is not null)
            {
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(3000);
                if (proc.ExitCode == 0)
                {
                    string? firstLine = output.Split('\n', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim();
                    if (firstLine is not null && File.Exists(firstLine))
                        return firstLine;
                }
            }
        }
        catch { }

        return null;
    }
}
