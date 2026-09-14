namespace AMANetworkAnalyzer.Parsers;

using System.Diagnostics;
using System.Net.Http;
using System.Security.Cryptography;

/// <summary>
/// Converts Microsoft ETL (Event Trace Log) network captures to pcapng format
/// using Microsoft's open-source etl2pcapng tool (MIT license).
/// Source: https://github.com/microsoft/etl2pcapng
/// </summary>
/// <remarks>
/// This type launches an external executable, so it is the highest-value target in the
/// application. Two rules hold throughout:
/// <list type="bullet">
/// <item>The binary is only ever located by absolute path. The current working directory
/// and PATH are attacker-influenceable and are never consulted (CWE-426).</item>
/// <item>The SHA-256 hash is verified on every launch, not just after download, and the
/// file handle used for verification stays open across <see cref="Process.Start(ProcessStartInfo)"/>
/// so the bytes cannot be swapped in between (CWE-367).</item>
/// </list>
/// </remarks>
public static class EtlConverter
{
    // Pinned to v1.11.0 — update these values together when upgrading.
    private const string PinnedVersion = "v1.11.0";
    private const string DownloadUrl = "https://github.com/microsoft/etl2pcapng/releases/download/v1.11.0/etl2pcapng.exe";
    private const string ExpectedSha256 = "C2D03AAC43EA0F5626FC8D909E6688393FEAF71BD6FACD39AAF8A637382D9043";
    private const long ExpectedSizeBytes = 163872;
    private const long MaxDownloadSizeBytes = 10 * 1024 * 1024;

    private const string ExecutableName = "etl2pcapng.exe";

    private static readonly TimeSpan DownloadTimeout = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan ConversionTimeout = TimeSpan.FromMinutes(10);

    private static readonly Lazy<HttpClient> HttpClientInstance = new(() =>
    {
        var client = new HttpClient { Timeout = DownloadTimeout };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("AMANetworkAnalyzer/2.1");
        return client;
    });

    /// <summary>Per-user location the tool is downloaded to. Not writable by other users.</summary>
    private static string ManagedToolPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "AMANetworkAnalyzer", "tools", ExecutableName);

    /// <summary>
    /// Absolute locations searched, in order. Relative paths and PATH lookups are
    /// deliberately excluded: both resolve against directories an attacker may control.
    /// </summary>
    private static IEnumerable<string> CandidatePaths()
    {
        yield return ManagedToolPath;
        yield return Path.Combine(AppContext.BaseDirectory, "tools", ExecutableName);
        yield return Path.Combine(AppContext.BaseDirectory, ExecutableName);
    }

    /// <summary>True if a hash-verified copy of the tool is already present.</summary>
    public static bool IsAvailable()
    {
        using var verified = TryOpenVerified();
        return verified is not null;
    }

    /// <summary>
    /// Opens the first candidate whose contents match the pinned hash, keeping the handle
    /// open so the file cannot be replaced or deleted by another process.
    /// </summary>
    private static FileStream? TryOpenVerified()
    {
        foreach (string path in CandidatePaths())
        {
            FileStream? stream = null;
            try
            {
                if (!File.Exists(path)) continue;

                // FileShare.Read permits the loader to execute the image but denies
                // any other process write or delete access for the lifetime of the handle.
                stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);

                if (stream.Length == ExpectedSizeBytes && MatchesPinnedHash(stream))
                {
                    stream.Position = 0;
                    return stream;
                }
            }
            catch (IOException) { /* locked or unreadable — try the next candidate */ }
            catch (UnauthorizedAccessException) { /* not ours to read — try the next candidate */ }

            stream?.Dispose();
        }

        return null;
    }

    private static bool MatchesPinnedHash(FileStream stream)
    {
        stream.Position = 0;
        byte[] hash = SHA256.HashData(stream);
        return CryptographicOperations.FixedTimeEquals(hash, Convert.FromHexString(ExpectedSha256));
    }

    /// <summary>
    /// Ensures a hash-verified etl2pcapng.exe is available, downloading it if necessary.
    /// Returns (true, null) on success, or (false, errorMessage) on failure.
    /// </summary>
    public static async Task<(bool Success, string? Error)> EnsureAvailableAsync(
        Action<string>? onStatus = null, CancellationToken cancellationToken = default)
    {
        if (IsAvailable())
            return (true, null);

        onStatus?.Invoke($"Downloading etl2pcapng {PinnedVersion} from GitHub…");

        string targetPath = ManagedToolPath;
        string targetDirectory = Path.GetDirectoryName(targetPath)!;
        string tempPath = Path.Combine(targetDirectory, $"etl2pcapng_{Guid.NewGuid():N}.tmp");

        try
        {
            Directory.CreateDirectory(targetDirectory);

            var (downloaded, downloadError) = await DownloadToTempAsync(tempPath, cancellationToken)
                .ConfigureAwait(false);
            if (!downloaded)
                return (false, downloadError);

            onStatus?.Invoke("Verifying SHA-256 integrity…");

            using (var temp = new FileStream(tempPath, FileMode.Open, FileAccess.Read, FileShare.None))
            {
                if (temp.Length != ExpectedSizeBytes)
                    return (false, IntegrityFailure($"expected {ExpectedSizeBytes} bytes, got {temp.Length}"));

                if (!MatchesPinnedHash(temp))
                    return (false, IntegrityFailure("SHA-256 hash does not match the pinned value"));
            }

            File.Move(tempPath, targetPath, overwrite: true);

            // Re-verify from the final location; the move target is what actually gets run.
            if (!IsAvailable())
                return (false, "Download completed but the installed tool failed verification.");

            onStatus?.Invoke($"etl2pcapng {PinnedVersion} ready (SHA-256 verified).");
            return (true, null);
        }
        catch (OperationCanceledException)
        {
            return (false, "Download was cancelled.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or HttpRequestException)
        {
            return (false, $"Auto-download failed: {ex.Message}\n\n{ManualInstructions}");
        }
        finally
        {
            TryDelete(tempPath);
        }
    }

    private static async Task<(bool Success, string? Error)> DownloadToTempAsync(
        string tempPath, CancellationToken cancellationToken)
    {
        using var response = await HttpClientInstance.Value
            .GetAsync(new Uri(DownloadUrl), HttpCompletionOption.ResponseHeadersRead, cancellationToken)
            .ConfigureAwait(false);

        response.EnsureSuccessStatusCode();

        if (response.Content.Headers.ContentLength > MaxDownloadSizeBytes)
            return (false, "Download rejected: declared size exceeds the safety limit.");

        using var source = await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false);
        using var destination = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write, FileShare.None);

        // Enforce the ceiling against bytes actually received; a hostile server can
        // understate or omit Content-Length.
        byte[] buffer = new byte[81920];
        long total = 0;

        while (true)
        {
            int read = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0) break;

            total += read;
            if (total > MaxDownloadSizeBytes)
                return (false, "Download rejected: response exceeded the size safety limit.");

            await destination.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }

        await destination.FlushAsync(cancellationToken).ConfigureAwait(false);
        return (true, null);
    }

    /// <summary>
    /// Converts an ETL file to a temporary pcapng file.
    /// The caller owns the returned file and is responsible for deleting it.
    /// </summary>
    public static async Task<(string? PcapngPath, string? Error)> ConvertAsync(
        string etlPath, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(etlPath);

        // The handle stays open for the whole call so the verified bytes are the executed bytes.
        using FileStream? verified = TryOpenVerified();
        if (verified is null)
            return (null, $"No verified copy of {ExecutableName} was found.\n\n{ManualInstructions}");

        string executablePath = verified.Name;
        string outputPath = Path.Combine(Path.GetTempPath(), $"ama_analyzer_{Guid.NewGuid():N}.pcapng");

        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = executablePath,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = Path.GetTempPath()
            };
            startInfo.ArgumentList.Add(etlPath);
            startInfo.ArgumentList.Add(outputPath);

            using var process = Process.Start(startInfo);
            if (process is null)
                return (null, "Failed to start etl2pcapng.");

            var (exitCode, standardError) = await RunToCompletionAsync(
                process, ConversionTimeout, cancellationToken).ConfigureAwait(false);

            if (exitCode != 0)
            {
                TryDelete(outputPath);
                return (null, $"etl2pcapng failed (exit {exitCode}): {standardError}".Trim());
            }

            if (!File.Exists(outputPath))
                return (null, "etl2pcapng completed but produced no output file.");

            return (outputPath, null);
        }
        catch (OperationCanceledException)
        {
            TryDelete(outputPath);
            throw;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            TryDelete(outputPath);
            return (null, $"ETL conversion error: {ex.Message}");
        }
    }

    /// <summary>
    /// Drains both pipes concurrently and waits for exit. Reading them one after the other
    /// deadlocks as soon as the child fills the pipe that is not being read.
    /// </summary>
    internal static async Task<(int ExitCode, string StandardError)> RunToCompletionAsync(
        Process process, TimeSpan timeout, CancellationToken cancellationToken)
    {
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);

        Task<string> standardOutput = process.StandardOutput.ReadToEndAsync(timeoutSource.Token);
        Task<string> standardError = process.StandardError.ReadToEndAsync(timeoutSource.Token);

        try
        {
            await Task.WhenAll(standardOutput, standardError).ConfigureAwait(false);
            await process.WaitForExitAsync(timeoutSource.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            TryKill(process);

            if (cancellationToken.IsCancellationRequested)
                throw;

            return (-1, $"Timed out after {timeout.TotalMinutes:0.#} minutes.");
        }

        return (process.ExitCode, standardError.IsCompletedSuccessfully ? standardError.Result : string.Empty);
    }

    private static string IntegrityFailure(string reason) =>
        $"SHA-256 verification FAILED ({reason}).\n\n" +
        "The downloaded file does not match the known-good binary. This could indicate " +
        "tampering or network interception.\n\n" +
        $"Download manually from:\nhttps://github.com/microsoft/etl2pcapng/releases/tag/{PinnedVersion}";

    private static string ManualInstructions =>
        $"Place a copy of {ExecutableName} ({PinnedVersion}) in either:\n" +
        $"  {Path.Combine(AppContext.BaseDirectory, "tools")}\n" +
        $"  {Path.GetDirectoryName(ManagedToolPath)}\n\n" +
        $"It must be the official {PinnedVersion} build; any other copy is rejected.\n" +
        $"Download: https://github.com/microsoft/etl2pcapng/releases/tag/{PinnedVersion}";

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited) process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException) { /* already gone */ }
        catch (NotSupportedException) { /* not killable on this platform */ }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path)) File.Delete(path);
        }
        catch (IOException) { /* best effort */ }
        catch (UnauthorizedAccessException) { /* best effort */ }
    }
}
