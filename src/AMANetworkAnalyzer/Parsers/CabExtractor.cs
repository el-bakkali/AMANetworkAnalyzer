namespace AMANetworkAnalyzer.Parsers;

using System.Diagnostics;

/// <summary>
/// Extracts .etl files from Windows .cab archives produced by netsh trace.
/// Uses the built-in Windows expand.exe — no third-party dependencies.
/// </summary>
public static class CabExtractor
{
    /// <summary>
    /// Extracts a .cab file and returns the path to the first .etl file found inside.
    /// The caller is responsible for cleaning up the temp directory.
    /// </summary>
    public static async Task<(string? EtlPath, string? TempDir, string? Error)> ExtractEtlFromCabAsync(
        string cabPath, CancellationToken ct = default)
    {
        // Create a temp directory with a random name for extraction
        string tempDir = Path.Combine(Path.GetTempPath(), $"ama_cab_{Guid.NewGuid():N}");

        try
        {
            Directory.CreateDirectory(tempDir);

            // Use Windows expand.exe to extract the .cab file
            var psi = new ProcessStartInfo
            {
                FileName = "expand.exe",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };
            psi.ArgumentList.Add(cabPath);
            psi.ArgumentList.Add("-F:*");
            psi.ArgumentList.Add(tempDir);

            using var proc = Process.Start(psi);
            if (proc is null)
                return (null, tempDir, "Failed to start expand.exe. Ensure Windows is the operating system.");

            string stdout = await proc.StandardOutput.ReadToEndAsync(ct);
            string stderr = await proc.StandardError.ReadToEndAsync(ct);

            await proc.WaitForExitAsync(ct);

            if (proc.ExitCode != 0)
                return (null, tempDir, $"expand.exe failed (exit {proc.ExitCode}): {stderr}".Trim());

            // Find the first .etl file in the extracted contents
            var etlFiles = Directory.GetFiles(tempDir, "*.etl", SearchOption.AllDirectories);
            if (etlFiles.Length == 0)
            {
                // Some cab files from netsh trace may contain files with different names
                // Try to find any network trace file
                return (null, tempDir, "No .etl file found inside the .cab archive. The .cab may not be a network trace.");
            }

            return (etlFiles[0], tempDir, null);
        }
        catch (Exception ex)
        {
            return (null, tempDir, $"CAB extraction error: {ex.Message}");
        }
    }

    /// <summary>Clean up the temporary extraction directory.</summary>
    public static void CleanupTempDir(string? tempDir)
    {
        if (tempDir is null) return;
        try
        {
            if (Directory.Exists(tempDir))
                Directory.Delete(tempDir, recursive: true);
        }
        catch { }
    }
}
