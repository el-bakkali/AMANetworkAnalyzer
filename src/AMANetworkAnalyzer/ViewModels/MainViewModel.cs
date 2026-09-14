namespace AMANetworkAnalyzer.ViewModels;

using System.Buffers.Binary;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;
using System.Windows;
using AMANetworkAnalyzer.Analysis;
using AMANetworkAnalyzer.Models;
using AMANetworkAnalyzer.Parsers;
using Microsoft.Win32;

public sealed class MainViewModel : INotifyPropertyChanged
{
    private readonly AnalysisEngine _engine = new();

    // Store all parsed packets for drill-down
    private List<ParsedPacket> _allPackets = [];

    private CancellationTokenSource? _analysisCts;

    public MainViewModel()
    {
        BrowseCommand = new RelayCommand(Browse);
        ExportCommand = new RelayCommand(ExportReport, () => Report is not null);
        ShowRelatedPacketsCommand = new RelayCommand<AnalysisFinding>(ShowRelatedPackets);
        ClearDetailCommand = new RelayCommand(() => { SelectedFinding = null; DetailPackets.Clear(); });
        FilterBySeverityCommand = new RelayCommand<string>(FilterBySeverity);
    }

    // ── Properties ───────────────────────────────────────────────────

    private string? _filePath;
    public string? FilePath
    {
        get => _filePath;
        set { _filePath = value; OnPropertyChanged(); OnPropertyChanged(nameof(HasFile)); }
    }

    private AnalysisReport? _report;
    public AnalysisReport? Report
    {
        get => _report;
        set { _report = value; OnPropertyChanged(); OnPropertyChanged(nameof(HasReport)); ((RelayCommand)ExportCommand).RaiseCanExecuteChanged(); }
    }

    private bool _isAnalyzing;
    public bool IsAnalyzing
    {
        get => _isAnalyzing;
        set { _isAnalyzing = value; OnPropertyChanged(); }
    }

    private string? _statusMessage;
    public string? StatusMessage
    {
        get => _statusMessage;
        set { _statusMessage = value; OnPropertyChanged(); }
    }

    private string? _errorMessage;
    public string? ErrorMessage
    {
        get => _errorMessage;
        set { _errorMessage = value; OnPropertyChanged(); OnPropertyChanged(nameof(HasError)); }
    }

    // Drill-down support
    private AnalysisFinding? _selectedFinding;
    public AnalysisFinding? SelectedFinding
    {
        get => _selectedFinding;
        set { _selectedFinding = value; OnPropertyChanged(); OnPropertyChanged(nameof(HasSelectedFinding)); }
    }

    public bool HasFile => FilePath is not null;
    public bool HasReport => Report is not null;
    public bool HasError => ErrorMessage is not null;
    public bool HasSelectedFinding => SelectedFinding is not null;

    public ObservableCollection<FindingGroup> GroupedFindings { get; } = [];

    // Packets related to a selected finding (drill-down detail)
    public ObservableCollection<ParsedPacket> DetailPackets { get; } = [];

    // ── Commands ─────────────────────────────────────────────────────

    public RelayCommand BrowseCommand { get; }
    public RelayCommand ExportCommand { get; }
    public RelayCommand<AnalysisFinding> ShowRelatedPacketsCommand { get; }
    public RelayCommand ClearDetailCommand { get; }
    public RelayCommand<string> FilterBySeverityCommand { get; }
    /// <summary>Read from the assembly so the footer cannot drift from the real version.</summary>
    public static string AppVersion { get; } =
        typeof(MainViewModel).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion.Split('+')[0]
        ?? typeof(MainViewModel).Assembly.GetName().Version?.ToString(3)
        ?? "";
    // ── Browse ───────────────────────────────────────────────────────

    private void Browse()
    {
        var dlg = new OpenFileDialog
        {
            Title = "Select Network Capture File",
            Filter = "Capture files (*.pcap;*.pcapng;*.etl;*.cab)|*.pcap;*.pcapng;*.etl;*.cab|All files (*.*)|*.*",
            CheckFileExists = true
        };

        if (dlg.ShowDialog() == true)
            _ = LoadAndAnalyzeAsync(dlg.FileName);
    }

    // ── Load & Analyze ───────────────────────────────────────────────

    public async Task LoadAndAnalyzeAsync(string path)
    {
        var cts = new CancellationTokenSource();
        var previous = Interlocked.Exchange(ref _analysisCts, cts);

        // Supersede any run still in flight; dropping a second file must not race the first.
        try { previous?.Cancel(); }
        catch (ObjectDisposedException) { /* already finished */ }

        CancellationToken cancellationToken = cts.Token;

        ErrorMessage = null;
        Report = null;
        SelectedFinding = null;
        GroupedFindings.Clear();
        DetailPackets.Clear();
        _allPackets = [];
        FilePath = path;
        IsAnalyzing = true;
        StatusMessage = "Loading capture file…";

        string? tempPcapng = null;
        string? cabTempDir = null;

        try
        {
            string fullPath = Path.GetFullPath(path);
            if (!File.Exists(fullPath))
            {
                ErrorMessage = "File not found.";
                StatusMessage = "Analysis failed.";
                return;
            }

            string extension = Path.GetExtension(fullPath).ToLowerInvariant();

            if (!AllowedCaptureTypes.IsSupported(extension) && !HasCaptureMagic(fullPath))
            {
                ErrorMessage = $"Unsupported file '{extension}'. Supported: .pcap, .pcapng, .cap, .etl, .cab";
                StatusMessage = "Analysis failed.";
                return;
            }

            string analysisPath = fullPath;

            if (AllowedCaptureTypes.IsCab(extension))
            {
                StatusMessage = "Extracting .etl from .cab archive…";

                var (etlPath, tempDir, cabError) = await CabExtractor
                    .ExtractEtlFromCabAsync(fullPath, cancellationToken);
                cabTempDir = tempDir;

                if (etlPath is null)
                {
                    ErrorMessage = $"CAB extraction failed:\n{cabError}";
                    StatusMessage = "Analysis failed.";
                    return;
                }

                analysisPath = etlPath;
                extension = ".etl";
            }

            if (AllowedCaptureTypes.IsEtl(extension))
            {
                StatusMessage = "Checking for etl2pcapng…";

                var (available, downloadError) = await EtlConverter.EnsureAvailableAsync(
                    status => StatusMessage = status, cancellationToken);

                if (!available)
                {
                    ErrorMessage = downloadError ?? "etl2pcapng.exe could not be obtained.";
                    StatusMessage = "Analysis failed.";
                    return;
                }

                StatusMessage = "Converting ETL to pcapng…";

                var (pcapngPath, conversionError) = await EtlConverter
                    .ConvertAsync(analysisPath, cancellationToken);
                if (pcapngPath is null)
                {
                    ErrorMessage = $"ETL conversion failed:\n{conversionError}";
                    StatusMessage = "Analysis failed.";
                    return;
                }

                tempPcapng = pcapngPath;
                analysisPath = pcapngPath;
            }

            StatusMessage = "Parsing packets…";

            // One read, one dissection. The parsed packets feed both the report and the
            // drill-down view; parsing twice previously doubled time and peak memory.
            var (packets, report) = await Task.Run(() =>
            {
                var (parsed, parseWarnings) = PcapReader.ReadAndParse(analysisPath, cancellationToken);
                return (parsed, _engine.AnalyzeParsed(fullPath, parsed, parseWarnings));
            }, cancellationToken);

            cancellationToken.ThrowIfCancellationRequested();

            _allPackets = packets;
            Report = report;

            foreach (var group in report.Findings
                         .GroupBy(f => f.Category)
                         .Select(g => new FindingGroup(g.Key, g.ToList())))
            {
                GroupedFindings.Add(group);
            }

            StatusMessage = $"Analysis complete — {report.TotalPackets:N0} packets, {report.Findings.Count} findings";
        }
        catch (OperationCanceledException)
        {
            // Superseded by a newer file; the newer run owns the UI state.
        }
        catch (InvalidDataException ex)
        {
            ErrorMessage = $"Invalid file: {ex.Message}";
            StatusMessage = "Analysis failed.";
        }
        catch (UnauthorizedAccessException)
        {
            ErrorMessage = "Access denied — cannot read the specified file.";
            StatusMessage = "Analysis failed.";
        }
        catch (IOException ex)
        {
            ErrorMessage = $"Could not read the file: {ex.Message}";
            StatusMessage = "Analysis failed.";
        }
        catch (Exception ex)
        {
            ErrorMessage = $"Error: {ex.Message}";
            StatusMessage = "Analysis failed.";
        }
        finally
        {
            if (Interlocked.CompareExchange(ref _analysisCts, null, cts) == cts)
                IsAnalyzing = false;

            cts.Dispose();

            if (tempPcapng is not null)
            {
                try { File.Delete(tempPcapng); }
                catch (IOException) { /* best effort */ }
                catch (UnauthorizedAccessException) { /* best effort */ }
            }
            CabExtractor.CleanupTempDir(cabTempDir);
        }
    }

    /// <summary>
    /// Fallback check for files whose extension is not recognised: the leading bytes must
    /// still identify a supported capture format before anything else touches the file.
    /// </summary>
    private static bool HasCaptureMagic(string fullPath)
    {
        try
        {
            using var probe = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);

            Span<byte> header = stackalloc byte[4];
            return probe.ReadAtLeast(header, 4, throwOnEndOfStream: false) >= 4
                   && PcapReader.IsKnownMagic(BinaryPrimitives.ReadUInt32LittleEndian(header));
        }
        catch (IOException) { return false; }
        catch (UnauthorizedAccessException) { return false; }
    }

    /// <summary>Drill-down: show packets related to a specific finding.</summary>
    private void ShowRelatedPackets(AnalysisFinding? finding)
    {
        if (finding is null) return;

        SelectedFinding = finding;
        DetailPackets.Clear();

        if (finding.RelatedPacketIndices.Count > 0)
        {
            var indexSet = finding.RelatedPacketIndices.ToHashSet();
            foreach (var pkt in _allPackets.Where(p => indexSet.Contains(p.Index)))
                DetailPackets.Add(pkt);
        }
        else
        {
            // No specific indices — show relevant packets by category heuristic
            var related = finding.Category switch
            {
                "DNS Resolution" => _allPackets.Where(p => p.Dns is not null),
                "TLS / SSL" or "TLS Cipher Compliance" => _allPackets.Where(p => p.Tls is not null),
                "Firewall Blocking" => _allPackets.Where(p => p.HasFlag(TcpFlags.RST) || (p.HasFlag(TcpFlags.SYN) && !p.HasFlag(TcpFlags.ACK))),
                "Proxy Detection" => _allPackets.Where(p => p.Http is not null),
                "Private Link" => _allPackets.Where(p => p.Dns is not null && p.Dns.IsResponse),
                _ => _allPackets.Where(p => p.Dns is not null || p.Tls is not null || p.Http is not null)
            };

            foreach (var pkt in related.Take(200))
                DetailPackets.Add(pkt);
        }

        StatusMessage = $"Showing {DetailPackets.Count} related packet(s) for: {finding.Title}";
    }

    /// <summary>Filter packets by severity badge click.</summary>
    private void FilterBySeverity(string? severity)
    {
        if (severity is null || Report is null) return;

        DetailPackets.Clear();
        SelectedFinding = null;

        var targetSev = severity switch
        {
            "Pass" => Severity.Pass,
            "Info" => Severity.Info,
            "Warning" => Severity.Warning,
            "Error" => Severity.Error,
            _ => (Severity?)null
        };

        if (targetSev is null) return;

        // Collect all packet indices from findings with this severity
        var indices = Report.Findings
            .Where(f => f.Severity == targetSev)
            .SelectMany(f => f.RelatedPacketIndices)
            .ToHashSet();

        if (indices.Count > 0)
        {
            foreach (var pkt in _allPackets.Where(p => indices.Contains(p.Index)).Take(500))
                DetailPackets.Add(pkt);
        }

        StatusMessage = $"Showing {DetailPackets.Count} packet(s) for {severity} findings";
    }

    // ── Export (async) ───────────────────────────────────────────────

    private async void ExportReport()
    {
        if (Report is null) return;

        var dlg = new SaveFileDialog
        {
            Title = "Export Analysis Report",
            Filter = "Text file (*.txt)|*.txt|Markdown (*.md)|*.md",
            FileName = $"AMA_Analysis_{Report.FileName}_{Report.AnalyzedAt:yyyyMMdd_HHmmss}"
        };

        if (dlg.ShowDialog() != true) return;

        bool markdown = dlg.FilterIndex == 2;
        var report = Report;
        string targetPath = dlg.FileName;
        StatusMessage = "Exporting report…";

        try
        {
            await Task.Run(() =>
            {
                using var writer = new StreamWriter(targetPath, false, Encoding.UTF8);
                WriteReport(writer, report, markdown);
            });
            StatusMessage = $"Report exported to {Path.GetFileName(targetPath)}";
        }
        catch (Exception ex)
        {
            // This is an async void handler: anything that escapes here terminates the
            // process rather than surfacing to the user, so the catch is deliberately broad.
            StatusMessage = $"Export failed: {ex.Message}";
        }
    }

    private static void WriteReport(StreamWriter writer, AnalysisReport report, bool md)
    {
        // Hostnames, URIs and TLS names come from the capture and are attacker-controlled,
        // so every value written here is escaped for the target format.
        string Text(string? value) => md ? SafeText.MarkdownEscape(value) : SafeText.PlainText(value);

        string h1 = md ? "# " : "";
        string h2 = md ? "## " : "=== ";
        string h3 = md ? "### " : "--- ";
        string bullet = md ? "- " : "  • ";

        writer.WriteLine($"{h1}AMA Network Trace Analysis Report");
        writer.WriteLine();
        writer.WriteLine($"File: {Text(report.FileName)}");
        writer.WriteLine($"Analyzed: {report.AnalyzedAt:yyyy-MM-dd HH:mm:ss} UTC");
        writer.WriteLine($"Packets: {report.TotalPackets:N0}");
        writer.WriteLine($"Duration: {report.CaptureDuration}");
        writer.WriteLine();
        writer.WriteLine($"{h2}Summary");
        writer.WriteLine($"{bullet}Pass: {report.PassCount}");
        writer.WriteLine($"{bullet}Info: {report.InfoCount}");
        writer.WriteLine($"{bullet}Warnings: {report.WarningCount}");
        writer.WriteLine($"{bullet}Errors: {report.ErrorCount}");
        writer.WriteLine();

        if (report.ParseWarnings.Count > 0)
        {
            writer.WriteLine($"{h2}Parser Warnings");
            writer.WriteLine();
            foreach (var warning in report.ParseWarnings)
                writer.WriteLine($"{bullet}{Text(warning)}");
            writer.WriteLine();
        }

        foreach (var group in report.Findings.GroupBy(f => f.Category))
        {
            writer.WriteLine($"{h2}{Text(group.Key)}");
            writer.WriteLine();

            foreach (var finding in group)
            {
                string icon = finding.Severity switch
                {
                    Severity.Pass => md ? ":white_check_mark:" : "[PASS]",
                    Severity.Info => md ? ":information_source:" : "[INFO]",
                    Severity.Warning => md ? ":warning:" : "[WARN]",
                    Severity.Error => md ? ":x:" : "[ERROR]",
                    _ => ""
                };

                writer.WriteLine($"{h3}{icon} {Text(finding.Title)}");
                writer.WriteLine(Text(finding.Detail));
                if (finding.ComplianceTag is not null)
                    writer.WriteLine($"{bullet}Compliance: {Text(finding.ComplianceTag)}");
                if (finding.Recommendation is not null)
                    writer.WriteLine($"{bullet}Recommendation: {Text(finding.Recommendation)}");
                if (finding.WiresharkFilter is not null)
                    writer.WriteLine($"{bullet}Wireshark filter: {(md ? $"`{finding.WiresharkFilter.Replace("`", "'", StringComparison.Ordinal)}`" : SafeText.PlainText(finding.WiresharkFilter))}");
                if (finding.RelatedPacketIndices.Count > 0)
                    writer.WriteLine($"{bullet}Related packets: {string.Join(", ", finding.RelatedPacketIndices.Take(20))}");
                writer.WriteLine();
            }
        }
    }

    // ── INotifyPropertyChanged ───────────────────────────────────────

    public event PropertyChangedEventHandler? PropertyChanged;

    private void OnPropertyChanged([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

/// <summary>Groups findings by category for the UI.</summary>
public sealed record FindingGroup(string Category, List<AnalysisFinding> Findings)
{
    public Severity WorstSeverity => Findings.Count > 0
        ? Findings.Max(f => f.Severity)
        : Severity.Pass;
}
