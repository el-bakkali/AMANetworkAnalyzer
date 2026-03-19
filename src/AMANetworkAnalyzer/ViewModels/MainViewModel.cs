namespace AMANetworkAnalyzer.ViewModels;

using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
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
            // Security: validate and sanitize path (OWASP path traversal)
            string fullPath = Path.GetFullPath(path);
            if (!File.Exists(fullPath))
            {
                ErrorMessage = "File not found.";
                StatusMessage = "Analysis failed.";
                return;
            }

            string ext = Path.GetExtension(fullPath).ToLowerInvariant();

            // Security: validate file extension (OWASP input validation / CIS-16)
            if (!AllowedCaptureTypes.IsSupported(ext))
            {
                // Fallback: check magic number for pcap
                using var probe = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.Read);
                byte[] header = new byte[4];
                if (probe.Read(header, 0, 4) >= 4)
                {
                    uint magic = BitConverter.ToUInt32(header, 0);
                    bool isPcapMagic = magic is 0xa1b2c3d4 or 0xd4c3b2a1 or 0xa1b23c4d or 0x4d3cb2a1 or 0x0a0d0d0a;
                    if (!isPcapMagic)
                    {
                        ErrorMessage = $"Unsupported file extension '{ext}'. Supported: .pcap, .pcapng, .cap, .etl, .cab";
                        StatusMessage = "Analysis failed.";
                        return;
                    }
                }
            }

            string analysisPath = fullPath;

            // CAB extraction: extract .etl from .cab archive
            if (AllowedCaptureTypes.IsCab(ext))
            {
                StatusMessage = "Extracting .etl from .cab archive…";

                var (etlPath, tempDir, cabError) = await CabExtractor.ExtractEtlFromCabAsync(fullPath);
                cabTempDir = tempDir;

                if (etlPath is null)
                {
                    ErrorMessage = $"CAB extraction failed:\n{cabError}";
                    return;
                }

                // Now treat the extracted .etl as the input
                analysisPath = etlPath;
                ext = ".etl";
            }

            // ETL conversion
            if (AllowedCaptureTypes.IsEtl(ext))
            {
                StatusMessage = "Checking for etl2pcapng…";

                var (available, dlError) = await EtlConverter.EnsureAvailableAsync(
                    status => StatusMessage = status);

                if (!available)
                {
                    ErrorMessage = dlError ?? "etl2pcapng.exe could not be obtained.";
                    return;
                }

                StatusMessage = "Converting ETL to pcapng…";

                var (pcapngPath, error) = await EtlConverter.ConvertAsync(analysisPath);
                if (pcapngPath is null)
                {
                    ErrorMessage = $"ETL conversion failed:\n{error}";
                    return;
                }

                tempPcapng = pcapngPath;
                analysisPath = pcapngPath;
            }

            StatusMessage = "Parsing packets…";

            var report = await Task.Run(() =>
            {
                var (rawPackets, parseWarnings) = PcapReader.ReadFile(analysisPath);
                return _engine.Analyze(fullPath, rawPackets, parseWarnings);
            });

            // Re-parse packets for drill-down (on background thread)
            _allPackets = await Task.Run(() =>
            {
                var (rawPackets, _) = PcapReader.ReadFile(analysisPath);
                return PacketParser.ParseAll(rawPackets);
            });

            Report = report;

            var groups = report.Findings
                .GroupBy(f => f.Category)
                .Select(g => new FindingGroup(g.Key, g.ToList()))
                .ToList();

            foreach (var group in groups)
                GroupedFindings.Add(group);

            StatusMessage = $"Analysis complete — {report.TotalPackets:N0} packets, {report.Findings.Count} findings";
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
        catch (Exception ex)
        {
            ErrorMessage = $"Error: {ex.Message}";
            StatusMessage = "Analysis failed.";
        }
        finally
        {
            IsAnalyzing = false;

            if (tempPcapng is not null)
            {
                try { File.Delete(tempPcapng); } catch { }
            }
            CabExtractor.CleanupTempDir(cabTempDir);
        }
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
        StatusMessage = "Exporting report…";

        try
        {
            await Task.Run(() =>
            {
                using var writer = new StreamWriter(dlg.FileName, false, Encoding.UTF8);
                WriteReport(writer, Report, markdown);
            });
            StatusMessage = $"Report exported to {Path.GetFileName(dlg.FileName)}";
        }
        catch (Exception ex)
        {
            System.Diagnostics.Debug.WriteLine($"Export error: {ex}");
            StatusMessage = "Export failed.";
        }
    }

    private static void WriteReport(StreamWriter writer, AnalysisReport report, bool md)
    {
        string h1 = md ? "# " : "";
        string h2 = md ? "## " : "=== ";
        string h3 = md ? "### " : "--- ";
        string bullet = md ? "- " : "  • ";

        writer.WriteLine($"{h1}AMA Network Trace Analysis Report");
        writer.WriteLine();
        writer.WriteLine($"File: {report.FileName}");
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
            foreach (var w in report.ParseWarnings)
                writer.WriteLine($"{bullet}{w}");
            writer.WriteLine();
        }

        var groups = report.Findings.GroupBy(f => f.Category);
        foreach (var group in groups)
        {
            writer.WriteLine($"{h2}{group.Key}");
            writer.WriteLine();

            foreach (var f in group)
            {
                string icon = f.Severity switch
                {
                    Severity.Pass => md ? ":white_check_mark:" : "[PASS]",
                    Severity.Info => md ? ":information_source:" : "[INFO]",
                    Severity.Warning => md ? ":warning:" : "[WARN]",
                    Severity.Error => md ? ":x:" : "[ERROR]",
                    _ => ""
                };

                writer.WriteLine($"{h3}{icon} {f.Title}");
                writer.WriteLine(f.Detail);
                if (f.ComplianceTag is not null)
                    writer.WriteLine($"{bullet}Compliance: {f.ComplianceTag}");
                if (f.Recommendation is not null)
                    writer.WriteLine($"{bullet}Recommendation: {f.Recommendation}");
                if (f.WiresharkFilter is not null)
                    writer.WriteLine($"{bullet}Wireshark filter: {(md ? $"`{f.WiresharkFilter}`" : f.WiresharkFilter)}");
                if (f.RelatedPacketIndices.Count > 0)
                    writer.WriteLine($"{bullet}Related packets: {string.Join(", ", f.RelatedPacketIndices.Take(20))}");
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
