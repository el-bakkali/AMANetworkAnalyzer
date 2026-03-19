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

    public MainViewModel()
    {
        BrowseCommand = new RelayCommand(Browse);
        ExportCommand = new RelayCommand(ExportReport, () => Report is not null);
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

    public bool HasFile => FilePath is not null;
    public bool HasReport => Report is not null;
    public bool HasError => ErrorMessage is not null;

    public ObservableCollection<FindingGroup> GroupedFindings { get; } = [];

    // ── Commands ─────────────────────────────────────────────────────

    public RelayCommand BrowseCommand { get; }
    public RelayCommand ExportCommand { get; }

    // ── Browse ───────────────────────────────────────────────────────

    private void Browse()
    {
        var dlg = new OpenFileDialog
        {
            Title = "Select Network Capture File",
            Filter = "Capture files (*.pcap;*.pcapng;*.etl)|*.pcap;*.pcapng;*.etl|All files (*.*)|*.*",
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
        GroupedFindings.Clear();
        FilePath = path;
        IsAnalyzing = true;
        StatusMessage = "Loading capture file…";

        string? tempPcapng = null;

        try
        {
            string analysisPath = path;

            // ETL conversion
            if (Path.GetExtension(path).Equals(".etl", StringComparison.OrdinalIgnoreCase))
            {
                StatusMessage = "Checking for etl2pcapng…";

                // Auto-download etl2pcapng if not found
                var (available, dlError) = await EtlConverter.EnsureAvailableAsync(
                    status => StatusMessage = status);

                if (!available)
                {
                    ErrorMessage = dlError ?? "etl2pcapng.exe could not be obtained.";
                    return;
                }

                StatusMessage = "Converting ETL to pcapng…";

                var (pcapngPath, error) = await EtlConverter.ConvertAsync(path);
                if (pcapngPath is null)
                {
                    ErrorMessage = $"ETL conversion failed:\n{error}";
                    return;
                }

                tempPcapng = pcapngPath;
                analysisPath = pcapngPath;
            }

            StatusMessage = "Parsing packets…";

            // Run parsing and analysis on a background thread
            var report = await Task.Run(() =>
            {
                var rawPackets = PcapReader.ReadFile(analysisPath);
                return _engine.Analyze(path, rawPackets);
            });

            Report = report;

            // Group findings by category
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
            ErrorMessage = $"Invalid file format:\n{ex.Message}";
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

            // Clean up temp file
            if (tempPcapng is not null)
            {
                try { File.Delete(tempPcapng); } catch { }
            }
        }
    }

    // ── Export ────────────────────────────────────────────────────────

    private void ExportReport()
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
        string content = FormatReport(Report, markdown);
        File.WriteAllText(dlg.FileName, content, Encoding.UTF8);

        StatusMessage = $"Report exported to {Path.GetFileName(dlg.FileName)}";
    }

    private static string FormatReport(AnalysisReport report, bool md)
    {
        var sb = new StringBuilder();
        string h1 = md ? "# " : "";
        string h2 = md ? "## " : "=== ";
        string h3 = md ? "### " : "--- ";
        string bullet = md ? "- " : "  • ";

        sb.AppendLine($"{h1}AMA Network Trace Analysis Report");
        sb.AppendLine();
        sb.AppendLine($"File: {report.FileName}");
        sb.AppendLine($"Analyzed: {report.AnalyzedAt:yyyy-MM-dd HH:mm:ss} UTC");
        sb.AppendLine($"Packets: {report.TotalPackets:N0}");
        sb.AppendLine($"Duration: {report.CaptureDuration}");
        sb.AppendLine();
        sb.AppendLine($"{h2}Summary");
        sb.AppendLine($"{bullet}Pass: {report.PassCount}");
        sb.AppendLine($"{bullet}Info: {report.InfoCount}");
        sb.AppendLine($"{bullet}Warnings: {report.WarningCount}");
        sb.AppendLine($"{bullet}Errors: {report.ErrorCount}");
        sb.AppendLine();

        var groups = report.Findings.GroupBy(f => f.Category);
        foreach (var group in groups)
        {
            sb.AppendLine($"{h2}{group.Key}");
            sb.AppendLine();

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

                sb.AppendLine($"{h3}{icon} {f.Title}");
                sb.AppendLine(f.Detail);
                if (f.Recommendation is not null)
                    sb.AppendLine($"{bullet}Recommendation: {f.Recommendation}");
                if (f.WiresharkFilter is not null)
                    sb.AppendLine($"{bullet}Wireshark filter: {(md ? $"`{f.WiresharkFilter}`" : f.WiresharkFilter)}");
                sb.AppendLine();
            }
        }

        return sb.ToString();
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
