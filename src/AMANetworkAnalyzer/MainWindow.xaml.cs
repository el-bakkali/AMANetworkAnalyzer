namespace AMANetworkAnalyzer;

using System.Windows;
using System.Windows.Input;
using AMANetworkAnalyzer.ViewModels;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        Drop += OnFileDrop;
        DragOver += OnDragOver;
    }

    private void OnDragOver(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            var files = (string[])e.Data.GetData(DataFormats.FileDrop);
            if (files?.Length == 1 && IsSupportedFile(files[0]))
            {
                e.Effects = DragDropEffects.Copy;
                e.Handled = true;
                return;
            }
        }

        e.Effects = DragDropEffects.None;
        e.Handled = true;
    }

    private void OnFileDrop(object sender, DragEventArgs e)
    {
        if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;

        var files = (string[])e.Data.GetData(DataFormats.FileDrop);
        if (files?.Length != 1 || !IsSupportedFile(files[0])) return;

        if (DataContext is MainViewModel vm)
            _ = vm.LoadAndAnalyzeAsync(files[0]);
    }

    private void CopyFilter_Click(object sender, MouseButtonEventArgs e)
    {
        if (sender is FrameworkElement el && el.Tag is string filter)
        {
            Clipboard.SetText(filter);

            // Brief visual feedback via the status bar
            if (DataContext is MainViewModel vm)
                vm.StatusMessage = $"Copied to clipboard: {filter}";
        }
    }

    private static bool IsSupportedFile(string path)
    {
        var ext = System.IO.Path.GetExtension(path).ToLowerInvariant();
        return ext is ".pcap" or ".pcapng" or ".etl" or ".cap";
    }
}
