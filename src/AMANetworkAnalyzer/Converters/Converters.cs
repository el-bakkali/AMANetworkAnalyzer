namespace AMANetworkAnalyzer.Converters;

using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using AMANetworkAnalyzer.Models;

/// <summary>Maps Severity → SolidColorBrush for badges and icons.</summary>
public sealed class SeverityToColorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is Severity s ? s switch
        {
            Severity.Pass => new SolidColorBrush(Color.FromRgb(0x4C, 0xAF, 0x50)),    // green
            Severity.Info => new SolidColorBrush(Color.FromRgb(0x21, 0x96, 0xF3)),     // blue
            Severity.Warning => new SolidColorBrush(Color.FromRgb(0xFF, 0x98, 0x00)),  // orange
            Severity.Error => new SolidColorBrush(Color.FromRgb(0xF4, 0x43, 0x36)),    // red
            _ => new SolidColorBrush(Colors.Gray)
        } : new SolidColorBrush(Colors.Gray);

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Maps Severity → icon glyph character.</summary>
public sealed class SeverityToIconConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is Severity s ? s switch
        {
            Severity.Pass => "✓",
            Severity.Info => "ℹ",
            Severity.Warning => "⚠",
            Severity.Error => "✕",
            _ => "?"
        } : "?";

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Maps Severity → readable text.</summary>
public sealed class SeverityToTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is Severity s ? s.ToString().ToUpperInvariant() : "";

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Boolean to Visibility (true → Visible, false → Collapsed).</summary>
public sealed class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Inverse boolean to Visibility (true → Collapsed, false → Visible).</summary>
public sealed class InverseBoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is true ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>Null → Collapsed, non-null → Visible.</summary>
public sealed class NullToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is not null ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}

/// <summary>String null/empty → Collapsed, otherwise Visible.</summary>
public sealed class StringToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is string s && !string.IsNullOrEmpty(s) ? Visibility.Visible : Visibility.Collapsed;

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
