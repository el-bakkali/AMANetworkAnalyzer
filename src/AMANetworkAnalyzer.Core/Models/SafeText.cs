namespace AMANetworkAnalyzer.Models;

using System.Text;

/// <summary>
/// Turns attacker-controlled bytes from a capture into strings that are safe to put
/// in the UI and in exported reports.
/// </summary>
public static class SafeText
{
    /// <summary>Longest hostname the DNS and TLS specs allow.</summary>
    public const int MaxHostNameLength = 253;

    /// <summary>
    /// Decodes printable ASCII, replacing control and non-ASCII bytes with '.'.
    /// Capture payloads are untrusted, so control characters must never reach the UI,
    /// the clipboard, or an exported report.
    /// </summary>
    public static string PrintableAscii(ReadOnlySpan<byte> bytes, int maxLength)
    {
        if (bytes.IsEmpty || maxLength <= 0) return string.Empty;
        if (bytes.Length > maxLength) bytes = bytes[..maxLength];

        var sb = new StringBuilder(bytes.Length);
        foreach (byte b in bytes)
            sb.Append(b is >= 0x20 and <= 0x7E ? (char)b : '.');
        return sb.ToString();
    }

    /// <summary>
    /// Strips characters that have no place in a DNS name or TLS SNI value.
    /// Returns null when nothing usable remains, so callers can treat it as absent.
    /// </summary>
    public static string? HostName(ReadOnlySpan<byte> bytes)
    {
        if (bytes.IsEmpty) return null;
        if (bytes.Length > MaxHostNameLength) bytes = bytes[..MaxHostNameLength];

        var sb = new StringBuilder(bytes.Length);
        foreach (byte b in bytes)
        {
            char c = (char)b;
            bool allowed = b is >= 0x20 and <= 0x7E &&
                           (char.IsAsciiLetterOrDigit(c) || c is '-' or '.' or '_' or '*');
            if (allowed) sb.Append(c);
        }

        return sb.Length > 0 ? sb.ToString() : null;
    }

    /// <summary>Escapes text for inclusion in a Markdown report body.</summary>
    public static string MarkdownEscape(string? text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;

        var sb = new StringBuilder(text.Length + 16);
        foreach (char c in text)
        {
            if (c is '\\' or '`' or '*' or '_' or '{' or '}' or '[' or ']'
                  or '(' or ')' or '#' or '+' or '-' or '.' or '!' or '|' or '<' or '>')
                sb.Append('\\');

            // Preserve newlines; drop every other control character.
            if (c is '\n' or '\r' || !char.IsControl(c))
                sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary>Removes control characters from text destined for a plain-text report.</summary>
    public static string PlainText(string? text)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;

        var sb = new StringBuilder(text.Length);
        foreach (char c in text)
        {
            if (c is '\n' or '\r' or '\t' || !char.IsControl(c))
                sb.Append(c);
        }
        return sb.ToString();
    }

    /// <summary>
    /// Strips every control character, including newlines. Used for values parsed out of a
    /// capture that must stay on one line, such as an HTTP method, URI, or header value.
    /// </summary>
    public static string SingleLine(string? text, int maxLength = 512)
    {
        if (string.IsNullOrEmpty(text)) return string.Empty;

        var sb = new StringBuilder(Math.Min(text.Length, maxLength));
        foreach (char c in text)
        {
            if (sb.Length >= maxLength) break;
            if (!char.IsControl(c)) sb.Append(c);
        }
        return sb.ToString();
    }
}
