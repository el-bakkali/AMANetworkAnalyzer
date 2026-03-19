namespace AMANetworkAnalyzer.Models;

// ── Link-layer types we support ──────────────────────────────────────
public enum LinkLayerType : uint
{
    Ethernet = 1,
    Raw = 101,       // Raw IP (no link-layer header)
    LinuxSll = 113   // Linux cooked capture v1
}

// ── IP protocols ─────────────────────────────────────────────────────
public enum IpProtocol : byte
{
    Tcp = 6,
    Udp = 17
}

// ── TCP flags ────────────────────────────────────────────────────────
[Flags]
public enum TcpFlags : byte
{
    None = 0,
    FIN = 0x01,
    SYN = 0x02,
    RST = 0x04,
    PSH = 0x08,
    ACK = 0x10,
    URG = 0x20
}

// ── Severity of an analysis finding ──────────────────────────────────
public enum Severity { Pass, Info, Warning, Error }

// ── Raw packet straight from the capture file ────────────────────────
public sealed record RawPacket(DateTime Timestamp, byte[] Data, LinkLayerType LinkType);

// ── Fully parsed packet ──────────────────────────────────────────────
public sealed class ParsedPacket
{
    public int Index { get; init; }
    public DateTime Timestamp { get; init; }

    // Layer 2
    public string? SourceMac { get; set; }
    public string? DestMac { get; set; }

    // Layer 3
    public string? SourceIp { get; set; }
    public string? DestIp { get; set; }
    public IpProtocol? Protocol { get; set; }

    // Layer 4
    public ushort SourcePort { get; set; }
    public ushort DestPort { get; set; }
    public TcpFlags TcpFlags { get; set; }
    public bool IsTcpRetransmission { get; set; }

    // Layer 7
    public DnsInfo? Dns { get; set; }
    public TlsInfo? Tls { get; set; }
    public HttpInfo? Http { get; set; }

    // Raw payload (TCP/UDP payload bytes, for content matching)
    public byte[] Payload { get; set; } = [];

    public bool HasFlag(TcpFlags flag) => (TcpFlags & flag) == flag;

    public override string ToString() =>
        $"#{Index} {Timestamp:HH:mm:ss.fff} {SourceIp}:{SourcePort} → {DestIp}:{DestPort} [{TcpFlags}]";
}

// ── DNS ──────────────────────────────────────────────────────────────
public sealed class DnsInfo
{
    public ushort TransactionId { get; set; }
    public bool IsResponse { get; set; }
    public ushort ResponseCode { get; set; } // 0=NoError, 2=SERVFAIL, 3=NXDOMAIN
    public List<string> QueryNames { get; set; } = [];
    public List<DnsAnswer> Answers { get; set; } = [];

    public string ResponseCodeName => ResponseCode switch
    {
        0 => "NoError",
        1 => "FormErr",
        2 => "ServFail",
        3 => "NXDomain",
        4 => "NotImp",
        5 => "Refused",
        _ => $"Unknown({ResponseCode})"
    };
}

public sealed record DnsAnswer(string Name, ushort Type, string Data);

// ── TLS ──────────────────────────────────────────────────────────────
public sealed class TlsInfo
{
    public byte ContentType { get; set; }   // 20=CCS, 21=Alert, 22=Handshake, 23=AppData
    public ushort RecordVersion { get; set; }
    public TlsHandshakeInfo? Handshake { get; set; }
    public TlsAlertInfo? Alert { get; set; }
}

public sealed class TlsHandshakeInfo
{
    public byte HandshakeType { get; set; } // 1=ClientHello, 2=ServerHello
    public ushort ClientVersion { get; set; }
    public string? ServerName { get; set; }  // SNI extension
    public List<ushort> OfferedCipherSuites { get; set; } = [];
    public ushort SelectedCipherSuite { get; set; }
    public List<ushort> SupportedVersions { get; set; } = []; // supported_versions ext
}

public sealed class TlsAlertInfo
{
    public byte Level { get; set; }       // 1=warning, 2=fatal
    public byte Description { get; set; }

    public string LevelName => Level switch { 1 => "Warning", 2 => "Fatal", _ => $"Unknown({Level})" };

    public string DescriptionName => Description switch
    {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        40 => "handshake_failure",
        42 => "bad_certificate",
        43 => "unsupported_certificate",
        44 => "certificate_revoked",
        45 => "certificate_expired",
        46 => "certificate_unknown",
        47 => "illegal_parameter",
        48 => "unknown_ca",
        50 => "decode_error",
        51 => "decrypt_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        90 => "user_canceled",
        109 => "missing_extension",
        112 => "unrecognized_name",
        120 => "no_application_protocol",
        _ => $"unknown({Description})"
    };
}

// ── HTTP (basic) ─────────────────────────────────────────────────────
public sealed class HttpInfo
{
    public string? Method { get; set; }      // GET, CONNECT, POST, etc.
    public string? RequestUri { get; set; }  // The URI from the request line
    public int? StatusCode { get; set; }     // Response status code
    public string? StatusPhrase { get; set; }
    public Dictionary<string, string> Headers { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

// ── Analysis output ──────────────────────────────────────────────────
public sealed class AnalysisFinding
{
    public required string RuleName { get; init; }
    public required string Category { get; init; }
    public required Severity Severity { get; init; }
    public required string Title { get; init; }
    public required string Detail { get; init; }
    public string? Recommendation { get; init; }
    public string? WiresharkFilter { get; init; }
    public List<int> RelatedPacketIndices { get; init; } = [];
}

public sealed class AnalysisReport
{
    public string FileName { get; set; } = "";
    public DateTime AnalyzedAt { get; set; } = DateTime.UtcNow;
    public int TotalPackets { get; set; }
    public TimeSpan CaptureDuration { get; set; }
    public List<AnalysisFinding> Findings { get; set; } = [];

    public int PassCount => Findings.Count(f => f.Severity == Severity.Pass);
    public int InfoCount => Findings.Count(f => f.Severity == Severity.Info);
    public int WarningCount => Findings.Count(f => f.Severity == Severity.Warning);
    public int ErrorCount => Findings.Count(f => f.Severity == Severity.Error);
}

// ── TLS cipher suites known to AMA ──────────────────────────────────
public static class AmaCipherSuites
{
    // TLS 1.3
    public const ushort TLS_AES_256_GCM_SHA384 = 0x1302;
    public const ushort TLS_AES_128_GCM_SHA256 = 0x1301;

    // TLS 1.2
    public const ushort TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030;
    public const ushort TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f;

    public static readonly Dictionary<ushort, string> Required = new()
    {
        [TLS_AES_256_GCM_SHA384] = "TLS_AES_256_GCM_SHA384",
        [TLS_AES_128_GCM_SHA256] = "TLS_AES_128_GCM_SHA256",
        [TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384] = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        [TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256] = "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    };

    public static string GetName(ushort id) =>
        Required.TryGetValue(id, out var name) ? name : $"0x{id:X4}";
}

// ── AMA endpoints ────────────────────────────────────────────────────
public static class AmaEndpoints
{
    // Endpoint patterns for Azure Commercial (.com), Government (.us), and China 21Vianet (.cn)
    // See: https://learn.microsoft.com/azure/azure-monitor/agents/azure-monitor-agent-network-configuration
    public static readonly (string Pattern, string Description)[] All =
    [
        // Azure Commercial
        ("global.handler.control.monitor.azure.com", "Global control service"),
        ("handler.control.monitor.azure.com", "Regional control service (DCR fetch)"),
        ("ods.opinsights.azure.com", "Log data ingestion (ODS)"),
        ("ingest.monitor.azure.com", "DCE data ingestion"),
        ("management.azure.com", "ARM (custom metrics)"),
        ("monitoring.azure.com", "Custom metrics ingestion"),
        ("global.prod.microsoftmetrics.com", "Metrics service"),

        // Azure Government
        ("global.handler.control.monitor.azure.us", "Global control service (Gov)"),
        ("handler.control.monitor.azure.us", "Regional control service (Gov)"),
        ("ods.opinsights.azure.us", "Log data ingestion (Gov)"),
        ("ingest.monitor.azure.us", "DCE data ingestion (Gov)"),
        ("management.azure.us", "ARM (Gov)"),
        ("monitoring.azure.us", "Custom metrics ingestion (Gov)"),

        // Azure China (21Vianet)
        ("global.handler.control.monitor.azure.cn", "Global control service (China)"),
        ("handler.control.monitor.azure.cn", "Regional control service (China)"),
        ("ods.opinsights.azure.cn", "Log data ingestion (China)"),
        ("ingest.monitor.azure.cn", "DCE data ingestion (China)"),
        ("management.azure.cn", "ARM (China)"),
        ("monitoring.azure.cn", "Custom metrics ingestion (China)"),
    ];

    /// <summary>Checks if a hostname matches any AMA endpoint pattern.</summary>
    public static bool IsAmaEndpoint(string hostname)
    {
        foreach (var (pattern, _) in All)
        {
            if (hostname.EndsWith(pattern, StringComparison.OrdinalIgnoreCase) ||
                hostname.Equals(pattern, StringComparison.OrdinalIgnoreCase))
                return true;
        }
        return false;
    }

    /// <summary>Returns the matching endpoint description, or null.</summary>
    public static string? MatchEndpoint(string hostname)
    {
        foreach (var (pattern, desc) in All)
        {
            if (hostname.EndsWith(pattern, StringComparison.OrdinalIgnoreCase) ||
                hostname.Equals(pattern, StringComparison.OrdinalIgnoreCase))
                return desc;
        }
        return null;
    }
}
