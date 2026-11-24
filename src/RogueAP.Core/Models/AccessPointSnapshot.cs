namespace RogueAP.Core.Models;

public sealed record AccessPointSnapshot(
    string Ssid,
    string Bssid,
    string SecurityProtocol,
    int SignalStrength,
    DateTimeOffset ObservedAt,
    IReadOnlyCollection<int>? RecentSignalSamples = null,
    double? BandGHz = null,
    int? Channel = null,
    string? VendorOui = null,
    string? GatewayIp = null,
    string? DhcpServerIp = null,
    int? GatewayTtl = null,
    int? ObservedGatewayTtl = null);