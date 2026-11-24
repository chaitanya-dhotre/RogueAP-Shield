namespace RogueAP.Core.Models;

public sealed record TrustedNetwork(
    string Ssid,
    string Bssid,
    string SecurityProtocol,
    DateTimeOffset AddedAt,
    double? BandGHz = null,
    int? Channel = null,
    string? VendorOui = null,
    string? GatewayIp = null,
    string? DhcpServerIp = null,
    int? GatewayTtl = null,
    string? InternalHostname = null,
    string? ExpectedInternalIp = null,
    string? BeaconFingerprintHash = null);