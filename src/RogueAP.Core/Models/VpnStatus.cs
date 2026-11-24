namespace RogueAP.Core.Models;

public sealed record VpnStatus(
    bool IsConnected,
    string? ProviderName,
    string? TunnelInterface,
    DateTimeOffset CheckedAt);