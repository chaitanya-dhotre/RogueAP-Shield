namespace RogueAP.Core.Models;

public sealed record VpnRuntimeConfig(
    string Mode,
    string? WireGuardConnectCommand,
    string? WireGuardDisconnectCommand,
    string? OpenVpnConnectCommand,
    string? OpenVpnDisconnectCommand,
    DateTimeOffset? AutoConnectSuppressedUntilUtc);