namespace RogueAP.Core.Models;

public sealed record VpnRuntimeConfigUpdate(
    string? Mode,
    string? WireGuardConnectCommand,
    string? WireGuardDisconnectCommand,
    string? OpenVpnConnectCommand,
    string? OpenVpnDisconnectCommand,
    DateTimeOffset? AutoConnectSuppressedUntilUtc = null);