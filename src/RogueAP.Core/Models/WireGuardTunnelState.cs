namespace RogueAP.Core.Models;

public sealed record WireGuardTunnelState(
    string TunnelName,
    bool IsUp,
    DateTime? LastHandshake,
    bool IsHandshakeStale,
    ulong RxBytes,
    ulong TxBytes,
    string? ErrorMessage);
