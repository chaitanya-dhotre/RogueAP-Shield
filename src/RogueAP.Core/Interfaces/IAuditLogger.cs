using RogueAP.Core.Models;

namespace RogueAP.Core.Interfaces;

public interface IAuditLogger
{
    Task LogAsync(
        string action,
        string category,
        string? detail = null,
        string? actorContext = null,
        CancellationToken ct = default);

    Task<IReadOnlyList<AuditLogEntry>> GetRecentAsync(
        int count = 100,
        CancellationToken ct = default);

    Task<AuditLogChainStatus> VerifyChainIntegrityAsync(
        CancellationToken ct = default);

    Task FlushPendingEntries(CancellationToken ct = default);
}

public sealed record AuditLogChainStatus(
    bool IsIntact,
    long TotalEntries,
    long? FirstBrokenAtSequence,
    string Message);
