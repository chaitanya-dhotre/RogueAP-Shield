namespace RogueAP.Core.Models;

public sealed record EnforcementStatus(
    bool IsBlockingActive,
    bool IsDryRun,
    bool IsSupported,
    string RuleName,
    DateTimeOffset CheckedAt,
    string? Note);
