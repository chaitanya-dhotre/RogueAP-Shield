using RogueAP.Core.Enums;

namespace RogueAP.Core.Models;

public sealed record EnforcementDecision(
    RiskLevel RiskLevel,
    bool IsTrustedNetwork,
    IReadOnlyCollection<PolicyAction> ImmediateActions,
    bool BlockIfVpnConnectFails,
    string Reason);