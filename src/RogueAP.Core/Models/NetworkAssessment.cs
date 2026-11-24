using RogueAP.Core.Enums;

namespace RogueAP.Core.Models;

public sealed record NetworkAssessment(
    AccessPointSnapshot? ConnectedNetwork,
    RiskLevel RiskLevel,
    bool IsTrustedNetwork,
    int RiskScore,
    IReadOnlyCollection<string> Signals,
    string Summary);