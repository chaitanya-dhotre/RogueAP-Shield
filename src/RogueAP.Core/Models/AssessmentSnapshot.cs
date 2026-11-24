namespace RogueAP.Core.Models;

public sealed record AssessmentSnapshot(
    NetworkAssessment Assessment,
    VpnStatus VpnStatus,
    IReadOnlyCollection<AccessPointSnapshot> NearbyNetworks,
    DateTimeOffset UpdatedAt);