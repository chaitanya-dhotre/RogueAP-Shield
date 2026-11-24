namespace RogueAP.Core.Models;

public sealed record NetworkProfile
{
    public string Ssid { get; init; } = "";
    public string DeploymentProfile { get; init; } = "Home";

    public bool LearningComplete { get; init; } = false;
    public DateTimeOffset LearningStartedAt { get; init; }
    public DateTimeOffset? LearningCompletedAt { get; init; }
    public int LearningDurationHours { get; init; } = 72;

    public IReadOnlyList<string> KnownBssids { get; init; } = [];

    public IReadOnlyDictionary<string, string> BeaconFingerprints { get; init; }
        = new Dictionary<string, string>();

    public string? CommonGatewayIp { get; init; }
    public int? CommonGatewayTtl { get; init; }
    public int GatewayTtlVariance { get; init; } = 5;

    public IReadOnlyDictionary<string, SignalStats> SignalProfiles { get; init; }
        = new Dictionary<string, SignalStats>();

    public string? CommonSecurityProtocol { get; init; }

    public int ObservedBssidCount { get; init; }
    public int MaxExpectedBssidCount { get; init; }
}
