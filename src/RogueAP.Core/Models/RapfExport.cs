namespace RogueAP.Core.Models;

public sealed record RapfExport
{
    public string FormatVersion { get; init; } = "1.0";
    public DateTimeOffset ExportedAt { get; init; }
    public string ExportedFromProfile { get; init; } = "Home";
    public string Description { get; init; } = "";

    public IReadOnlyList<TrustedNetwork> TrustedNetworks { get; init; } = [];

    public IReadOnlyList<NetworkProfile> NetworkProfiles { get; init; } = [];

    public string DeploymentProfile { get; init; } = "Home";

    public string ContentHash { get; init; } = "";
}
