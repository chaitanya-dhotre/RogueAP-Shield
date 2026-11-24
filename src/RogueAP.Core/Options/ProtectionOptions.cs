namespace RogueAP.Core.Options;

public sealed class ProtectionOptions
{
    public const string SectionName = "Protection";

    public int ScanIntervalSeconds { get; init; } = 15;

    public bool AlertOnlyOnTrustedNetworks { get; init; } = true;

    public bool EnableHardBlockOnCritical { get; init; } = true;

    public bool AutoAttemptVpnOnMediumUntrusted { get; init; } = true;

    public bool AutoAttemptVpnOnHighUntrusted { get; init; } = true;

    // Home | Enterprise | Campus
    public string DeploymentProfile { get; init; } = "Home";
}