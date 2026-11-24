namespace RogueAP.Core.Options;

public sealed class EnforcementOptions
{
    public const string SectionName = "Enforcement";

    public bool UseWindowsFirewall { get; init; } = true;

    public bool DryRun { get; init; } = true;

    public string FirewallRuleName { get; init; } = "RogueAP_BlockAllOutbound";
}