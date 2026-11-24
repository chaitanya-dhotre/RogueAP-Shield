namespace RogueAP.Core.Options;

public sealed class VpnIntegrationOptions
{
    public const string SectionName = "Vpn";

    public string Mode { get; init; } = "Auto";

    public string? WireGuardConnectCommand { get; init; }

    public string? WireGuardDisconnectCommand { get; init; }

    public string? OpenVpnConnectCommand { get; init; }

    public string? OpenVpnDisconnectCommand { get; init; }

    public int CommandTimeoutSeconds { get; init; } = 20;

    public int MaxCommandRetries { get; init; } = 2;

    public int RetryDelaySeconds { get; init; } = 2;

    public bool EnableCommandValidation { get; init; } = true;

    public bool UseVendorProcessAsConnectedFallback { get; init; } = true;

    public List<string> BlockedCommandTokens { get; init; } =
    [
        "Remove-Item",
        "Remove-ItemProperty",
        "Format-Volume",
        "diskpart",
        "Stop-Computer",
        "Restart-Computer",
        "shutdown",
        "net user",
        "sc delete",
        "reg delete"
    ];

    public List<string> TunnelInterfaceHints { get; init; } =
    [
        "WireGuard",
        "Wintun",
        "TAP",
        "TUN",
        "VPN",
        "PPP"
    ];

    public List<string> VendorStatusProcessNames { get; init; } =
    [
        "nordvpn",
        "surfshark",
        "expressvpn",
        "protonvpn",
        "tunnelbear"
    ];
}