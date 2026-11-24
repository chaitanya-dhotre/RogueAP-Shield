namespace RogueAP.Core.Options;

public sealed class SecureStorageOptions
{
    public const string SectionName = "SecureStorage";

    public string DataDirectory { get; init; } = "";

    public string TrustedNetworksFileName { get; init; } = "trusted-networks.secure.json";

    public string MasterKeyStateFileName { get; init; } = "master-key-state.secure.json";

    public bool SeedDefaultTrustedNetworks { get; init; } = true;
}