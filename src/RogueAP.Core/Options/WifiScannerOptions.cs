namespace RogueAP.Core.Options;

public sealed class WifiScannerOptions
{
    public const string SectionName = "WifiScanner";

    public bool UseNetshScanner { get; init; } = true;

    public int SignalHistoryLimit { get; init; } = 6;
}