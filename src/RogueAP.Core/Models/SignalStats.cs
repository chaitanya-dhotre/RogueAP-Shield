namespace RogueAP.Core.Models;

public sealed record SignalStats(
    double Mean,
    double StdDev,
    int SampleCount);
