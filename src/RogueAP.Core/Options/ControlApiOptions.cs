namespace RogueAP.Core.Options;

public sealed class ControlApiOptions
{
    public const string SectionName = "ControlApi";

    public bool Enabled { get; init; } = true;

    public string Url { get; init; } = "http://127.0.0.1:5088";
}