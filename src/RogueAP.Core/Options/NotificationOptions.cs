namespace RogueAP.Core.Options;

public sealed class NotificationOptions
{
    public const string SectionName = "Notifications";

    public bool EnableWindowsNotifications { get; init; } = true;

    public bool EnableMsgFallback { get; init; } = true;

    public int MsgTimeoutSeconds { get; init; } = 15;

    public bool UseBurntToastModule { get; init; } = true;

    public bool PopupMediumOrHigherOnly { get; init; } = true;

    public bool NotifyImmediatelyOnSeverityIncrease { get; init; } = true;

    public int RepeatAfterFirstMinutes { get; init; } = 5;

    public int RepeatAfterSecondMinutes { get; init; } = 15;

    public int RepeatAfterThirdMinutes { get; init; } = 30;

    public int ResetAfterQuietMinutes { get; init; } = 60;
}