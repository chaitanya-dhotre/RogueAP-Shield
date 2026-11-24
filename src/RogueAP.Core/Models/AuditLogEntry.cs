using System.Security.Cryptography;
using System.Text;

namespace RogueAP.Core.Models;

public sealed record AuditLogEntry
{
    public long Sequence { get; init; }
    public DateTimeOffset Timestamp { get; init; }
    public string Action { get; init; } = "";
    public string Category { get; init; } = "";
    public string? Detail { get; init; }
    public string? ActorContext { get; init; }
    public string PreviousEntryHash { get; init; } = "";
    public string EntryHash { get; init; } = "";

    public static string ComputeHash(
        long sequence,
        DateTimeOffset timestamp,
        string action,
        string category,
        string? detail,
        string? actorContext,
        string previousEntryHash)
    {
        var input = $"{sequence}{timestamp:O}{action}{category}{detail ?? ""}{actorContext ?? ""}{previousEntryHash}";
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public string RecomputeHash()
    {
        return ComputeHash(Sequence, Timestamp, Action, Category, Detail, ActorContext, PreviousEntryHash);
    }
}

public static class AuditCategories
{
    public const string Network = "NETWORK";
    public const string Risk = "RISK";
    public const string Trust = "TRUST";
    public const string Enforcement = "ENFORCEMENT";
    public const string Vpn = "VPN";
    public const string Auth = "AUTH";
    public const string System = "SYSTEM";
    public const string Learning = "LEARNING";
}

public static class AuditActions
{
    public const string Connected = "CONNECTED";
    public const string Disconnected = "DISCONNECTED";
    public const string ScanComplete = "SCAN_COMPLETE";

    public const string RiskCritical = "RISK_CRITICAL";
    public const string RiskHigh = "RISK_HIGH";
    public const string RiskMedium = "RISK_MEDIUM";
    public const string RiskLow = "RISK_LOW";
    public const string AlertFired = "ALERT_FIRED";

    public const string TrustedAdded = "TRUSTED_ADDED";
    public const string TrustedRemoved = "TRUSTED_REMOVED";

    public const string BlockEngaged = "BLOCK_ENGAGED";
    public const string BlockReleased = "BLOCK_RELEASED";

    public const string VpnConnected = "VPN_CONNECTED";
    public const string VpnDisconnected = "VPN_DISCONNECTED";
    public const string VpnFailed = "VPN_FAILED";

    public const string MasterKeyVerified = "MASTER_KEY_VERIFIED";
    public const string MasterKeyWrongAttempt = "MASTER_KEY_WRONG_ATTEMPT";

    public const string AppStarted = "APP_STARTED";
    public const string AppStopped = "APP_STOPPED";
    public const string FactoryReset = "FACTORY_RESET";

    public const string LearningStarted = "LEARNING_STARTED";
    public const string LearningComplete = "LEARNING_COMPLETE";
}
