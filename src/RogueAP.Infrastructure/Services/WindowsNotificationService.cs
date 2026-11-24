using System.Collections.Concurrent;
using System.Security.AccessControl;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Toolkit.Uwp.Notifications;
using Microsoft.Win32;
using Windows.UI.Notifications;
using RogueAP.Core.Enums;
using RogueAP.Core.Interfaces;
using RogueAP.Core.Options;

namespace RogueAP.Infrastructure.Services;

public sealed class WindowsNotificationService : INotificationService
{
    private const string RiskThrottleKey = "risk-popup";

    private static readonly string PendingPath =
        Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData),
            "RogueAP",
            "pending-notification.json");

    private readonly ILogger<WindowsNotificationService> _logger;
    private readonly NotificationOptions _options;
    private readonly ConcurrentDictionary<string, ThrottleState> _throttle = new(StringComparer.OrdinalIgnoreCase);

    public WindowsNotificationService(
        ILogger<WindowsNotificationService> logger,
        IOptions<NotificationOptions> options)
    {
        _logger = logger;
        _options = options.Value;
        RegisterAsAlarmApp();
    }

    private static void RegisterAsAlarmApp()
    {
        try
        {
            const string aumid = "RogueAPShield";
            var keyPath =
                $"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Notifications\\Settings\\{aumid}";

            using var key = Registry.CurrentUser
                .CreateSubKey(keyPath);
            // 2 = bypass DND for this app
            key?.SetValue("Enabled", 1,
                RegistryValueKind.DWord);
            // Allow during focus assist
            key?.SetValue(
                "ShowInActionCenter", 1,
                RegistryValueKind.DWord);
        }
        catch { } // never crash service for this
    }

    public Task PublishAsync(PolicyAction action, string title, string message, CancellationToken cancellationToken)
    {
        _logger.LogInformation("Notification action={Action}, title={Title}, message={Message}", action, title, message);

        if (_options.PopupMediumOrHigherOnly && action is not (PolicyAction.AlertHighPriority or PolicyAction.AlertCritical))
        {
            return Task.CompletedTask;
        }

        var severity = ResolveSeverity(action, title, message);
        if (!ShouldNotifyNow(RiskThrottleKey, severity, DateTimeOffset.UtcNow, out var nextDueAt))
        {
            _logger.LogDebug("Notification throttled for severity={Severity}. Next due at {NextDueAt}.", severity, nextDueAt);
            return Task.CompletedTask;
        }

        if (!OperatingSystem.IsWindows() || !_options.EnableWindowsNotifications)
        {
            return Task.CompletedTask;
        }

        var effectiveTitle = BuildSeverityTitle(action, title);
        SendNativeToast(effectiveTitle, message, severity);
        return Task.CompletedTask;
    }

    private void SendNativeToast(string title, string message, NotificationSeverity severity)
    {
        try
        {
            var builder = new ToastContentBuilder()
                .AddText(title)
                .AddText(message)
                .AddAttributionText("RogueAP Shield");

            if (severity >= NotificationSeverity.High)
            {
                builder.SetToastScenario(ToastScenario.Alarm);
            }

            var toastContent = builder.GetToastContent();
            var notification = new ToastNotification(toastContent.GetXml());

            // High priority for Critical/High risk alerts to bypass DND
            if (severity >= NotificationSeverity.High)
            {
                notification.Priority = ToastNotificationPriority.High;
                notification.SuppressPopup = false;
            }

            ToastNotificationManager.CreateToastNotifier().Show(notification);
            _logger.LogInformation("Windows toast notification delivered (severity={Severity}, priority={Priority}).", severity, notification.Priority);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Native toast notification failed (likely SYSTEM context). Writing pending notification for GUI to display.");
            WritePendingNotification(title, message, severity.ToString());
        }
    }

    private void WritePendingNotification(string title, string message, string severity)
    {
        try
        {
            var dir = Path.GetDirectoryName(PendingPath);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var notification = new
            {
                title,
                message,
                severity,
                timestamp = DateTimeOffset.UtcNow
            };
            var json = JsonSerializer.Serialize(notification);
            File.WriteAllText(PendingPath, json);
            _logger.LogInformation("Pending notification written to {Path}", PendingPath);

            // FIX 2: Grant Users group permission to read/write/delete the file
            // This allows GUI (running as user) to delete the file written by SYSTEM
            try
            {
                var fileInfo = new FileInfo(PendingPath);
                var security = fileInfo.GetAccessControl();
                security.AddAccessRule(
                    new FileSystemAccessRule(
                        "Users",
                        FileSystemRights.FullControl,
                        AccessControlType.Allow));
                fileInfo.SetAccessControl(security);
            }
            catch { }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to write pending notification to {Path}", PendingPath);
        }
    }

    private static string BuildSeverityTitle(PolicyAction action, string title)
    {
        return action switch
        {
            PolicyAction.AlertCritical => $"CRITICAL - {title}",
            PolicyAction.AlertHighPriority => $"HIGH RISK - {title}",
            PolicyAction.AlertInfo => $"INFO - {title}",
            _ => title
        };
    }

    private bool ShouldNotifyNow(string key, NotificationSeverity severity, DateTimeOffset now, out DateTimeOffset nextDueAt)
    {
        var state = _throttle.GetOrAdd(key, _ => new ThrottleState());

        lock (state.Sync)
        {
            var quietResetMinutes = Math.Max(1, _options.ResetAfterQuietMinutes);
            var quietWindow = TimeSpan.FromMinutes(quietResetMinutes);
            var shouldResetForQuietPeriod =
                state.LastSentAt is not null
                && now - state.LastSentAt.Value >= quietWindow;

            if (shouldResetForQuietPeriod)
            {
                state.SentCount = 0;
                state.NextAllowedAt = null;
                state.LastSeverity = NotificationSeverity.None;
                _logger.LogInformation("Notification throttle reset after quiet period of {Minutes} minutes.", quietResetMinutes);
            }

            var shouldBypassThrottle =
                _options.NotifyImmediatelyOnSeverityIncrease
                && severity > state.LastSeverity
                && state.LastSeverity is not NotificationSeverity.None;

            if (shouldBypassThrottle)
            {
                state.SentCount = 0;
                state.NextAllowedAt = null;
                _logger.LogInformation("Notification severity increased from {Previous} to {Current}; bypassing throttle.", state.LastSeverity, severity);
            }

            if (state.NextAllowedAt is not null && now < state.NextAllowedAt.Value)
            {
                nextDueAt = state.NextAllowedAt.Value;
                return false;
            }

            state.SentCount++;
            var delay = ResolveNextDelay(state.SentCount);
            state.NextAllowedAt = now.Add(delay);
            state.LastSeverity = severity;
            state.LastSentAt = now;
            nextDueAt = state.NextAllowedAt.Value;
            return true;
        }
    }

    private TimeSpan ResolveNextDelay(int sentCount)
    {
        var first = Math.Max(1, _options.RepeatAfterFirstMinutes);
        var second = Math.Max(first, _options.RepeatAfterSecondMinutes);
        var third = Math.Max(1, _options.RepeatAfterThirdMinutes);

        return sentCount switch
        {
            1 => TimeSpan.FromMinutes(first),
            2 => TimeSpan.FromMinutes(Math.Max(1, second - first)),
            _ => TimeSpan.FromMinutes(third)
        };
    }

    private sealed class ThrottleState
    {
        public object Sync { get; } = new();

        public int SentCount { get; set; }

        public DateTimeOffset? NextAllowedAt { get; set; }

        public NotificationSeverity LastSeverity { get; set; } = NotificationSeverity.None;

        public DateTimeOffset? LastSentAt { get; set; }
    }

    private static NotificationSeverity ResolveSeverity(PolicyAction action, string title, string message)
    {
        if (action == PolicyAction.AlertCritical)
        {
            return NotificationSeverity.Critical;
        }

        if (action == PolicyAction.AlertInfo)
        {
            return NotificationSeverity.Low;
        }

        if (action == PolicyAction.AlertHighPriority)
        {
            if (ContainsRiskToken(title, message, "critical"))
            {
                return NotificationSeverity.Critical;
            }

            if (ContainsRiskToken(title, message, "high"))
            {
                return NotificationSeverity.High;
            }

            if (ContainsRiskToken(title, message, "medium"))
            {
                return NotificationSeverity.Medium;
            }

            return NotificationSeverity.High;
        }

        return NotificationSeverity.None;
    }

    private static bool ContainsRiskToken(string title, string message, string token)
    {
        return title.Contains(token, StringComparison.OrdinalIgnoreCase)
            || message.Contains(token, StringComparison.OrdinalIgnoreCase);
    }

    private enum NotificationSeverity
    {
        None = 0,
        Low = 1,
        Medium = 2,
        High = 3,
        Critical = 4
    }
}