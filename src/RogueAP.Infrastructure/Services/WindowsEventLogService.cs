using System.Diagnostics;
using Microsoft.Extensions.Logging;
using RogueAP.Core.Interfaces;
using RogueAP.Core.Models;

namespace RogueAP.Infrastructure.Services;

public sealed class WindowsEventLogService : IDisposable
{
    private const string SourceName = "RogueAP Shield";
    private const string LogName = "Application";
    private readonly ILogger<WindowsEventLogService> _logger;

    public WindowsEventLogService(
        ILogger<WindowsEventLogService> logger)
    {
        _logger = logger;
        EnsureEventSourceExists();
    }

    private void EnsureEventSourceExists()
    {
        try
        {
            if (!EventLog.SourceExists(SourceName))
                EventLog.CreateEventSource(SourceName, LogName);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Could not create Windows Event Log source. " +
                "Event logging will be unavailable.");
        }
    }

    public void WriteSecurityEvent(
        string message,
        EventLogEntryType entryType,
        int eventId)
    {
        try
        {
            if (!EventLog.SourceExists(SourceName)) return;

            using var log = new EventLog(LogName)
            {
                Source = SourceName
            };
            log.WriteEntry(message, entryType, eventId);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Failed to write Windows Event Log entry.");
        }
    }

    public void WriteRogueApDetected(
        string ssid, string bssid, int riskScore)
    {
        WriteSecurityEvent(
            $"Rogue access point detected.\n" +
            $"SSID: {ssid}\n" +
            $"BSSID: {bssid}\n" +
            $"Risk Score: {riskScore}/100\n" +
            $"Action: Internet access blocked.",
            EventLogEntryType.Warning,
            eventId: 1001);
    }

    public void WriteBlockEngaged(string reason)
    {
        WriteSecurityEvent(
            $"Network protection engaged.\n" +
            $"Reason: {reason}\n" +
            $"Action: All internet traffic blocked " +
            $"pending VPN verification.",
            EventLogEntryType.Warning,
            eventId: 1002);
    }

    public void WriteBlockReleased()
    {
        WriteSecurityEvent(
            "Network protection released. " +
            "Internet access restored.",
            EventLogEntryType.Information,
            eventId: 1003);
    }

    public void WriteVpnFailed(string context)
    {
        WriteSecurityEvent(
            $"VPN connection failed during " +
            $"high-risk network state.\n" +
            $"Context: {context}",
            EventLogEntryType.Error,
            eventId: 1004);
    }

    public void WriteAppStarted()
    {
        WriteSecurityEvent(
            "RogueAP Shield protection service started.",
            EventLogEntryType.Information,
            eventId: 1000);
    }

    public void WriteAppStopped()
    {
        WriteSecurityEvent(
            "RogueAP Shield protection service stopped.",
            EventLogEntryType.Information,
            eventId: 1099);
    }

    public void Dispose() { }
}