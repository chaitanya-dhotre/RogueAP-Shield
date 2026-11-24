using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text.RegularExpressions;
using ManagedNativeWifi;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RogueAP.Core.Interfaces;
using RogueAP.Core.Models;
using RogueAP.Core.Options;

namespace RogueAP.Infrastructure.Services;

public sealed partial class WindowsNetshWifiScanner : IWifiScanner
{
    private readonly ILogger<WindowsNetshWifiScanner> _logger;
    private readonly WifiScannerOptions _options;
    private readonly IBeaconFrameService _beaconFrameService;
    private readonly ConcurrentDictionary<string, Queue<int>> _signalHistory = new(StringComparer.OrdinalIgnoreCase);

    public WindowsNetshWifiScanner(
        ILogger<WindowsNetshWifiScanner> logger,
        IOptions<WifiScannerOptions> options,
        IBeaconFrameService beaconFrameService)
    {
        _logger = logger;
        _options = options.Value;
        _beaconFrameService = beaconFrameService;
    }

    public async Task<IReadOnlyCollection<AccessPointSnapshot>> ScanNearbyAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows() || !_options.UseNetshScanner)
        {
            return [];
        }

        await TriggerActiveScanAsync(cancellationToken);
        _beaconFrameService.ScheduleRescan(TimeSpan.FromSeconds(3));
        await Task.Delay(2000, cancellationToken);

        var merged = new Dictionary<string, AccessPointSnapshot>(StringComparer.OrdinalIgnoreCase);

        async Task MergePassAsync()
        {
            var output = await RunNetshAsync("wlan show networks mode=bssid", cancellationToken);
            if (string.IsNullOrWhiteSpace(output))
            {
                return;
            }

            foreach (var snapshot in ParseNearbyOutput(output))
            {
                var key = $"{snapshot.Bssid}|{snapshot.Ssid}";
                if (merged.TryGetValue(key, out var existing))
                {
                    if (snapshot.SignalStrength > existing.SignalStrength)
                    {
                        merged[key] = snapshot;
                    }

                    continue;
                }

                merged[key] = snapshot;
            }
        }

        await MergePassAsync();
        if (merged.Count <= 1)
        {
            var previousCount = merged.Count;
            const int maxAdditionalPasses = 4;
            for (var i = 0; i < maxAdditionalPasses; i++)
            {
                await Task.Delay(TimeSpan.FromMilliseconds(750), cancellationToken);
                await MergePassAsync();

                if (merged.Count <= previousCount)
                {
                    continue;
                }

                previousCount = merged.Count;
                if (merged.Count > 1)
                {
                    break;
                }
            }
        }

        return merged.Values
            .OrderByDescending(item => item.SignalStrength)
            .ToArray();
    }

    private IReadOnlyCollection<AccessPointSnapshot> ParseNearbyOutput(string output)
    {
        if (string.IsNullOrWhiteSpace(output))
        {
            return [];
        }

        var now = DateTimeOffset.UtcNow;
        var results = new List<AccessPointSnapshot>();

        string? currentSsid = null;
        string? currentAuthentication = null;
        string? currentEncryption = null;
        string? currentBssid = null;
        int currentSignalPercent = 0;
        double? currentBandGHz = null;
        int? currentChannel = null;

        void FlushCurrent()
        {
            if (string.IsNullOrWhiteSpace(currentBssid))
            {
                return;
            }

            var ssid = string.IsNullOrWhiteSpace(currentSsid)
                ? $"<hidden:{currentBssid}>"
                : currentSsid;

            var samples = UpdateSignalHistory(currentBssid, currentSignalPercent);

            results.Add(new AccessPointSnapshot(
                ssid,
                currentBssid,
                BuildSecurityProtocol(currentAuthentication, currentEncryption),
                SignalPercentToDbm(currentSignalPercent),
                now,
                samples,
                currentBandGHz,
                currentChannel,
                ExtractOui(currentBssid)));
        }

        foreach (var rawLine in output.Split(Environment.NewLine, StringSplitOptions.None))
        {
            var line = rawLine.Trim();
            if (line.Length == 0)
            {
                continue;
            }

            var ssidMatch = SsidPattern().Match(line);
            if (ssidMatch.Success)
            {
                FlushCurrent();
                currentSsid = ssidMatch.Groups[1].Value.Trim();
                currentAuthentication = null;
                currentEncryption = null;
                currentBssid = null;
                currentSignalPercent = 0;
                currentBandGHz = null;
                currentChannel = null;
                continue;
            }

            var authMatch = AuthPattern().Match(line);
            if (authMatch.Success)
            {
                currentAuthentication = authMatch.Groups[1].Value.Trim();
                continue;
            }

            var encryptionMatch = EncryptionPattern().Match(line);
            if (encryptionMatch.Success)
            {
                currentEncryption = encryptionMatch.Groups[1].Value.Trim();
                continue;
            }

            var bssidMatch = BssidPattern().Match(line);
            if (bssidMatch.Success)
            {
                FlushCurrent();
                currentBssid = bssidMatch.Groups[1].Value.Trim();
                currentSignalPercent = 0;
                currentBandGHz = null;
                currentChannel = null;
                continue;
            }

            var signalMatch = SignalPattern().Match(line);
            if (signalMatch.Success)
            {
                _ = int.TryParse(signalMatch.Groups[1].Value, out currentSignalPercent);
                continue;
            }

            var bandMatch = BandPattern().Match(line);
            if (bandMatch.Success)
            {
                currentBandGHz = ParseBandGHz(bandMatch.Groups[1].Value);
                continue;
            }

            var channelMatch = ChannelPattern().Match(line);
            if (channelMatch.Success)
            {
                if (int.TryParse(channelMatch.Groups[1].Value, out var parsedChannel))
                {
                    currentChannel = parsedChannel;
                }
            }
        }

        FlushCurrent();
        return results;
    }

    public async Task<AccessPointSnapshot?> GetConnectedNetworkAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows() || !_options.UseNetshScanner)
        {
            return null;
        }

        await TriggerActiveScanAsync(cancellationToken);

        var output = await RunNetshAsync("wlan show interfaces", cancellationToken);
        if (string.IsNullOrWhiteSpace(output) || !output.Contains("State", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        string? ssid = null;
        string? bssid = null;
        string? auth = null;
        string? cipher = null;
        int signalPercent = 0;
        int? rssi = null;
        string? state = null;
        string? interfaceName = null;
        double? bandGHz = null;
        int? channel = null;

        foreach (var rawLine in output.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries))
        {
            var line = rawLine.Trim();
            if (line.StartsWith("State", StringComparison.OrdinalIgnoreCase))
            {
                state = ExtractValue(line);
            }
            else if (line.StartsWith("Name", StringComparison.OrdinalIgnoreCase))
            {
                interfaceName = ExtractValue(line);
            }
            if (line.StartsWith("SSID", StringComparison.OrdinalIgnoreCase) && !line.StartsWith("SSID name", StringComparison.OrdinalIgnoreCase))
            {
                ssid = ExtractValue(line);
            }
            else if (line.StartsWith("BSSID", StringComparison.OrdinalIgnoreCase)
                || line.StartsWith("AP BSSID", StringComparison.OrdinalIgnoreCase))
            {
                bssid = ExtractValue(line);
            }
            else if (line.StartsWith("Authentication", StringComparison.OrdinalIgnoreCase))
            {
                auth = ExtractValue(line);
            }
            else if (line.StartsWith("Cipher", StringComparison.OrdinalIgnoreCase))
            {
                cipher = ExtractValue(line);
            }
            else if (line.StartsWith("Signal", StringComparison.OrdinalIgnoreCase))
            {
                var value = ExtractValue(line).Replace("%", string.Empty, StringComparison.OrdinalIgnoreCase).Trim();
                _ = int.TryParse(value, out signalPercent);
            }
            else if (line.StartsWith("Rssi", StringComparison.OrdinalIgnoreCase))
            {
                var value = ExtractValue(line).Trim();
                _ = int.TryParse(value, out var rssiValue);
                if (rssiValue != 0)
                {
                    rssi = rssiValue;
                }
            }
            else if (line.StartsWith("Band", StringComparison.OrdinalIgnoreCase))
            {
                bandGHz = ParseBandGHz(ExtractValue(line));
            }
            else if (line.StartsWith("Channel", StringComparison.OrdinalIgnoreCase))
            {
                var value = ExtractValue(line);
                if (int.TryParse(value, out var parsedChannel))
                {
                    channel = parsedChannel;
                }
            }
        }

        if (!string.IsNullOrWhiteSpace(state)
            && state.Contains("disconnected", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(ssid) || string.IsNullOrWhiteSpace(bssid))
        {
            return null;
        }

        var signalDbm = rssi ?? SignalPercentToDbm(signalPercent);
        var samples = UpdateSignalHistory(bssid, signalPercent);
        var (gatewayIp, dhcpServerIp) = TryGetNetworkLayerFingerprint(interfaceName);
        var gatewayTtl = await ProbeGatewayTtlAsync(gatewayIp ?? string.Empty);

        return new AccessPointSnapshot(
            ssid,
            bssid,
            BuildSecurityProtocol(auth, cipher),
            signalDbm,
            DateTimeOffset.UtcNow,
            samples,
            bandGHz,
            channel,
            ExtractOui(bssid),
            gatewayIp,
            dhcpServerIp,
            gatewayTtl,
            gatewayTtl);
    }

    private async Task TriggerActiveScanAsync(CancellationToken cancellationToken)
    {
        try
        {
            await NativeWifi.ScanNetworksAsync(TimeSpan.FromSeconds(3), cancellationToken);
            _logger.LogDebug("Active WiFi scan triggered via WlanScan()");
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "WlanScan() failed; continuing with cached netsh results");
        }
    }

    private async Task<int?> ProbeGatewayTtlAsync(string gatewayIp)
    {
        if (string.IsNullOrWhiteSpace(gatewayIp))
        {
            return null;
        }

        try
        {
            using var ping = new Ping();
            for (var i = 0; i < 3; i++)
            {
                var reply = await ping.SendPingAsync(gatewayIp, 1000);
                if (reply.Status == IPStatus.Success
                    && reply.Options is not null)
                {
                    return reply.Options.Ttl;
                }
            }
        }
        catch (Exception exception)
        {
            _logger.LogDebug(exception, "Gateway TTL probe failed for gateway '{GatewayIp}'", gatewayIp);
        }

        return null;
    }

    private async Task<string> RunNetshAsync(string arguments, CancellationToken cancellationToken)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = arguments,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = new Process { StartInfo = psi };
            process.Start();

            var output = await process.StandardOutput.ReadToEndAsync(cancellationToken);
            var error = await process.StandardError.ReadToEndAsync(cancellationToken);

            await process.WaitForExitAsync(cancellationToken);
            if (process.ExitCode != 0)
            {
                _logger.LogWarning("netsh command '{Arguments}' failed with exit code {ExitCode}: {Error}", arguments, process.ExitCode, error.Trim());
                return string.Empty;
            }

            return output;
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Failed to execute netsh command: {Arguments}", arguments);
            return string.Empty;
        }
    }

    private IReadOnlyCollection<int> UpdateSignalHistory(string bssid, int currentSignal)
    {
        var queue = _signalHistory.GetOrAdd(bssid, _ => new Queue<int>());
        lock (queue)
        {
            queue.Enqueue(currentSignal);
            var limit = Math.Max(10, _options.SignalHistoryLimit);
            while (queue.Count > limit)
            {
                queue.Dequeue();
            }

            return queue.ToArray();
        }
    }

    private static int SignalPercentToDbm(int percent)
    {
        var clamped = Math.Clamp(percent, 0, 100);
        return (clamped * 2) - 100;
    }

    private static string BuildSecurityProtocol(string? authentication, string? encryption)
    {
        if (string.IsNullOrWhiteSpace(authentication) && string.IsNullOrWhiteSpace(encryption))
        {
            return "Unknown";
        }

        if (string.IsNullOrWhiteSpace(encryption))
        {
            return authentication!.Trim();
        }

        if (string.IsNullOrWhiteSpace(authentication))
        {
            return encryption.Trim();
        }

        return $"{authentication.Trim()}/{encryption.Trim()}";
    }

    private static string ExtractValue(string line)
    {
        var index = line.IndexOf(':');
        if (index < 0 || index == line.Length - 1)
        {
            return string.Empty;
        }

        return line[(index + 1)..].Trim();
    }

    private static double? ParseBandGHz(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var numberMatch = Regex.Match(value, @"(\d+(?:\.\d+)?)", RegexOptions.IgnoreCase);
        if (!numberMatch.Success)
        {
            return null;
        }

        return double.TryParse(numberMatch.Groups[1].Value, out var parsed)
            ? parsed
            : null;
    }

    private static string? ExtractOui(string? bssid)
    {
        if (string.IsNullOrWhiteSpace(bssid))
        {
            return null;
        }

        var parts = bssid.Split(':', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < 3)
        {
            return null;
        }

        return $"{parts[0]}:{parts[1]}:{parts[2]}".ToUpperInvariant();
    }

    private static (string? GatewayIp, string? DhcpServerIp) TryGetNetworkLayerFingerprint(string? interfaceName)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (null, null);
        }

        try
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                .Where(ni => ni.OperationalStatus == OperationalStatus.Up)
                .ToArray();

            NetworkInterface? selected = null;
            if (!string.IsNullOrWhiteSpace(interfaceName))
            {
                selected = interfaces.FirstOrDefault(ni =>
                    string.Equals(ni.Name, interfaceName, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(ni.Description, interfaceName, StringComparison.OrdinalIgnoreCase));
            }

            selected ??= interfaces.FirstOrDefault(ni =>
                ni.NetworkInterfaceType == NetworkInterfaceType.Wireless80211);

            if (selected is null)
            {
                return (null, null);
            }

            var properties = selected.GetIPProperties();
            var gatewayIp = properties.GatewayAddresses
                .Select(address => address.Address)
                .FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork)
                ?.ToString();

            var dhcpServerIp = properties.DhcpServerAddresses
                .FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork)
                ?.ToString();

            return (gatewayIp, dhcpServerIp);
        }
        catch
        {
            return (null, null);
        }
    }

    [GeneratedRegex(@"^SSID\s+\d+\s*:\s*(.+)$", RegexOptions.IgnoreCase)]
    private static partial Regex SsidPattern();

    [GeneratedRegex(@"^Authentication\s*:\s*(.+)$", RegexOptions.IgnoreCase)]
    private static partial Regex AuthPattern();

    [GeneratedRegex(@"^Encryption\s*:\s*(.+)$", RegexOptions.IgnoreCase)]
    private static partial Regex EncryptionPattern();

    [GeneratedRegex(@"^BSSID\s+\d+\s*:\s*([0-9A-Fa-f:\-]+)$", RegexOptions.IgnoreCase)]
    private static partial Regex BssidPattern();

    [GeneratedRegex(@"^Signal\s*:\s*(\d+)%$", RegexOptions.IgnoreCase)]
    private static partial Regex SignalPattern();

    [GeneratedRegex(@"^Band\s*:\s*(.+)$", RegexOptions.IgnoreCase)]
    private static partial Regex BandPattern();

    [GeneratedRegex(@"^Channel\s*:\s*(\d+)$", RegexOptions.IgnoreCase)]
    private static partial Regex ChannelPattern();
}