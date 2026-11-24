using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RogueAP.Core.Interfaces;
using RogueAP.Core.Models;
using RogueAP.Core.Options;

namespace RogueAP.Infrastructure.Services;

public sealed class CommandVpnIntegrationService : IVpnIntegrationService
{
    private readonly ILogger<CommandVpnIntegrationService> _logger;
    private readonly VpnIntegrationOptions _options;
    private readonly IVpnRuntimeConfigStore _runtimeConfigStore;
    private readonly WireGuardPipeMonitor _pipeMonitor;

    public CommandVpnIntegrationService(
        ILogger<CommandVpnIntegrationService> logger,
        IOptions<VpnIntegrationOptions> options,
        IVpnRuntimeConfigStore runtimeConfigStore,
        WireGuardPipeMonitor pipeMonitor)
    {
        _logger = logger;
        _options = options.Value;
        _runtimeConfigStore = runtimeConfigStore;
        _pipeMonitor = pipeMonitor;
    }

    public async Task<VpnStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        var runtime = _runtimeConfigStore.GetCurrent();
        var mode = NormalizeMode(runtime.Mode);

        if ((mode == "wireguard" || mode == "auto")
            && !string.IsNullOrWhiteSpace(runtime.WireGuardConnectCommand))
        {
            var tunnelName = WireGuardPipeMonitor.ExtractTunnelName(runtime.WireGuardConnectCommand);
            if (tunnelName is not null)
            {
                var state = await _pipeMonitor.QueryTunnelAsync(tunnelName, cancellationToken);
                if (state is not null)
                {
                    var isConnected = state.IsUp && !state.IsHandshakeStale;
                    return new VpnStatus(
                        IsConnected: isConnected,
                        ProviderName: isConnected ? "WireGuard (verified)" : "WireGuard (stale/down)",
                        TunnelInterface: tunnelName,
                        CheckedAt: DateTimeOffset.UtcNow);
                }
            }
        }

        string? processProvider = DetectVendorProcess();
        string? tunnelInterface = await DetectConnectedTunnelInterfaceAsync(cancellationToken);
        tunnelInterface ??= await DetectConnectedTunnelAdapterByNetAdapterAsync(cancellationToken);
        var processConnectedFallback =
            _options.UseVendorProcessAsConnectedFallback
            && mode == "statusonly"
            && !string.IsNullOrWhiteSpace(processProvider)
            && !string.Equals(processProvider, "ProtonVPN", StringComparison.OrdinalIgnoreCase);

        return new VpnStatus(
            IsConnected: !string.IsNullOrWhiteSpace(tunnelInterface) || processConnectedFallback,
            ProviderName: processProvider ?? ResolveProviderNameFromMode(),
            TunnelInterface: tunnelInterface,
            CheckedAt: DateTimeOffset.UtcNow);
    }

    public async Task<bool> TryConnectAsync(CancellationToken cancellationToken)
    {
        var runtime = _runtimeConfigStore.GetCurrent();
        var mode = NormalizeMode(runtime.Mode);

        if (mode == "wireguard")
        {
            var commandSucceeded = await RunConfiguredCommandAsync(runtime.WireGuardConnectCommand, cancellationToken);
            if (!commandSucceeded)
            {
                return false;
            }

            return await WaitForWireGuardTunnelAsync(runtime.WireGuardConnectCommand, cancellationToken);
        }

        if (mode == "auto" && !string.IsNullOrWhiteSpace(runtime.WireGuardConnectCommand))
        {
            var commandSucceeded = await RunConfiguredCommandAsync(runtime.WireGuardConnectCommand, cancellationToken);
            if (commandSucceeded)
            {
                return await WaitForWireGuardTunnelAsync(runtime.WireGuardConnectCommand, cancellationToken);
            }
        }

        return mode switch
        {
            "openvpn" => await RunConfiguredCommandAsync(runtime.OpenVpnConnectCommand, cancellationToken),
            "statusonly" => false,
            _ => await TryAutoConnectAsync(runtime, cancellationToken)
        };
    }

    private async Task<bool> WaitForWireGuardTunnelAsync(string? connectCommand, CancellationToken cancellationToken)
    {
        var tunnelName = WireGuardPipeMonitor.ExtractTunnelName(connectCommand ?? string.Empty);
        if (tunnelName is null)
        {
            return true;
        }

        for (var i = 0; i < 15; i++)
        {
            await Task.Delay(1000, cancellationToken);
            var state = await _pipeMonitor.QueryTunnelAsync(tunnelName, cancellationToken);
            if (state?.IsUp == true && !state.IsHandshakeStale)
            {
                _logger.LogInformation(
                    "WireGuard tunnel '{TunnelName}' confirmed up via named pipe after {Seconds}s.",
                    tunnelName, i + 1);
                return true;
            }
        }

        _logger.LogWarning(
            "WireGuard command succeeded but tunnel '{TunnelName}' did not confirm healthy within 15s.",
            tunnelName);
        return false;
    }

    public async Task<bool> TryDisconnectAsync(CancellationToken cancellationToken)
    {
        var runtime = _runtimeConfigStore.GetCurrent();
        var disconnected = NormalizeMode(runtime.Mode) switch
        {
            "wireguard" => await RunConfiguredCommandAsync(runtime.WireGuardDisconnectCommand, cancellationToken),
            "openvpn" => await RunConfiguredCommandAsync(runtime.OpenVpnDisconnectCommand, cancellationToken),
            "statusonly" => false,
            _ => await TryAutoDisconnectAsync(runtime, cancellationToken)
        };

        if (disconnected)
        {
            return true;
        }

        return await TryBestEffortDisconnectAsync(cancellationToken);
    }

    private async Task<bool> TryAutoConnectAsync(VpnRuntimeConfig runtime, CancellationToken cancellationToken)
    {
        if (await RunConfiguredCommandAsync(runtime.WireGuardConnectCommand, cancellationToken))
        {
            return true;
        }

        return await RunConfiguredCommandAsync(runtime.OpenVpnConnectCommand, cancellationToken);
    }

    private async Task<bool> TryAutoDisconnectAsync(VpnRuntimeConfig runtime, CancellationToken cancellationToken)
    {
        if (await RunConfiguredCommandAsync(runtime.WireGuardDisconnectCommand, cancellationToken))
        {
            return true;
        }

        return await RunConfiguredCommandAsync(runtime.OpenVpnDisconnectCommand, cancellationToken);
    }

    private async Task<bool> TryBestEffortDisconnectAsync(CancellationToken cancellationToken)
    {
        var status = await GetStatusAsync(cancellationToken);
        if (!status.IsConnected || string.IsNullOrWhiteSpace(status.TunnelInterface))
        {
            return false;
        }

        if (!status.TunnelInterface.Contains("WireGuard", StringComparison.OrdinalIgnoreCase)
            && !status.TunnelInterface.Contains("Wintun", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var tunnelName = status.TunnelInterface.Split('|', StringSplitOptions.RemoveEmptyEntries)[0].Trim();
        if (string.IsNullOrWhiteSpace(tunnelName))
        {
            return false;
        }

        var wireGuardPath = "C:\\Program Files\\WireGuard\\wireguard.exe";
        var uninstallCommand = $"& \"{wireGuardPath}\" /uninstalltunnelservice \"{tunnelName}\"";

        _logger.LogInformation("Attempting best-effort WireGuard disconnect for tunnel '{TunnelName}'.", tunnelName);
        var success = await RunConfiguredCommandAsync(uninstallCommand, cancellationToken);
        if (!success)
        {
            var removeServiceFallback = $"sc.exe stop \"WireGuardTunnel${tunnelName}\"";
            success = await RunConfiguredCommandAsync(removeServiceFallback, cancellationToken);
        }

        return success;
    }

    private async Task<bool> RunConfiguredCommandAsync(string? command, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(command))
        {
            return false;
        }

        if (_options.EnableCommandValidation && !IsCommandAllowed(command, out var blockedToken))
        {
            _logger.LogWarning("VPN command rejected by validation due to blocked token: {Token}", blockedToken);
            return false;
        }

        var retries = Math.Max(0, _options.MaxCommandRetries);
        var delaySeconds = Math.Max(1, _options.RetryDelaySeconds);

        for (var attempt = 0; attempt <= retries; attempt++)
        {
            var (success, stderr) = await ExecuteCommandOnceAsync(command, cancellationToken);
            if (success)
            {
                _logger.LogInformation("VPN command completed successfully on attempt {Attempt}/{TotalAttempts}.", attempt + 1, retries + 1);
                return true;
            }

            if (attempt < retries)
            {
                _logger.LogWarning("VPN command attempt {Attempt}/{TotalAttempts} failed. Retrying in {Delay}s. Error: {Error}", attempt + 1, retries + 1, delaySeconds, stderr);
                await Task.Delay(TimeSpan.FromSeconds(delaySeconds), cancellationToken);
                continue;
            }

            _logger.LogWarning("VPN command failed after {TotalAttempts} attempt(s). Last error: {Error}", retries + 1, stderr);
        }

        return false;
    }

    private async Task<(bool Success, string Error)> ExecuteCommandOnceAsync(string command, CancellationToken cancellationToken)
    {
        try
        {
            using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(Math.Max(5, _options.CommandTimeoutSeconds)));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeoutCts.Token);

            var psi = new ProcessStartInfo
            {
                FileName = "powershell",
                Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{command.Replace("\"", "\\\"")}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = new Process { StartInfo = psi };
            process.Start();
            var stdOutTask = process.StandardOutput.ReadToEndAsync(linkedCts.Token);
            var stdErrTask = process.StandardError.ReadToEndAsync(linkedCts.Token);
            await process.WaitForExitAsync(linkedCts.Token);

            var stdOut = await stdOutTask;
            var stdErr = await stdErrTask;

            if (process.ExitCode == 0)
            {
                if (!string.IsNullOrWhiteSpace(stdOut))
                {
                    _logger.LogDebug("VPN command stdout: {StdOut}", Truncate(stdOut));
                }

                return (true, string.Empty);
            }

            return (false, $"ExitCode={process.ExitCode}; Error={stdErr.Trim()}");
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return (false, $"Timed out after {_options.CommandTimeoutSeconds} second(s)");
        }
        catch (Exception exception)
        {
            return (false, exception.Message);
        }
    }

    private bool IsCommandAllowed(string command, out string blockedToken)
    {
        foreach (var token in _options.BlockedCommandTokens)
        {
            if (string.IsNullOrWhiteSpace(token))
            {
                continue;
            }

            if (command.Contains(token, StringComparison.OrdinalIgnoreCase))
            {
                blockedToken = token;
                return false;
            }
        }

        blockedToken = string.Empty;
        return true;
    }

    private static string Truncate(string value)
    {
        const int limit = 400;
        if (value.Length <= limit)
        {
            return value.Trim();
        }

        var builder = new StringBuilder(limit + 20);
        builder.Append(value.AsSpan(0, limit));
        builder.Append("...<truncated>");
        return builder.ToString().Trim();
    }

    private async Task<string?> DetectConnectedTunnelInterfaceAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = "interface show interface",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = new Process { StartInfo = psi };
            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken);

            if (process.ExitCode != 0)
            {
                return null;
            }

            foreach (var line in output.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries))
            {
                var parsed = ParseInterfaceLine(line);
                if (parsed is null)
                {
                    continue;
                }

                var (state, interfaceName) = parsed.Value;
                if (!string.Equals(state, "Connected", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (IsLikelyTunnelInterface(interfaceName))
                {
                    return interfaceName;
                }
            }

            return null;
        }
        catch (Exception exception)
        {
            _logger.LogDebug(exception, "Unable to detect connected tunnel interface.");
            return null;
        }
    }

    private async Task<string?> DetectConnectedTunnelAdapterByNetAdapterAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return null;
        }

        try
        {
            var script = "Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | "
                + "Where-Object { $_.Status -eq 'Up' } | "
                + "ForEach-Object { Write-Output ($_.Name + '|' + $_.InterfaceDescription) }";

            var psi = new ProcessStartInfo
            {
                FileName = "powershell",
                Arguments = $"-NoProfile -Command \"{script.Replace("\"", "\\\"")}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = new Process { StartInfo = psi };
            process.Start();
            var output = await process.StandardOutput.ReadToEndAsync(cancellationToken);
            await process.WaitForExitAsync(cancellationToken);

            if (process.ExitCode != 0 || string.IsNullOrWhiteSpace(output))
            {
                return null;
            }

            foreach (var line in output.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries))
            {
                var parts = line.Split('|');
                var name = parts.Length > 0 ? parts[0].Trim() : string.Empty;
                var description = parts.Length > 1 ? parts[1].Trim() : string.Empty;
                var combined = string.IsNullOrWhiteSpace(description)
                    ? name
                    : $"{name}|{description}";

                if (IsLikelyTunnelInterface(combined))
                {
                    return combined;
                }
            }

            return null;
        }
        catch (Exception exception)
        {
            _logger.LogDebug(exception, "Unable to detect VPN adapters via Get-NetAdapter.");
            return null;
        }
    }

    private bool IsLikelyTunnelInterface(string interfaceText)
    {
        if (string.IsNullOrWhiteSpace(interfaceText))
        {
            return false;
        }

        if (ContainsExcludedInterfaceToken(interfaceText))
        {
            return false;
        }

        foreach (var hint in _options.TunnelInterfaceHints)
        {
            if (string.IsNullOrWhiteSpace(hint))
            {
                continue;
            }

            var normalizedHint = hint.Trim();
            if (normalizedHint.Length <= 3)
            {
                if (Regex.IsMatch(interfaceText, $@"\b{Regex.Escape(normalizedHint)}\b", RegexOptions.IgnoreCase))
                {
                    return true;
                }

                continue;
            }

            if (interfaceText.Contains(normalizedHint, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return interfaceText.Contains("WireGuard", StringComparison.OrdinalIgnoreCase)
               || interfaceText.Contains("Wintun", StringComparison.OrdinalIgnoreCase)
               || interfaceText.Contains("OpenVPN", StringComparison.OrdinalIgnoreCase)
               || interfaceText.Contains("TAP-Windows", StringComparison.OrdinalIgnoreCase)
               || interfaceText.Contains("DCO", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ContainsExcludedInterfaceToken(string interfaceText)
    {
        var excludedTokens = new[]
        {
            "Teredo",
            "Wi-Fi Direct",
            "WAN Miniport",
            "Hyper-V",
            "WSL",
            "vEthernet",
            "Virtual Switch",
            "Bluetooth",
            "Kernel Debug",
            "IP-HTTPS"
        };

        return excludedTokens.Any(token =>
            interfaceText.Contains(token, StringComparison.OrdinalIgnoreCase));
    }

    private string? DetectVendorProcess()
    {
        try
        {
            var processes = Process.GetProcesses();
            foreach (var process in processes)
            {
                if (_options.VendorStatusProcessNames.Any(name =>
                    string.Equals(name, process.ProcessName, StringComparison.OrdinalIgnoreCase)
                    || process.ProcessName.Contains(name, StringComparison.OrdinalIgnoreCase)))
                {
                    return NormalizeProviderName(process.ProcessName);
                }
            }
        }
        catch (Exception exception)
        {
            _logger.LogDebug(exception, "Unable to enumerate VPN vendor processes.");
        }

        return null;
    }

    private static string NormalizeMode(string mode)
    {
        return string.IsNullOrWhiteSpace(mode) ? "auto" : mode.Trim().ToLowerInvariant();
    }

    private string? ResolveProviderNameFromMode()
    {
        var runtime = _runtimeConfigStore.GetCurrent();
        return NormalizeMode(runtime.Mode) switch
        {
            "wireguard" => "WireGuard",
            "openvpn" => "OpenVPN",
            _ => null
        };
    }

    private static string NormalizeProviderName(string processName)
    {
        return processName.ToLowerInvariant() switch
        {
            var value when value.Contains("nord") => "NordVPN",
            var value when value.Contains("surf") => "Surfshark",
            var value when value.Contains("express") => "ExpressVPN",
            var value when value.Contains("proton") => "ProtonVPN",
            var value when value.Contains("tunnelbear") => "TunnelBear",
            _ => processName
        };
    }

    private static (string State, string InterfaceName)? ParseInterfaceLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return null;
        }

        var trimmed = line.Trim();
        if (trimmed.StartsWith("Admin", StringComparison.OrdinalIgnoreCase)
            || trimmed.StartsWith("---", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        var match = Regex.Match(
            line,
            @"^\s*(Enabled|Disabled)\s+(Connected|Disconnected)\s+\S+\s+(.+?)\s*$",
            RegexOptions.IgnoreCase);

        if (!match.Success)
        {
            return null;
        }

        var state = match.Groups[2].Value.Trim();
        var interfaceName = match.Groups[3].Value.Trim();
        if (string.IsNullOrWhiteSpace(interfaceName))
        {
            return null;
        }

        return (state, interfaceName);
    }
}