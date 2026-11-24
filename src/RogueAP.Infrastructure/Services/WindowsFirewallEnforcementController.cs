// Legacy implementation — replaced by WfpEnforcementController
using System.Diagnostics;
using System.Security.Principal;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RogueAP.Core.Interfaces;
using RogueAP.Core.Models;
using RogueAP.Core.Options;

namespace RogueAP.Infrastructure.Services;

public sealed class WindowsFirewallEnforcementController : IEnforcementController
{
    private readonly ILogger<WindowsFirewallEnforcementController> _logger;
    private readonly EnforcementOptions _options;
    private string? _lastNote;

    public WindowsFirewallEnforcementController(
        ILogger<WindowsFirewallEnforcementController> logger,
        IOptions<EnforcementOptions> options)
    {
        _logger = logger;
        _options = options.Value;
    }

    public async Task BlockInternetAsync(string reason, CancellationToken cancellationToken)
    {
        if (!_options.UseWindowsFirewall || !OperatingSystem.IsWindows())
        {
            _logger.LogWarning("Internet block requested but firewall enforcement is disabled. Reason: {Reason}", reason);
            _lastNote = "Firewall enforcement disabled or unsupported OS.";
            return;
        }

        if (!IsProcessElevated())
        {
            _lastNote = "Firewall enforcement requires administrator privileges.";
            _logger.LogWarning("Internet block requested but process is not elevated. Reason: {Reason}", reason);
            return;
        }

        if (_options.DryRun)
        {
            _logger.LogWarning("DRY-RUN: would block internet with firewall rule '{Rule}'. Reason: {Reason}", _options.FirewallRuleName, reason);
            _lastNote = $"Dry-run mode: block requested ({reason}).";
            return;
        }

        var command = $"advfirewall firewall add rule name=\"{_options.FirewallRuleName}\" dir=out action=block protocol=any remoteip=any";
        var success = await RunNetshAsync(command, cancellationToken);
        if (success)
        {
            _logger.LogWarning("Firewall rule '{Rule}' applied. Internet egress should be blocked.", _options.FirewallRuleName);
            _lastNote = $"Blocking rule applied ({reason}).";
        }
        else
        {
            _lastNote = $"Failed to apply blocking rule ({reason}).";
        }
    }

    public async Task UnblockInternetAsync(string reason, CancellationToken cancellationToken)
    {
        if (!_options.UseWindowsFirewall || !OperatingSystem.IsWindows())
        {
            _logger.LogInformation("Internet unblock requested while firewall enforcement is disabled. Reason: {Reason}", reason);
            _lastNote = "Firewall enforcement disabled or unsupported OS.";
            return;
        }

        if (!IsProcessElevated())
        {
            _lastNote = "Firewall enforcement requires administrator privileges.";
            _logger.LogWarning("Internet unblock requested but process is not elevated. Reason: {Reason}", reason);
            return;
        }

        if (_options.DryRun)
        {
            _logger.LogInformation("DRY-RUN: would remove firewall rule '{Rule}'. Reason: {Reason}", _options.FirewallRuleName, reason);
            _lastNote = $"Dry-run mode: unblock requested ({reason}).";
            return;
        }

        var command = $"advfirewall firewall delete rule name=\"{_options.FirewallRuleName}\"";
        var success = await RunNetshAsync(command, cancellationToken);
        if (success)
        {
            _logger.LogInformation("Firewall rule '{Rule}' removed.", _options.FirewallRuleName);
            _lastNote = $"Blocking rule removed ({reason}).";
        }
        else
        {
            _lastNote = $"Failed to remove blocking rule ({reason}).";
        }
    }

    public async Task<EnforcementStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        if (!_options.UseWindowsFirewall || !OperatingSystem.IsWindows())
        {
            return new EnforcementStatus(
                IsBlockingActive: false,
                IsDryRun: _options.DryRun,
                IsSupported: false,
                RuleName: _options.FirewallRuleName,
                CheckedAt: DateTimeOffset.UtcNow,
                Note: "Firewall enforcement disabled or unsupported OS.");
        }

        if (!IsProcessElevated())
        {
            return new EnforcementStatus(
                IsBlockingActive: false,
                IsDryRun: _options.DryRun,
                IsSupported: true,
                RuleName: _options.FirewallRuleName,
                CheckedAt: DateTimeOffset.UtcNow,
                Note: "Administrator privileges required for firewall enforcement.");
        }

        if (_options.DryRun)
        {
            return new EnforcementStatus(
                IsBlockingActive: false,
                IsDryRun: true,
                IsSupported: true,
                RuleName: _options.FirewallRuleName,
                CheckedAt: DateTimeOffset.UtcNow,
                Note: _lastNote ?? "Dry-run mode is enabled; no real blocking applied.");
        }

        var exists = await FirewallRuleExistsAsync(cancellationToken);
        return new EnforcementStatus(
            IsBlockingActive: exists,
            IsDryRun: false,
            IsSupported: true,
            RuleName: _options.FirewallRuleName,
            CheckedAt: DateTimeOffset.UtcNow,
            Note: _lastNote);
    }

    private async Task<bool> FirewallRuleExistsAsync(CancellationToken cancellationToken)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh",
                Arguments = $"advfirewall firewall show rule name=\"{_options.FirewallRuleName}\"",
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
                var outputText = output.Trim();
                var errorText = error.Trim();
                var combined = string.Join(" | ", new[] { outputText, errorText }.Where(text => !string.IsNullOrWhiteSpace(text)));
                _logger.LogDebug("Unable to query firewall rule status. ExitCode={ExitCode}; Output={Output}", process.ExitCode, combined);
                return false;
            }

            return output.Contains("Rule Name", StringComparison.OrdinalIgnoreCase)
                && output.Contains(_options.FirewallRuleName, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception)
        {
            _logger.LogDebug(exception, "Failed to query firewall rule status.");
            return false;
        }
    }

    private async Task<bool> RunNetshAsync(string arguments, CancellationToken cancellationToken)
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

            if (process.ExitCode == 0)
            {
                _logger.LogInformation("netsh enforcement command succeeded: {Output}", output.Trim());
                return true;
            }

            var outputText = output.Trim();
            var errorText = error.Trim();
            var combined = string.Join(" | ", new[] { outputText, errorText }.Where(text => !string.IsNullOrWhiteSpace(text)));
            _logger.LogWarning("netsh enforcement command failed with exit code {ExitCode}. Output: {Output}", process.ExitCode, combined);
            return false;
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Failed running netsh enforcement command.");
            return false;
        }
    }

    private static bool IsProcessElevated()
    {
        try
        {
            if (!OperatingSystem.IsWindows())
            {
                return false;
            }

            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }
}