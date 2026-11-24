using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RogueAP.Core.Interfaces;
using RogueAP.Core.Models;
using RogueAP.Core.Options;
using WindowsFirewallHelper;
using WindowsFirewallHelper.FirewallRules;

namespace RogueAP.Infrastructure.Services;

public sealed class WfpEnforcementController : IEnforcementController
{
    private const string OutboundRuleName = "RogueAP_KS_BlockOutbound";
    private const string InboundRuleName = "RogueAP_KS_BlockInbound";
    private const string RulePrefix = "RogueAP_KS_";

    private readonly ILogger<WfpEnforcementController> _logger;
    private readonly EnforcementOptions _options;

    public WfpEnforcementController(
        ILogger<WfpEnforcementController> logger,
        IOptions<EnforcementOptions> options)
    {
        _logger = logger;
        _options = options.Value;
    }

    public Task BlockInternetAsync(string reason, CancellationToken cancellationToken)
    {
        if (_options.DryRun)
        {
            _logger.LogWarning("[DryRun] Would engage WFP kill switch. Reason: {Reason}", reason);
            return Task.CompletedTask;
        }

        try
        {
            CleanupRules();

            var outbound = new FirewallWASRule(
                OutboundRuleName,
                FirewallAction.Block,
                FirewallDirection.Outbound,
                FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public);
            outbound.IsEnable = true;
            FirewallManager.Instance.Rules.Add(outbound);

            var inbound = new FirewallWASRule(
                InboundRuleName,
                FirewallAction.Block,
                FirewallDirection.Inbound,
                FirewallProfiles.Domain | FirewallProfiles.Private | FirewallProfiles.Public);
            inbound.IsEnable = true;
            FirewallManager.Instance.Rules.Add(inbound);

            _logger.LogWarning("WFP kill switch engaged: {Reason}", reason);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to engage WFP kill switch. Reason: {Reason}", reason);
        }

        return Task.CompletedTask;
    }

    public Task UnblockInternetAsync(string reason, CancellationToken cancellationToken)
    {
        if (_options.DryRun)
        {
            _logger.LogInformation("[DryRun] Would release WFP kill switch. Reason: {Reason}", reason);
            return Task.CompletedTask;
        }

        try
        {
            CleanupRules();
            _logger.LogInformation("WFP kill switch released. Reason: {Reason}", reason);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to release WFP kill switch. Reason: {Reason}", reason);
        }

        return Task.CompletedTask;
    }

    public Task<EnforcementStatus> GetStatusAsync(CancellationToken cancellationToken)
    {
        bool isBlocking;
        string note;

        try
        {
            var rules = FirewallManager.Instance.Rules
                .Where(r => r.Name.StartsWith(RulePrefix, StringComparison.Ordinal))
                .ToList();

            isBlocking = rules.Count > 0;
            note = isBlocking ? "WFP kill switch active" : "No active blocks";
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Unable to query WFP rule status.");
            isBlocking = false;
            note = "Unable to query WFP rule status.";
        }

        return Task.FromResult(new EnforcementStatus(
            IsBlockingActive: isBlocking,
            IsDryRun: _options.DryRun,
            IsSupported: true,
            RuleName: OutboundRuleName,
            CheckedAt: DateTimeOffset.UtcNow,
            Note: note));
    }

    private void CleanupRules()
    {
        var toRemove = FirewallManager.Instance.Rules
            .Where(r => r.Name.StartsWith(RulePrefix, StringComparison.Ordinal))
            .ToList();

        foreach (var rule in toRemove)
        {
            FirewallManager.Instance.Rules.Remove(rule);
        }
    }
}
