using RogueAP.Core.Enums;
using RogueAP.Core.Interfaces;
using RogueAP.Core.Options;
using RogueAP.Core.Models;
using Microsoft.Extensions.Options;

namespace RogueAP.Core.Services;

public sealed class PolicyEngine : IPolicyEngine
{
    private readonly ProtectionOptions _options;

    public PolicyEngine(IOptions<ProtectionOptions> options)
    {
        _options = options.Value;
    }

    public EnforcementDecision Decide(NetworkAssessment assessment, VpnStatus vpnStatus)
    {
        var actions = new List<PolicyAction>();
        var shouldBlockOnVpnFailure = false;

        if (assessment.ConnectedNetwork is null)
        {
            actions.Add(PolicyAction.None);
            return new EnforcementDecision(
                assessment.RiskLevel,
                assessment.IsTrustedNetwork,
                actions,
                false,
                "No active network connection detected.");
        }

        if (assessment.RiskLevel == RiskLevel.Critical)
        {
            actions.Add(PolicyAction.AlertCritical);

            if (!vpnStatus.IsConnected)
            {
                // FIX 1: Try VPN first on Critical risk
                // If VPN connect fails, block internet
                actions.Add(PolicyAction.AttemptVpnConnect);
                shouldBlockOnVpnFailure = _options.EnableHardBlockOnCritical;
            }
            else
            {
                // VPN already connected — no block needed
                // VPN is providing protection
            }

            return new EnforcementDecision(
                assessment.RiskLevel,
                assessment.IsTrustedNetwork,
                actions,
                shouldBlockOnVpnFailure,
                "Critical risk: attempting VPN connection. Will block if VPN fails.");
        }

        if (assessment.IsTrustedNetwork && _options.AlertOnlyOnTrustedNetworks)
        {
            actions.Add(assessment.RiskLevel switch
            {
                RiskLevel.High => PolicyAction.AlertHighPriority,
                RiskLevel.Medium => PolicyAction.AlertInfo,
                _ => PolicyAction.None
            });

            return new EnforcementDecision(
                assessment.RiskLevel,
                true,
                actions,
                false,
                "Trusted network policy reduces enforcement to alert-only.");
        }

        switch (assessment.RiskLevel)
        {
            case RiskLevel.High:
                actions.Add(PolicyAction.AlertHighPriority);
                if (!vpnStatus.IsConnected && _options.AutoAttemptVpnOnHighUntrusted)
                {
                    actions.Add(PolicyAction.AttemptVpnConnect);
                    shouldBlockOnVpnFailure = true;
                }

                break;

            case RiskLevel.Medium:
                actions.Add(PolicyAction.AlertHighPriority);
                if (!vpnStatus.IsConnected && _options.AutoAttemptVpnOnMediumUntrusted)
                {
                    actions.Add(PolicyAction.AttemptVpnConnect);
                }

                break;

            default:
                actions.Add(PolicyAction.AlertInfo);
                break;
        }

        return new EnforcementDecision(
            assessment.RiskLevel,
            assessment.IsTrustedNetwork,
            actions,
            shouldBlockOnVpnFailure,
            "Policy decision computed from risk, trust, and VPN state.");
    }
}