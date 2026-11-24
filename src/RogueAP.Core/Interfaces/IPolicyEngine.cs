using RogueAP.Core.Models;

namespace RogueAP.Core.Interfaces;

public interface IPolicyEngine
{
    EnforcementDecision Decide(NetworkAssessment assessment, VpnStatus vpnStatus);
}