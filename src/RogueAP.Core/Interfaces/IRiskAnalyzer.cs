using RogueAP.Core.Models;

namespace RogueAP.Core.Interfaces;

public interface IRiskAnalyzer
{
    Task<NetworkAssessment> Analyze(
        AccessPointSnapshot? connectedNetwork,
        IReadOnlyCollection<AccessPointSnapshot> nearbyNetworks,
        IReadOnlyCollection<TrustedNetwork> trustedNetworks);
}