using RogueAP.Core.Models;

namespace RogueAP.Core.Interfaces;

public interface INetworkLearningService
{
    Task ObserveAsync(
        string ssid,
        AccessPointSnapshot connectedAp,
        IReadOnlyCollection<AccessPointSnapshot> nearbyAps,
        CancellationToken cancellationToken);

    bool IsLearning(string ssid);

    Task<NetworkProfile?> GetProfileAsync(string ssid, CancellationToken cancellationToken);

    Task StartLearningAsync(string ssid, string deploymentProfile, CancellationToken cancellationToken);

    Task CompleteLearningAsync(string ssid, CancellationToken cancellationToken);

    Task ResetLearningAsync(string ssid, CancellationToken cancellationToken);
}
