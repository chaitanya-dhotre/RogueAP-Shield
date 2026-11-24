using RogueAP.Core.Models;

namespace RogueAP.Core.Interfaces;

public interface IWifiScanner
{
    Task<IReadOnlyCollection<AccessPointSnapshot>> ScanNearbyAsync(CancellationToken cancellationToken);

    Task<AccessPointSnapshot?> GetConnectedNetworkAsync(CancellationToken cancellationToken);
}