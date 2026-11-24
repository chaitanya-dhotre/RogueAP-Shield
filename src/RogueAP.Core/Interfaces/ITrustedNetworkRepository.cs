using RogueAP.Core.Models;

namespace RogueAP.Core.Interfaces;

public interface ITrustedNetworkRepository
{
    Task<IReadOnlyCollection<TrustedNetwork>> GetAllAsync(CancellationToken cancellationToken);

    Task AddOrUpdateAsync(TrustedNetwork network, CancellationToken cancellationToken);

    Task<bool> RemoveByBssidAsync(string bssid, CancellationToken cancellationToken);

    Task ClearAsync(CancellationToken cancellationToken);
}