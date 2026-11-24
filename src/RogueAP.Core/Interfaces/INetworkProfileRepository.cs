using RogueAP.Core.Models;

namespace RogueAP.Core.Interfaces;

public interface INetworkProfileRepository
{
    Task<NetworkProfile?> GetAsync(string ssid, CancellationToken cancellationToken);
    Task SaveAsync(NetworkProfile profile, CancellationToken cancellationToken);
    Task<IReadOnlyList<NetworkProfile>> GetAllAsync(CancellationToken cancellationToken);
    Task DeleteAsync(string ssid, CancellationToken cancellationToken);
}
