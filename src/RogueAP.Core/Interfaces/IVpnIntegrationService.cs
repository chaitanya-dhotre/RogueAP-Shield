using RogueAP.Core.Models;

namespace RogueAP.Core.Interfaces;

public interface IVpnIntegrationService
{
    Task<VpnStatus> GetStatusAsync(CancellationToken cancellationToken);

    Task<bool> TryConnectAsync(CancellationToken cancellationToken);

    Task<bool> TryDisconnectAsync(CancellationToken cancellationToken);
}