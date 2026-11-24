using RogueAP.Core.Models;

namespace RogueAP.Core.Interfaces;

public interface IEnforcementController
{
    Task BlockInternetAsync(string reason, CancellationToken cancellationToken);

    Task UnblockInternetAsync(string reason, CancellationToken cancellationToken);

    Task<EnforcementStatus> GetStatusAsync(CancellationToken cancellationToken);
}