namespace RogueAP.Core.Interfaces;

public interface ISystemResetService
{
    Task ResetAllAsync(CancellationToken cancellationToken);
}