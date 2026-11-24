using RogueAP.Core.Enums;

namespace RogueAP.Core.Interfaces;

public interface INotificationService
{
    Task PublishAsync(PolicyAction action, string title, string message, CancellationToken cancellationToken);
}