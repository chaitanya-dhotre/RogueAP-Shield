namespace RogueAP.Core.Interfaces;

public interface IMasterKeyGate
{
    bool IsInitialized { get; }

    Task InitializeAsync(string masterKey, string recoveryKey, CancellationToken cancellationToken);

    Task<bool> VerifyMasterKeyAsync(string candidate, CancellationToken cancellationToken);

    Task<bool> RecoverWithRecoveryKeyAsync(string recoveryKey, string newMasterKey, string newRecoveryKey, CancellationToken cancellationToken);

    Task ResetAsync(CancellationToken cancellationToken);
}