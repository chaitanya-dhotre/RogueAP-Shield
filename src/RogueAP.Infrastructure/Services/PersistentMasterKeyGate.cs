using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RogueAP.Core.Interfaces;
using RogueAP.Core.Options;

namespace RogueAP.Infrastructure.Services;

public sealed class PersistentMasterKeyGate : IMasterKeyGate
{
    private const string Purpose = "RogueAP-SecureState-v1";
    private readonly object _sync = new();
    private readonly ILogger<PersistentMasterKeyGate> _logger;
    private readonly IDekProvider _dekProvider;
    private readonly IAuditLogger _auditLogger;
    private readonly string _filePath;
    private MasterKeyState? _state;

    public PersistentMasterKeyGate(
        ILogger<PersistentMasterKeyGate> logger,
        IDekProvider dekProvider,
        IAuditLogger auditLogger,
        IOptions<SecureStorageOptions> options)
    {
        _logger = logger;
        _dekProvider = dekProvider;
        _auditLogger = auditLogger;
        var dataDirectory = ResolveDataDirectory(options.Value.DataDirectory);
        Directory.CreateDirectory(dataDirectory);
        _filePath = Path.Combine(dataDirectory, options.Value.MasterKeyStateFileName);
        _state = LoadState();
    }

    public bool IsInitialized => _state is not null;

    public async Task InitializeAsync(string masterKey, string recoveryKey, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(masterKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(recoveryKey);

        lock (_sync)
        {
            _state = CreateState(masterKey, recoveryKey);
            EnsureDekExistsAndPersistIfMissing(masterKey);
            PersistState(_state);
        }

        await _auditLogger.FlushPendingEntries(cancellationToken);
    }

    public Task<bool> VerifyMasterKeyAsync(string candidate, CancellationToken cancellationToken)
    {
        lock (_sync)
        {
            if (_state is null)
            {
                return Task.FromResult(false);
            }

            return Task.FromResult(VerifySecret(candidate, _state.MasterHash, _state.MasterSalt));
        }
    }

    public async Task<bool> RecoverWithRecoveryKeyAsync(string recoveryKey, string newMasterKey, string newRecoveryKey, CancellationToken cancellationToken)
    {
        bool result;
        lock (_sync)
        {
            if (_state is null)
            {
                return false;
            }

            var canRecover = VerifySecret(recoveryKey, _state.RecoveryHash, _state.RecoverySalt);
            if (!canRecover)
            {
                return false;
            }

            _state = CreateState(newMasterKey, newRecoveryKey);
            EnsureDekExistsAndPersistIfMissing(newMasterKey);
            PersistState(_state);
            result = true;
        }

        if (result)
        {
            await _auditLogger.FlushPendingEntries(cancellationToken);
        }

        return result;
    }

    public Task ResetAsync(CancellationToken cancellationToken)
    {
        lock (_sync)
        {
            _state = null;
            if (File.Exists(_filePath))
            {
                File.Delete(_filePath);
            }
        }

        return Task.CompletedTask;
    }

    private MasterKeyState? LoadState()
    {
        try
        {
            if (!File.Exists(_filePath))
            {
                return null;
            }

            var payloadText = File.ReadAllText(_filePath);
            var payload = JsonSerializer.Deserialize<SecurePayload>(payloadText);
            if (payload is null)
            {
                return null;
            }

            if (!TryUnprotectStatePayload(payload, out var plainText) || string.IsNullOrWhiteSpace(plainText))
            {
                _logger.LogWarning("Master key state failed integrity/decrypt validation. State file will be ignored.");
                return null;
            }

            return JsonSerializer.Deserialize<MasterKeyState>(plainText);
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Failed to load persisted master key state.");
            return null;
        }
    }

    private void PersistState(MasterKeyState state)
    {
        var plain = JsonSerializer.Serialize(state);
        var payload = ProtectStatePayload(plain);
        var text = JsonSerializer.Serialize(payload);
        File.WriteAllText(_filePath, text);
    }

    private void EnsureDekExistsAndPersistIfMissing(string masterKey)
    {
        if (_state is null)
        {
            return;
        }

        if (!string.IsNullOrWhiteSpace(_state.DpapiWrappedDek)
            && !string.IsNullOrWhiteSpace(_state.MasterKeyWrappedDek))
        {
            return;
        }

        var dek = _dekProvider.HasInMemoryDek
            ? _dekProvider.GetInMemoryDekIfExists()
            : null;

        dek ??= RandomNumberGenerator.GetBytes(32);
        if (dek.Length != 32)
        {
            throw new InvalidOperationException("DEK must be 32 bytes.");
        }

        var dpapiWrapped = WrapDekWithDpapi(dek);
        var masterKeyWrapped = WrapDekWithMasterKey(dek, masterKey);

        _state = _state with
        {
            DpapiWrappedDek = Convert.ToBase64String(dpapiWrapped),
            MasterKeyWrappedDek = Convert.ToBase64String(masterKeyWrapped)
        };
    }

    private static byte[] WrapDekWithDpapi(byte[] dek)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("DPAPI DEK wrapping is implemented for Windows only.");
        }

        return ProtectedData.Protect(dek, Encoding.UTF8.GetBytes(Purpose), DataProtectionScope.CurrentUser);
    }

    private static byte[] WrapDekWithMasterKey(byte[] dek, string masterKey)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var derivedKey = Rfc2898DeriveBytes.Pbkdf2(masterKey, salt, 600_000, HashAlgorithmName.SHA256, 32);
        var nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];
        var cipher = new byte[dek.Length];

        using (var aes = new AesGcm(derivedKey, AesGcm.TagByteSizes.MaxSize))
        {
            aes.Encrypt(nonce, dek, cipher, tag);
        }

        var wrapped = new byte[salt.Length + nonce.Length + tag.Length + cipher.Length];
        Buffer.BlockCopy(salt, 0, wrapped, 0, salt.Length);
        Buffer.BlockCopy(nonce, 0, wrapped, salt.Length, nonce.Length);
        Buffer.BlockCopy(tag, 0, wrapped, salt.Length + nonce.Length, tag.Length);
        Buffer.BlockCopy(cipher, 0, wrapped, salt.Length + nonce.Length + tag.Length, cipher.Length);
        return wrapped;
    }

    private static SecurePayload ProtectStatePayload(string plainText)
    {
        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("Secure state protection is currently implemented for Windows only.");
        }

        var protectedBytes = ProtectedData.Protect(plainBytes, Encoding.UTF8.GetBytes(Purpose), DataProtectionScope.CurrentUser);
        var hash = SHA256.HashData(protectedBytes);
        return new SecurePayload(
            ProtectedData: Convert.ToBase64String(protectedBytes),
            IntegrityHash: Convert.ToBase64String(hash));
    }

    private static bool TryUnprotectStatePayload(SecurePayload payload, out string? plainText)
    {
        plainText = null;
        if (string.IsNullOrWhiteSpace(payload.ProtectedData))
        {
            return false;
        }

        byte[] protectedBytes;
        try
        {
            protectedBytes = Convert.FromBase64String(payload.ProtectedData);
        }
        catch
        {
            return false;
        }

#pragma warning disable CS0618
        if (!string.IsNullOrWhiteSpace(payload.IntegrityHash))
        {
            try
            {
                var expectedHash = Convert.FromBase64String(payload.IntegrityHash);
                var actualHash = SHA256.HashData(protectedBytes);
                if (!CryptographicOperations.FixedTimeEquals(actualHash, expectedHash))
                {
                    return false;
                }
            }
            catch
            {
                return false;
            }
        }
#pragma warning restore CS0618

        try
        {
            if (!OperatingSystem.IsWindows())
            {
                return false;
            }

            var plainBytes = ProtectedData.Unprotect(protectedBytes, Encoding.UTF8.GetBytes(Purpose), DataProtectionScope.CurrentUser);
            plainText = Encoding.UTF8.GetString(plainBytes);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static MasterKeyState CreateState(string masterKey, string recoveryKey)
    {
        var (masterHash, masterSalt) = HashSecret(masterKey);
        var (recoveryHash, recoverySalt) = HashSecret(recoveryKey);

        return new MasterKeyState(masterHash, masterSalt, recoveryHash, recoverySalt);
    }

    private static (byte[] Hash, byte[] Salt) HashSecret(string secret)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = Rfc2898DeriveBytes.Pbkdf2(secret, salt, 120_000, HashAlgorithmName.SHA256, 32);
        return (hash, salt);
    }

    private static bool VerifySecret(string candidate, byte[] expectedHash, byte[] salt)
    {
        var candidateHash = Rfc2898DeriveBytes.Pbkdf2(candidate, salt, 120_000, HashAlgorithmName.SHA256, 32);
        return CryptographicOperations.FixedTimeEquals(candidateHash, expectedHash);
    }

    private static string ResolveDataDirectory(string configuredDirectory)
    {
        if (!string.IsNullOrWhiteSpace(configuredDirectory))
        {
            return configuredDirectory;
        }

        if (OperatingSystem.IsWindows())
        {
            var common = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            return Path.Combine(common, "RogueAP");
        }

        return Path.Combine(AppContext.BaseDirectory, "data");
    }

    private sealed record MasterKeyState(
        byte[] MasterHash,
        byte[] MasterSalt,
        byte[] RecoveryHash,
        byte[] RecoverySalt,
        string? DpapiWrappedDek = null,
        string? MasterKeyWrappedDek = null);
}