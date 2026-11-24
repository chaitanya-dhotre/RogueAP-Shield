using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Options;
using RogueAP.Core.Interfaces;
using RogueAP.Core.Options;

namespace RogueAP.Infrastructure.Services;

public sealed class DekProvider : IDekProvider
{
    private const string Purpose = "RogueAP-SecureState-v1";
    private readonly object _sync = new();
    private readonly string _masterKeyStateFilePath;
    private byte[]? _inMemoryDek;

    public DekProvider(IOptions<SecureStorageOptions> options)
    {
        var dataDirectory = ResolveDataDirectory(options.Value.DataDirectory);
        _masterKeyStateFilePath = Path.Combine(dataDirectory, options.Value.MasterKeyStateFileName);
    }

    public bool HasInMemoryDek
    {
        get
        {
            lock (_sync)
            {
                return _inMemoryDek is not null;
            }
        }
    }

    public byte[]? GetInMemoryDekIfExists()
    {
        lock (_sync)
        {
            return _inMemoryDek is null ? null : _inMemoryDek.ToArray();
        }
    }

    public byte[] GetDek()
    {
        lock (_sync)
        {
            if (_inMemoryDek is not null)
            {
                return _inMemoryDek.ToArray();
            }

            if (!File.Exists(_masterKeyStateFilePath))
            {
                _inMemoryDek = RandomNumberGenerator.GetBytes(32);
                return _inMemoryDek.ToArray();
            }

            var payloadText = File.ReadAllText(_masterKeyStateFilePath);
            var payload = JsonSerializer.Deserialize<SecurePayload>(payloadText);
            if (payload is null || !TryUnprotectStatePayload(payload, out var plainText) || string.IsNullOrWhiteSpace(plainText))
            {
                throw new InvalidOperationException("Failed to read persisted master key state payload.");
            }

            var state = JsonSerializer.Deserialize<MasterKeyStateSnapshot>(plainText);
            if (state is null || string.IsNullOrWhiteSpace(state.DpapiWrappedDek))
            {
                throw new InvalidOperationException("Persisted master key state does not contain a DPAPI-wrapped DEK.");
            }

            var wrappedDek = Convert.FromBase64String(state.DpapiWrappedDek);
            _inMemoryDek = UnwrapDekWithDpapi(wrappedDek);
            if (_inMemoryDek.Length != 32)
            {
                throw new InvalidOperationException("Persisted DEK is invalid.");
            }

            return _inMemoryDek.ToArray();
        }
    }

    private static bool TryUnprotectStatePayload(SecurePayload payload, out string? plainText)
    {
        plainText = null;
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

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
            var plainBytes = ProtectedData.Unprotect(protectedBytes, Encoding.UTF8.GetBytes(Purpose), DataProtectionScope.CurrentUser);
            plainText = Encoding.UTF8.GetString(plainBytes);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static byte[] UnwrapDekWithDpapi(byte[] wrappedDek)
    {
        if (!OperatingSystem.IsWindows())
        {
            throw new PlatformNotSupportedException("DPAPI DEK unwrap is implemented for Windows only.");
        }

        return ProtectedData.Unprotect(wrappedDek, Encoding.UTF8.GetBytes(Purpose), DataProtectionScope.CurrentUser);
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

    private sealed record MasterKeyStateSnapshot(
        byte[] MasterHash,
        byte[] MasterSalt,
        byte[] RecoveryHash,
        byte[] RecoverySalt,
        string? DpapiWrappedDek,
        string? MasterKeyWrappedDek);
}

