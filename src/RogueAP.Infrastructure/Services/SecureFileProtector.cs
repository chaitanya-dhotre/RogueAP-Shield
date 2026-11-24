using System.Security.Cryptography;
using System.Text;
using RogueAP.Core.Interfaces;

namespace RogueAP.Infrastructure.Services;

public sealed class SecureFileProtector
{
    private static readonly byte[] VersionMarker = [0x52, 0x41, 0x50, 0x47]; // RAPG
    private const string Purpose = "RogueAP-SecureState-v1";
    private readonly IDekProvider _dekProvider;

    public SecureFileProtector(IDekProvider dekProvider)
    {
        _dekProvider = dekProvider;
    }

    internal SecurePayload ProtectWithDek(string plainText)
    {
        var plainBytes = Encoding.UTF8.GetBytes(plainText);
        var protectedBytes = ProtectWithDekBytes(plainBytes);

        return new SecurePayload(
            ProtectedData: Convert.ToBase64String(protectedBytes),
            IntegrityHash: string.Empty);
    }

    internal bool TryUnprotect(SecurePayload payload, out string? plainText, out bool usedLegacyDpapi)
    {
        plainText = null;
        usedLegacyDpapi = false;

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

        if (IsNewFormat(protectedBytes))
        {
            try
            {
                var plainBytes = UnprotectWithDekBytes(protectedBytes);
                plainText = Encoding.UTF8.GetString(plainBytes);
                return true;
            }
            catch
            {
                return false;
            }
        }

        try
        {
            var plainBytes = UnprotectLegacyDpapiBytes(protectedBytes, payload);
            plainText = Encoding.UTF8.GetString(plainBytes);
            usedLegacyDpapi = true;
            return true;
        }
        catch
        {
            return false;
        }
    }

    internal bool TryUnprotect(SecurePayload payload, out string? plainText)
    {
        return TryUnprotect(payload, out plainText, out _);
    }

    private byte[] ProtectWithDekBytes(byte[] plainBytes)
    {
        var dek = _dekProvider.GetDek();
        if (dek.Length != 32)
        {
            throw new InvalidOperationException("DEK must be 32 bytes.");
        }

        var nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
        var cipherBytes = new byte[plainBytes.Length];
        var tag = new byte[AesGcm.TagByteSizes.MaxSize];

        using (var aes = new AesGcm(dek, AesGcm.TagByteSizes.MaxSize))
        {
            aes.Encrypt(nonce, plainBytes, cipherBytes, tag);
        }

        var output = new byte[VersionMarker.Length + nonce.Length + tag.Length + cipherBytes.Length];
        Buffer.BlockCopy(VersionMarker, 0, output, 0, VersionMarker.Length);
        Buffer.BlockCopy(nonce, 0, output, VersionMarker.Length, nonce.Length);
        Buffer.BlockCopy(tag, 0, output, VersionMarker.Length + nonce.Length, tag.Length);
        Buffer.BlockCopy(cipherBytes, 0, output, VersionMarker.Length + nonce.Length + tag.Length, cipherBytes.Length);

        return output;
    }

    private byte[] UnprotectWithDekBytes(byte[] protectedBytes)
    {
        var dek = _dekProvider.GetDek();
        if (dek.Length != 32)
        {
            throw new InvalidOperationException("DEK must be 32 bytes.");
        }

        var minimumSize = VersionMarker.Length + AesGcm.NonceByteSizes.MaxSize + AesGcm.TagByteSizes.MaxSize;
        if (protectedBytes.Length <= minimumSize)
        {
            throw new InvalidDataException("Invalid encrypted payload length for RAPG format.");
        }

        var nonce = protectedBytes.AsSpan(VersionMarker.Length, AesGcm.NonceByteSizes.MaxSize).ToArray();
        var tag = protectedBytes.AsSpan(VersionMarker.Length + AesGcm.NonceByteSizes.MaxSize, AesGcm.TagByteSizes.MaxSize).ToArray();
        var ciphertext = protectedBytes.AsSpan(minimumSize).ToArray();
        var plainBytes = new byte[ciphertext.Length];

        using (var aes = new AesGcm(dek, AesGcm.TagByteSizes.MaxSize))
        {
            aes.Decrypt(nonce, ciphertext, tag, plainBytes);
        }

        return plainBytes;
    }

    private static bool IsNewFormat(byte[] bytes)
    {
        return bytes.Length >= VersionMarker.Length
            && bytes[0] == VersionMarker[0]
            && bytes[1] == VersionMarker[1]
            && bytes[2] == VersionMarker[2]
            && bytes[3] == VersionMarker[3];
    }

    private static byte[] UnprotectLegacyDpapiBytes(byte[] bytes, SecurePayload payload)
    {
#pragma warning disable CS0618
        if (string.IsNullOrWhiteSpace(payload.IntegrityHash))
        {
            throw new CryptographicException("Legacy integrity hash is missing.");
        }

        var expectedHash = Convert.FromBase64String(payload.IntegrityHash);
#pragma warning restore CS0618
        var actualHash = SHA256.HashData(bytes);
        if (!CryptographicOperations.FixedTimeEquals(actualHash, expectedHash))
        {
            throw new CryptographicException("Legacy integrity hash validation failed.");
        }

        if (OperatingSystem.IsWindows())
        {
            return ProtectedData.Unprotect(bytes, Encoding.UTF8.GetBytes(Purpose), DataProtectionScope.CurrentUser);
        }

        throw new PlatformNotSupportedException("Legacy DPAPI migration is implemented for Windows only.");
    }
}