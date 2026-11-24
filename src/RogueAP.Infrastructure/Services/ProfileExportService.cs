using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using RogueAP.Core.Interfaces;
using RogueAP.Core.Models;

namespace RogueAP.Infrastructure.Services;

public sealed class ProfileExportService : IProfileExportService
{
    private static readonly byte[] Magic = [0x52, 0x41, 0x50, 0x46]; // RAPF
    private static readonly byte[] FormatVersion = [0x00, 0x01, 0x00, 0x00];
    private const int SaltLength = 16;
    private const int NonceLength = 12;
    private const int TagLength = 16;
    private const int Pbkdf2Iterations = 600_000;
    private const int KeyLength = 32;
    private const int HeaderLength = 4 + 4 + SaltLength + NonceLength + TagLength; // 52 bytes

    private readonly ITrustedNetworkRepository _trustedRepo;
    private readonly INetworkProfileRepository _profileRepo;
    private readonly IProtectionRuntimeConfigStore _configStore;
    private readonly IAuditLogger _auditLogger;
    private readonly ILogger<ProfileExportService> _logger;

    public ProfileExportService(
        ITrustedNetworkRepository trustedRepo,
        INetworkProfileRepository profileRepo,
        IProtectionRuntimeConfigStore configStore,
        IAuditLogger auditLogger,
        ILogger<ProfileExportService> logger)
    {
        _trustedRepo = trustedRepo;
        _profileRepo = profileRepo;
        _configStore = configStore;
        _auditLogger = auditLogger;
        _logger = logger;
    }

    public async Task<byte[]> ExportAsync(string masterKey, string description, CancellationToken ct)
    {
        var trusted = await _trustedRepo.GetAllAsync(ct);
        var allProfiles = await _profileRepo.GetAllAsync(ct);
        var completedProfiles = allProfiles.Where(p => p.LearningComplete).ToList();
        var deploymentProfile = _configStore.GetDeploymentProfile() ?? "Home";

        var sortedTrusted = trusted
            .OrderBy(t => t.Bssid, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var sortedProfiles = completedProfiles
            .OrderBy(p => p.Ssid, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var contentHash = ComputeContentHash(sortedTrusted, sortedProfiles);

        var export = new RapfExport
        {
            FormatVersion = "1.0",
            ExportedAt = DateTimeOffset.UtcNow,
            ExportedFromProfile = deploymentProfile,
            Description = description,
            TrustedNetworks = sortedTrusted,
            NetworkProfiles = sortedProfiles,
            DeploymentProfile = deploymentProfile,
            ContentHash = contentHash
        };

        var json = JsonSerializer.Serialize(export);
        var plainBytes = Encoding.UTF8.GetBytes(json);

        var salt = RandomNumberGenerator.GetBytes(SaltLength);
        var nonce = RandomNumberGenerator.GetBytes(NonceLength);
        var key = DeriveKey(masterKey, salt);
        var tag = new byte[TagLength];
        var cipher = new byte[plainBytes.Length];

        using (var aes = new AesGcm(key, TagLength))
        {
            aes.Encrypt(nonce, plainBytes, cipher, tag);
        }

        var result = new byte[Magic.Length + FormatVersion.Length + salt.Length + nonce.Length + tag.Length + cipher.Length];
        var offset = 0;
        Buffer.BlockCopy(Magic, 0, result, offset, Magic.Length); offset += Magic.Length;
        Buffer.BlockCopy(FormatVersion, 0, result, offset, FormatVersion.Length); offset += FormatVersion.Length;
        Buffer.BlockCopy(salt, 0, result, offset, salt.Length); offset += salt.Length;
        Buffer.BlockCopy(nonce, 0, result, offset, nonce.Length); offset += nonce.Length;
        Buffer.BlockCopy(tag, 0, result, offset, tag.Length); offset += tag.Length;
        Buffer.BlockCopy(cipher, 0, result, offset, cipher.Length);

        await _auditLogger.LogAsync(
            "PROFILE_EXPORTED",
            AuditCategories.System,
            $"{sortedTrusted.Count} networks, {sortedProfiles.Count} profiles exported",
            ct: ct);

        _logger.LogInformation(
            "Profile export: {TrustedCount} trusted networks, {ProfileCount} profiles.",
            sortedTrusted.Count, sortedProfiles.Count);

        return result;
    }

    public Task<RapfImportPreview> PreviewAsync(byte[] rapfBytes, string masterKey, CancellationToken ct)
    {
        var (export, _) = DecryptAndDeserialize(rapfBytes, masterKey);

        var sortedTrusted = export.TrustedNetworks
            .OrderBy(t => t.Bssid, StringComparer.OrdinalIgnoreCase)
            .ToList();
        var sortedProfiles = export.NetworkProfiles
            .OrderBy(p => p.Ssid, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var computedHash = ComputeContentHash(sortedTrusted, sortedProfiles);
        var hashValid = string.Equals(computedHash, export.ContentHash, StringComparison.OrdinalIgnoreCase);

        return Task.FromResult(new RapfImportPreview(
            export.FormatVersion,
            export.ExportedAt,
            export.ExportedFromProfile,
            export.Description,
            export.TrustedNetworks.Count,
            export.NetworkProfiles.Count,
            hashValid));
    }

    public async Task<RapfImportResult> ImportAsync(byte[] rapfBytes, string masterKey, bool mergeMode, CancellationToken ct)
    {
        var preview = await PreviewAsync(rapfBytes, masterKey, ct);

        if (!preview.ContentHashValid)
        {
            return new RapfImportResult(
                false, 0, 0, 0,
                "Content hash mismatch — file may be corrupted or tampered");
        }

        var (export, _) = DecryptAndDeserialize(rapfBytes, masterKey);

        var existingTrusted = await _trustedRepo.GetAllAsync(ct);
        var existingBssids = existingTrusted
            .Select(t => t.Bssid.ToUpperInvariant())
            .ToHashSet();

        var imported = 0;
        var skipped = 0;

        foreach (var network in export.TrustedNetworks)
        {
            if (!mergeMode || !existingBssids.Contains(network.Bssid.ToUpperInvariant()))
            {
                await _trustedRepo.AddOrUpdateAsync(network, ct);
                imported++;
            }
            else
            {
                skipped++;
            }
        }

        var profilesImported = 0;
        foreach (var profile in export.NetworkProfiles)
        {
            await _profileRepo.SaveAsync(profile, ct);
            profilesImported++;
        }

        await _auditLogger.LogAsync(
            "PROFILE_IMPORTED",
            AuditCategories.System,
            $"{imported} networks imported, {skipped} skipped, {profilesImported} profiles imported",
            ct: ct);

        _logger.LogInformation(
            "Profile import: {Imported} trusted networks imported, {Skipped} skipped, {Profiles} profiles.",
            imported, skipped, profilesImported);

        return new RapfImportResult(
            true,
            imported,
            skipped,
            profilesImported,
            $"{imported} trusted networks imported, {skipped} skipped, {profilesImported} learned profiles imported.");
    }

    private (RapfExport Export, byte[] PlainBytes) DecryptAndDeserialize(byte[] rapfBytes, string masterKey)
    {
        if (rapfBytes.Length < HeaderLength)
        {
            throw new InvalidDataException("Not a valid .rapf file");
        }

        for (var i = 0; i < Magic.Length; i++)
        {
            if (rapfBytes[i] != Magic[i])
            {
                throw new InvalidDataException("Not a valid .rapf file");
            }
        }

        var offset = Magic.Length + FormatVersion.Length; // skip magic + version (8 bytes)
        var salt = rapfBytes[offset..(offset + SaltLength)]; offset += SaltLength;
        var nonce = rapfBytes[offset..(offset + NonceLength)]; offset += NonceLength;
        var tag = rapfBytes[offset..(offset + TagLength)]; offset += TagLength;
        var cipher = rapfBytes[offset..];

        var key = DeriveKey(masterKey, salt);
        var plain = new byte[cipher.Length];

        try
        {
            using var aes = new AesGcm(key, TagLength);
            aes.Decrypt(nonce, cipher, tag, plain);
        }
        catch (CryptographicException)
        {
            throw new UnauthorizedAccessException("Invalid master key for this file");
        }

        var json = Encoding.UTF8.GetString(plain);
        var export = JsonSerializer.Deserialize<RapfExport>(json)
            ?? throw new InvalidDataException("Not a valid .rapf file");

        return (export, plain);
    }

    private static byte[] DeriveKey(string masterKey, byte[] salt)
    {
        return Rfc2898DeriveBytes.Pbkdf2(masterKey, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, KeyLength);
    }

    private static string ComputeContentHash(
        IEnumerable<TrustedNetwork> trustedNetworks,
        IEnumerable<NetworkProfile> networkProfiles)
    {
        var trustedJson = JsonSerializer.Serialize(trustedNetworks);
        var profilesJson = JsonSerializer.Serialize(networkProfiles);
        var combined = Encoding.UTF8.GetBytes(trustedJson + profilesJson);
        var hash = SHA256.HashData(combined);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}
