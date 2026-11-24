using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RogueAP.Core.Interfaces;
using RogueAP.Core.Models;
using RogueAP.Core.Options;

namespace RogueAP.Infrastructure.Services;

public sealed class PersistentTrustedNetworkRepository : ITrustedNetworkRepository
{
    private readonly object _sync = new();
    private readonly ILogger<PersistentTrustedNetworkRepository> _logger;
    private readonly SecureFileProtector _secureFileProtector;
    private readonly IAuditLogger _auditLogger;
    private readonly string _filePath;
    private readonly bool _seedDefaults;
    private List<TrustedNetwork>? _cache;

    public PersistentTrustedNetworkRepository(
        ILogger<PersistentTrustedNetworkRepository> logger,
        SecureFileProtector secureFileProtector,
        IAuditLogger auditLogger,
        IOptions<SecureStorageOptions> options)
    {
        _logger = logger;
        _secureFileProtector = secureFileProtector;
        _auditLogger = auditLogger;
        _seedDefaults = options.Value.SeedDefaultTrustedNetworks;
        var dataDirectory = ResolveDataDirectory(options.Value.DataDirectory);
        Directory.CreateDirectory(dataDirectory);
        _filePath = Path.Combine(dataDirectory, options.Value.TrustedNetworksFileName);
    }

    public Task<IReadOnlyCollection<TrustedNetwork>> GetAllAsync(CancellationToken cancellationToken)
    {
        lock (_sync)
        {
            _cache ??= LoadOrInitialize();
            IReadOnlyCollection<TrustedNetwork> copy = _cache.ToArray();
            return Task.FromResult(copy);
        }
    }

    public async Task AddOrUpdateAsync(TrustedNetwork network, CancellationToken cancellationToken)
    {
        lock (_sync)
        {
            _cache ??= LoadOrInitialize();

            var index = _cache.FindIndex(item =>
                string.Equals(item.Bssid, network.Bssid, StringComparison.OrdinalIgnoreCase));

            if (index >= 0)
            {
                _cache[index] = network;
            }
            else
            {
                _cache.Add(network);
            }

            Persist(_cache);
        }

        await _auditLogger.LogAsync(
            AuditActions.TrustedAdded,
            AuditCategories.Trust,
            $"SSID: {network.Ssid} BSSID: {network.Bssid}",
            ct: cancellationToken);
    }

    public async Task<bool> RemoveByBssidAsync(string bssid, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(bssid))
        {
            return false;
        }

        bool removed;
        lock (_sync)
        {
            _cache ??= LoadOrInitialize();
            var removedCount = _cache.RemoveAll(item =>
                string.Equals(item.Bssid, bssid, StringComparison.OrdinalIgnoreCase));

            removed = removedCount > 0;
            if (removed)
            {
                Persist(_cache);
            }
        }

        if (removed)
        {
            await _auditLogger.LogAsync(
                AuditActions.TrustedRemoved,
                AuditCategories.Trust,
                $"BSSID: {bssid}",
                ct: cancellationToken);
        }

        return removed;
    }

    public Task ClearAsync(CancellationToken cancellationToken)
    {
        lock (_sync)
        {
            _cache = [];
            if (File.Exists(_filePath))
            {
                File.Delete(_filePath);
            }
        }

        return Task.CompletedTask;
    }

    private List<TrustedNetwork> LoadOrInitialize()
    {
        if (!File.Exists(_filePath))
        {
            var initial = _seedDefaults
                ? new List<TrustedNetwork>
                {
                    new("Campus-WiFi", "00:11:22:33:44:55", "WPA2", DateTimeOffset.UtcNow),
                    new("OfficeSecure", "AA:BB:CC:DD:EE:FF", "WPA3", DateTimeOffset.UtcNow)
                }
                : [];

            Persist(initial);
            return initial;
        }

        try
        {
            var payloadText = File.ReadAllText(_filePath);
            var payload = JsonSerializer.Deserialize<SecurePayload>(payloadText);
            if (payload is null
                || !_secureFileProtector.TryUnprotect(payload, out var plainText, out var usedLegacyDpapi)
                || string.IsNullOrWhiteSpace(plainText))
            {
                _logger.LogWarning("Trusted network file failed integrity validation; using empty set.");
                return [];
            }

            var trustedNetworks = JsonSerializer.Deserialize<List<TrustedNetwork>>(plainText);
            var result = trustedNetworks ?? [];
            if (usedLegacyDpapi)
            {
                // One-time migration: rewrite legacy DPAPI payload to RAPG/AES-GCM using DEK.
                Persist(result);
            }

            return result;
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Failed to load trusted network state; using empty set.");
            return [];
        }
    }

    private void Persist(List<TrustedNetwork> networks)
    {
        var plain = JsonSerializer.Serialize(networks);
        var payload = _secureFileProtector.ProtectWithDek(plain);
        var text = JsonSerializer.Serialize(payload);
        File.WriteAllText(_filePath, text);
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
}