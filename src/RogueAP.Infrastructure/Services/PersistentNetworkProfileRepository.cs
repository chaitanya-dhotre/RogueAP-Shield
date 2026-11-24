using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RogueAP.Core.Interfaces;
using RogueAP.Core.Models;
using RogueAP.Core.Options;

namespace RogueAP.Infrastructure.Services;

public sealed class PersistentNetworkProfileRepository : INetworkProfileRepository
{
    private const string FileName = "network-profiles.secure.json";

    private readonly object _sync = new();
    private readonly ILogger<PersistentNetworkProfileRepository> _logger;
    private readonly SecureFileProtector _secureFileProtector;
    private readonly string _filePath;
    private List<NetworkProfile>? _cache;

    public PersistentNetworkProfileRepository(
        ILogger<PersistentNetworkProfileRepository> logger,
        SecureFileProtector secureFileProtector,
        IOptions<SecureStorageOptions> options)
    {
        _logger = logger;
        _secureFileProtector = secureFileProtector;
        var dataDirectory = ResolveDataDirectory(options.Value.DataDirectory);
        Directory.CreateDirectory(dataDirectory);
        _filePath = Path.Combine(dataDirectory, FileName);
    }

    public Task<NetworkProfile?> GetAsync(string ssid, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(ssid))
        {
            return Task.FromResult<NetworkProfile?>(null);
        }

        lock (_sync)
        {
            _cache ??= LoadOrInitialize();
            var profile = _cache.FirstOrDefault(p =>
                string.Equals(p.Ssid, ssid, StringComparison.OrdinalIgnoreCase));
            return Task.FromResult(profile);
        }
    }

    public Task SaveAsync(NetworkProfile profile, CancellationToken cancellationToken)
    {
        lock (_sync)
        {
            _cache ??= LoadOrInitialize();

            var index = _cache.FindIndex(p =>
                string.Equals(p.Ssid, profile.Ssid, StringComparison.OrdinalIgnoreCase));

            if (index >= 0)
            {
                _cache[index] = profile;
            }
            else
            {
                _cache.Add(profile);
            }

            Persist(_cache);
        }

        return Task.CompletedTask;
    }

    public Task<IReadOnlyList<NetworkProfile>> GetAllAsync(CancellationToken cancellationToken)
    {
        lock (_sync)
        {
            _cache ??= LoadOrInitialize();
            IReadOnlyList<NetworkProfile> copy = _cache.ToArray();
            return Task.FromResult(copy);
        }
    }

    public Task DeleteAsync(string ssid, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(ssid))
        {
            return Task.CompletedTask;
        }

        lock (_sync)
        {
            _cache ??= LoadOrInitialize();
            var removed = _cache.RemoveAll(p =>
                string.Equals(p.Ssid, ssid, StringComparison.OrdinalIgnoreCase));

            if (removed > 0)
            {
                Persist(_cache);
            }
        }

        return Task.CompletedTask;
    }

    private List<NetworkProfile> LoadOrInitialize()
    {
        if (!File.Exists(_filePath))
        {
            return [];
        }

        try
        {
            var payloadText = File.ReadAllText(_filePath);
            var payload = JsonSerializer.Deserialize<SecurePayload>(payloadText);
            if (payload is null
                || !_secureFileProtector.TryUnprotect(payload, out var plainText, out var usedLegacyDpapi)
                || string.IsNullOrWhiteSpace(plainText))
            {
                _logger.LogWarning("Network profile file failed integrity validation; using empty set.");
                return [];
            }

            var profiles = JsonSerializer.Deserialize<List<NetworkProfile>>(plainText);
            var result = profiles ?? [];

            if (usedLegacyDpapi)
            {
                Persist(result);
            }

            return result;
        }
        catch (Exception exception)
        {
            _logger.LogWarning(exception, "Failed to load network profile state; using empty set.");
            return [];
        }
    }

    private void Persist(List<NetworkProfile> profiles)
    {
        var plain = JsonSerializer.Serialize(profiles);
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
