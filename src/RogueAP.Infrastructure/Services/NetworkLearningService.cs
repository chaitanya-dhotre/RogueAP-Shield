using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using RogueAP.Core.Interfaces;
using RogueAP.Core.Models;

namespace RogueAP.Infrastructure.Services;

public sealed class NetworkLearningService : INetworkLearningService
{
    private readonly INetworkProfileRepository _profileRepository;
    private readonly IBeaconFrameService _beaconFrameService;
    private readonly IAuditLogger _auditLogger;
    private readonly ILogger<NetworkLearningService> _logger;

    private readonly ConcurrentDictionary<string, LearningState> _learningStates = new(StringComparer.OrdinalIgnoreCase);

    public NetworkLearningService(
        INetworkProfileRepository profileRepository,
        IBeaconFrameService beaconFrameService,
        IAuditLogger auditLogger,
        ILogger<NetworkLearningService> logger)
    {
        _profileRepository = profileRepository;
        _beaconFrameService = beaconFrameService;
        _auditLogger = auditLogger;
        _logger = logger;
    }

    public async Task ObserveAsync(
        string ssid,
        AccessPointSnapshot connectedAp,
        IReadOnlyCollection<AccessPointSnapshot> nearbyAps,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(ssid))
            return;

        var profile = await _profileRepository.GetAsync(ssid, cancellationToken);
        if (profile is null || profile.LearningComplete)
            return;

        var elapsed = DateTimeOffset.UtcNow - profile.LearningStartedAt;
        if (elapsed.TotalHours >= profile.LearningDurationHours)
        {
            await CompleteLearningAsync(ssid, cancellationToken);
            return;
        }

        var state = _learningStates.GetOrAdd(ssid, _ => new LearningState());

        // FIX 2: Set seed BSSID from first connected AP if not already set
        if (string.IsNullOrWhiteSpace(state.SeedBssid) && !string.IsNullOrWhiteSpace(connectedAp.Bssid))
        {
            state.SeedBssid = connectedAp.Bssid.ToUpperInvariant();
            _logger.LogInformation("Learning seed BSSID set to {SeedBssid} for SSID {Ssid}", state.SeedBssid, ssid);
        }

        var seedOui = state.SeedBssid?.Length >= 8
            ? state.SeedBssid.Substring(0, 8).ToUpperInvariant()
            : null;

        var sameSsidAps = nearbyAps
            .Where(ap => string.Equals(ap.Ssid, ssid, StringComparison.OrdinalIgnoreCase))
            .Append(connectedAp)
            .GroupBy(ap => ap.Bssid, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();

        foreach (var ap in sameSsidAps)
        {
            var apBssid = ap.Bssid.ToUpperInvariant();

            // FIX 2: OUI filtering - skip BSSIDs from different manufacturers
            if (seedOui != null && apBssid.Length >= 8)
            {
                var candidateOui = apBssid.Substring(0, 8).ToUpperInvariant();
                if (candidateOui != seedOui)
                {
                    _logger.LogWarning(
                        "Learning: skipping BSSID {Bssid} for SSID {Ssid} — OUI {Oui} does not match seed OUI {SeedOui}. Possible rogue AP during learning.",
                        ap.Bssid, ssid, candidateOui, seedOui);
                    continue; // skip this BSSID
                }
            }

            state.KnownBssids.Add(apBssid);

            var fingerprint = _beaconFrameService.GetLatestFingerprint(ap.Bssid);
            if (fingerprint is not null && !string.IsNullOrWhiteSpace(fingerprint.FingerprintHash))
            {
                var bssidKey = ap.Bssid.ToUpperInvariant();
                if (!state.BeaconFingerprints.TryGetValue(bssidKey, out var existingHash))
                {
                    state.BeaconFingerprints[bssidKey] = fingerprint.FingerprintHash;
                }
                else if (!string.Equals(existingHash, fingerprint.FingerprintHash, StringComparison.OrdinalIgnoreCase))
                {
                    _logger.LogWarning(
                        "Beacon fingerprint changed for BSSID {Bssid} during learning — keeping first observed hash",
                        ap.Bssid);
                }
            }

            UpdateSignalStats(state, ap.Bssid, ap.SignalStrength);
        }

        if (!string.IsNullOrWhiteSpace(connectedAp.GatewayIp))
        {
            state.GatewayIpCounts.AddOrUpdate(
                connectedAp.GatewayIp,
                1,
                (_, count) => count + 1);
        }

        var observedTtl = connectedAp.ObservedGatewayTtl ?? connectedAp.GatewayTtl;
        if (observedTtl.HasValue)
        {
            state.GatewayTtlCounts.AddOrUpdate(
                observedTtl.Value,
                1,
                (_, count) => count + 1);
        }

        if (!string.IsNullOrWhiteSpace(connectedAp.SecurityProtocol))
        {
            state.SecurityProtocolCounts.AddOrUpdate(
                connectedAp.SecurityProtocol,
                1,
                (_, count) => count + 1);
        }

        var currentSameSsidCount = sameSsidAps.Count;
        if (currentSameSsidCount > state.MaxObservedBssidCount)
        {
            state.MaxObservedBssidCount = currentSameSsidCount;
        }

        var updatedProfile = profile with
        {
            KnownBssids = state.KnownBssids.ToList(),
            BeaconFingerprints = new Dictionary<string, string>(state.BeaconFingerprints),
            CommonGatewayIp = GetMostCommon(state.GatewayIpCounts),
            CommonGatewayTtl = GetMostCommonInt(state.GatewayTtlCounts),
            CommonSecurityProtocol = GetMostCommon(state.SecurityProtocolCounts),
            ObservedBssidCount = state.KnownBssids.Count,
            SignalProfiles = BuildSignalProfiles(state)
        };

        await _profileRepository.SaveAsync(updatedProfile, cancellationToken);
    }

    public bool IsLearning(string ssid)
    {
        if (string.IsNullOrWhiteSpace(ssid))
            return false;

        return _learningStates.ContainsKey(ssid);
    }

    public Task<NetworkProfile?> GetProfileAsync(string ssid, CancellationToken cancellationToken)
    {
        return _profileRepository.GetAsync(ssid, cancellationToken);
    }

    public async Task StartLearningAsync(string ssid, string deploymentProfile, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(ssid))
            return;

        var normalizedProfile = deploymentProfile?.Trim().ToLowerInvariant() ?? "home";
        // FIX 3: Reduced Home duration from 24h to 2h for faster protection
        var durationHours = normalizedProfile switch
        {
            "enterprise" => 72,
            "campus" => 72,
            _ => 2
        };

        var profile = new NetworkProfile
        {
            Ssid = ssid,
            DeploymentProfile = deploymentProfile ?? "Home",
            LearningStartedAt = DateTimeOffset.UtcNow,
            LearningComplete = false,
            LearningDurationHours = durationHours
        };

        _learningStates[ssid] = new LearningState();
        await _profileRepository.SaveAsync(profile, cancellationToken);

        await _auditLogger.LogAsync(
            AuditActions.LearningStarted,
            AuditCategories.Learning,
            $"{ssid} — {durationHours}h duration",
            ssid,
            cancellationToken);

        _logger.LogInformation(
            "Learning started for SSID '{Ssid}' with profile '{Profile}' — duration {Hours} hours",
            ssid, deploymentProfile, durationHours);
    }

    public async Task CompleteLearningAsync(string ssid, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(ssid))
            return;

        var profile = await _profileRepository.GetAsync(ssid, cancellationToken);
        if (profile is null)
            return;

        if (_learningStates.TryRemove(ssid, out var state))
        {
            var completedProfile = profile with
            {
                LearningComplete = true,
                LearningCompletedAt = DateTimeOffset.UtcNow,
                KnownBssids = state.KnownBssids.ToList(),
                BeaconFingerprints = new Dictionary<string, string>(state.BeaconFingerprints),
                CommonGatewayIp = GetMostCommon(state.GatewayIpCounts),
                CommonGatewayTtl = GetMostCommonInt(state.GatewayTtlCounts),
                CommonSecurityProtocol = GetMostCommon(state.SecurityProtocolCounts),
                ObservedBssidCount = state.KnownBssids.Count,
                MaxExpectedBssidCount = state.MaxObservedBssidCount + 2,
                SignalProfiles = BuildSignalProfiles(state)
            };

            await _profileRepository.SaveAsync(completedProfile, cancellationToken);

            await _auditLogger.LogAsync(
                AuditActions.LearningComplete,
                AuditCategories.Learning,
                $"{ssid} — {completedProfile.KnownBssids.Count} BSSIDs learned",
                ssid,
                cancellationToken);

            _logger.LogInformation(
                "Learning complete for '{Ssid}': {BssidCount} BSSIDs, {FingerprintCount} fingerprints",
                ssid,
                completedProfile.KnownBssids.Count,
                completedProfile.BeaconFingerprints.Count);
        }
        else
        {
            var completedProfile = profile with
            {
                LearningComplete = true,
                LearningCompletedAt = DateTimeOffset.UtcNow,
                MaxExpectedBssidCount = profile.ObservedBssidCount + 2
            };

            await _profileRepository.SaveAsync(completedProfile, cancellationToken);

            await _auditLogger.LogAsync(
                AuditActions.LearningComplete,
                AuditCategories.Learning,
                $"{ssid} — {completedProfile.KnownBssids.Count} BSSIDs learned",
                ssid,
                cancellationToken);

            _logger.LogInformation(
                "Learning complete for '{Ssid}': {BssidCount} BSSIDs (state not in memory)",
                ssid,
                completedProfile.KnownBssids.Count);
        }
    }

    public async Task ResetLearningAsync(string ssid, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(ssid))
            return;

        // Remove from in-memory state
        _learningStates.TryRemove(ssid, out _);

        // Delete from repository
        await _profileRepository.DeleteAsync(ssid, cancellationToken);

        _logger.LogInformation("Learning reset for SSID '{Ssid}' — profile deleted", ssid);
    }

    private static void UpdateSignalStats(LearningState state, string bssid, int signalStrength)
    {
        var key = bssid.ToUpperInvariant();
        var stats = state.SignalRunningStats.GetOrAdd(key, _ => new WelfordStats());
        stats.Update(signalStrength);
    }

    private static IReadOnlyDictionary<string, SignalStats> BuildSignalProfiles(LearningState state)
    {
        var result = new Dictionary<string, SignalStats>(StringComparer.OrdinalIgnoreCase);
        foreach (var (bssid, stats) in state.SignalRunningStats)
        {
            if (stats.Count > 0)
            {
                result[bssid] = new SignalStats(stats.Mean, stats.StdDev, stats.Count);
            }
        }
        return result;
    }

    private static string? GetMostCommon(ConcurrentDictionary<string, int> counts)
    {
        if (counts.IsEmpty)
            return null;

        return counts
            .OrderByDescending(kvp => kvp.Value)
            .Select(kvp => kvp.Key)
            .FirstOrDefault();
    }

    private static int? GetMostCommonInt(ConcurrentDictionary<int, int> counts)
    {
        if (counts.IsEmpty)
            return null;

        return counts
            .OrderByDescending(kvp => kvp.Value)
            .Select(kvp => kvp.Key)
            .FirstOrDefault();
    }

    private sealed class LearningState
    {
        public HashSet<string> KnownBssids { get; } = new(StringComparer.OrdinalIgnoreCase);
        public ConcurrentDictionary<string, string> BeaconFingerprints { get; } = new(StringComparer.OrdinalIgnoreCase);
        public ConcurrentDictionary<string, int> GatewayIpCounts { get; } = new(StringComparer.OrdinalIgnoreCase);
        public ConcurrentDictionary<int, int> GatewayTtlCounts { get; } = new();
        public ConcurrentDictionary<string, int> SecurityProtocolCounts { get; } = new(StringComparer.OrdinalIgnoreCase);
        public ConcurrentDictionary<string, WelfordStats> SignalRunningStats { get; } = new(StringComparer.OrdinalIgnoreCase);
        public int MaxObservedBssidCount { get; set; }
        public string? SeedBssid { get; set; }
    }

    private sealed class WelfordStats
    {
        private int _count;
        private double _mean;
        private double _m2;

        public int Count => _count;
        public double Mean => _mean;
        public double Variance => _count < 2 ? 0 : _m2 / (_count - 1);
        public double StdDev => Math.Sqrt(Variance);

        public void Update(double value)
        {
            _count++;
            var delta = value - _mean;
            _mean += delta / _count;
            var delta2 = value - _mean;
            _m2 += delta * delta2;
        }
    }
}
