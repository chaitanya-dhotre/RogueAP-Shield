using RogueAP.Core.Enums;
using RogueAP.Core.Interfaces;
using RogueAP.Core.Models;
using Microsoft.Extensions.Logging;

namespace RogueAP.Infrastructure.Services;

public sealed class HeuristicRiskAnalyzer : IRiskAnalyzer
{
    private readonly IProtectionRuntimeConfigStore _runtimeConfigStore;
    private readonly DnsResolutionProbe _dnsResolutionProbe;
    private readonly IBeaconFrameService _beaconFrameService;
    private readonly INetworkLearningService _learningService;
    private readonly ILogger<HeuristicRiskAnalyzer> _logger;

    public HeuristicRiskAnalyzer(
        ILogger<HeuristicRiskAnalyzer> logger,
        IProtectionRuntimeConfigStore runtimeConfigStore,
        DnsResolutionProbe dnsResolutionProbe,
        IBeaconFrameService beaconFrameService,
        INetworkLearningService learningService)
    {
        _runtimeConfigStore = runtimeConfigStore;
        _dnsResolutionProbe = dnsResolutionProbe;
        _beaconFrameService = beaconFrameService;
        _learningService = learningService;
        _logger = logger;
    }

    public async Task<NetworkAssessment> Analyze(
        AccessPointSnapshot? connectedNetwork,
        IReadOnlyCollection<AccessPointSnapshot> nearbyNetworks,
        IReadOnlyCollection<TrustedNetwork> trustedNetworks)
    {
        if (connectedNetwork is null)
        {
            return new NetworkAssessment(
                ConnectedNetwork: null,
                RiskLevel: RiskLevel.Low,
                IsTrustedNetwork: false,
                RiskScore: 0,
                Signals: ["No active Wi-Fi connection"],
                Summary: "Device is not connected to a Wi-Fi network.");
        }

        var signals = new List<string>();
        var riskScore = 0;
        var deploymentProfile = NormalizeProfile(_runtimeConfigStore.GetDeploymentProfile());
        var sameSsidTolerance = GetSameSsidTolerance(deploymentProfile);

        var networkProfile = await _learningService.GetProfileAsync(connectedNetwork.Ssid, CancellationToken.None);

        var isTrusted = trustedNetworks.Any(network =>
            string.Equals(network.Bssid, connectedNetwork.Bssid, StringComparison.OrdinalIgnoreCase));

        var trustedSsidBaselines = trustedNetworks
            .Where(network => string.Equals(network.Ssid, connectedNetwork.Ssid, StringComparison.OrdinalIgnoreCase))
            .ToArray();

        var connectedOui = connectedNetwork.VendorOui ?? ExtractOui(connectedNetwork.Bssid);

        var combined = nearbyNetworks
            .Append(connectedNetwork)
            .GroupBy(network => network.Bssid, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToArray();

        var sameSsidDifferentBssidCount = combined.Count(network =>
            string.Equals(network.Ssid, connectedNetwork.Ssid, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(network.Bssid, connectedNetwork.Bssid, StringComparison.OrdinalIgnoreCase));

        var sameSsidPeers = combined
            .Where(network =>
                string.Equals(network.Ssid, connectedNetwork.Ssid, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(network.Bssid, connectedNetwork.Bssid, StringComparison.OrdinalIgnoreCase))
            .ToArray();

        if (sameSsidDifferentBssidCount > 0)
        {
            signals.Add($"Warning: {sameSsidDifferentBssidCount} Wi-Fi network(s) with similar SSID but different BSSID detected");

            if (isTrusted)
            {
                var threshold = deploymentProfile switch
                {
                    "enterprise" => 8,
                    "campus" => 10,
                    _ => 2
                };

                if (sameSsidDifferentBssidCount >= threshold)
                {
                    riskScore += 8;
                    signals.Add("Dense same-SSID environment detected while on trusted BSSID");
                }
            }
            else if (trustedSsidBaselines.Length == 0)
            {
                var threshold = deploymentProfile switch
                {
                    "enterprise" => 8,
                    "campus" => 10,
                    _ => 2
                };

                if (sameSsidDifferentBssidCount >= threshold)
                {
                    if (deploymentProfile == "enterprise" || deploymentProfile == "campus")
                    {
                        signals.Add("Multiple APs detected with this SSID — add a trusted baseline during a verified connection to enable evil-twin detection");
                    }
                    else
                    {
                        var scoreDelta = 6 + Math.Min(8, sameSsidDifferentBssidCount * 2);
                        riskScore += scoreDelta;
                    }
                }
            }
        }

        if (!isTrusted && trustedSsidBaselines.Length > 0)
        {
            var trustedVisibleNearby = combined.Any(network =>
                trustedSsidBaselines.Any(trusted =>
                    string.Equals(trusted.Bssid, network.Bssid, StringComparison.OrdinalIgnoreCase)));

            var securityMismatch = trustedSsidBaselines.All(trusted =>
                !string.Equals(trusted.SecurityProtocol, connectedNetwork.SecurityProtocol, StringComparison.OrdinalIgnoreCase));

            var trustedOuiSet = trustedSsidBaselines
                .Select(trusted => trusted.VendorOui ?? ExtractOui(trusted.Bssid))
                .Where(oui => !string.IsNullOrWhiteSpace(oui))
                .Select(oui => oui!)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var ouiMismatch = trustedOuiSet.Count > 0
                && !string.IsNullOrWhiteSpace(connectedNetwork.VendorOui)
                && !trustedOuiSet.Contains(connectedNetwork.VendorOui);

            var trustedBands = trustedSsidBaselines
                .Select(trusted => trusted.BandGHz)
                .Where(band => band.HasValue)
                .Select(band => band!.Value)
                .ToArray();

            var bandOutlier = connectedNetwork.BandGHz.HasValue
                && trustedBands.Length > 0
                && trustedBands.All(band => Math.Abs(band - connectedNetwork.BandGHz.Value) > 0.6);

            var trustedGatewaySet = trustedSsidBaselines
                .Select(trusted => trusted.GatewayIp)
                .Where(ip => !string.IsNullOrWhiteSpace(ip))
                .Select(ip => ip!)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var trustedDhcpSet = trustedSsidBaselines
                .Select(trusted => trusted.DhcpServerIp)
                .Where(ip => !string.IsNullOrWhiteSpace(ip))
                .Select(ip => ip!)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);

            var gatewayMismatch = trustedGatewaySet.Count > 0
                && !string.IsNullOrWhiteSpace(connectedNetwork.GatewayIp)
                && !trustedGatewaySet.Contains(connectedNetwork.GatewayIp);

            var dhcpMismatch = trustedDhcpSet.Count > 0
                && !string.IsNullOrWhiteSpace(connectedNetwork.DhcpServerIp)
                && !trustedDhcpSet.Contains(connectedNetwork.DhcpServerIp);

            riskScore += 18;
            signals.Add("Connected BSSID does not match trusted baseline for this SSID");

            if (trustedVisibleNearby)
            {
                riskScore += 20;
                signals.Add("Trusted baseline BSSID is in range while connected to a different BSSID");
            }

            if (securityMismatch)
            {
                riskScore += 20;
                signals.Add("Security protocol differs from all trusted baselines for this SSID");
            }

            if (ouiMismatch)
            {
                riskScore += 14;
                signals.Add("Vendor fingerprint differs from trusted baseline family");
            }

            if (bandOutlier)
            {
                riskScore += 8;
                signals.Add("Connected band is outside trusted baseline bands for this SSID");
            }

            if (gatewayMismatch)
            {
                riskScore += 18;
                signals.Add("Connected gateway fingerprint differs from trusted baseline");
            }

            if (dhcpMismatch)
            {
                riskScore += 16;
                signals.Add("Connected DHCP fingerprint differs from trusted baseline");
            }

            var likelyExpectedRoaming = sameSsidDifferentBssidCount <= sameSsidTolerance
                && !securityMismatch
                && !ouiMismatch
                && !trustedVisibleNearby;

            if (likelyExpectedRoaming)
            {
                riskScore -= 14;
                signals.Add("Likely expected roaming in multi-AP environment");
            }

            if (trustedVisibleNearby && (securityMismatch || ouiMismatch))
            {
                riskScore = Math.Max(riskScore, 80);
                signals.Add("Possible evil twin confidence increased by baseline conflict");
            }

            if (trustedVisibleNearby && (gatewayMismatch || dhcpMismatch))
            {
                riskScore = Math.Max(riskScore, 85);
                signals.Add("Possible evil twin confidence increased by gateway/DHCP mismatch");
            }
        }

        if (!isTrusted && trustedSsidBaselines.Length == 0 && sameSsidPeers.Length >= 3)
        {
            var peerOuiCounts = sameSsidPeers
                .Select(peer => peer.VendorOui ?? ExtractOui(peer.Bssid))
                .Where(oui => !string.IsNullOrWhiteSpace(oui))
                .GroupBy(oui => oui!, StringComparer.OrdinalIgnoreCase)
                .Select(group => new { Oui = group.Key, Count = group.Count() })
                .OrderByDescending(entry => entry.Count)
                .ToArray();

            var peerSecurityCounts = sameSsidPeers
                .Select(peer => NormalizeSecurity(peer.SecurityProtocol))
                .Where(security => !string.IsNullOrWhiteSpace(security))
                .GroupBy(security => security!, StringComparer.OrdinalIgnoreCase)
                .Select(group => new { Security = group.Key, Count = group.Count() })
                .OrderByDescending(entry => entry.Count)
                .ToArray();

            var connectedSecurity = NormalizeSecurity(connectedNetwork.SecurityProtocol);

            var ouiClusterMismatch = peerOuiCounts.Length > 0
                && !string.IsNullOrWhiteSpace(connectedOui)
                && !peerOuiCounts.Any(entry => string.Equals(entry.Oui, connectedOui, StringComparison.OrdinalIgnoreCase));

            var securityClusterMismatch = peerSecurityCounts.Length > 0
                && !string.IsNullOrWhiteSpace(connectedSecurity)
                && !peerSecurityCounts.Any(entry => string.Equals(entry.Security, connectedSecurity, StringComparison.OrdinalIgnoreCase));

            if (ouiClusterMismatch)
            {
                riskScore += 28;
                signals.Add("Connected AP vendor fingerprint differs from nearby same-SSID cluster");
            }

            if (securityClusterMismatch)
            {
                riskScore += 18;
                signals.Add("Connected AP security profile differs from nearby same-SSID cluster");
            }

            if (ouiClusterMismatch && securityClusterMismatch)
            {
                riskScore = Math.Max(riskScore, 75);
                signals.Add("Possible rogue AP detected by surrounding same-SSID baseline");
            }
        }

        if (IsOpenSecurity(connectedNetwork.SecurityProtocol))
        {
            riskScore += 30;
            signals.Add("Connected network is open/unencrypted");

            var clusterThreshold = deploymentProfile == "campus" ? 3 : 2;
            if (!isTrusted && sameSsidDifferentBssidCount >= clusterThreshold)
            {
                riskScore += 20;
                signals.Add("Open network with dense same-SSID environment raises rogue AP confidence");
            }
        }

        if (isTrusted)
        {
            var trusted = trustedNetworks.First(network =>
                string.Equals(network.Bssid, connectedNetwork.Bssid, StringComparison.OrdinalIgnoreCase));

            if (!string.Equals(trusted.SecurityProtocol, connectedNetwork.SecurityProtocol, StringComparison.OrdinalIgnoreCase))
            {
                riskScore += 30;
                signals.Add("Security protocol changed from trusted baseline");
            }

            var observedGatewayTtl = connectedNetwork.ObservedGatewayTtl ?? connectedNetwork.GatewayTtl;
            if (observedGatewayTtl.HasValue
                && trusted.GatewayTtl.HasValue
                && Math.Abs(trusted.GatewayTtl.Value - observedGatewayTtl.Value) > 5)
            {
                var ttlRiskWeight = deploymentProfile == "campus" ? 8 : 12;
                riskScore += ttlRiskWeight;
                signals.Add(
                    $"Gateway TTL mismatch: expected {trusted.GatewayTtl.Value}, observed {observedGatewayTtl.Value} - possible upstream path change");
            }

            if (deploymentProfile != "home" && !string.IsNullOrWhiteSpace(trusted.InternalHostname))
            {
                try
                {
                    using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(2000));
                    var resolvedIp = await _dnsResolutionProbe.ResolveAsync(trusted.InternalHostname, cts.Token);
                    if (string.IsNullOrWhiteSpace(resolvedIp))
                    {
                        riskScore += 10;
                        signals.Add($"Internal DNS resolution failed for '{trusted.InternalHostname}'");
                    }
                    else if (!string.IsNullOrWhiteSpace(trusted.ExpectedInternalIp)
                             && !string.Equals(resolvedIp, trusted.ExpectedInternalIp, StringComparison.OrdinalIgnoreCase))
                    {
                        riskScore += 10;
                        signals.Add($"Internal DNS mismatch for '{trusted.InternalHostname}': expected {trusted.ExpectedInternalIp}, observed {resolvedIp}");
                    }
                    else
                    {
                        riskScore -= 5;
                        signals.Add($"Internal DNS verified for '{trusted.InternalHostname}' ({resolvedIp})");
                    }
                }
                catch (Exception exception)
                {
                    _logger.LogDebug(exception, "DNS resolution probe failed for hostname '{Hostname}'", trusted.InternalHostname);
                }
            }

            if (!string.IsNullOrWhiteSpace(trusted.BeaconFingerprintHash))
            {
                var currentFingerprint = _beaconFrameService.GetLatestFingerprint(connectedNetwork.Bssid);
                if (currentFingerprint is not null && !string.IsNullOrWhiteSpace(currentFingerprint.FingerprintHash))
                {
                    if (string.Equals(trusted.BeaconFingerprintHash, currentFingerprint.FingerprintHash, StringComparison.OrdinalIgnoreCase))
                    {
                        riskScore -= 8;
                        signals.Add("Beacon frame hardware fingerprint verified");
                    }
                    else
                    {
                        riskScore += 20;
                        signals.Add("Beacon frame hardware fingerprint mismatch — AP hardware signature differs from trusted baseline");
                    }
                }
            }
        }
        else
        {
            if (trustedSsidBaselines.Length == 0)
            {
                riskScore += 8;
                signals.Add("Connected network is not in trusted list");
            }
        }

        if (networkProfile is { LearningComplete: true })
        {
            var connectedBssidUpper = connectedNetwork.Bssid.ToUpperInvariant();
            if (networkProfile.KnownBssids.Any(b => string.Equals(b, connectedBssidUpper, StringComparison.OrdinalIgnoreCase)))
            {
                riskScore -= 15;
                signals.Add("BSSID is within learned network profile pool");
            }
            else
            {
                riskScore += 20;
                signals.Add("BSSID not seen during learning period — possible new or rogue AP");
            }

            var sameSsidCount = combined.Count(n => string.Equals(n.Ssid, connectedNetwork.Ssid, StringComparison.OrdinalIgnoreCase));
            if (networkProfile.MaxExpectedBssidCount > 0 && sameSsidCount > networkProfile.MaxExpectedBssidCount)
            {
                riskScore += 10;
                signals.Add($"More APs than expected ({sameSsidCount} vs max {networkProfile.MaxExpectedBssidCount})");
            }

            var observedTtl = connectedNetwork.ObservedGatewayTtl ?? connectedNetwork.GatewayTtl;
            if (networkProfile.CommonGatewayTtl.HasValue && observedTtl.HasValue)
            {
                var ttlDiff = Math.Abs(observedTtl.Value - networkProfile.CommonGatewayTtl.Value);
                if (ttlDiff <= networkProfile.GatewayTtlVariance)
                {
                    riskScore -= 5;
                    signals.Add("Gateway TTL matches learned profile");
                }
            }
        }

        if (connectedNetwork.RecentSignalSamples is { Count: > 6 })
        {
            var samples = connectedNetwork.RecentSignalSamples;
            var max = samples.Max();
            var min = samples.Min();
            if (max - min >= 30)
            {
                riskScore += 10;
                signals.Add($"Signal instability detected (variance: {max - min}% over recent samples)");
            }
        }

        var outlierSignal = CheckSignalOutlier(connectedNetwork);
        if (outlierSignal.IsOutlier)
        {
            var outlierRiskWeight = deploymentProfile == "home" ? 10 : 6;
            riskScore += outlierRiskWeight;
            signals.Add("Signal significantly stronger than historical baseline - possible rogue AP placed closer to device");
        }

        riskScore = Math.Clamp(riskScore, 0, 100);

        var riskLevel = riskScore switch
        {
            >= 80 => RiskLevel.Critical,
            >= 60 => RiskLevel.High,
            >= 35 => RiskLevel.Medium,
            _ => RiskLevel.Low
        };

        if (signals.Count == 0)
        {
            signals.Add("No anomaly signal detected");
        }

        return new NetworkAssessment(
            connectedNetwork,
            riskLevel,
            isTrusted,
            riskScore,
            signals,
            $"Risk assessed as {riskLevel} with score {riskScore}.");
    }

    private static string NormalizeProfile(string? profile)
    {
        return string.IsNullOrWhiteSpace(profile)
            ? "home"
            : profile.Trim().ToLowerInvariant();
    }

    private static int GetSameSsidTolerance(string profile)
    {
        return profile switch
        {
            "enterprise" => 16,
            "campus" => 24,
            _ => 3
        };
    }

    private static string? ExtractOui(string? bssid)
    {
        if (string.IsNullOrWhiteSpace(bssid))
        {
            return null;
        }

        var parts = bssid.Split(':', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length < 3)
        {
            return null;
        }

        return $"{parts[0]}:{parts[1]}:{parts[2]}".ToUpperInvariant();
    }

    private static bool IsOpenSecurity(string? securityProtocol)
    {
        if (string.IsNullOrWhiteSpace(securityProtocol))
        {
            return false;
        }

        var normalized = securityProtocol.Trim();
        return normalized.Contains("open", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("none", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("unsecured", StringComparison.OrdinalIgnoreCase)
            || normalized.Contains("unauthenticated", StringComparison.OrdinalIgnoreCase);
    }

    private static string? NormalizeSecurity(string? securityProtocol)
    {
        if (string.IsNullOrWhiteSpace(securityProtocol))
        {
            return null;
        }

        var normalized = securityProtocol.Trim();
        if (IsOpenSecurity(normalized))
        {
            return "open";
        }

        var separatorIndex = normalized.IndexOf('/');
        if (separatorIndex > 0)
        {
            normalized = normalized[..separatorIndex];
        }

        return normalized.Trim().ToLowerInvariant();
    }

    private (bool IsOutlier, int Mean, int Current) CheckSignalOutlier(AccessPointSnapshot snapshot)
    {
        if (snapshot.RecentSignalSamples is null || snapshot.RecentSignalSamples.Count < 5)
        {
            return (IsOutlier: false, Mean: 0, Current: snapshot.SignalStrength);
        }

        var samples = snapshot.RecentSignalSamples.ToArray();
        if (samples.Length < 5)
        {
            return (IsOutlier: false, Mean: 0, Current: snapshot.SignalStrength);
        }

        var current = samples[^1];
        var history = samples.Take(samples.Length - 1).ToArray();
        if (history.Length < 4)
        {
            return (IsOutlier: false, Mean: 0, Current: snapshot.SignalStrength);
        }

        var meanValue = history.Average();
        var variance = history.Select(sample => Math.Pow(sample - meanValue, 2)).Average();
        _ = Math.Sqrt(variance);
        var mean = (int)Math.Round(meanValue);
        var isOutlier = current > meanValue + 15;

        return (IsOutlier: isOutlier, Mean: mean, Current: current);
    }
}