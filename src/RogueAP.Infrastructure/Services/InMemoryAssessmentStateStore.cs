using RogueAP.Core.Interfaces;
using RogueAP.Core.Models;

namespace RogueAP.Infrastructure.Services;

public sealed class InMemoryAssessmentStateStore : IAssessmentStateStore
{
    private readonly object _sync = new();
    private AssessmentSnapshot? _latest;
    private DateTimeOffset _lastHeartbeat = DateTimeOffset.UtcNow;
    private bool _vpnUserConnected = false;

    public void Update(AssessmentSnapshot snapshot)
    {
        lock (_sync)
        {
            _latest = snapshot;
        }
    }

    public AssessmentSnapshot? GetLatest()
    {
        lock (_sync)
        {
            return _latest;
        }
    }

    public void RecordHeartbeat()
        => _lastHeartbeat = DateTimeOffset.UtcNow;

    public bool IsServiceResponsive(int maxAgeSeconds = 60)
        => (DateTimeOffset.UtcNow - _lastHeartbeat)
            .TotalSeconds <= maxAgeSeconds;

    // FIX 1: Track whether user manually connected VPN
    public void SetVpnUserConnected(bool value)
        => _vpnUserConnected = value;

    public bool GetVpnUserConnected()
        => _vpnUserConnected;
}