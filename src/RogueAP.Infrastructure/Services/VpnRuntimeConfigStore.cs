using RogueAP.Core.Interfaces;
using RogueAP.Core.Models;
using RogueAP.Core.Options;

namespace RogueAP.Infrastructure.Services;

public sealed class VpnRuntimeConfigStore : IVpnRuntimeConfigStore
{
    private readonly object _sync = new();
    private VpnRuntimeConfig _current;

    public VpnRuntimeConfigStore(VpnIntegrationOptions options)
    {
        _current = new VpnRuntimeConfig(
            options.Mode,
            options.WireGuardConnectCommand,
            options.WireGuardDisconnectCommand,
            options.OpenVpnConnectCommand,
            options.OpenVpnDisconnectCommand,
            null);
    }

    public VpnRuntimeConfig GetCurrent()
    {
        lock (_sync)
        {
            return _current;
        }
    }

    public void Update(VpnRuntimeConfigUpdate update)
    {
        lock (_sync)
        {
            _current = _current with
            {
                Mode = update.Mode ?? _current.Mode,
                WireGuardConnectCommand = update.WireGuardConnectCommand ?? _current.WireGuardConnectCommand,
                WireGuardDisconnectCommand = update.WireGuardDisconnectCommand ?? _current.WireGuardDisconnectCommand,
                OpenVpnConnectCommand = update.OpenVpnConnectCommand ?? _current.OpenVpnConnectCommand,
                OpenVpnDisconnectCommand = update.OpenVpnDisconnectCommand ?? _current.OpenVpnDisconnectCommand,
                AutoConnectSuppressedUntilUtc = update.AutoConnectSuppressedUntilUtc ?? _current.AutoConnectSuppressedUntilUtc
            };
        }
    }

    public void SetAutoConnectSuppressedUntil(DateTimeOffset? utcTimestamp)
    {
        lock (_sync)
        {
            _current = _current with { AutoConnectSuppressedUntilUtc = utcTimestamp };
        }
    }

    public bool IsAutoConnectSuppressed(DateTimeOffset nowUtc)
    {
        lock (_sync)
        {
            return _current.AutoConnectSuppressedUntilUtc is DateTimeOffset until
                && until > nowUtc;
        }
    }

    // FIX 3: Manual block suppression fields
    private bool _blockingSuppressedUntilNetworkChange = false;
    private string? _suppressedForBssid = null;

    public void SuppressBlockingUntilNetworkChange(string bssid)
    {
        lock (_sync)
        {
            _blockingSuppressedUntilNetworkChange = true;
            _suppressedForBssid = bssid;
        }
    }

    public bool IsBlockingSuppressed(string currentBssid)
    {
        lock (_sync)
        {
            if (!_blockingSuppressedUntilNetworkChange)
                return false;

            // If BSSID changed, suppression expires
            if (_suppressedForBssid != currentBssid)
            {
                _blockingSuppressedUntilNetworkChange = false;
                _suppressedForBssid = null;
                return false;
            }
            return true;
        }
    }

    public void ClearBlockingSuppression()
    {
        lock (_sync)
        {
            _blockingSuppressedUntilNetworkChange = false;
            _suppressedForBssid = null;
        }
    }
}