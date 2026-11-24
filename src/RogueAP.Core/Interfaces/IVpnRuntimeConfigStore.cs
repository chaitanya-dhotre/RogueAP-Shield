using RogueAP.Core.Models;

namespace RogueAP.Core.Interfaces;

public interface IVpnRuntimeConfigStore
{
    VpnRuntimeConfig GetCurrent();

    void Update(VpnRuntimeConfigUpdate update);

    void SetAutoConnectSuppressedUntil(DateTimeOffset? utcTimestamp);

    bool IsAutoConnectSuppressed(DateTimeOffset nowUtc);

    // FIX 3: Manual block suppression (prevents auto-block after user unblock)
    void SuppressBlockingUntilNetworkChange(string bssid);

    bool IsBlockingSuppressed(string currentBssid);

    void ClearBlockingSuppression();
}