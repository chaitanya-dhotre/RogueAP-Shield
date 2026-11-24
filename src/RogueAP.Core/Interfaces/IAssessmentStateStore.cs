using RogueAP.Core.Models;

namespace RogueAP.Core.Interfaces;

public interface IAssessmentStateStore
{
    void Update(AssessmentSnapshot snapshot);

    AssessmentSnapshot? GetLatest();

    void RecordHeartbeat();

    bool IsServiceResponsive(int maxAgeSeconds = 60);

    // FIX 1: Track whether user manually connected VPN
    void SetVpnUserConnected(bool value);
    bool GetVpnUserConnected();
}