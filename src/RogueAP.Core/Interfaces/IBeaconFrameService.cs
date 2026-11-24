using RogueAP.Core.Models;

namespace RogueAP.Core.Interfaces;

public interface IBeaconFrameService
{
    Task StartAsync(CancellationToken cancellationToken);
    Task StopAsync(CancellationToken cancellationToken);
    BeaconFingerprint? GetLatestFingerprint(string bssid);
    IReadOnlyDictionary<string, BeaconFingerprint> GetAllFingerprints();
    void ScheduleRescan(TimeSpan delay);
}
