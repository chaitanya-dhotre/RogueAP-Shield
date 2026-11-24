namespace RogueAP.Core.Models;

public sealed record BeaconFingerprint(
    string Bssid,
    string FingerprintHash,
    IReadOnlyDictionary<int, byte[]> RawIEs,
    bool HasQbssLoad,
    bool HasVhtCapabilities,
    bool HasHeCapabilities,
    DateTime CapturedAt);
