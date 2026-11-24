namespace RogueAP.Infrastructure.Services;

internal sealed record SecurePayload(
    string ProtectedData,
    [property: Obsolete("IntegrityHash is deprecated. AES-GCM authentication tags are used for integrity.", false)]
    string IntegrityHash);