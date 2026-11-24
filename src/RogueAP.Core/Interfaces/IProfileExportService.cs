namespace RogueAP.Core.Interfaces;

public interface IProfileExportService
{
    Task<byte[]> ExportAsync(
        string masterKey,
        string description,
        CancellationToken ct);

    Task<RapfImportPreview> PreviewAsync(
        byte[] rapfBytes,
        string masterKey,
        CancellationToken ct);

    Task<RapfImportResult> ImportAsync(
        byte[] rapfBytes,
        string masterKey,
        bool mergeMode,
        CancellationToken ct);
}

public sealed record RapfImportPreview(
    string FormatVersion,
    DateTimeOffset ExportedAt,
    string ExportedFromProfile,
    string Description,
    int TrustedNetworkCount,
    int NetworkProfileCount,
    bool ContentHashValid);

public sealed record RapfImportResult(
    bool Success,
    int TrustedNetworksImported,
    int TrustedNetworksSkipped,
    int NetworkProfilesImported,
    string Message);
