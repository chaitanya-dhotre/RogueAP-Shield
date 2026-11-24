using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using RogueAP.Core.Interfaces;
using RogueAP.Core.Models;
using RogueAP.Core.Options;

namespace RogueAP.Infrastructure.Services;

public sealed class ChainedAuditLogger : IAuditLogger
{
    private enum LoadResult { Success, FileNotFound, Tampered }

    private const string FileName = "audit-log.secure.json";
    private const string GenesisHash = "GENESIS";
    private const int MaxEntries = 10000;

    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly List<(string action, string category, string? detail, string? actorContext, DateTimeOffset ts)> _pendingEntries = new();
    private bool _dekReady = false;
    private readonly ILogger<ChainedAuditLogger> _logger;
    private readonly SecureFileProtector _secureFileProtector;
    private readonly string _filePath;

    public ChainedAuditLogger(
        ILogger<ChainedAuditLogger> logger,
        SecureFileProtector secureFileProtector,
        IOptions<SecureStorageOptions> options)
    {
        _logger = logger;
        _secureFileProtector = secureFileProtector;
        var dataDirectory = ResolveDataDirectory(options.Value.DataDirectory);
        Directory.CreateDirectory(dataDirectory);
        _filePath = Path.Combine(dataDirectory, FileName);
    }

    public async Task LogAsync(
        string action,
        string category,
        string? detail = null,
        string? actorContext = null,
        CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct);
        try
        {
            // Try to write — if DEK not ready, queue
            try
            {
                await WriteEntryAsync(action, category, detail, actorContext, ct);
                _dekReady = true;

                // Flush any pending entries
                if (_pendingEntries.Count > 0)
                {
                    var pending = _pendingEntries.ToList();
                    _pendingEntries.Clear();
                    foreach (var p in pending)
                    {
                        await WriteEntryAsync(p.action, p.category, p.detail, p.actorContext, ct);
                    }
                }
            }
            catch (Exception ex)
                when (!_dekReady)
            {
                // DEK not ready yet — queue for later
                _pendingEntries.Add((
                    action, category,
                    detail, actorContext,
                    DateTimeOffset.UtcNow));
                _logger.LogDebug(ex,
                    "Audit entry queued " +
                    "(DEK not ready): {Action}",
                    action);
            }
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private async Task WriteEntryAsync(
        string action,
        string category,
        string? detail,
        string? actorContext,
        CancellationToken ct)
    {
        var (entries, _) = LoadEntries();

        var previousHash = entries.Count > 0
            ? entries[^1].EntryHash
            : GenesisHash;

        var sequence = entries.Count > 0
            ? entries[^1].Sequence + 1
            : 1;

        var timestamp = DateTimeOffset.UtcNow;

        var entryHash = AuditLogEntry.ComputeHash(
            sequence, timestamp, action, category, detail, actorContext, previousHash);

        var entry = new AuditLogEntry
        {
            Sequence = sequence,
            Timestamp = timestamp,
            Action = action,
            Category = category,
            Detail = detail,
            ActorContext = actorContext,
            PreviousEntryHash = previousHash,
            EntryHash = entryHash
        };

        entries.Add(entry);

        if (entries.Count > MaxEntries)
        {
            var rotatedCount = entries.Count - MaxEntries + 1;
            entries.RemoveRange(0, rotatedCount);

            var rotationTimestamp = DateTimeOffset.UtcNow;
            var rotationPreviousHash = entries.Count > 0 ? entries[^1].EntryHash : GenesisHash;
            var rotationSequence = entries.Count > 0 ? entries[^1].Sequence + 1 : 1;
            var rotationHash = AuditLogEntry.ComputeHash(
                rotationSequence, rotationTimestamp, "LOG_ROTATED", AuditCategories.System,
                $"Rotated {rotatedCount} oldest entries", null, rotationPreviousHash);

            entries.Add(new AuditLogEntry
            {
                Sequence = rotationSequence,
                Timestamp = rotationTimestamp,
                Action = "LOG_ROTATED",
                Category = AuditCategories.System,
                Detail = $"Rotated {rotatedCount} oldest entries",
                ActorContext = null,
                PreviousEntryHash = rotationPreviousHash,
                EntryHash = rotationHash
            });
        }

        SaveEntries(entries);
    }

    public async Task FlushPendingEntries(CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct);
        try
        {
            if (_pendingEntries.Count == 0 || !_dekReady)
                return;

            var pending = _pendingEntries.ToList();
            _pendingEntries.Clear();
            foreach (var p in pending)
            {
                await WriteEntryAsync(p.action, p.category, p.detail, p.actorContext, ct);
            }
            _logger.LogInformation("Flushed {Count} pending audit entries", pending.Count);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<IReadOnlyList<AuditLogEntry>> GetRecentAsync(
        int count = 100,
        CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct);
        try
        {
            var (entries, loadResult) = LoadEntries();
            if (loadResult == LoadResult.Tampered)
                return [];
            return entries
                .OrderByDescending(e => e.Sequence)
                .Take(count)
                .ToList();
        }
        finally
        {
            _writeLock.Release();
        }
    }

    public async Task<AuditLogChainStatus> VerifyChainIntegrityAsync(CancellationToken ct = default)
    {
        await _writeLock.WaitAsync(ct);
        try
        {
            var (entries, loadResult) = LoadEntries();

            if (loadResult == LoadResult.Tampered)
            {
                return new AuditLogChainStatus(
                    IsIntact: false,
                    TotalEntries: 0,
                    FirstBrokenAtSequence: null,
                    Message: "Audit log file is corrupted or has been tampered with. Decryption failed.");
            }

            if (loadResult == LoadResult.FileNotFound || entries.Count == 0)
            {
                return new AuditLogChainStatus(
                    IsIntact: true,
                    TotalEntries: 0,
                    FirstBrokenAtSequence: null,
                    Message: "Audit log is empty.");
            }

            var first = entries[0];
            var expectedFirstHash = AuditLogEntry.ComputeHash(
                first.Sequence, first.Timestamp, first.Action, first.Category,
                first.Detail, first.ActorContext, first.PreviousEntryHash);

            if (!string.Equals(first.EntryHash, expectedFirstHash, StringComparison.OrdinalIgnoreCase))
            {
                return new AuditLogChainStatus(
                    IsIntact: false,
                    TotalEntries: entries.Count,
                    FirstBrokenAtSequence: first.Sequence,
                    Message: $"Entry hash mismatch at sequence {first.Sequence}.");
            }

            for (var i = 1; i < entries.Count; i++)
            {
                var current = entries[i];
                var previous = entries[i - 1];

                if (!string.Equals(current.PreviousEntryHash, previous.EntryHash, StringComparison.OrdinalIgnoreCase))
                {
                    return new AuditLogChainStatus(
                        IsIntact: false,
                        TotalEntries: entries.Count,
                        FirstBrokenAtSequence: current.Sequence,
                        Message: $"Chain link broken at sequence {current.Sequence}: PreviousEntryHash does not match prior entry.");
                }

                var expectedHash = AuditLogEntry.ComputeHash(
                    current.Sequence, current.Timestamp, current.Action, current.Category,
                    current.Detail, current.ActorContext, current.PreviousEntryHash);

                if (!string.Equals(current.EntryHash, expectedHash, StringComparison.OrdinalIgnoreCase))
                {
                    return new AuditLogChainStatus(
                        IsIntact: false,
                        TotalEntries: entries.Count,
                        FirstBrokenAtSequence: current.Sequence,
                        Message: $"Entry hash mismatch at sequence {current.Sequence}.");
                }
            }

            return new AuditLogChainStatus(
                IsIntact: true,
                TotalEntries: entries.Count,
                FirstBrokenAtSequence: null,
                Message: $"Chain integrity verified for {entries.Count} entries.");
        }
        finally
        {
            _writeLock.Release();
        }
    }

    private (List<AuditLogEntry> Entries, LoadResult Result) LoadEntries()
    {
        try
        {
            if (!File.Exists(_filePath))
                return ([], LoadResult.FileNotFound);

            var payloadText = File.ReadAllText(_filePath);
            var payload = JsonSerializer.Deserialize<SecurePayload>(payloadText);

            if (payload is null
                || !_secureFileProtector.TryUnprotect(payload, out var plainText, out _)
                || string.IsNullOrWhiteSpace(plainText))
            {
                _logger.LogWarning("Audit log file failed integrity check — file may be tampered");
                return ([], LoadResult.Tampered);
            }

            var entries = JsonSerializer.Deserialize<List<AuditLogEntry>>(plainText) ?? [];
            return (entries, LoadResult.Success);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Audit log read failed — possible corruption or tampering");
            return ([], LoadResult.Tampered);
        }
    }

    private void SaveEntries(List<AuditLogEntry> entries)
    {
        var plain = JsonSerializer.Serialize(entries);
        var payload = _secureFileProtector.ProtectWithDek(plain);
        var text = JsonSerializer.Serialize(payload);
        File.WriteAllText(_filePath, text);
    }

    private static string ResolveDataDirectory(string configuredDirectory)
    {
        if (!string.IsNullOrWhiteSpace(configuredDirectory))
        {
            return configuredDirectory;
        }

        if (OperatingSystem.IsWindows())
        {
            var common = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            return Path.Combine(common, "RogueAP");
        }

        return Path.Combine(AppContext.BaseDirectory, "data");
    }
}
