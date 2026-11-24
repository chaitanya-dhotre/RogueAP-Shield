using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace RogueAP.Infrastructure.Services;

public sealed class ProcessIntegrityService
{
    private readonly ILogger<ProcessIntegrityService> _logger;
    private const string HashFileName = "service.integrity";

    public ProcessIntegrityService(
        ILogger<ProcessIntegrityService> logger)
    {
        _logger = logger;
    }

    public bool VerifyAndUpdateIntegrity()
    {
        try
        {
            var exePath = Environment
                .ProcessPath ?? GetFallbackExePath();

            if (string.IsNullOrEmpty(exePath)
                || !File.Exists(exePath))
            {
                _logger.LogWarning(
                    "Cannot locate service executable " +
                    "for integrity check.");
                return true; // non-fatal, allow startup
            }

            var currentHash = ComputeFileHash(exePath);
            var hashFilePath = Path.Combine(
                GetDataDirectory(), HashFileName);

            if (!File.Exists(hashFilePath))
            {
                // First run — store hash as baseline
                File.WriteAllText(hashFilePath, currentHash);
                _logger.LogInformation(
                    "Process integrity baseline established.");
                return true;
            }

            var storedHash = File.ReadAllText(hashFilePath)
                .Trim();

            if (!string.Equals(
                currentHash, storedHash,
                StringComparison.OrdinalIgnoreCase))
            {
                _logger.LogCritical(
                    "INTEGRITY CHECK FAILED: " +
                    "Service binary hash mismatch. " +
                    "Expected: {Stored} " +
                    "Actual: {Current}",
                    storedHash[..16] + "...",
                    currentHash[..16] + "...");
                return false;
            }

            _logger.LogDebug(
                "Process integrity check passed.");
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Process integrity check encountered " +
                "an error — allowing startup.");
            return true; // non-fatal
        }
    }

    public void UpdateHash()
    {
        try
        {
            var exePath = Environment.ProcessPath
                ?? GetFallbackExePath();
            if (string.IsNullOrEmpty(exePath)) return;

            var hash = ComputeFileHash(exePath);
            var hashFilePath = Path.Combine(
                GetDataDirectory(), HashFileName);
            File.WriteAllText(hashFilePath, hash);

            _logger.LogInformation(
                "Process integrity hash updated.");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Failed to update integrity hash.");
        }
    }

    private static string ComputeFileHash(string filePath)
    {
        using var sha256 = SHA256.Create();
        using var stream = File.OpenRead(filePath);
        var hashBytes = sha256.ComputeHash(stream);
        return Convert.ToHexString(hashBytes)
            .ToLowerInvariant();
    }

    private static string GetDataDirectory()
    {
        var dir = OperatingSystem.IsWindows()
            ? Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder
                        .CommonApplicationData),
                "RogueAP")
            : Path.Combine(
                AppContext.BaseDirectory, "data");

        Directory.CreateDirectory(dir);
        return dir;
    }

    private static string GetFallbackExePath()
        => Path.Combine(
            AppContext.BaseDirectory,
            "RogueAP.Service.exe");
}
