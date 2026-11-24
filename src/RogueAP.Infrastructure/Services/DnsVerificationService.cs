using System.Net;

namespace RogueAP.Infrastructure.Services;

public interface IDnsVerificationService
{
    Task<DnsVerificationResult> VerifyAsync(string hostname, string? expectedIp);
}

public sealed record DnsVerificationResult(
    bool Resolved,
    string? ResolvedIp,
    bool MatchesExpected);

public sealed class DnsVerificationService : IDnsVerificationService
{
    public async Task<DnsVerificationResult> VerifyAsync(string hostname, string? expectedIp)
    {
        if (string.IsNullOrWhiteSpace(hostname))
        {
            return new DnsVerificationResult(
                Resolved: false,
                ResolvedIp: null,
                MatchesExpected: false);
        }

        try
        {
            var dnsTask = Dns.GetHostAddressesAsync(hostname);
            var timeoutTask = Task.Delay(2000);

            var completed = await Task.WhenAny(dnsTask, timeoutTask);
            if (!ReferenceEquals(completed, dnsTask))
            {
                return new DnsVerificationResult(
                    Resolved: false,
                    ResolvedIp: null,
                    MatchesExpected: false);
            }

            var addresses = await dnsTask;
            if (addresses is null || addresses.Length == 0)
            {
                return new DnsVerificationResult(
                    Resolved: false,
                    ResolvedIp: null,
                    MatchesExpected: false);
            }

            var resolvedIp = addresses[0].ToString();

            var matchesExpected = string.IsNullOrWhiteSpace(expectedIp)
                ? true
                : IPAddress.TryParse(expectedIp, out var expectedAddress)
                    ? addresses.Any(ip => ip.Equals(expectedAddress))
                    : addresses.Any(ip => string.Equals(ip.ToString(), expectedIp, StringComparison.OrdinalIgnoreCase));

            return new DnsVerificationResult(
                Resolved: true,
                ResolvedIp: resolvedIp,
                MatchesExpected: matchesExpected);
        }
        catch
        {
            return new DnsVerificationResult(
                Resolved: false,
                ResolvedIp: null,
                MatchesExpected: false);
        }
    }
}

