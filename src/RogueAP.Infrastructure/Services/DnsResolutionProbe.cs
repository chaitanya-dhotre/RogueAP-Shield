using System.Net;
using System.Net.Sockets;

namespace RogueAP.Infrastructure.Services;

public sealed class DnsResolutionProbe
{
    public async Task<string?> ResolveAsync(string hostname, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(hostname))
        {
            return null;
        }

        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            cts.CancelAfter(TimeSpan.FromMilliseconds(2000));

            var addresses = await Dns.GetHostAddressesAsync(hostname, cts.Token);
            var firstIpv4 = addresses.FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork);
            return firstIpv4?.ToString();
        }
        catch
        {
            return null;
        }
    }
}

