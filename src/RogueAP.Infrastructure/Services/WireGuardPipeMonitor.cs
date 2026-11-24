using System.IO.Pipes;
using System.Text;
using Microsoft.Extensions.Logging;
using RogueAP.Core.Models;

namespace RogueAP.Infrastructure.Services;

public sealed class WireGuardPipeMonitor
{
    private readonly ILogger<WireGuardPipeMonitor> _logger;

    public WireGuardPipeMonitor(ILogger<WireGuardPipeMonitor> logger)
    {
        _logger = logger;
    }

    public async Task<WireGuardTunnelState?> QueryTunnelAsync(string tunnelName, CancellationToken ct)
    {
        try
        {
            using var connectCts = new CancellationTokenSource(TimeSpan.FromMilliseconds(2000));
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, connectCts.Token);

            using var pipe = new NamedPipeClientStream(
                ".",
                $"ProtectedPrefix\\Administrators\\WireGuard\\{tunnelName}",
                PipeDirection.InOut,
                PipeOptions.Asynchronous);

            await pipe.ConnectAsync(linkedCts.Token);

            var request = Encoding.UTF8.GetBytes("get=1\n\n");
            await pipe.WriteAsync(request, linkedCts.Token);
            await pipe.FlushAsync(linkedCts.Token);

            using var ms = new MemoryStream();
            var buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = await pipe.ReadAsync(buffer, linkedCts.Token)) > 0)
            {
                ms.Write(buffer, 0, bytesRead);
                if (bytesRead < buffer.Length)
                {
                    break;
                }
            }

            var response = Encoding.UTF8.GetString(ms.ToArray());
            return ParseResponse(tunnelName, response);
        }
        catch (OperationCanceledException)
        {
            _logger.LogDebug("WireGuard pipe query timed out for tunnel '{TunnelName}'.", tunnelName);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "WireGuard pipe not available for tunnel '{TunnelName}'.", tunnelName);
            return null;
        }
    }

    public static string? ExtractTunnelName(string connectCommand)
    {
        if (string.IsNullOrWhiteSpace(connectCommand))
        {
            return null;
        }

        var parts = connectCommand.Split([' ', '"', '\''], StringSplitOptions.RemoveEmptyEntries);
        foreach (var part in parts)
        {
            if (part.EndsWith(".conf", StringComparison.OrdinalIgnoreCase))
            {
                return Path.GetFileNameWithoutExtension(part);
            }
        }

        return null;
    }

    private static WireGuardTunnelState ParseResponse(string tunnelName, string response)
    {
        DateTime? lastHandshake = null;
        ulong rxBytes = 0;
        ulong txBytes = 0;
        string? errorMessage = null;

        foreach (var line in response.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            var sep = line.IndexOf('=');
            if (sep <= 0)
            {
                continue;
            }

            var key = line[..sep].Trim();
            var value = line[(sep + 1)..].Trim();

            switch (key)
            {
                case "last_handshake_time_sec":
                    if (long.TryParse(value, out var unixSec) && unixSec != 0)
                    {
                        lastHandshake = DateTimeOffset.FromUnixTimeSeconds(unixSec).UtcDateTime;
                    }

                    break;

                case "rx_bytes":
                    ulong.TryParse(value, out rxBytes);
                    break;

                case "tx_bytes":
                    ulong.TryParse(value, out txBytes);
                    break;

                case "errno":
                    if (int.TryParse(value, out var errno) && errno != 0)
                    {
                        errorMessage = $"WireGuard pipe errno={errno}";
                    }

                    break;
            }
        }

        var isHandshakeStale = lastHandshake is null
            || (DateTime.UtcNow - lastHandshake.Value).TotalSeconds > 185;

        var isUp = errorMessage is null && lastHandshake is not null;

        return new WireGuardTunnelState(
            TunnelName: tunnelName,
            IsUp: isUp,
            LastHandshake: lastHandshake,
            IsHandshakeStale: isHandshakeStale,
            RxBytes: rxBytes,
            TxBytes: txBytes,
            ErrorMessage: errorMessage);
    }
}
