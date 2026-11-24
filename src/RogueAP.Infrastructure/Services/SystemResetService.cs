using Microsoft.Extensions.Options;
using RogueAP.Core.Interfaces;
using RogueAP.Core.Models;
using RogueAP.Core.Options;

namespace RogueAP.Infrastructure.Services;

public sealed class SystemResetService : ISystemResetService
{
    private readonly IMasterKeyGate _masterKeyGate;
    private readonly ITrustedNetworkRepository _trustedNetworkRepository;
    private readonly IVpnRuntimeConfigStore _vpnRuntimeConfigStore;
    private readonly VpnIntegrationOptions _vpnOptions;
    private readonly SecureStorageOptions _storageOptions;

    public SystemResetService(
        IMasterKeyGate masterKeyGate,
        ITrustedNetworkRepository trustedNetworkRepository,
        IVpnRuntimeConfigStore vpnRuntimeConfigStore,
        IOptions<VpnIntegrationOptions> vpnOptions,
        IOptions<SecureStorageOptions> storageOptions)
    {
        _masterKeyGate = masterKeyGate;
        _trustedNetworkRepository = trustedNetworkRepository;
        _vpnRuntimeConfigStore = vpnRuntimeConfigStore;
        _vpnOptions = vpnOptions.Value;
        _storageOptions = storageOptions.Value;
    }

    public async Task ResetAllAsync(CancellationToken cancellationToken)
    {
        await _trustedNetworkRepository.ClearAsync(cancellationToken);
        await _masterKeyGate.ResetAsync(cancellationToken);

        _vpnRuntimeConfigStore.Update(new VpnRuntimeConfigUpdate(
            _vpnOptions.Mode,
            _vpnOptions.WireGuardConnectCommand,
            _vpnOptions.WireGuardDisconnectCommand,
            _vpnOptions.OpenVpnConnectCommand,
            _vpnOptions.OpenVpnDisconnectCommand));

        var dataDirectory = ResolveDataDirectory(_storageOptions.DataDirectory);
        if (Directory.Exists(dataDirectory))
        {
            foreach (var file in Directory.GetFiles(dataDirectory, "*.secure.json", SearchOption.TopDirectoryOnly))
            {
                try
                {
                    File.Delete(file);
                }
                catch
                {
                }
            }
        }
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