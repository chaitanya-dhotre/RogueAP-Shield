using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using RogueAP.Core.Interfaces;
using RogueAP.Core.Options;
using RogueAP.Core.Services;
using RogueAP.Infrastructure.Services;

namespace RogueAP.Infrastructure.DependencyInjection;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddRogueApProtection(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        services.Configure<ProtectionOptions>(configuration.GetSection(ProtectionOptions.SectionName));
        services.Configure<WifiScannerOptions>(configuration.GetSection(WifiScannerOptions.SectionName));
        services.Configure<VpnIntegrationOptions>(configuration.GetSection(VpnIntegrationOptions.SectionName));
        services.Configure<EnforcementOptions>(configuration.GetSection(EnforcementOptions.SectionName));
        services.Configure<SecureStorageOptions>(configuration.GetSection(SecureStorageOptions.SectionName));
        services.Configure<NotificationOptions>(configuration.GetSection(NotificationOptions.SectionName));
        services.Configure<ControlApiOptions>(configuration.GetSection(ControlApiOptions.SectionName));

        services.AddSingleton<IVpnRuntimeConfigStore>(provider =>
        {
            var options = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<VpnIntegrationOptions>>().Value;
            return new VpnRuntimeConfigStore(options);
        });

        services.AddSingleton<IProtectionRuntimeConfigStore>(provider =>
        {
            var options = provider.GetRequiredService<Microsoft.Extensions.Options.IOptions<ProtectionOptions>>().Value;
            return new ProtectionRuntimeConfigStore(options);
        });

        services.AddSingleton<WindowsEventLogService>();
        services.AddSingleton<ProcessIntegrityService>();
        services.AddSingleton<IDekProvider, DekProvider>();
        services.AddSingleton<SecureFileProtector>();
        services.AddSingleton<IPolicyEngine, PolicyEngine>();
        services.AddSingleton<IRiskAnalyzer, HeuristicRiskAnalyzer>();
        services.AddSingleton<DnsResolutionProbe>();
        services.AddSingleton<IWifiScanner, WindowsNetshWifiScanner>();
        services.AddSingleton<IBeaconFrameService, NativeWifiBeaconService>();
        services.AddSingleton<IVpnIntegrationService, CommandVpnIntegrationService>();
        services.AddSingleton<IAssessmentStateStore, InMemoryAssessmentStateStore>();
        services.AddSingleton<ISystemResetService, SystemResetService>();
        services.AddSingleton<INotificationService, WindowsNotificationService>();
        services.AddSingleton<WireGuardPipeMonitor>();
        services.AddSingleton<IEnforcementController, WfpEnforcementController>();
        services.AddSingleton<ITrustedNetworkRepository, PersistentTrustedNetworkRepository>();
        services.AddSingleton<IMasterKeyGate, PersistentMasterKeyGate>();
        services.AddSingleton<INetworkProfileRepository, PersistentNetworkProfileRepository>();
        services.AddSingleton<INetworkLearningService, NetworkLearningService>();
        services.AddSingleton<IAuditLogger, ChainedAuditLogger>();
        services.AddSingleton<IProfileExportService, ProfileExportService>();

        return services;
    }
}