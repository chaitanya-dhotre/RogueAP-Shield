using Microsoft.Extensions.Options;
using RogueAP.Core.Enums;
using RogueAP.Core.Interfaces;
using RogueAP.Core.Models;
using RogueAP.Core.Options;
using RogueAP.Infrastructure.Services;
using System.Net.NetworkInformation;

namespace RogueAP.Service;

public sealed class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly IWifiScanner _wifiScanner;
    private readonly IRiskAnalyzer _riskAnalyzer;
    private readonly IPolicyEngine _policyEngine;
    private readonly IVpnIntegrationService _vpnIntegrationService;
    private readonly INotificationService _notificationService;
    private readonly IEnforcementController _enforcementController;
    private readonly ITrustedNetworkRepository _trustedNetworkRepository;
    private readonly IAssessmentStateStore _assessmentStateStore;
    private readonly IVpnRuntimeConfigStore _vpnRuntimeConfigStore;
    private readonly IBeaconFrameService _beaconFrameService;
    private readonly INetworkLearningService _learningService;
    private readonly IProtectionRuntimeConfigStore _protectionConfigStore;
    private readonly IAuditLogger _auditLogger;
    private readonly WindowsEventLogService _eventLog;
    private readonly ProcessIntegrityService _integrityService;
    private readonly ProtectionOptions _options;
    private RiskLevel? _previousRiskLevel;
    private volatile bool _networkChangedFlag = false;
    private bool _wasUnresponsive = false;
    private string? _lastConnectedBssid = null;
    private bool _vpnAutoConnected = false;
    private bool _vpnUserConnected = false;

    private void OnNetworkChanged(object? sender, EventArgs e)
    {
        _networkChangedFlag = true;
        _vpnRuntimeConfigStore.ClearBlockingSuppression();
        _logger.LogDebug(
            "Network address change detected — " +
            "triggering immediate scan, clearing block suppression");

        try
        {
            _eventLog.WriteSecurityEvent(
                $"Network change detected at " +
                $"{DateTimeOffset.UtcNow:HH:mm:ss}. " +
                $"Immediate protection scan triggered.",
                System.Diagnostics.EventLogEntryType.Information,
                eventId: 1010);
        }
        catch { }
    }

    private void OnNetworkAvailabilityChanged(object? sender, NetworkAvailabilityEventArgs e)
    {
        _networkChangedFlag = true;
        _logger.LogDebug(
            "Network availability changed: {Available}",
            e.IsAvailable);

        try
        {
            _eventLog.WriteSecurityEvent(
                $"Network availability changed: " +
                $"{(e.IsAvailable ? "Available" : "Unavailable")} " +
                $"at {DateTimeOffset.UtcNow:HH:mm:ss}.",
                System.Diagnostics.EventLogEntryType.Information,
                eventId: 1010);
        }
        catch { }
    }

    public Worker(
        ILogger<Worker> logger,
        IWifiScanner wifiScanner,
        IRiskAnalyzer riskAnalyzer,
        IPolicyEngine policyEngine,
        IVpnIntegrationService vpnIntegrationService,
        INotificationService notificationService,
        IEnforcementController enforcementController,
        ITrustedNetworkRepository trustedNetworkRepository,
        IAssessmentStateStore assessmentStateStore,
        IVpnRuntimeConfigStore vpnRuntimeConfigStore,
        IBeaconFrameService beaconFrameService,
        INetworkLearningService learningService,
        IProtectionRuntimeConfigStore protectionConfigStore,
        IAuditLogger auditLogger,
        WindowsEventLogService eventLogService,
        ProcessIntegrityService integrityService,
        IOptions<ProtectionOptions> options)
    {
        _logger = logger;
        _wifiScanner = wifiScanner;
        _riskAnalyzer = riskAnalyzer;
        _policyEngine = policyEngine;
        _vpnIntegrationService = vpnIntegrationService;
        _notificationService = notificationService;
        _enforcementController = enforcementController;
        _trustedNetworkRepository = trustedNetworkRepository;
        _assessmentStateStore = assessmentStateStore;
        _vpnRuntimeConfigStore = vpnRuntimeConfigStore;
        _beaconFrameService = beaconFrameService;
        _learningService = learningService;
        _protectionConfigStore = protectionConfigStore;
        _auditLogger = auditLogger;
        _eventLog = eventLogService;
        _integrityService = integrityService;
        _options = options.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Integrity check — verify binary hasn't been tampered
        if (!_integrityService.VerifyAndUpdateIntegrity())
        {
            _logger.LogCritical(
                "Service binary integrity check FAILED. " +
                "Refusing to start protection loop. " +
                "Please reinstall RogueAP Shield.");

            // Write to Windows Event Log
            _eventLog.WriteSecurityEvent(
                "CRITICAL: RogueAP Shield service binary " +
                "integrity check failed. " +
                "The executable may have been tampered with. " +
                "Service startup aborted.",
                System.Diagnostics.EventLogEntryType.Error,
                eventId: 9001);

            return; // abort the protection loop
        }

        _logger.LogInformation("RogueAP protection loop started.");

        await _auditLogger.LogAsync(
            AuditActions.AppStarted,
            AuditCategories.System,
            "Protection loop started",
            ct: stoppingToken);

        _eventLog.WriteAppStarted();

        await _beaconFrameService.StartAsync(stoppingToken);

        // Subscribe to network change events for instant detection
        NetworkChange.NetworkAddressChanged += OnNetworkChanged;
        NetworkChange.NetworkAvailabilityChanged += OnNetworkAvailabilityChanged;

        try
        {
            var startupStatus = await _enforcementController.GetStatusAsync(stoppingToken);
            if (startupStatus.IsBlockingActive)
            {
                _logger.LogWarning(
                    "Startup: persistent firewall block detected from previous session. " +
                    "Protection maintained until risk clears.");
                await _notificationService.PublishAsync(
                    PolicyAction.AlertCritical,
                    "Protection active from previous session",
                    "RogueAP block persisted from previous session — internet remains blocked until risk clears.",
                    stoppingToken);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Unable to check enforcement status at startup.");
        }

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ExecuteProtectionCycleAsync(stoppingToken);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception exception)
            {
                _logger.LogError(exception, "Protection cycle failed unexpectedly.");
            }

            // If a network change was detected, scan immediately
            // Otherwise wait the normal interval
            if (_networkChangedFlag)
            {
                _networkChangedFlag = false;
                _logger.LogInformation(
                    "Network change detected — " +
                    "running immediate protection cycle");
                await Task.Delay(
                    TimeSpan.FromSeconds(2),
                    stoppingToken);
            }
            else
            {
                await Task.Delay(
                    TimeSpan.FromSeconds(
                        Math.Max(10, _options.ScanIntervalSeconds)),
                    stoppingToken);
            }
        }
    }

    private async Task ExecuteProtectionCycleAsync(CancellationToken cancellationToken)
    {
        _assessmentStateStore.RecordHeartbeat();

        if (_wasUnresponsive)
        {
            _wasUnresponsive = false;
            try
            {
                _eventLog.WriteSecurityEvent(
                    "Protection service heartbeat " +
                    "recovered after unresponsive period.",
                    System.Diagnostics.EventLogEntryType.Information,
                    eventId: 1011);
            }
            catch { }
        }

        var nearby = await _wifiScanner.ScanNearbyAsync(cancellationToken);
        var connected = await _wifiScanner.GetConnectedNetworkAsync(cancellationToken);
        var trustedNetworks = await _trustedNetworkRepository.GetAllAsync(cancellationToken);

        if (connected is not null)
        {
            var existingProfile = await _learningService.GetProfileAsync(connected.Ssid, cancellationToken);
            var trustedBaselines = trustedNetworks
                .Where(t => string.Equals(t.Ssid, connected.Ssid, StringComparison.OrdinalIgnoreCase))
                .ToArray();

            if (existingProfile is null && trustedBaselines.Length == 0)
            {
                var deploymentProfile = _protectionConfigStore.GetDeploymentProfile() ?? "Home";
                await _learningService.StartLearningAsync(connected.Ssid, deploymentProfile, cancellationToken);
                _logger.LogInformation("Auto-learning started for new network: {Ssid}", connected.Ssid);
            }

            await _learningService.ObserveAsync(connected.Ssid, connected, nearby, cancellationToken);

            if (_learningService.IsLearning(connected.Ssid))
            {
                _logger.LogDebug("Learning mode active for {Ssid} — enforcement suppressed", connected.Ssid);

                var learningDurationHours = existingProfile?.LearningDurationHours ?? 72;
                var learningAssessment = new NetworkAssessment(
                    ConnectedNetwork: connected,
                    RiskLevel: RiskLevel.Low,
                    IsTrustedNetwork: false,
                    RiskScore: 0,
                    Signals: [$"Learning mode active — monitoring network for {learningDurationHours}h before active detection"],
                    Summary: $"Auto-learning in progress for '{connected.Ssid}'. The app is observing network characteristics and will begin active detection after the learning period completes.");

                var learningVpnStatus = await _vpnIntegrationService.GetStatusAsync(cancellationToken);
                _assessmentStateStore.Update(new AssessmentSnapshot(learningAssessment, learningVpnStatus, nearby, DateTimeOffset.UtcNow));
                return;
            }
        }

        var assessment = await _riskAnalyzer.Analyze(connected, nearby, trustedNetworks);
        var vpnStatus = await _vpnIntegrationService.GetStatusAsync(cancellationToken);
        _assessmentStateStore.Update(new AssessmentSnapshot(assessment, vpnStatus, nearby, DateTimeOffset.UtcNow));
        var decision = _policyEngine.Decide(assessment, vpnStatus);
        var autoConnectSuppressed = _vpnRuntimeConfigStore.IsAutoConnectSuppressed(DateTimeOffset.UtcNow);

        if (_previousRiskLevel != assessment.RiskLevel)
        {
            _previousRiskLevel = assessment.RiskLevel;
            await _auditLogger.LogAsync(
                $"RISK_{assessment.RiskLevel.ToString().ToUpperInvariant()}",
                AuditCategories.Risk,
                $"Score: {assessment.RiskScore} — {assessment.Summary}",
                connected?.Ssid,
                cancellationToken);
        }

        _logger.LogInformation(
            "Assessment: Risk={RiskLevel}, Score={RiskScore}, Trusted={Trusted}, VpnConnected={VpnConnected}, Summary={Summary}",
            assessment.RiskLevel,
            assessment.RiskScore,
            assessment.IsTrustedNetwork,
            vpnStatus.IsConnected,
            assessment.Summary);

        // FIX 1: Sync VPN user flag from state store at start of cycle
        _vpnUserConnected = _assessmentStateStore.GetVpnUserConnected();

        // FIX 1: Network change detection with proper VPN state handling
        var bssidChanged =
            _lastConnectedBssid != null &&
            connected != null &&
            _lastConnectedBssid != connected.Bssid;

        if (bssidChanged)
        {
            _logger.LogInformation(
                "Network changed: {Old} → {New}",
                _lastConnectedBssid, connected?.Bssid);

            // Clear block suppression on network change
            _vpnRuntimeConfigStore.ClearBlockingSuppression();

            // If user had VPN on, try to maintain it
            if (_vpnUserConnected)
            {
                var currentVpnStatus = await
                    _vpnIntegrationService
                        .GetStatusAsync(cancellationToken);

                if (!currentVpnStatus.IsConnected)
                {
                    _logger.LogInformation(
                        "User VPN dropped after network " +
                        "change. Reconnecting...");

                    await _auditLogger.LogAsync(
                        "VPN_RECONNECT_AFTER_NETWORK_CHANGE",
                        "VPN",
                        $"Network changed to " +
                        $"{connected?.Bssid}. " +
                        $"Maintaining user VPN connection.",
                        connected?.Ssid,
                        cancellationToken);

                    await Task.Delay(
                        TimeSpan.FromSeconds(3),
                        cancellationToken);

                    var reconnected = await
                        _vpnIntegrationService
                            .TryConnectAsync(cancellationToken);

                    await _auditLogger.LogAsync(
                        reconnected
                            ? "VPN_RECONNECT_SUCCESS"
                            : "VPN_RECONNECT_FAILED",
                        "VPN",
                        reconnected
                            ? "User VPN reconnected after " +
                              "network change"
                            : "User VPN reconnect failed " +
                              "after network change",
                        connected?.Ssid,
                        cancellationToken);
                }
            }
            else if (_vpnAutoConnected)
            {
                // App had auto-connected VPN on previous
                // network. Reset auto flag since we are
                // on a new network — risk will be
                // re-evaluated below
                _vpnAutoConnected = false;

                var currentVpnStatus = await
                    _vpnIntegrationService
                        .GetStatusAsync(cancellationToken);

                if (currentVpnStatus.IsConnected)
                {
                    // Disconnect auto-VPN — let risk
                    // re-evaluation decide if it should
                    // reconnect on new network
                    await _vpnIntegrationService
                        .TryDisconnectAsync(cancellationToken);
                }
            }
        }

        if (connected != null)
            _lastConnectedBssid = connected.Bssid;

        foreach (var action in decision.ImmediateActions)
        {
            if (action == PolicyAction.AttemptVpnConnect)
            {
                // FIX 1: Inline VPN auto-connect handling with full context
                if (autoConnectSuppressed)
                {
                    _logger.LogInformation("Skipping VPN auto-connect because manual disconnect suppression is active.");
                    continue;
                }

                if (_vpnRuntimeConfigStore.IsAutoConnectSuppressed(DateTimeOffset.UtcNow))
                {
                    _logger.LogDebug("VPN auto-connect suppressed");
                    continue;
                }

                // Do not auto-connect if user explicitly turned VPN off recently
                if (_vpnUserConnected == false && _vpnAutoConnected == false)
                {
                    await _auditLogger.LogAsync(
                        "VPN_AUTO_CONNECT_ATTEMPTED",
                        "VPN",
                        $"App attempting VPN connect — " +
                        $"{assessment.RiskLevel} risk " +
                        $"on '{connected?.Ssid}'",
                        connected?.Ssid,
                        cancellationToken);
                }

                var vpnResult = await _vpnIntegrationService.TryConnectAsync(cancellationToken);

                if (vpnResult)
                    _vpnAutoConnected = true;

                await _auditLogger.LogAsync(
                    vpnResult
                        ? "VPN_AUTO_CONNECT_SUCCESS"
                        : "VPN_AUTO_CONNECT_FAILED",
                    "VPN",
                    vpnResult
                        ? "VPN connected automatically by app"
                        : "Automatic VPN connection failed",
                    connected?.Ssid,
                    cancellationToken);
                continue;
            }

            await HandleActionAsync(action, assessment.Summary, cancellationToken);
        }

        await TryRecoverInternetIfRiskReducedAsync(assessment, vpnStatus, cancellationToken);

        if (decision.BlockIfVpnConnectFails && !autoConnectSuppressed)
        {
            var vpnResult = await _vpnIntegrationService.TryConnectAsync(cancellationToken);

            await _auditLogger.LogAsync(
                vpnResult ? AuditActions.VpnConnected : AuditActions.VpnFailed,
                AuditCategories.Vpn,
                vpnResult ? "VPN connected (block-if-fail path)" : "VPN failed (block-if-fail path)",
                ct: cancellationToken);

            if (!vpnResult)
            {
                // FIX 3: Check if blocking is suppressed for this BSSID
                if (connected != null && _vpnRuntimeConfigStore.IsBlockingSuppressed(connected.Bssid))
                {
                    _logger.LogDebug(
                        "Block suppressed for {Bssid} — user manually unblocked. Skipping auto-block.",
                        connected.Bssid);
                }
                else
                {
                    _eventLog.WriteVpnFailed(connected?.Ssid ?? "unknown");
                    await _enforcementController.BlockInternetAsync(
                        "VPN connection failed during high-risk untrusted network state.",
                        cancellationToken);

                await _auditLogger.LogAsync(
                    AuditActions.BlockEngaged,
                    AuditCategories.Enforcement,
                    "VPN connection failed during high-risk untrusted network state.",
                    connected?.Ssid,
                    cancellationToken);

                await _notificationService.PublishAsync(
                    PolicyAction.AlertCritical,
                    "Connection blocked",
                    "VPN connection failed in high-risk scenario. Internet access has been blocked.",
                    cancellationToken);
                }
            }
        }
        else if (decision.BlockIfVpnConnectFails && autoConnectSuppressed)
        {
            _logger.LogInformation("VPN auto-connect suppression is active. Skipping connect-and-block fallback.");
        }

        // FIX 1: Auto-disconnect VPN when risk drops on trusted network
        var vpnNowStatus = await _vpnIntegrationService.GetStatusAsync(cancellationToken);

        if (_vpnAutoConnected &&
            vpnNowStatus.IsConnected &&
            assessment.RiskLevel <= RiskLevel.Low &&
            assessment.IsTrustedNetwork)
        {
            // Risk is gone — auto-disconnect VPN
            // that was auto-connected
            // But only if user didn't turn it on
            _logger.LogInformation(
                "Risk cleared on trusted network. " +
                "Auto-disconnecting VPN.");

            await _vpnIntegrationService.TryDisconnectAsync(cancellationToken);
            _vpnAutoConnected = false;

            await _auditLogger.LogAsync(
                "VPN_AUTO_DISCONNECTED",
                "VPN",
                "VPN auto-disconnected — connected to " +
                "trusted network with low risk",
                connected?.Ssid,
                cancellationToken);
        }
    }

    private async Task TryRecoverInternetIfRiskReducedAsync(NetworkAssessment assessment, VpnStatus vpnStatus, CancellationToken cancellationToken)
    {
        var enforcementStatus = await _enforcementController.GetStatusAsync(cancellationToken);
        if (!enforcementStatus.IsBlockingActive)
        {
            return;
        }

        var shouldRecoverBecauseRiskDropped = assessment.RiskLevel != RiskLevel.Critical;
        var shouldRecoverBecauseVpnConnected = vpnStatus.IsConnected;
        if (!shouldRecoverBecauseRiskDropped && !shouldRecoverBecauseVpnConnected)
        {
            return;
        }

        var reason = shouldRecoverBecauseVpnConnected
            ? $"VPN connected during {assessment.RiskLevel} state. Reverting protective block."
            : $"Risk reduced to {assessment.RiskLevel}. Reverting protective block.";

        await _enforcementController.UnblockInternetAsync(
            reason,
            cancellationToken);

        await _auditLogger.LogAsync(
            AuditActions.BlockReleased,
            AuditCategories.Enforcement,
            reason,
            assessment.ConnectedNetwork?.Ssid,
            cancellationToken);

        _eventLog.WriteBlockReleased();

        await _notificationService.PublishAsync(
            PolicyAction.AlertInfo,
            "Internet block reverted",
            shouldRecoverBecauseVpnConnected
                ? $"VPN is connected. Internet block has been reverted during {assessment.RiskLevel} state."
                : $"Risk reduced to {assessment.RiskLevel}. Internet block has been reverted.",
            cancellationToken);
    }

    private async Task HandleActionAsync(PolicyAction action, string summary, CancellationToken cancellationToken)
    {
        switch (action)
        {
            case PolicyAction.AlertInfo:
                await _notificationService.PublishAsync(action, "Network status", summary, cancellationToken);
                break;

            case PolicyAction.AlertHighPriority:
                await _notificationService.PublishAsync(action, "Suspicious network detected", summary, cancellationToken);
                break;

            case PolicyAction.AlertCritical:
                await _notificationService.PublishAsync(action, "Critical network threat", summary, cancellationToken);
                break;

            case PolicyAction.AttemptVpnConnect:
                // FIX 1: Now handled inline in ExecuteProtectionCycleAsync
                // to have access to connected/assessment variables
                break;

            case PolicyAction.BlockInternet:
                // FIX 3: Check if blocking is suppressed for this BSSID
                var connectedForBlock = await _wifiScanner.GetConnectedNetworkAsync(cancellationToken);
                if (connectedForBlock != null && _vpnRuntimeConfigStore.IsBlockingSuppressed(connectedForBlock.Bssid))
                {
                    _logger.LogDebug(
                        "Block suppressed for {Bssid} — user manually unblocked. Skipping policy block.",
                        connectedForBlock.Bssid);
                    break;
                }
                await _enforcementController.BlockInternetAsync("Critical network policy triggered", cancellationToken);
                await _auditLogger.LogAsync(
                    AuditActions.BlockEngaged,
                    AuditCategories.Enforcement,
                    "Critical network policy triggered",
                    ct: cancellationToken);
                _eventLog.WriteBlockEngaged("Critical network policy triggered");
                break;

            case PolicyAction.UnblockInternet:
                await _enforcementController.UnblockInternetAsync("Policy recovery action", cancellationToken);
                await _auditLogger.LogAsync(
                    AuditActions.BlockReleased,
                    AuditCategories.Enforcement,
                    "Policy recovery action",
                    ct: cancellationToken);
                break;

            case PolicyAction.None:
            default:
                break;
        }
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        NetworkChange.NetworkAddressChanged -= OnNetworkChanged;
        NetworkChange.NetworkAvailabilityChanged -= OnNetworkAvailabilityChanged;

        await _beaconFrameService.StopAsync(cancellationToken);

        var enforcementStatus = await _enforcementController.GetStatusAsync(cancellationToken);
        if (enforcementStatus.IsBlockingActive)
        {
            _logger.LogWarning(
                "App shutting down with active internet block. " +
                "Firewall rules will persist to maintain protection.");
        }

        await _auditLogger.LogAsync(
            AuditActions.AppStopped,
            AuditCategories.System,
            ct: cancellationToken);

        _eventLog.WriteAppStopped();

        await base.StopAsync(cancellationToken);
    }
}
