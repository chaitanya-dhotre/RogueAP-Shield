using RogueAP.Gui.Api;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Microsoft.Toolkit.Uwp.Notifications;
using Windows.UI.Notifications;

namespace RogueAP.Gui;

public partial class MainWindow : Window
{
    private ControlApiClient _apiClient;
    private readonly ObservableCollection<NearbyWifiItem> _nearbyWifiItems = [];
    private readonly DispatcherTimer _dashboardRefreshTimer = new();
    private bool _dashboardRefreshInProgress;
    private List<string> _trustedBssids = new();
    private bool _isBlockingActive;
    private readonly ObservableCollection<TrustedNetworkItem> _trustedNetworkItems = new();
    private bool _skipNextProfilePopulate;
    private Border? _activeNavBorder;
    private TextBlock? _activeNavText;
    private string _setupMasterKey = string.Empty;
    private string _setupRecoveryKey = string.Empty;
    private string _setupSelectedProfile = "";

    private static readonly string PendingPath =
        Path.Combine(
            Environment.GetFolderPath(
                Environment.SpecialFolder.CommonApplicationData),
            "RogueAP",
            "pending-notification.json");

    public MainWindow()
    {
        InitializeComponent();
        _apiClient = new ControlApiClient(ApiBaseUrlTextBox.Text);
        NearbyWifiListBox.ItemsSource = _nearbyWifiItems;
        _dashboardRefreshTimer.Tick += DashboardRefreshTimer_Tick;
        SetDashboardRefreshIntervalFromUi();
        _dashboardRefreshTimer.Start();
    }

    private void EnsureClient()
    {
        _apiClient = new ControlApiClient(ApiBaseUrlTextBox.Text);
    }

    private async Task RefreshDashboardAsync()
    {
        if (_dashboardRefreshInProgress)
        {
            return;
        }

        _dashboardRefreshInProgress = true;
        EnsureClient();

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));

            var healthJson = await _apiClient.GetHealthAsync(cts.Token);
            var watchdogJson = await _apiClient.GetWatchdogHealthAsync(cts.Token);
            var masterJson = await _apiClient.GetMasterKeyStatusAsync(cts.Token);
            var vpnJson = await _apiClient.GetVpnStatusAsync(cts.Token);
            var trustedJson = await _apiClient.GetTrustedNetworksAsync(cts.Token);
            var assessmentJson = await _apiClient.GetAssessmentLatestAsync(cts.Token);
            var connectedJson = await _apiClient.GetConnectedWifiAsync(cts.Token);
            var enforcementJson = await _apiClient.GetEnforcementStatusAsync(cts.Token);
            var vpnConfigJson = await _apiClient.GetVpnConfigAsync(cts.Token);
            var profileJson = await _apiClient.GetProtectionProfileAsync(cts.Token);

            var healthStatus = ExtractSimpleValue(healthJson, "status", fallback: "Unknown");
            DashboardHealthText.Text = healthStatus;
            DashboardHealthText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(
                healthStatus.Equals("ok", StringComparison.OrdinalIgnoreCase) ? "#3B6D11" : "#A32D2D"));

            var watchdogResponsive = ExtractBoolean(watchdogJson, "responsive");
            var vpnConnected = ExtractBoolean(vpnJson, "isConnected");
            var provider = ExtractSimpleValue(vpnJson, "providerName", fallback: "Unknown");

            // FIX 1: Three-state enforcement banner
            if (!watchdogResponsive)
            {
                // Watchdog unresponsive - special state
                SetBannerState(
                    "#FEF2F2", "#FCA5A5",
                    "Service may be unresponsive", "#A32D2D",
                    "The protection service heartbeat has not been detected recently. The service may have stopped responding.",
                    "#791F1F");
            }
            else
            {
                // Parse enforcement and assessment for three-state banner
                var (isBlocking, isDryRun, enforcementNote) = ParseEnforcementStatus(enforcementJson);
                var (riskScore, signals, isConnected, isTrustedNetwork) = ParseAssessmentStatus(assessmentJson);
                var riskIsHigh = riskScore >= 60;

                if (isBlocking)
                {
                    // STATE A - Red (blocking active)
                    SetBannerState(
                        "#FEF2F2", "#FCA5A5",
                        "Internet blocking active", "#A32D2D",
                        enforcementNote ?? "Rogue AP detected — all outbound connections blocked",
                        "#791F1F");
                }
                else if (riskIsHigh && !isBlocking)
                {
                    // STATE B - Amber (suspicious but not blocking)
                    var detail = vpnConnected
                        ? "Blocking inactive — protected by VPN"
                        : "Blocking manually disabled — high risk network";
                    SetBannerState(
                        "#FFFBEB", "#FCD34D",
                        "Suspicious network detected", "#854F0B",
                        detail,
                        "#633806");
                }
                else
                {
                    // STATE C - Green (safe)
                    var primarySignal = signals.FirstOrDefault(s =>
                        s.Contains("verified") ||
                        s.Contains("match") ||
                        s.Contains("Learning")) ?? "Protection active";

                    // FIX 5: Context-aware detail text based on VPN and trust state
                    string detail;
                    if (vpnConnected && isTrustedNetwork)
                    {
                        detail = $"VPN ({provider}) active on trusted network — maximum protection";
                    }
                    else if (vpnConnected && !isTrustedNetwork && riskScore < 60)
                    {
                        detail = $"VPN ({provider}) active — network traffic is encrypted";
                    }
                    else if (vpnConnected && riskScore >= 60)
                    {
                        detail = $"VPN ({provider}) connected — protecting against detected threat";
                    }
                    else if (!vpnConnected && isTrustedNetwork)
                    {
                        detail = "Trusted network — no active blocks";
                    }
                    else
                    {
                        detail = "No active blocks";
                    }

                    SetBannerState(
                        "#F0FDF4", "#86EFAC",
                        primarySignal, "#3B6D11",
                        detail,
                        "#27500A");
                }
            }

            var initialized = ExtractBoolean(masterJson, "initialized");
            DashboardMasterKeyText.Text = initialized ? "Initialized" : "Not initialized";

            DashboardVpnText.Text = vpnConnected ? $"Connected ({provider})" : $"Disconnected ({provider})";
            DashboardVpnText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(
                vpnConnected ? "#3B6D11" : "#A32D2D"));

            var trustedCount = ExtractArrayCount(trustedJson);
            DashboardTrustedCountText.Text = trustedCount.ToString();
            ParseAndPopulateTrustedNetworks(trustedJson);

            try
            {
                using var trustedDoc = JsonDocument.Parse(trustedJson);
                if (trustedDoc.RootElement.ValueKind == JsonValueKind.Array)
                {
                    _trustedBssids = trustedDoc.RootElement
                        .EnumerateArray()
                        .Select(n => n.TryGetProperty("bssid", out var b) ? b.GetString() ?? string.Empty : string.Empty)
                        .Where(s => s.Length > 0)
                        .Select(s => s.ToUpperInvariant())
                        .ToList();
                }
            }
            catch
            {
                _trustedBssids = new();
            }

            PopulateConnectedNetworkCard(connectedJson);
            PopulateAssessmentCard(assessmentJson, vpnConnected, provider);
            // PopulateEnforcementCard removed - now handled by SetBannerState above
            PopulateVpnInlineStatus(vpnJson, vpnConfigJson);
            PopulateDeploymentProfile(profileJson);

            DashboardLastUpdateText.Text = $"Updated: {DateTime.Now:HH:mm:ss}";
        }
        catch (Exception exception)
        {
            DashboardHealthText.Text = "Unavailable";
            DashboardLastUpdateText.Text = $"Dashboard error: {exception.Message}";
            DashboardEnforcementText.Text = "Enforcement: Unknown";
            VpnInlineStatusText.Text = "VPN status: Unknown";
        }
        finally
        {
            _dashboardRefreshInProgress = false;
        }

        CheckPendingNotification();
    }

    private void DashboardRefreshTimer_Tick(object? sender, EventArgs e)
    {
        _ = RefreshDashboardAsync();
    }

    private void DashboardRefreshIntervalComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        SetDashboardRefreshIntervalFromUi();
    }

    private void SetDashboardRefreshIntervalFromUi()
    {
        if (DashboardRefreshIntervalComboBox.SelectedItem is not ComboBoxItem item)
        {
            _dashboardRefreshTimer.Interval = TimeSpan.FromSeconds(10);
            return;
        }

        var text = item.Content?.ToString();
        if (!int.TryParse(text, out var seconds) || seconds < 5)
        {
            seconds = 10;
        }

        _dashboardRefreshTimer.Interval = TimeSpan.FromSeconds(seconds);
    }

    private void PopulateEnforcementCard(string enforcementJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(enforcementJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                DashboardSimilarSsidWarningText.Text = "Enforcement status unknown";
                DashboardEnforcementText.Text = "Unable to determine enforcement state";
                DashboardEnforcementText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#444444"));
                return;
            }

            var isSupported = doc.RootElement.TryGetProperty("isSupported", out var supportedElement)
                && supportedElement.ValueKind == JsonValueKind.True;
            var isDryRun = doc.RootElement.TryGetProperty("isDryRun", out var dryRunElement)
                && dryRunElement.ValueKind == JsonValueKind.True;
            var isBlockingActive = doc.RootElement.TryGetProperty("isBlockingActive", out var blockingElement)
                && blockingElement.ValueKind == JsonValueKind.True;
            _isBlockingActive = isBlockingActive;
            var note = doc.RootElement.TryGetProperty("note", out var noteElement)
                ? noteElement.GetString()
                : null;

            if (!isSupported)
            {
                DashboardSimilarSsidWarningText.Text = "Enforcement not supported";
                DashboardEnforcementText.Text = "This runtime does not support network blocking";
                DashboardEnforcementText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#555555"));
                return;
            }

            if (isDryRun)
            {
                DashboardSimilarSsidWarningText.Text = "Dry-run mode active";
                DashboardEnforcementText.Text = string.IsNullOrWhiteSpace(note)
                    ? "No real blocks will be applied"
                    : $"No real blocks will be applied | {note}";
                DashboardEnforcementText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#8A4B00"));
                return;
            }

            if (isBlockingActive)
            {
                DashboardSimilarSsidWarningText.Text = "Internet blocking active";
                DashboardEnforcementText.Text = string.IsNullOrWhiteSpace(note)
                    ? "All outbound connections blocked"
                    : $"All outbound connections blocked | {note}";
                DashboardEnforcementText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#B00020"));
                return;
            }

            DashboardSimilarSsidWarningText.Text = "Internet blocking inactive";
            DashboardEnforcementText.Text = string.IsNullOrWhiteSpace(note)
                ? "No active blocks"
                : $"No active blocks | {note}";
            DashboardEnforcementText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2E7D32"));
        }
        catch
        {
            DashboardSimilarSsidWarningText.Text = "Enforcement status unknown";
            DashboardEnforcementText.Text = "Unable to determine enforcement state";
            DashboardEnforcementText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#444444"));
        }
    }

    private void PopulateVpnInlineStatus(string vpnStatusJson, string vpnConfigJson)
    {
        try
        {
            using var statusDoc = JsonDocument.Parse(vpnStatusJson);
            using var configDoc = JsonDocument.Parse(vpnConfigJson);

            if (statusDoc.RootElement.ValueKind != JsonValueKind.Object)
            {
                VpnInlineStatusText.Text = "VPN status: Unknown";
                return;
            }

            var connected = statusDoc.RootElement.TryGetProperty("isConnected", out var connectedElement)
                && connectedElement.ValueKind == JsonValueKind.True;
            var provider = statusDoc.RootElement.TryGetProperty("providerName", out var providerElement)
                ? providerElement.GetString()
                : null;
            var mode = configDoc.RootElement.ValueKind == JsonValueKind.Object
                && configDoc.RootElement.TryGetProperty("mode", out var modeElement)
                    ? modeElement.GetString()
                    : "Auto";

            var resolvedProvider = !string.IsNullOrWhiteSpace(provider)
                ? provider
                : mode;

            VpnInlineStatusText.Text = connected
                ? $"Connected via {resolvedProvider}"
                : $"Disconnected (mode: {mode})";
            var vpnColor = connected ? "#3B6D11" : "#A32D2D";
            VpnInlineStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(vpnColor));
            VpnStatusDot.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString(vpnColor));
        }
        catch
        {
            VpnInlineStatusText.Text = "VPN status: Unknown";
            VpnInlineStatusText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#555555"));
            VpnStatusDot.Fill = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#854F0B"));
        }
    }

    private void PopulateDeploymentProfile(string profileJson)
    {
        if (_skipNextProfilePopulate)
        {
            _skipNextProfilePopulate = false;
            return;
        }

        try
        {
            using var doc = JsonDocument.Parse(profileJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object
                || !doc.RootElement.TryGetProperty("deploymentProfile", out var profileElement))
            {
                return;
            }

            var profile = profileElement.GetString() ?? "Home";
            SelectDeploymentProfile(profile);
        }
        catch
        {
        }
    }

    private void PopulateConnectedNetworkCard(string connectedJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(connectedJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object || !doc.RootElement.TryGetProperty("ssid", out var ssidElement))
            {
                DashboardConnectedText.Text = "Not connected";
                return;
            }

            var ssid = ssidElement.GetString() ?? "Unknown";
            var bssid = doc.RootElement.TryGetProperty("bssid", out var bssidElement)
                ? bssidElement.GetString() ?? "Unknown"
                : "Unknown";

            DashboardConnectedText.Text = $"{ssid} ({bssid})";
        }
        catch
        {
            DashboardConnectedText.Text = "Unknown";
        }
    }

    private void PopulateAssessmentCard(string assessmentJson, bool vpnConnected, string provider)
    {
        try
        {
            using var doc = JsonDocument.Parse(assessmentJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object || !doc.RootElement.TryGetProperty("assessment", out var assessment))
            {
                DashboardRiskText.Text = "Pending";
                DashboardNetworkDetailsText.Text = "No assessment available yet.";
                // FIX 2: Removed - DashboardSimilarSsidWarningText is now set by SetBannerState
                RiskSignalsControl.ItemsSource = null;
                return;
            }

            var riskLevel = assessment.TryGetProperty("riskLevel", out var riskElement)
                ? riskElement.ToString()
                : "Unknown";
            var riskScore = assessment.TryGetProperty("riskScore", out var scoreElement)
                ? scoreElement.ToString()
                : "0";
            var isTrustedNetwork = assessment.TryGetProperty("isTrustedNetwork", out var trustedElement)
                && trustedElement.ValueKind == JsonValueKind.True;
            var summary = assessment.TryGetProperty("summary", out var summaryElement)
                ? summaryElement.GetString() ?? string.Empty
                : string.Empty;

            int.TryParse(riskScore, out var scoreInt);
            var connectedNetwork = assessment.TryGetProperty("connectedNetwork", out var cnPre)
                && cnPre.ValueKind == JsonValueKind.Object;
            var isLearningPre = false;
            if (assessment.TryGetProperty("signals", out var sigsPre) && sigsPre.ValueKind == JsonValueKind.Array)
                foreach (var sig in sigsPre.EnumerateArray())
                    if ((sig.GetString() ?? "").Contains("Learning mode")) { isLearningPre = true; break; }

            // FIX 3: Update risk badge and signals
            var scheme = GetStatusColorScheme(scoreInt, riskLevel, isLearningPre, _isBlockingActive, connectedNetwork, isTrustedNetwork);

            // Risk badge setter
            Action<string, string, string> setRiskBadge = (text, fg, bg) =>
            {
                DashboardRiskText.Text = text;
                DashboardRiskText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString(fg));
                RiskLevelBadge.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(bg));
                RiskLevelBadge.BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(fg));
            };

            if (!connectedNetwork)
                setRiskBadge("Not connected", "#71717A", "#F4F4F5");
            else if (isLearningPre)
                setRiskBadge("Learning network", "#185FA5", "#EFF6FF");
            else if (isTrustedNetwork && scoreInt == 0)
                setRiskBadge("Protected", "#3B6D11", "#F0FDF4");
            else if (scoreInt <= 34)
                setRiskBadge("Low risk", "#3B6D11", "#F0FDF4");
            else if (scoreInt <= 59)
                setRiskBadge("Medium risk", "#854F0B", "#FFFBEB");
            else if (scoreInt <= 79)
                setRiskBadge("High risk", "#A32D2D", "#FEF2F2");
            else
                setRiskBadge("Critical", "#791F1F", "#FEF2F2");

            UpdateRiskGauge(scoreInt);
            UpdateTopBarStatus(scheme);

            var connected = assessment.TryGetProperty("connectedNetwork", out var connectedEl)
                ? connectedEl
                : default;
            if (connected.ValueKind == JsonValueKind.Object)
            {
                var ssid = connected.TryGetProperty("ssid", out var ssidElem) ? ssidElem.GetString() : "Unknown";
                var bssid = connected.TryGetProperty("bssid", out var bssidElem) ? bssidElem.GetString() : "Unknown";
                var security = connected.TryGetProperty("securityProtocol", out var secElem) ? secElem.GetString() : "Unknown";
                DashboardNetworkDetailsText.Text = $"Connected: {ssid} ({bssid}) | Security: {security}\n{summary}";

                // Connection details card
                DetailSsidText.Text = ssid ?? "Not connected";
                DetailBssidText.Text = bssid ?? "—";
                DetailSecurityText.Text = security ?? "—";

                var gatewayIp = connected.TryGetProperty("gatewayIp", out var gwEl) ? gwEl.GetString() : null;
                DetailGatewayText.Text = gatewayIp ?? "—";

                var gatewayTtl = connected.TryGetProperty("gatewayTtl", out var ttlEl) && ttlEl.ValueKind == JsonValueKind.Number
                    ? ttlEl.GetInt32() : (int?)null;
                DetailTtlText.Text = gatewayTtl.HasValue ? $"TTL: {gatewayTtl}" : "TTL: —";

                var band = connected.TryGetProperty("bandGHz", out var bandEl) && bandEl.ValueKind == JsonValueKind.Number
                    ? bandEl.GetDouble() : (double?)null;
                var channel = connected.TryGetProperty("channel", out var chEl) && chEl.ValueKind == JsonValueKind.Number
                    ? chEl.GetInt32() : (int?)null;
                DetailBandText.Text = band.HasValue ? $"{band} GHz · Ch {channel}" : "—";
            }
            else
            {
                DashboardNetworkDetailsText.Text = summary;

                DetailSsidText.Text = "Not connected";
                DetailBssidText.Text = "—";
                DetailSecurityText.Text = "—";
                DetailGatewayText.Text = "—";
                DetailTtlText.Text = "TTL: —";
                DetailBandText.Text = "—";
            }

            var warning = string.Empty;
            var matchedSignals = new List<string>();
            if (assessment.TryGetProperty("signals", out var signalsElement) && signalsElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var signal in signalsElement.EnumerateArray())
                {
                    var text = signal.GetString() ?? string.Empty;
                    if (!string.IsNullOrWhiteSpace(text))
                    {
                        matchedSignals.Add(text);
                    }
                }
            }

            // FIX 2: Populate signals control with colored items
            var signalItems = matchedSignals.Select(s => {
                string dotColor;

                // Explicitly green signals
                if (s.Contains("verified") ||
                    s.Contains("within learned") ||
                    s.Contains("matches") ||
                    s.Contains("normal") ||
                    s.Contains("Learning mode"))
                    dotColor = "#3B6D11";

                // Explicitly red signals
                else if (s.Contains("mismatch") ||
                         s.Contains("rogue") ||
                         s.Contains("not seen during") ||
                         s.Contains("does not match") ||
                         s.Contains("Critical") ||
                         s.Contains("Trusted baseline BSSID"))
                    dotColor = "#A32D2D";

                // Amber for warnings
                else if (s.Contains("instability") ||
                         s.Contains("stronger than") ||
                         s.Contains("Multiple APs") ||
                         s.Contains("suspicious"))
                    dotColor = "#854F0B";

                // Default grey
                else
                    dotColor = "#A1A1AA";

                return new RiskSignalItem(s, dotColor);
            }).ToList();
            RiskSignalsControl.ItemsSource = signalItems;

            // FIX 2: Removed - DashboardSimilarSsidWarningText is now set by SetBannerState
            // warning = BuildRiskWarningMessage(...);
            // DashboardSimilarSsidWarningText.Text = warning;
            // ApplyWarningStyle(...);

            DetailProtectionText.Text = isLearningPre ? "Learning" : riskLevel;
            DetailLearningText.Text = isLearningPre
                ? "Monitoring network characteristics"
                : $"{matchedSignals.Count} signal(s) evaluated";
        }
        catch
        {
            DashboardRiskText.Text = "Unknown";
            DashboardNetworkDetailsText.Text = "Unable to parse assessment details.";
            // FIX 2: Removed - DashboardSimilarSsidWarningText is now set by SetBannerState
            RiskSignalsControl.ItemsSource = null;
        }
    }

    private static string BuildRiskWarningMessage(IReadOnlyCollection<string> signals, bool vpnConnected, string provider, bool isTrustedNetwork)
    {
        var normalizedSignals = signals
            .Where(text => !string.IsNullOrWhiteSpace(text))
            .ToArray();

        static string WithVpnContext(string baseMessage, bool connected, string vpnProvider, bool recommendTrustedSwitch = true)
        {
            if (!connected)
            {
                return baseMessage;
            }

            return recommendTrustedSwitch
                ? $"{baseMessage} Temporarily safer because VPN ({vpnProvider}) is connected, but switching to a trusted network is recommended."
                : $"{baseMessage} Temporarily safer because VPN ({vpnProvider}) is connected.";
        }

        static int? ExtractSimilarSsidCount(string[] signalTexts)
        {
            foreach (var text in signalTexts)
            {
                if (!text.Contains("Wi-Fi network(s)", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var match = Regex.Match(text, @"(\d+)");
                if (match.Success && int.TryParse(match.Groups[1].Value, out var count))
                {
                    return count;
                }
            }

            return null;
        }

        var isRogueConnection = normalizedSignals.Any(text =>
            text.Contains("possible evil twin", StringComparison.OrdinalIgnoreCase)
            || text.Contains("possible rogue ap", StringComparison.OrdinalIgnoreCase)
            || text.Contains("does not match trusted baseline", StringComparison.OrdinalIgnoreCase)
            || text.Contains("trusted baseline BSSID is in range", StringComparison.OrdinalIgnoreCase)
            || text.Contains("gateway fingerprint differs", StringComparison.OrdinalIgnoreCase)
            || text.Contains("DHCP fingerprint differs", StringComparison.OrdinalIgnoreCase)
            || text.Contains("same-SSID cluster", StringComparison.OrdinalIgnoreCase));

        if (isRogueConnection)
        {
            return WithVpnContext("Alert: connected to a potential rogue Wi-Fi point.", vpnConnected, provider);
        }

        var hasSimilarSsid = normalizedSignals.Any(text =>
            text.Contains("similar SSID", StringComparison.OrdinalIgnoreCase)
            || text.Contains("different BSSID", StringComparison.OrdinalIgnoreCase));
        if (hasSimilarSsid)
        {
            var count = ExtractSimilarSsidCount(normalizedSignals);
            if (isTrustedNetwork)
            {
                return WithVpnContext("Warning: a network with the same SSID is nearby. You are currently on a trusted network, but stay alert.", vpnConnected, provider, recommendTrustedSwitch: false);
            }

            var countText = count is > 1
                ? $"{count} connections with the same SSID are nearby"
                : "Multiple connections with the same SSID are nearby";

            return WithVpnContext($"Warning: {countText}. You might be connected to a rogue network.", vpnConnected, provider);
        }

        var hasOpenNetwork = normalizedSignals.Any(text =>
            text.Contains("open/unencrypted", StringComparison.OrdinalIgnoreCase));
        if (hasOpenNetwork)
        {
            return WithVpnContext("Warning: connected network is open/unencrypted.", vpnConnected, provider);
        }

        var hasSecurityChanged = normalizedSignals.Any(text =>
            text.Contains("Security protocol changed", StringComparison.OrdinalIgnoreCase));
        if (hasSecurityChanged)
        {
            return "Alert: security protocol changed from trusted baseline.";
        }

        var hasSignalInstability = normalizedSignals.Any(text =>
            text.Contains("Signal instability", StringComparison.OrdinalIgnoreCase));
        if (hasSignalInstability)
        {
            return "Notice: unusual signal instability detected on current connection.";
        }

        if (vpnConnected && normalizedSignals.Length > 0)
        {
            return $"Notice: VPN ({provider}) is connected. Current state is temporarily safer, but switching to a trusted network is recommended.";
        }

        return normalizedSignals.FirstOrDefault() ?? "No active warning signals.";
    }

    private WarningSeverity ClassifyWarningSeverity(string riskLevel, string warningText)
    {
        if (string.Equals(riskLevel, "Critical", StringComparison.OrdinalIgnoreCase))
        {
            return WarningSeverity.Critical;
        }

        if (string.Equals(riskLevel, "High", StringComparison.OrdinalIgnoreCase))
        {
            return WarningSeverity.Warning;
        }

        if (warningText.StartsWith("Alert:", StringComparison.OrdinalIgnoreCase))
        {
            return WarningSeverity.Critical;
        }

        if (warningText.StartsWith("Warning:", StringComparison.OrdinalIgnoreCase))
        {
            return WarningSeverity.Warning;
        }

        return WarningSeverity.Notice;
    }

    private void ApplyWarningStyle(WarningSeverity severity)
    {
        DashboardWarningBorder.Visibility = Visibility.Visible;
        switch (severity)
        {
            case WarningSeverity.Critical:
                DashboardWarningBorder.BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#B00020"));
                DashboardWarningBorder.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FDECEC"));
                DashboardSimilarSsidWarningText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#7F0000"));
                break;

            case WarningSeverity.Warning:
                DashboardWarningBorder.BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F5A623"));
                DashboardWarningBorder.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FFF8E1"));
                DashboardSimilarSsidWarningText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#8A4B00"));
                break;

            case WarningSeverity.Notice:
            default:
                DashboardWarningBorder.BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#2B6CB0"));
                DashboardWarningBorder.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EBF8FF"));
                DashboardSimilarSsidWarningText.Foreground = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#1A4A74"));
                break;
        }
    }

    // FIX 1: Helper to set enforcement banner state with consistent colors
    private void SetBannerState(
        string bg, string border,
        string title, string titleColor,
        string detail, string detailColor)
    {
        DashboardWarningBorder.Background =
            new SolidColorBrush((Color)ColorConverter.ConvertFromString(bg));
        DashboardWarningBorder.BorderBrush =
            new SolidColorBrush((Color)ColorConverter.ConvertFromString(border));
        DashboardSimilarSsidWarningText.Text = title;
        DashboardSimilarSsidWarningText.Foreground =
            new SolidColorBrush((Color)ColorConverter.ConvertFromString(titleColor));
        DashboardEnforcementText.Text = detail;
        DashboardEnforcementText.Foreground =
            new SolidColorBrush((Color)ColorConverter.ConvertFromString(detailColor));
        DashboardWarningBorder.Visibility = Visibility.Visible;
    }

    // FIX 1: Helper to parse enforcement status for banner
    private static (bool isBlocking, bool isDryRun, string? note) ParseEnforcementStatus(string enforcementJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(enforcementJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
                return (false, false, null);

            var isBlocking = doc.RootElement.TryGetProperty("isBlockingActive", out var blockingElement)
                && blockingElement.ValueKind == JsonValueKind.True;
            var isDryRun = doc.RootElement.TryGetProperty("isDryRun", out var dryRunElement)
                && dryRunElement.ValueKind == JsonValueKind.True;
            var note = doc.RootElement.TryGetProperty("note", out var noteElement)
                ? noteElement.GetString()
                : null;

            return (isBlocking, isDryRun, note);
        }
        catch
        {
            return (false, false, null);
        }
    }

    // FIX 1: Helper to parse assessment for banner
    private static (int riskScore, List<string> signals, bool isConnected, bool isTrustedNetwork) ParseAssessmentStatus(string assessmentJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(assessmentJson);
            if (doc.RootElement.ValueKind != JsonValueKind.Object
                || !doc.RootElement.TryGetProperty("assessment", out var assessment))
            {
                return (0, new List<string>(), false, false);
            }

            var riskScore = assessment.TryGetProperty("riskScore", out var scoreElement)
                && scoreElement.ValueKind == JsonValueKind.Number
                ? scoreElement.GetInt32()
                : 0;

            var isConnected = assessment.TryGetProperty("connectedNetwork", out var cnElement)
                && cnElement.ValueKind == JsonValueKind.Object;

            var isTrustedNetwork = assessment.TryGetProperty("isTrustedNetwork", out var trustedElement)
                && trustedElement.ValueKind == JsonValueKind.True;

            var signals = new List<string>();
            if (assessment.TryGetProperty("signals", out var signalsElement)
                && signalsElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var signal in signalsElement.EnumerateArray())
                {
                    var text = signal.GetString();
                    if (!string.IsNullOrWhiteSpace(text))
                        signals.Add(text);
                }
            }

            return (riskScore, signals, isConnected, isTrustedNetwork);
        }
        catch
        {
            return (0, new List<string>(), false, false);
        }
    }

    private static string ExtractSimpleValue(string json, string propertyName, string fallback)
    {
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty(propertyName, out var element))
        {
            return fallback;
        }

        return element.ValueKind switch
        {
            JsonValueKind.String => element.GetString() ?? fallback,
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Number => element.GetRawText(),
            _ => fallback
        };
    }

    private static bool ExtractBoolean(string json, string propertyName)
    {
        using var doc = JsonDocument.Parse(json);
        if (!doc.RootElement.TryGetProperty(propertyName, out var element))
        {
            return false;
        }

        return element.ValueKind == JsonValueKind.True
            || (element.ValueKind == JsonValueKind.String && bool.TryParse(element.GetString(), out var parsed) && parsed);
    }

    private static int ExtractArrayCount(string json)
    {
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.ValueKind == JsonValueKind.Array
            ? doc.RootElement.GetArrayLength()
            : 0;
    }

    private async Task RunActionAsync(string label, Func<CancellationToken, Task<string>> action)
    {
        EnsureClient();
        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            var result = await action(cts.Token);
            AppendOutput(label, result);
        }
        catch (Exception exception)
        {
            AppendOutput(label, $"ERROR: {exception.Message}");
        }
    }

    private async Task RunProtectedActionAsync(
        string label,
        Func<string, CancellationToken, Task<string>> action)
    {
        var masterKey = PromptForMasterKey(label);
        if (string.IsNullOrWhiteSpace(masterKey))
        {
            AppendOutput(label,
                "Cancelled: master key prompt " +
                "was not completed.");
            return;
        }

        EnsureClient();

        try
        {
            using var cts = new CancellationTokenSource(
                TimeSpan.FromSeconds(20));

            // Verify master key first — this triggers
            // audit logging for both correct and wrong attempts
            var (isValid, _) = await _apiClient
                .VerifyMasterKeyAsync(masterKey, cts.Token);

            if (!isValid)
            {
                var wrongKeyMsg =
                    "Incorrect master key. " +
                    "Action was not performed.";
                AppendOutput(label, wrongKeyMsg);
                ShowStyledDialog(
                    "Authentication failed",
                    wrongKeyMsg,
                    isError: true);
                return;
            }

            // Key is correct — proceed with action
            var result = await action(
                masterKey, cts.Token);
            var success = IsOperationSuccessful(result);
            AppendOutput(label, result);
            ShowStyledDialog(
                success
                    ? $"{label} successful"
                    : $"{label} unsuccessful",
                success
                    ? $"{label} completed successfully."
                    : result,
                isError: !success);
        }
        catch (Exception exception)
        {
            var message = $"ERROR: {exception.Message}";
            AppendOutput(label, message);
            ShowStyledDialog($"{label} failed", message, isError: true);
        }
    }

    private static bool IsOperationSuccessful(string message)
    {
        if (string.IsNullOrWhiteSpace(message))
        {
            return false;
        }

        return !message.Contains("unauthorized", StringComparison.OrdinalIgnoreCase)
               && !message.Contains("error", StringComparison.OrdinalIgnoreCase)
               && !message.Contains("failed", StringComparison.OrdinalIgnoreCase)
               && !message.Contains("not found", StringComparison.OrdinalIgnoreCase);
    }

    private string? PromptForMasterKey(string prompt)
    {
        var dialog = new Window
        {
            Title = "RogueAP Shield — Authentication",
            Width = 400,
            Height = 230,
            WindowStartupLocation =
                WindowStartupLocation.CenterOwner,
            Owner = this,
            ResizeMode = ResizeMode.NoResize,
            Background = new SolidColorBrush(
                Colors.White),
            FontFamily = new FontFamily("Segoe UI")
        };

        var outerStack = new StackPanel();

        var accent = new Border
        {
            Height = 3,
            Background = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(
                    "#185FA5"))
        };

        var inner = new StackPanel
        {
            Margin = new Thickness(28, 20, 28, 24)
        };

        var titleText = new TextBlock
        {
            Text = "Master key required",
            FontSize = 15,
            FontWeight = FontWeights.Medium,
            Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(
                    "#18181B")),
            Margin = new Thickness(0, 0, 0, 6)
        };

        var subtitleText = new TextBlock
        {
            Text = prompt,
            FontSize = 12,
            Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(
                    "#71717A")),
            TextWrapping = TextWrapping.Wrap,
            Margin = new Thickness(0, 0, 0, 16)
        };

        var passwordBox = new PasswordBox
        {
            FontSize = 13,
            Padding = new Thickness(10, 8, 10, 8),
            Margin = new Thickness(0, 0, 0, 20),
            BorderBrush = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(
                    "#E4E4E7")),
            BorderThickness = new Thickness(1)
        };

        var buttonRow = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right
        };

        var cancelBtn = new Button
        {
            Content = "Cancel",
            Width = 88,
            Height = 36,
            Margin = new Thickness(0, 0, 8, 0),
            FontSize = 13,
            Background = new SolidColorBrush(Colors.White),
            BorderBrush = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(
                    "#E4E4E7")),
            BorderThickness = new Thickness(1),
            Cursor = System.Windows.Input.Cursors.Hand
        };

        var confirmBtn = new Button
        {
            Content = "Confirm",
            Width = 88,
            Height = 36,
            FontSize = 13,
            FontWeight = FontWeights.Medium,
            Background = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(
                    "#185FA5")),
            Foreground = new SolidColorBrush(
                Colors.White),
            BorderThickness = new Thickness(0),
            Cursor = System.Windows.Input.Cursors.Hand
        };

        string? result = null;

        cancelBtn.Click += (_, _) =>
            dialog.DialogResult = false;

        confirmBtn.Click += (_, _) =>
        {
            if (string.IsNullOrWhiteSpace(
                    passwordBox.Password))
            {
                passwordBox.BorderBrush =
                    new SolidColorBrush(
                        (Color)ColorConverter
                            .ConvertFromString("#A32D2D"));
                return;
            }
            result = passwordBox.Password;
            dialog.DialogResult = true;
        };

        passwordBox.KeyDown += (_, e) =>
        {
            if (e.Key == System.Windows.Input.Key.Enter)
                confirmBtn.RaiseEvent(
                    new RoutedEventArgs(
                        Button.ClickEvent));
        };

        buttonRow.Children.Add(cancelBtn);
        buttonRow.Children.Add(confirmBtn);
        inner.Children.Add(titleText);
        inner.Children.Add(subtitleText);
        inner.Children.Add(passwordBox);
        inner.Children.Add(buttonRow);
        outerStack.Children.Add(accent);
        outerStack.Children.Add(inner);
        dialog.Content = outerStack;

        dialog.Loaded += (_, _) =>
            passwordBox.Focus();

        dialog.ShowDialog();
        return result;
    }

    private void ShowStyledDialog(
        string title,
        string message,
        bool isError = false)
    {
        var dialog = new Window
        {
            Title = "RogueAP Shield",
            Width = 420,
            Height = 210,
            WindowStartupLocation =
                WindowStartupLocation.CenterOwner,
            Owner = this,
            ResizeMode = ResizeMode.NoResize,
            Background = new SolidColorBrush(
                Colors.White),
            FontFamily = new FontFamily("Segoe UI")
        };

        var outerStack = new StackPanel();

        var accent = new Border
        {
            Height = 3,
            Background = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(
                    isError ? "#A32D2D" : "#185FA5"))
        };

        var inner = new StackPanel
        {
            Margin = new Thickness(28, 20, 28, 24)
        };

        var titleText = new TextBlock
        {
            Text = title,
            FontSize = 14,
            FontWeight = FontWeights.Medium,
            Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(
                    isError ? "#A32D2D" : "#18181B")),
            Margin = new Thickness(0, 0, 0, 8)
        };

        var messageText = new TextBlock
        {
            Text = message,
            FontSize = 12,
            TextWrapping = TextWrapping.Wrap,
            Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(
                    "#71717A")),
            Margin = new Thickness(0, 0, 0, 24)
        };

        var okBtn = new Button
        {
            Content = "OK",
            Width = 88,
            Height = 36,
            FontSize = 13,
            FontWeight = FontWeights.Medium,
            HorizontalAlignment =
                HorizontalAlignment.Right,
            Background = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(
                    isError ? "#A32D2D" : "#185FA5")),
            Foreground = new SolidColorBrush(
                Colors.White),
            BorderThickness = new Thickness(0),
            Cursor = System.Windows.Input.Cursors.Hand
        };

        okBtn.Click += (_, _) => dialog.Close();

        inner.Children.Add(titleText);
        inner.Children.Add(messageText);
        inner.Children.Add(okBtn);
        outerStack.Children.Add(accent);
        outerStack.Children.Add(inner);
        dialog.Content = outerStack;
        dialog.ShowDialog();
    }

    private bool ShowStyledConfirmDialog(
        string title,
        string message)
    {
        var dialog = new Window
        {
            Title = "RogueAP Shield — Confirm",
            Width = 440,
            Height = 230,
            WindowStartupLocation =
                WindowStartupLocation.CenterOwner,
            Owner = this,
            ResizeMode = ResizeMode.NoResize,
            Background = new SolidColorBrush(
                Colors.White),
            FontFamily = new FontFamily("Segoe UI")
        };

        var outerStack = new StackPanel();

        var accent = new Border
        {
            Height = 3,
            Background = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(
                    "#A32D2D"))
        };

        var inner = new StackPanel
        {
            Margin = new Thickness(28, 20, 28, 24)
        };

        var titleText = new TextBlock
        {
            Text = title,
            FontSize = 14,
            FontWeight = FontWeights.Medium,
            Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(
                    "#18181B")),
            Margin = new Thickness(0, 0, 0, 8)
        };

        var messageText = new TextBlock
        {
            Text = message,
            FontSize = 12,
            TextWrapping = TextWrapping.Wrap,
            Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(
                    "#71717A")),
            Margin = new Thickness(0, 0, 0, 24)
        };

        var buttonRow = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right
        };

        var cancelBtn = new Button
        {
            Content = "Cancel",
            Width = 88,
            Height = 36,
            Margin = new Thickness(0, 0, 8, 0),
            FontSize = 13,
            Background = new SolidColorBrush(
                Colors.White),
            BorderBrush = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(
                    "#E4E4E7")),
            BorderThickness = new Thickness(1),
            Cursor = System.Windows.Input.Cursors.Hand
        };

        var confirmBtn = new Button
        {
            Content = "Confirm",
            Width = 88,
            Height = 36,
            FontSize = 13,
            FontWeight = FontWeights.Medium,
            Background = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(
                    "#A32D2D")),
            Foreground = new SolidColorBrush(
                Colors.White),
            BorderThickness = new Thickness(0),
            Cursor = System.Windows.Input.Cursors.Hand
        };

        bool result = false;
        cancelBtn.Click += (_, _) => dialog.Close();
        confirmBtn.Click += (_, _) =>
        {
            result = true;
            dialog.Close();
        };

        buttonRow.Children.Add(cancelBtn);
        buttonRow.Children.Add(confirmBtn);
        inner.Children.Add(titleText);
        inner.Children.Add(messageText);
        inner.Children.Add(buttonRow);
        outerStack.Children.Add(accent);
        outerStack.Children.Add(inner);
        dialog.Content = outerStack;
        dialog.ShowDialog();
        return result;
    }

    private void AppendOutput(string label, string content)
    {
        // Legacy method - audit log now uses structured entries
    }

    private void ClearOutput_Click(object sender, RoutedEventArgs e)
    {
        // Legacy method - audit log is append-only
    }

    private void ShowKeysResult(string title, string message, bool success)
    {
        KeysResultTitle.Text = title;
        KeysResultText.Text = message;
        KeysResultCard.Background = success
            ? new SolidColorBrush((Color)ColorConverter.ConvertFromString("#F0FDF4"))
            : new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FEF2F2"));
        KeysResultCard.BorderBrush = success
            ? new SolidColorBrush((Color)ColorConverter.ConvertFromString("#86EFAC"))
            : new SolidColorBrush((Color)ColorConverter.ConvertFromString("#FCA5A5"));
        KeysResultCard.BorderThickness = new Thickness(1);
        KeysResultTitle.Foreground = success
            ? new SolidColorBrush((Color)ColorConverter.ConvertFromString("#166534"))
            : new SolidColorBrush((Color)ColorConverter.ConvertFromString("#991B1B"));
        KeysResultCard.Visibility = Visibility.Visible;
    }

    private async void MasterKeyStatus_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var json = await _apiClient.GetMasterKeyStatusAsync(CancellationToken.None);
            AppendOutput("MasterKey Status", json);
            var initialized = json.Contains("true", StringComparison.OrdinalIgnoreCase)
                || json.Contains("\"initialized\":true", StringComparison.OrdinalIgnoreCase);
            ShowKeysResult(
                "Master key status",
                initialized ? "Master key is initialized and active."
                            : "Master key has not been set up yet.",
                initialized);
        }
        catch (Exception ex)
        {
            ShowKeysResult("Master key status", $"Error: {ex.Message}", false);
        }
        await RefreshDashboardAsync();
    }

    private async void MasterKeyRecover_Click(object sender, RoutedEventArgs e)
    {
        await RunActionAsync("MasterKey Recover", token =>
            _apiClient.RecoverMasterKeyAsync(
                RecoverOldKeyBox.Password,
                RecoverNewMasterKeyBox.Password,
                RecoverNewRecoveryKeyBox.Password,
                token));
        await RefreshDashboardAsync();
    }

    private void SortNearby_Click(object sender, RoutedEventArgs e)
    {
        var sorted = _nearbyWifiItems
            .OrderByDescending(x =>
            {
                if (int.TryParse(x.SignalStrength.Trim(), out var v)) return v;
                return -100;
            })
            .ToList();
        _nearbyWifiItems.Clear();
        foreach (var item in sorted)
            _nearbyWifiItems.Add(item);
    }

    private void SortNearbyByName_Click(object sender, RoutedEventArgs e)
    {
        var sorted = _nearbyWifiItems
            .OrderBy(x => x.Ssid)
            .ToList();
        _nearbyWifiItems.Clear();
        foreach (var item in sorted)
            _nearbyWifiItems.Add(item);
    }

    private async void NearbyWifiScan_Click(object sender, RoutedEventArgs e)
    {
        await RunActionAsync("Nearby Wi-Fi", async token =>
        {
            var json = await _apiClient.GetNearbyWifiAsync(token);
            PopulateNearbyWifi(json);
            return json;
        });
    }

    private void PopulateNearbyWifi(string json)
    {
        _nearbyWifiItems.Clear();
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Array)
            {
                return;
            }

            var parsed = doc.RootElement.EnumerateArray().Select(item =>
            {
                var ssid = item.TryGetProperty("ssid", out var ssidElem) ? ssidElem.GetString() ?? "Unknown" : "Unknown";
                var bssid = item.TryGetProperty("bssid", out var bssidElem) ? bssidElem.GetString() ?? "Unknown" : "Unknown";
                var security = item.TryGetProperty("securityProtocol", out var secElem) ? secElem.GetString() ?? "Unknown" : "Unknown";
                var signal = item.TryGetProperty("signalStrength", out var sigElem) ? sigElem.ToString() : "0";
                return (ssid, bssid, security, signal);
            }).ToList();

            foreach (var (ssid, bssid, security, signal) in parsed)
            {
                var isTrusted = _trustedBssids.Contains(bssid.ToUpperInvariant());
                var isSuspicious = !isTrusted && parsed.Count(x => x.ssid == ssid) > 1;
                _nearbyWifiItems.Add(new NearbyWifiItem(ssid, bssid, security, signal,
                    IsTrusted: isTrusted,
                    IsSuspicious: isSuspicious));
            }
        }
        catch
        {
        }
    }

    private async void TrustedRefresh_Click(object sender, RoutedEventArgs e)
    {
        var json = await _apiClient.GetTrustedNetworksAsync(CancellationToken.None);
        ParseAndPopulateTrustedNetworks(json);
        await RefreshDashboardAsync();
    }

    private async void TrustedRemoveInline_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button btn && btn.Tag is string bssid)
        {
            TrustedRemoveBssidTextBox.Text = bssid;
            _dashboardRefreshTimer.Stop();
            try
            {
                await RunProtectedActionAsync("Trusted Remove",
                    (masterKey, token) => _apiClient.RemoveTrustedNetworkAsync(bssid, masterKey, token));
                await RefreshDashboardAsync();
            }
            finally
            {
                _dashboardRefreshTimer.Start();
            }
        }
    }

    private void ParseAndPopulateTrustedNetworks(string json)
    {
        try
        {
            _trustedNetworkItems.Clear();
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement.ValueKind == JsonValueKind.Array
                ? doc.RootElement
                : doc.RootElement.GetProperty("networks");
            foreach (var el in root.EnumerateArray())
            {
                var ssid  = el.TryGetProperty("ssid",             out var s)  ? s.GetString()  ?? "" : "";
                var bssid = el.TryGetProperty("bssid",            out var b)  ? b.GetString()  ?? "" : "";
                var sec   = el.TryGetProperty("securityProtocol", out var sp) ? sp.GetString() ?? "" : "";
                var added = el.TryGetProperty("addedAt",          out var a)  ? a.GetString()  ?? "" : "";
                _trustedNetworkItems.Add(new TrustedNetworkItem(ssid, bssid, sec, added));
            }
            TrustedCountLabel.Text = $"{_trustedNetworkItems.Count} network(s) trusted";
            TrustedEmptyText.Visibility = _trustedNetworkItems.Count == 0
                ? Visibility.Visible : Visibility.Collapsed;
        }
        catch { }
    }

    private async void TrustConnectedAp_Click(object sender, RoutedEventArgs e)
    {
        _dashboardRefreshTimer.Stop();
        try
        {
            var connectedJson = await _apiClient.GetConnectedWifiAsync(CancellationToken.None);
            using var doc = JsonDocument.Parse(connectedJson);
            var root = doc.RootElement;
            var ssid = root.TryGetProperty("ssid", out var s) ? s.GetString() ?? "" : "";
            var bssid = root.TryGetProperty("bssid", out var b) ? b.GetString() ?? "" : "";
            var sec = root.TryGetProperty("securityProtocol", out var sp) ? sp.GetString() ?? "" : "";
            if (string.IsNullOrEmpty(bssid))
            {
                ShowStyledDialog("Not connected", "No active Wi-Fi connection found.");
                return;
            }
            await RunProtectedActionAsync("Trust Connected AP",
                (masterKey, token) => _apiClient.UpsertTrustedNetworkAsync(masterKey, ssid, bssid, sec, token));
            await RefreshDashboardAsync();
        }
        finally
        {
            _dashboardRefreshTimer.Start();
        }
    }

    private async void TrustedAddSelected_Click(object sender, RoutedEventArgs e)
    {
        var selected =
            (NearbyWifiListBoxFull.SelectedItem
                ?? NearbyWifiListBox.SelectedItem)
                as NearbyWifiItem;

        if (selected is null)
        {
            AppendOutput("Trusted Add", "No nearby Wi-Fi selected.");
            return;
        }

        _dashboardRefreshTimer.Stop();
        try
        {
            await RunProtectedActionAsync("Trusted Add Selected", (masterKey, token) =>
                _apiClient.UpsertTrustedNetworkAsync(
                    masterKey,
                    selected.Ssid,
                    selected.Bssid,
                    selected.SecurityProtocol,
                    token));
            await RefreshDashboardAsync();
        }
        finally
        {
            _dashboardRefreshTimer.Start();
        }
    }

    private async void TrustedRemove_Click(object sender, RoutedEventArgs e)
    {
        _dashboardRefreshTimer.Stop();
        try
        {
            await RunProtectedActionAsync("Trusted Remove", (masterKey, token) =>
                _apiClient.RemoveTrustedNetworkAsync(
                    TrustedRemoveBssidTextBox.Text,
                    masterKey,
                    token));
            await RefreshDashboardAsync();
        }
        finally
        {
            _dashboardRefreshTimer.Start();
        }
    }

    private async void VpnStatus_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var json = await _apiClient.GetVpnStatusAsync(CancellationToken.None);
            var configJson = await _apiClient.GetVpnConfigAsync(CancellationToken.None);
            PopulateVpnInlineStatus(json, configJson);
            AppendOutput("VPN Status", json);
        }
        catch (Exception ex)
        {
            AppendOutput("VPN Status", $"Error: {ex.Message}");
        }
    }

    private async void VpnConfigGet_Click(object sender, RoutedEventArgs e)
    {
        await RunActionAsync("VPN Config", async token =>
        {
            var json = await _apiClient.GetVpnConfigAsync(token);
            TryPopulateVpnConfigControls(json);
            return json;
        });
    }

    private async void VpnConfigUpdate_Click(object sender, RoutedEventArgs e)
    {
        _dashboardRefreshTimer.Stop();
        try
        {
            await RunProtectedActionAsync("VPN Config Update", (masterKey, token) =>
                _apiClient.UpdateVpnConfigAsync(
                    masterKey,
                    GetSelectedVpnModeValue(),
                    WgConnectTextBox.Text,
                    WgDisconnectTextBox.Text,
                    OvConnectTextBox.Text,
                    OvDisconnectTextBox.Text,
                    token));
            await RefreshDashboardAsync();
        }
        finally
        {
            _dashboardRefreshTimer.Start();
        }
    }

    private void FillWireGuardTemplate_Click(object sender, RoutedEventArgs e)
    {
        SelectVpnMode("WireGuard");
        WgConnectTextBox.Text = "& \"C:\\Program Files\\WireGuard\\wireguard.exe\" /installtunnelservice \"C:\\VPN\\wg-test.conf\"";
        WgDisconnectTextBox.Text = "& \"C:\\Program Files\\WireGuard\\wireguard.exe\" /uninstalltunnelservice wg-test";

        ShowVpnConfigHint("WireGuard template applied. Update the profile path (C:\\VPN\\wg-test.conf) and tunnel name (wg-test) before saving config.");
    }

    private void FillOpenVpnTemplate_Click(object sender, RoutedEventArgs e)
    {
        SelectVpnMode("OpenVpn");
        OvConnectTextBox.Text = "Start-Process -FilePath \"C:\\Program Files\\OpenVPN\\bin\\openvpn-gui.exe\" -WindowStyle Hidden; Start-Sleep -Seconds 2; & \"C:\\Program Files\\OpenVPN\\bin\\openvpn-gui.exe\" --command connect lab";
        OvDisconnectTextBox.Text = "& \"C:\\Program Files\\OpenVPN\\bin\\openvpn-gui.exe\" --command disconnect lab";

        ShowVpnConfigHint("OpenVPN template applied. Update the profile name (lab) and executable path before saving config.");
    }

    private void ShowVpnConfigHint(string message)
    {
        VpnConfigHintText.Text = message;
        VpnConfigHintBorder.Visibility = Visibility.Visible;
    }

    private void VpnAdvancedToggle_Click(object sender, RoutedEventArgs e)
    {
        var expanded = VpnAdvancedContent.Visibility == Visibility.Visible;
        VpnAdvancedContent.Visibility = expanded ? Visibility.Collapsed : Visibility.Visible;
        VpnAdvancedChevron.Text = expanded ? "▼" : "▲";
    }

    private async void VpnConnect_Click(object sender, RoutedEventArgs e)
    {
        VpnInlineStatusText.Text = "Connecting...";
        VpnStatusDot.Fill = new SolidColorBrush(
            (Color)ColorConverter.ConvertFromString("#854F0B"));
        await RunVpnOperationWithModeSyncAsync("VPN Connect", token => _apiClient.ConnectVpnAsync(token));
        await RefreshDashboardAsync();
    }

    private async void VpnDisconnect_Click(object sender, RoutedEventArgs e)
    {
        VpnInlineStatusText.Text = "Disconnecting...";
        VpnStatusDot.Fill = new SolidColorBrush(
            (Color)ColorConverter.ConvertFromString("#A32D2D"));
        await RunVpnOperationWithModeSyncAsync("VPN Disconnect", token => _apiClient.DisconnectVpnAsync(token));
        await RefreshDashboardAsync();
    }

    private async Task RunVpnOperationWithModeSyncAsync(string label, Func<CancellationToken, Task<string>> operation)
    {
        EnsureClient();

        try
        {
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(25));
            var synced = await TrySyncVpnConfigIfNeededAsync(cts.Token);
            if (!synced)
            {
                AppendOutput(label, "Cancelled: VPN mode/commands were not synchronized.");
                return;
            }

            var result = await operation(cts.Token);
            AppendOutput(label, result);
        }
        catch (Exception exception)
        {
            AppendOutput(label, $"ERROR: {exception.Message}");
        }
    }

    private async Task<bool> TrySyncVpnConfigIfNeededAsync(CancellationToken cancellationToken)
    {
        var currentConfigJson = await _apiClient.GetVpnConfigAsync(cancellationToken);
        using var doc = JsonDocument.Parse(currentConfigJson);

        if (doc.RootElement.ValueKind != JsonValueKind.Object)
        {
            return true;
        }

        var selectedMode = GetSelectedVpnModeValue();
        var currentMode = doc.RootElement.TryGetProperty("mode", out var modeElement)
            ? modeElement.GetString() ?? "Auto"
            : "Auto";

        var currentWgConnect = doc.RootElement.TryGetProperty("wireGuardConnectCommand", out var wgConnectElem)
            ? wgConnectElem.GetString() ?? string.Empty
            : string.Empty;
        var currentWgDisconnect = doc.RootElement.TryGetProperty("wireGuardDisconnectCommand", out var wgDisconnectElem)
            ? wgDisconnectElem.GetString() ?? string.Empty
            : string.Empty;
        var currentOvConnect = doc.RootElement.TryGetProperty("openVpnConnectCommand", out var ovConnectElem)
            ? ovConnectElem.GetString() ?? string.Empty
            : string.Empty;
        var currentOvDisconnect = doc.RootElement.TryGetProperty("openVpnDisconnectCommand", out var ovDisconnectElem)
            ? ovDisconnectElem.GetString() ?? string.Empty
            : string.Empty;

        var needsSync = !string.Equals(NormalizeVpnMode(currentMode), NormalizeVpnMode(selectedMode), StringComparison.OrdinalIgnoreCase)
                        || !string.Equals(currentWgConnect, WgConnectTextBox.Text, StringComparison.Ordinal)
                        || !string.Equals(currentWgDisconnect, WgDisconnectTextBox.Text, StringComparison.Ordinal)
                        || !string.Equals(currentOvConnect, OvConnectTextBox.Text, StringComparison.Ordinal)
                        || !string.Equals(currentOvDisconnect, OvDisconnectTextBox.Text, StringComparison.Ordinal);

        if (!needsSync)
        {
            return true;
        }

        var masterKey = PromptForMasterKey("Sync VPN Config") ?? string.Empty;
        if (string.IsNullOrWhiteSpace(masterKey))
        {
            return false;
        }

        var updateResult = await _apiClient.UpdateVpnConfigAsync(
            masterKey,
            selectedMode,
            WgConnectTextBox.Text,
            WgDisconnectTextBox.Text,
            OvConnectTextBox.Text,
            OvDisconnectTextBox.Text,
            cancellationToken);

        AppendOutput("VPN Config Auto Sync", updateResult);
        return IsOperationSuccessful(updateResult);
    }

    private async void SystemReset_Click(object sender, RoutedEventArgs e)
    {
        _dashboardRefreshTimer.Stop();
        try
        {
            await RunProtectedActionAsync("System Reset", (masterKey, token) => _apiClient.ResetSystemAsync(masterKey, token));
            await RefreshDashboardAsync();
            SetupOverlay.Visibility = Visibility.Visible;
            SetupStep1.Visibility = Visibility.Visible;
            SetupStep2.Visibility = Visibility.Collapsed;
            SetupStep3.Visibility = Visibility.Collapsed;
            SetupStepText.Text = "Step 1 of 3 — Set your master key";
            SetupStatusText.Visibility = Visibility.Collapsed;
            SetupMasterKeyBox.Clear();
        }
        finally
        {
            _dashboardRefreshTimer.Start();
        }
    }

    private string GenerateRecoveryKey()
    {
        const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
        var bytes = new byte[24];
        rng.GetBytes(bytes);
        var result = new System.Text.StringBuilder();
        for (int i = 0; i < 20; i++)
        {
            if (i > 0 && i % 5 == 0) result.Append('-');
            result.Append(chars[bytes[i] % chars.Length]);
        }
        return result.ToString();
    }

    private void ProfileCardHome_MouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e) => SelectProfileCard("Home");
    private void ProfileCardEnterprise_MouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e) => SelectProfileCard("Enterprise");
    private void ProfileCardCampus_MouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e) => SelectProfileCard("Campus");

    private void SelectProfileCard(string profile)
    {
        _setupSelectedProfile = profile;
        SetupProfileContinueBtn.IsEnabled = true;

        var selected = profile switch
        {
            "Home" => ProfileCardHome,
            "Enterprise" => ProfileCardEnterprise,
            _ => ProfileCardCampus
        };
        var others = new[] { ProfileCardHome, ProfileCardEnterprise, ProfileCardCampus }
            .Where(c => c != selected);

        selected.BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#185FA5"));
        selected.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#EFF6FF"));
        foreach (var card in others)
        {
            card.BorderBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString("#E4E4E7"));
            card.Background = new SolidColorBrush(Colors.White);
        }
    }

    private void SetupContinueStep0_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_setupSelectedProfile))
            return;
        SetupStep0.Visibility = Visibility.Collapsed;
        SetupStep1.Visibility = Visibility.Visible;
        SetupStepText.Text = "Step 2 of 4 — Set your master key";
    }

    private async void SetupContinueStep1_Click(object sender, RoutedEventArgs e)
    {
        var key = SetupMasterKeyBox.Password;
        var confirm = SetupConfirmMasterKeyBox.Password;

        SetupMasterKeyMatchError.Visibility = Visibility.Collapsed;
        SetupStatusText.Visibility = Visibility.Collapsed;

        if (key.Length < 8)
        {
            SetupStatusText.Text = "Master key must be at least 8 characters.";
            SetupStatusText.Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString("#A32D2D"));
            SetupStatusText.Visibility = Visibility.Visible;
            return;
        }
        if (key != confirm)
        {
            SetupMasterKeyMatchError.Visibility = Visibility.Visible;
            return;
        }
        _setupMasterKey = key;
        _setupRecoveryKey = GenerateRecoveryKey();
        SetupRecoveryKeyText.Text = _setupRecoveryKey;
        SetupStep1.Visibility = Visibility.Collapsed;
        SetupStep2.Visibility = Visibility.Visible;
        SetupStepText.Text = "Step 3 of 4 — Save your recovery key";
        await Task.CompletedTask;
    }

    private void SetupContinueStep2_Click(object sender, RoutedEventArgs e)
    {
        SetupStep2.Visibility = Visibility.Collapsed;
        SetupStep3.Visibility = Visibility.Visible;
        SetupStepText.Text = "Step 4 of 4 — Confirm your recovery key";
    }

    private void SetupBackToStep2_Click(object sender, RoutedEventArgs e)
    {
        SetupStep3.Visibility = Visibility.Collapsed;
        SetupStep2.Visibility = Visibility.Visible;
        SetupStepText.Text = "Step 3 of 4 — Save your recovery key";
        SetupConfirmRecoveryBox.Clear();
        SetupConfirmError.Visibility = Visibility.Collapsed;
    }

    private async void SetupComplete_Click(object sender, RoutedEventArgs e)
    {
        var confirmed = SetupConfirmRecoveryBox.Text.Trim();
        if (confirmed != _setupRecoveryKey)
        {
            SetupConfirmError.Text = "Recovery key does not match. Please check and try again.";
            SetupConfirmError.Visibility = Visibility.Visible;
            return;
        }
        SetupConfirmError.Visibility = Visibility.Collapsed;

        try
        {
            await _apiClient.InitMasterKeyAsync(
                _setupMasterKey,
                _setupRecoveryKey,
                CancellationToken.None);
            if (!string.IsNullOrEmpty(_setupSelectedProfile))
            {
                await _apiClient.UpdateProtectionProfileAsync(
                    _setupMasterKey,
                    _setupSelectedProfile,
                    CancellationToken.None);
                UpdateSidebarProfile(_setupSelectedProfile);
            }
            _setupMasterKey = string.Empty;
            SetupOverlay.Visibility = Visibility.Collapsed;
            await RefreshDashboardAsync();
            SetActiveNav(NavBorderDashboard, NavTextDashboard);
        }
        catch (Exception ex)
        {
            SetupStatusText.Text = $"Setup failed: {ex.Message}";
            SetupStatusText.Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString("#A32D2D"));
            SetupStatusText.Visibility = Visibility.Visible;
        }
    }

    private async void RefreshDashboard_Click(object sender, RoutedEventArgs e)
    {
        await RefreshDashboardAsync();
    }

    private async void RevertNetworkBlock_Click(object sender, RoutedEventArgs e)
    {
        _dashboardRefreshTimer.Stop();
        try
        {
            await RunProtectedActionAsync("Revert Network Block", (masterKey, token) =>
                _apiClient.ManualUnblockEnforcementAsync(masterKey, token));
            await RefreshDashboardAsync();
        }
        finally
        {
            _dashboardRefreshTimer.Start();
        }
    }

    private async void ApplyDeploymentProfile_Click(object sender, RoutedEventArgs e)
    {
        _dashboardRefreshTimer.Stop();
        try
        {
            await RunProtectedActionAsync("Apply Deployment Profile", (masterKey, token) =>
                _apiClient.UpdateProtectionProfileAsync(masterKey, GetSelectedDeploymentProfileValue(), token));
            SidebarProfileText.Text = GetSelectedDeploymentProfileValue();
            _skipNextProfilePopulate = true;
            await RefreshDashboardAsync();
        }
        finally
        {
            _dashboardRefreshTimer.Start();
        }
    }

    private void ToggleApiUrl_Click(object sender, RoutedEventArgs e)
    {
        ApiBaseUrlTextBox.Visibility = ApiBaseUrlTextBox.Visibility == Visibility.Visible
            ? Visibility.Collapsed
            : Visibility.Visible;
    }

    private void SetActiveNav(Border border, TextBlock text)
    {
        if (_activeNavBorder != null)
        {
            _activeNavBorder.Background = new SolidColorBrush(Colors.Transparent);
            _activeNavBorder.BorderThickness = new Thickness(0);
        }
        if (_activeNavText != null)
        {
            _activeNavText.Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString("#71717A"));
            _activeNavText.FontWeight = FontWeights.Normal;
        }
        border.Background = new SolidColorBrush(
            (Color)ColorConverter.ConvertFromString("#EFF6FF"));
        border.BorderBrush = new SolidColorBrush(
            (Color)ColorConverter.ConvertFromString("#185FA5"));
        border.BorderThickness = new Thickness(2, 0, 0, 0);
        text.Foreground = new SolidColorBrush(
            (Color)ColorConverter.ConvertFromString("#18181B"));
        text.FontWeight = FontWeights.Medium;
        _activeNavBorder = border;
        _activeNavText = text;
    }

    private void ShowPage(UIElement page, string title)
    {
        PageDashboard.Visibility = Visibility.Collapsed;
        PageNearby.Visibility   = Visibility.Collapsed;
        PageLog.Visibility      = Visibility.Collapsed;
        PageTrusted.Visibility  = Visibility.Collapsed;
        PageKeys.Visibility     = Visibility.Collapsed;
        PageVpn.Visibility      = Visibility.Collapsed;
        PageSettings.Visibility = Visibility.Collapsed;
        page.Visibility = Visibility.Visible;
        PageTitleText.Text = title;
    }

    private void NavDashboard_Click(object sender, RoutedEventArgs e)
    {
        SetActiveNav(NavBorderDashboard, NavTextDashboard);
        ShowPage(PageDashboard, "Dashboard");
    }

    private void NavNearby_Click(object sender, RoutedEventArgs e)
    {
        SetActiveNav(NavBorderNearby, NavTextNearby);
        ShowPage(PageNearby, "Nearby Networks");
    }

    private async void NavLog_Click(object sender, RoutedEventArgs e)
    {
        SetActiveNav(NavBorderLog, NavTextLog);
        ShowPage(PageLog, "Activity Log");
        await LoadAuditLogAsync();
    }

    private void NavTrusted_Click(object sender, RoutedEventArgs e)
    {
        SetActiveNav(NavBorderTrusted, NavTextTrusted);
        ShowPage(PageTrusted, "Trusted Networks");
    }

    private void NavKeys_Click(object sender, RoutedEventArgs e)
    {
        SetActiveNav(NavBorderKeys, NavTextKeys);
        ShowPage(PageKeys, "Recovery");
    }

    private void NavVpn_Click(object sender, RoutedEventArgs e)
    {
        SetActiveNav(NavBorderVpn, NavTextVpn);
        ShowPage(PageVpn, "VPN & Firewall");
    }

    private void NavSettings_Click(object sender, RoutedEventArgs e)
    {
        SetActiveNav(NavBorderSettings, NavTextSettings);
        ShowPage(PageSettings, "Settings");
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        SetActiveNav(NavBorderDashboard, NavTextDashboard);
        NearbyWifiListBoxFull.ItemsSource = _nearbyWifiItems;
        TrustedNetworkListBox.ItemsSource = _trustedNetworkItems;
        await RefreshDashboardAsync();

        try
        {
            var masterKeyJson = await _apiClient.GetMasterKeyStatusAsync(CancellationToken.None);
            var isInitialized = masterKeyJson.Contains("true", StringComparison.OrdinalIgnoreCase)
                || masterKeyJson.Contains("\"initialized\":true", StringComparison.OrdinalIgnoreCase);
            if (!isInitialized)
            {
                SetupStep0.Visibility = Visibility.Visible;
                SetupStep1.Visibility = Visibility.Collapsed;
                SetupStepText.Text = "Step 1 of 4 — Choose your environment";
                SetupOverlay.Visibility = Visibility.Visible;
                return;
            }
        }
        catch
        {
        }

        try
        {
            var enforcementJson = await _apiClient.GetEnforcementStatusAsync(CancellationToken.None);
            bool wasBlocking = false;
            using var enfDoc = JsonDocument.Parse(enforcementJson);
            if (enfDoc.RootElement.TryGetProperty("isBlockingActive", out var bv))
                wasBlocking = bv.GetBoolean();

            if (wasBlocking)
            {
                ShowStyledDialog(
                    "Blocking was active on last close",
                    "RogueAP Shield was closed while internet blocking was active.\n\nA rogue access point may still be present. Internet access remains blocked until you manually unblock or connect to a trusted network.",
                    isError: true);
            }
        }
        catch { }

        await RunActionAsync("VPN Config (initial)", async token =>
        {
            var json = await _apiClient.GetVpnConfigAsync(token);
            TryPopulateVpnConfigControls(json);
            return "VPN configuration loaded.";
        });
        await RunActionAsync("Nearby Wi-Fi (initial)", async token =>
        {
            var json = await _apiClient.GetNearbyWifiAsync(token);
            PopulateNearbyWifi(json);
            return "Nearby Wi-Fi list initialized.";
        });
    }

    private async void Window_Closing(object sender, System.ComponentModel.CancelEventArgs e)
    {
        bool isBlocking = false;
        try
        {
            var status = await _apiClient.GetEnforcementStatusAsync(CancellationToken.None);
            using var doc = JsonDocument.Parse(status);
            if (doc.RootElement.TryGetProperty("isBlockingActive", out var val))
                isBlocking = val.GetBoolean();
        }
        catch { }

        if (!isBlocking) return;

        e.Cancel = true;

        var confirmed = ShowStyledConfirmDialog(
            "Active protection — confirm exit",
            "Internet blocking is currently active to protect you from a detected rogue access point.\n\nClosing the app will remove this protection. Are you sure you want to close?");

        if (!confirmed) return;

        var key = PromptForMasterKey("Confirm exit — enter master key");
        if (key == null) return;

        bool verified = false;
        try
        {
            var (isValid, _) = await _apiClient.VerifyMasterKeyAsync(key, CancellationToken.None);
            verified = isValid;
        }
        catch { }

        if (!verified)
        {
            ShowStyledDialog("Authentication failed", "Incorrect master key. Exit cancelled.", isError: true);
            return;
        }

        Application.Current.Shutdown();
    }

    private void TryPopulateVpnConfigControls(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.ValueKind != JsonValueKind.Object)
            {
                return;
            }

            var mode = doc.RootElement.TryGetProperty("mode", out var modeElement)
                ? modeElement.GetString() ?? "Auto"
                : "Auto";

            SelectVpnMode(mode);

            if (doc.RootElement.TryGetProperty("wireGuardConnectCommand", out var wgConn) && wgConn.ValueKind == JsonValueKind.String)
            {
                WgConnectTextBox.Text = wgConn.GetString() ?? string.Empty;
            }

            if (doc.RootElement.TryGetProperty("wireGuardDisconnectCommand", out var wgDisconn) && wgDisconn.ValueKind == JsonValueKind.String)
            {
                WgDisconnectTextBox.Text = wgDisconn.GetString() ?? string.Empty;
            }

            if (doc.RootElement.TryGetProperty("openVpnConnectCommand", out var ovConn) && ovConn.ValueKind == JsonValueKind.String)
            {
                OvConnectTextBox.Text = ovConn.GetString() ?? string.Empty;
            }

            if (doc.RootElement.TryGetProperty("openVpnDisconnectCommand", out var ovDisconn) && ovDisconn.ValueKind == JsonValueKind.String)
            {
                OvDisconnectTextBox.Text = ovDisconn.GetString() ?? string.Empty;
            }
        }
        catch
        {
        }
    }

    private void SelectVpnMode(string mode)
    {
        var target = NormalizeVpnMode(mode);

        foreach (var item in VpnModeComboBox.Items)
        {
            if (item is not ComboBoxItem comboItem)
            {
                continue;
            }

            var value = comboItem.Content?.ToString() ?? string.Empty;
            if (string.Equals(NormalizeVpnMode(value), target, StringComparison.OrdinalIgnoreCase))
            {
                VpnModeComboBox.SelectedItem = comboItem;
                return;
            }
        }

        VpnModeComboBox.SelectedIndex = 0;
    }

    private void SelectDeploymentProfile(string profile)
    {
        var target = (profile ?? "Home").Trim();
        foreach (var item in DeploymentProfileComboBox.Items)
        {
            if (item is not ComboBoxItem comboItem)
            {
                continue;
            }

            var value = comboItem.Content?.ToString() ?? string.Empty;
            if (string.Equals(value, target, StringComparison.OrdinalIgnoreCase))
            {
                DeploymentProfileComboBox.SelectedItem = comboItem;
                SyncSettingsProfileComboBox(DeploymentProfileComboBox.SelectedIndex);
                ApplyProfileDisplayUpdates(target);
                return;
            }
        }

        DeploymentProfileComboBox.SelectedIndex = 0;
        SyncSettingsProfileComboBox(0);
        ApplyProfileDisplayUpdates("Home");
    }

    private void ApplyProfileDisplayUpdates(string profile)
    {
        var (abbrev, fg, bg) = profile.ToLowerInvariant() switch
        {
            "enterprise" => ("EN", "#3B6D11", "#F0FDF4"),
            "campus"     => ("CA", "#854F0B", "#FFFBEB"),
            _            => ("HM", "#185FA5", "#EFF6FF")
        };
        var fgBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(fg));
        var bgBrush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(bg));
        if (SidebarProfileIcon != null)
        {
            SidebarProfileIcon.Text = abbrev;
            SidebarProfileIcon.Foreground = fgBrush;
            SidebarProfileIconBorder.Background = bgBrush;
        }
        if (DashboardProfileIcon != null)
        {
            DashboardProfileIcon.Text = abbrev;
            DashboardProfileIcon.Foreground = fgBrush;
            DashboardProfileIconBorder.Background = bgBrush;
        }
        if (DashboardProfileLabel != null) DashboardProfileLabel.Text = profile + " mode";
        if (SidebarProfileText != null) SidebarProfileText.Text = profile;
    }

    private void UpdateSidebarProfile(string profile)
    {
        ApplyProfileDisplayUpdates(profile);
    }

    private void SyncSettingsProfileComboBox(int index)
    {
        if (SettingsDeploymentProfileComboBox != null &&
            index >= 0 &&
            index < SettingsDeploymentProfileComboBox.Items.Count)
        {
            SettingsDeploymentProfileComboBox.SelectedIndex = index;
        }
    }

    private void SettingsProfileComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (DeploymentProfileComboBox != null &&
            SettingsDeploymentProfileComboBox.SelectedIndex >= 0)
        {
            DeploymentProfileComboBox.SelectedIndex =
                SettingsDeploymentProfileComboBox.SelectedIndex;
        }
    }

    private string GetSelectedDeploymentProfileValue()
    {
        if (DeploymentProfileComboBox.SelectedItem is ComboBoxItem item)
        {
            var value = item.Content?.ToString();
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return "Home";
    }

    private string GetSelectedVpnModeValue()
    {
        if (VpnModeComboBox.SelectedItem is ComboBoxItem item)
        {
            var value = item.Content?.ToString();
            if (!string.IsNullOrWhiteSpace(value))
            {
                return value;
            }
        }

        return "Auto";
    }

    private record ColorScheme(string Primary, string Light, string Border, string Label);

    private static ColorScheme GetStatusColorScheme(
        int riskScore, string riskLevel, bool isLearning, bool isBlocking, bool isConnected, bool isTrustedNetwork)
    {
        if (!isConnected)
            return new ColorScheme("#71717A", "#F4F4F5", "#E4E4E7", "Not connected");
        if (isLearning)
            return new ColorScheme("#185FA5", "#EFF6FF", "#BFDBFE", "Learning");
        if (isBlocking)
            return new ColorScheme("#791F1F", "#FEF2F2", "#FCA5A5", "Blocked");
        // FIX 1: Show "Protected" for trusted networks with 0 risk
        if (isConnected && isTrustedNetwork && riskScore == 0)
            return new ColorScheme("#3B6D11", "#F0FDF4", "#86EFAC", "Protected");
        return riskLevel.ToLowerInvariant() switch
        {
            "low"      => new ColorScheme("#3B6D11", "#F0FDF4", "#86EFAC", "Protected"),
            "medium"   => new ColorScheme("#854F0B", "#FFFBEB", "#FCD34D", "Caution"),
            "high"     => new ColorScheme("#A32D2D", "#FEF2F2", "#FCA5A5", "High Risk"),
            "critical" => new ColorScheme("#791F1F", "#FEF2F2", "#FCA5A5", "Critical"),
            // FIX 1: "Unknown" should never show for connected networks
            _ => isConnected
                ? new ColorScheme("#854F0B", "#FFFBEB", "#FCD34D", "Scanning")
                : new ColorScheme("#71717A", "#F4F4F5", "#E4E4E7", "Not connected")
        };
    }

    private bool IsConnectedToNetwork()
    {
        return DashboardConnectedText?.Text is not null
            and not ""
            and not "Not connected";
    }

    private void UpdateRiskGauge(int score)
    {
        // FIX 2: Correct circumference calculation
        // Ellipse is 90x90, stroke is 8px
        // Radius = (diameter/2) - (stroke/2) = 45 - 4 = 41
        const double radius = 41.0;
        const double circumference = 2 * Math.PI * radius; // = 257.6

        var clamped = Math.Clamp(score, 0, 100);
        var filled = circumference * clamped / 100.0;
        var empty = circumference - filled;

        RiskGaugeArc.StrokeDashArray = new DoubleCollection { filled, empty };

        var color = score switch
        {
            0 when !IsConnectedToNetwork() => "#71717A",
            0 => "#3B6D11",
            <= 34 => "#3B6D11",
            <= 59 => "#854F0B",
            <= 79 => "#A32D2D",
            _ => "#791F1F"
        };

        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(color));
        RiskGaugeArc.Stroke = brush;
        RiskGaugeScore.Text = score.ToString();
        RiskGaugeScore.Foreground = brush;

        // Update background ring to lighter version
        var bgColor = score switch
        {
            0 => "#E4E4E7",
            <= 34 => "#C0DD97",
            <= 59 => "#FAC775",
            <= 79 => "#F7C1C1",
            _ => "#F09595"
        };
        RiskGaugeBackground.Stroke = new SolidColorBrush((Color)ColorConverter.ConvertFromString(bgColor));
    }

    private void UpdateTopBarStatus(ColorScheme scheme)
    {
        TopBarStatusText.Text = scheme.Label;
        TopBarStatusChip.Background = new SolidColorBrush((Color)ColorConverter.ConvertFromString(scheme.Primary));
        TopBarStatusText.Foreground = new SolidColorBrush(Colors.White);
    }

    private static string NormalizeVpnMode(string mode)
    {
        if (string.IsNullOrWhiteSpace(mode))
        {
            return "auto";
        }

        return mode.Trim().ToLowerInvariant();
    }

    private sealed record NearbyWifiItem(
        string Ssid,
        string Bssid,
        string SecurityProtocol,
        string SignalStrength,
        bool IsTrusted = false,
        bool IsSuspicious = false)
    {
        public string DisplayText =>
            $"{Ssid} | {Bssid} | {SecurityProtocol} | Signal {SignalStrength}";

        public string TrustLabel => IsSuspicious ? "Suspicious" :
                                    IsTrusted ? "Trusted" : "Unknown";

        public string ShortSecurity => SecurityProtocol switch
        {
            var s when s.Contains("WPA3") => "WPA3",
            var s when s.Contains("WPA2") => "WPA2",
            var s when s.Contains("WPA") => "WPA",
            var s when s.Contains("Open") => "Open",
            _ => SecurityProtocol.Length > 8
                 ? SecurityProtocol[..8]
                 : SecurityProtocol
        };

        public int SignalBars
        {
            get
            {
                if (!int.TryParse(SignalStrength.Replace(" dBm", "").Trim(), out var dbm)) return 1;
                return dbm switch
                {
                    >= -50 => 4,
                    >= -65 => 3,
                    >= -75 => 2,
                    _      => 1
                };
            }
        }

        public bool HasAnySignal => SignalBars >= 1;

        public string SignalColor => IsSuspicious ? "#A32D2D" : IsTrusted ? "#3B6D11" : "#185FA5";
    }

    private sealed record TrustedNetworkItem(
        string Ssid,
        string Bssid,
        string SecurityProtocol,
        string AddedAt)
    {
        public string ShortDate =>
            DateTimeOffset.TryParse(AddedAt, out var d)
            ? d.LocalDateTime.ToString("dd MMM yyyy")
            : AddedAt;
    }

    private sealed record RiskSignalItem(string Text, string DotColor);

    private enum WarningSeverity
    {
        Notice,
        Warning,
        Critical
    }

    private async void AuditRefresh_Click(object sender, RoutedEventArgs e)
    {
        await LoadAuditLogAsync();
    }

    private async void AuditVerify_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var json = await _apiClient.VerifyAuditChainAsync(CancellationToken.None);
            using var doc = JsonDocument.Parse(json);
            var intact = doc.RootElement.GetProperty("isIntact").GetBoolean();
            var total = doc.RootElement.GetProperty("totalEntries").GetInt64();

            AuditChainStatusText.Text = intact
                ? $"Chain intact — {total} entries verified"
                : "Chain integrity FAILED — tampering detected";
            AuditChainStatusText.Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(intact ? "#3B6D11" : "#A32D2D")!);
        }
        catch (Exception ex)
        {
            AuditChainStatusText.Text = $"Verification failed: {ex.Message}";
            AuditChainStatusText.Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString("#A32D2D")!);
        }
    }

    private async Task LoadAuditLogAsync()
    {
        try
        {
            var json = await _apiClient.GetAuditLogAsync(50, CancellationToken.None);
            PopulateAuditLog(json);
        }
        catch (Exception ex)
        {
            AuditChainStatusText.Text = $"Failed to load: {ex.Message}";
        }
    }

    private void PopulateAuditLog(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var entries = new List<AuditLogDisplayItem>();
            var root = doc.RootElement.ValueKind == JsonValueKind.Array
                ? doc.RootElement
                : doc.RootElement.GetProperty("entries");

            foreach (var el in root.EnumerateArray())
            {
                var timestamp = el.TryGetProperty("timestamp", out var ts)
                    ? (DateTimeOffset.TryParse(ts.GetString(), out var dt) ? dt : DateTimeOffset.MinValue)
                    : DateTimeOffset.MinValue;

                entries.Add(new AuditLogDisplayItem(
                    el.TryGetProperty("sequence", out var seq) ? seq.GetInt64() : 0,
                    timestamp,
                    el.TryGetProperty("action", out var act) ? act.GetString() ?? "" : "",
                    el.TryGetProperty("category", out var cat) ? cat.GetString() ?? "" : "",
                    el.TryGetProperty("detail", out var det) ? det.GetString() : null));
            }

            AuditLogItemsControl.ItemsSource = entries;
            AuditEmptyText.Visibility = entries.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            AuditChainStatusText.Text = $"{entries.Count} recent entries";
        }
        catch
        {
            AuditEmptyText.Visibility = Visibility.Visible;
        }
    }

    private sealed record AuditLogDisplayItem(
        long Sequence,
        DateTimeOffset Timestamp,
        string Action,
        string Category,
        string? Detail)
    {
        public DateTimeOffset ParsedTimestamp => Timestamp.ToLocalTime();
    }

    private byte[]? _selectedRapfBytes = null;

    private void SelectRapfFile_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "RogueAP Profile (*.rapf)|*.rapf",
            Title = "Select profile file"
        };
        if (dialog.ShowDialog() == true)
        {
            _selectedRapfBytes = File.ReadAllBytes(dialog.FileName);
            SelectedRapfFileText.Text = Path.GetFileName(dialog.FileName);
            RapfPreviewCard.Visibility = Visibility.Collapsed;
            ProfileActionResultCard.Visibility = Visibility.Collapsed;
        }
    }

    private async void ExportProfile_Click(object sender, RoutedEventArgs e)
    {
        var key = PromptForMasterKey("Export profile");
        if (key == null) return;

        try
        {
            var bytes = await _apiClient.ExportProfileAsync(key, $"Export {DateTime.Now:yyyy-MM-dd}", CancellationToken.None);

            var saveDialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "RogueAP Profile (*.rapf)|*.rapf",
                FileName = $"rogueap-profile-{DateTime.Now:yyyyMMdd}.rapf",
                Title = "Save profile file"
            };

            if (saveDialog.ShowDialog() == true)
            {
                await File.WriteAllBytesAsync(saveDialog.FileName, bytes);
                ShowProfileResult($"Profile exported successfully — {bytes.Length / 1024.0:F1} KB", true);
            }
        }
        catch (Exception ex)
        {
            ShowProfileResult($"Export failed: {ex.Message}", false);
        }
    }

    private async void PreviewRapf_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedRapfBytes == null)
        {
            ShowProfileResult("Please select a .rapf file first.", false);
            return;
        }
        var key = PromptForMasterKey("Preview profile");
        if (key == null) return;

        try
        {
            var json = await _apiClient.PreviewProfileAsync(key, _selectedRapfBytes, CancellationToken.None);

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            var exportedAt = root.TryGetProperty("exportedAt", out var ea) ? ea.GetString() ?? "" : "";
            var desc = root.TryGetProperty("description", out var d) ? d.GetString() ?? "" : "";
            var netCount = root.TryGetProperty("trustedNetworkCount", out var nc) ? nc.GetInt32() : 0;
            var profCount = root.TryGetProperty("networkProfileCount", out var pc) ? pc.GetInt32() : 0;
            var hashValid = root.TryGetProperty("contentHashValid", out var hv) && hv.GetBoolean();

            RapfPreviewTitle.Text = hashValid ? "File verified — ready to import" : "Warning: content hash invalid";
            RapfPreviewDetail.Text =
                $"Exported: {exportedAt}\n" +
                $"Description: {(string.IsNullOrEmpty(desc) ? "none" : desc)}\n" +
                $"Trusted networks: {netCount}\n" +
                $"Learned profiles: {profCount}";

            RapfPreviewCard.Background = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(hashValid ? "#F0FDF4" : "#FFFBEB")!);
            RapfPreviewCard.BorderBrush = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(hashValid ? "#86EFAC" : "#FCD34D")!);
            RapfPreviewTitle.Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(hashValid ? "#166534" : "#92400E")!);
            RapfPreviewDetail.Foreground = new SolidColorBrush(
                (Color)ColorConverter.ConvertFromString(hashValid ? "#3B6D11" : "#854F0B")!);
            RapfPreviewCard.Visibility = Visibility.Visible;
        }
        catch (UnauthorizedAccessException)
        {
            ShowProfileResult("Wrong master key for this file.", false);
        }
        catch (Exception ex)
        {
            ShowProfileResult($"Preview failed: {ex.Message}", false);
        }
    }

    private async void ImportRapf_Click(object sender, RoutedEventArgs e)
    {
        if (_selectedRapfBytes == null)
        {
            ShowProfileResult("Please select a .rapf file first.", false);
            return;
        }
        var key = PromptForMasterKey("Import profile");
        if (key == null) return;

        var merge = ImportMergeMode.IsChecked == true;

        try
        {
            var json = await _apiClient.ImportProfileAsync(key, _selectedRapfBytes, merge, CancellationToken.None);

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            var success = root.TryGetProperty("success", out var s) && s.GetBoolean();
            var message = root.TryGetProperty("message", out var m) ? m.GetString() ?? "" : "";

            ShowProfileResult(message, success);
            if (success)
                await RefreshDashboardAsync();
        }
        catch (Exception ex)
        {
            ShowProfileResult($"Import failed: {ex.Message}", false);
        }
    }

    private void ShowProfileResult(string message, bool success)
    {
        ProfileActionResultText.Text = message;
        ProfileActionResultCard.Background = new SolidColorBrush(
            (Color)ColorConverter.ConvertFromString(success ? "#F0FDF4" : "#FEF2F2")!);
        ProfileActionResultCard.BorderBrush = new SolidColorBrush(
            (Color)ColorConverter.ConvertFromString(success ? "#86EFAC" : "#FCA5A5")!);
        ProfileActionResultCard.BorderThickness = new Thickness(1);
        ProfileActionResultText.Foreground = new SolidColorBrush(
            (Color)ColorConverter.ConvertFromString(success ? "#166534" : "#991B1B")!);
        ProfileActionResultCard.Visibility = Visibility.Visible;
    }

    private void CheckPendingNotification()
    {
        try
        {
            if (!File.Exists(PendingPath)) return;

            string json;

            // Read AND overwrite with empty in one step —
            // even if delete fails, empty file won't trigger again
            try
            {
                json = File.ReadAllText(PendingPath);

                // Immediately overwrite with empty BEFORE showing notification
                // This prevents re-reading even if delete fails due to permissions
                File.WriteAllText(PendingPath, "");
            }
            catch (UnauthorizedAccessException)
            {
                // Cannot access file at all — skip
                return;
            }

            // Now try to delete (best effort)
            try { File.Delete(PendingPath); }
            catch { }

            // Guard against empty file (from previous overwrite)
            if (string.IsNullOrWhiteSpace(json))
                return;

            // Guard against showing same notification twice — track timestamp
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                // Check timestamp — don't show if older than 30 seconds
                if (root.TryGetProperty(
                    "timestamp", out var ts))
                {
                    if (DateTimeOffset.TryParse(
                        ts.GetString(),
                        out var notifTime))
                    {
                        var age = DateTimeOffset.UtcNow
                            - notifTime;
                        if (age.TotalSeconds > 30)
                        {
                            // Stale notification — discard silently
                            return;
                        }
                    }
                }

                var title = root.TryGetProperty(
                    "title", out var t)
                    ? t.GetString()
                        ?? "RogueAP Shield"
                    : "RogueAP Shield";

                var message = root.TryGetProperty(
                    "message", out var m)
                    ? m.GetString() ?? ""
                    : "";

                var severity = root.TryGetProperty(
                    "severity", out var s)
                    ? s.GetString() ?? ""
                    : "";

                Application.Current.Dispatcher
                    .Invoke(() =>
                {
                    try
                    {
                        var builder =
                            new ToastContentBuilder()
                                .AddText(title)
                                .AddText(message)
                                .AddAttributionText(
                                    "RogueAP Shield");

                        if (severity is "Critical"
                            or "High")
                        {
                            builder.SetToastScenario(
                                ToastScenario.Alarm);
                        }

                        builder.Show();
                    }
                    catch { }
                });
            }
            catch { }
        }
        catch { }
    }
}
