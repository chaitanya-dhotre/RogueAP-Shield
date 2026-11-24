using System.Net;
using System.Net.Http;
using System.Net.Http.Json;
using System.Text.Json;

namespace RogueAP.Gui.Api;

public sealed class ControlApiClient
{
    private readonly HttpClient _httpClient;

    public ControlApiClient(string baseUrl)
    {
        _httpClient = new HttpClient
        {
            BaseAddress = new Uri(baseUrl.TrimEnd('/') + "/")
        };
    }

    public async Task<string> GetHealthAsync(CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync("control/health", cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        response.EnsureSuccessStatusCode();
        return content;
    }

    public async Task<string> GetWatchdogHealthAsync(CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync("control/health/watchdog", cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        response.EnsureSuccessStatusCode();
        return content;
    }

    public async Task<string> GetMasterKeyStatusAsync(CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync("control/master-key/status", cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        response.EnsureSuccessStatusCode();
        return content;
    }

    public async Task<string> InitMasterKeyAsync(string masterKey, string recoveryKey, CancellationToken cancellationToken)
    {
        using var response = await _httpClient.PostAsJsonAsync(
            "control/master-key/init",
            new { masterKey, recoveryKey },
            cancellationToken);

        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        response.EnsureSuccessStatusCode();
        return content;
    }

    public async Task<(bool IsValid, string Raw)> VerifyMasterKeyAsync(string masterKey, CancellationToken cancellationToken)
    {
        using var response = await _httpClient.PostAsJsonAsync(
            "control/master-key/verify",
            new { masterKey },
            cancellationToken);

        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        response.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(content);
        var isValid = doc.RootElement.TryGetProperty("valid", out var validElement) && validElement.GetBoolean();
        return (isValid, content);
    }

    public async Task<string> RecoverMasterKeyAsync(string recoveryKey, string newMasterKey, string newRecoveryKey, CancellationToken cancellationToken)
    {
        using var response = await _httpClient.PostAsJsonAsync(
            "control/master-key/recover",
            new { recoveryKey, newMasterKey, newRecoveryKey },
            cancellationToken);

        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        if (!response.IsSuccessStatusCode)
        {
            return $"Recover failed ({(int)response.StatusCode}): {content}";
        }

        return content;
    }

    public async Task<string> GetTrustedNetworksAsync(CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync("control/trusted-networks", cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        response.EnsureSuccessStatusCode();
        return content;
    }

    public async Task<string> UpsertTrustedNetworkAsync(
        string masterKey,
        string ssid,
        string bssid,
        string securityProtocol,
        CancellationToken cancellationToken)
    {
        using var response = await _httpClient.PostAsJsonAsync(
            "control/trusted-networks",
            new { masterKey, ssid, bssid, securityProtocol },
            cancellationToken);

        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            return "Unauthorized: invalid master key.";
        }

        response.EnsureSuccessStatusCode();
        return content;
    }

    public async Task<string> RemoveTrustedNetworkAsync(string bssid, string masterKey, CancellationToken cancellationToken)
    {
        var requestUri = $"control/trusted-networks/{Uri.EscapeDataString(bssid)}?masterKey={Uri.EscapeDataString(masterKey)}";
        using var response = await _httpClient.DeleteAsync(requestUri, cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            return "Unauthorized: invalid master key.";
        }

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return "Not found: no trusted network with that BSSID.";
        }

        response.EnsureSuccessStatusCode();
        return content;
    }

    public async Task<string> GetVpnStatusAsync(CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync("control/vpn/status", cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        response.EnsureSuccessStatusCode();
        return content;
    }

    public async Task<string> GetVpnConfigAsync(CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync("control/vpn/config", cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        response.EnsureSuccessStatusCode();
        return content;
    }

    public async Task<string> UpdateVpnConfigAsync(
        string masterKey,
        string mode,
        string wireGuardConnectCommand,
        string wireGuardDisconnectCommand,
        string openVpnConnectCommand,
        string openVpnDisconnectCommand,
        CancellationToken cancellationToken)
    {
        using var response = await _httpClient.PostAsJsonAsync(
            "control/vpn/config",
            new
            {
                masterKey,
                mode,
                wireGuardConnectCommand,
                wireGuardDisconnectCommand,
                openVpnConnectCommand,
                openVpnDisconnectCommand
            },
            cancellationToken);

        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            return "Unauthorized: invalid master key.";
        }

        response.EnsureSuccessStatusCode();
        return content;
    }

    public async Task<string> ConnectVpnAsync(CancellationToken cancellationToken)
    {
        using var response = await _httpClient.PostAsJsonAsync("control/vpn/connect", new { }, cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        return response.IsSuccessStatusCode ? content : $"Connect failed ({(int)response.StatusCode}): {content}";
    }

    public async Task<string> DisconnectVpnAsync(CancellationToken cancellationToken)
    {
        using var response = await _httpClient.PostAsJsonAsync("control/vpn/disconnect", new { }, cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        return response.IsSuccessStatusCode ? content : $"Disconnect failed ({(int)response.StatusCode}): {content}";
    }

    public async Task<string> GetAssessmentLatestAsync(CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync("control/assessment/latest", cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);

        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return "{}";
        }

        response.EnsureSuccessStatusCode();
        return content;
    }

    public async Task<string> GetProtectionProfileAsync(CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync("control/protection/profile", cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        response.EnsureSuccessStatusCode();
        return content;
    }

    public async Task<string> UpdateProtectionProfileAsync(string masterKey, string deploymentProfile, CancellationToken cancellationToken)
    {
        using var response = await _httpClient.PostAsJsonAsync(
            "control/protection/profile",
            new { masterKey, deploymentProfile },
            cancellationToken);

        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            return "Unauthorized: invalid master key.";
        }

        response.EnsureSuccessStatusCode();
        return content;
    }

    public async Task<string> GetConnectedWifiAsync(CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync("control/wifi/connected", cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        return response.IsSuccessStatusCode ? content : "{}";
    }

    public async Task<string> GetEnforcementStatusAsync(CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync("control/enforcement/status", cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        return response.IsSuccessStatusCode ? content : "{}";
    }

    public async Task<string> ManualUnblockEnforcementAsync(string masterKey, CancellationToken cancellationToken)
    {
        using var response = await _httpClient.PostAsJsonAsync(
            "control/enforcement/unblock",
            new { masterKey },
            cancellationToken);

        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            return "Unauthorized: invalid master key.";
        }

        response.EnsureSuccessStatusCode();
        return content;
    }

    public async Task<string> GetNearbyWifiAsync(CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync("control/wifi/nearby", cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        response.EnsureSuccessStatusCode();
        return content;
    }

    public async Task<string> ResetSystemAsync(string masterKey, CancellationToken cancellationToken)
    {
        using var response = await _httpClient.PostAsJsonAsync("control/system/reset", new { masterKey }, cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            return "Unauthorized: invalid master key.";
        }

        response.EnsureSuccessStatusCode();
        return content;
    }

    public async Task<string> GetAuditLogAsync(int count, CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync($"control/audit/recent?count={count}", cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        response.EnsureSuccessStatusCode();
        return content;
    }

    public async Task<string> VerifyAuditChainAsync(CancellationToken cancellationToken)
    {
        using var response = await _httpClient.GetAsync("control/audit/verify", cancellationToken);
        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        response.EnsureSuccessStatusCode();
        return content;
    }

    public async Task<byte[]> ExportProfileAsync(string masterKey, string description, CancellationToken cancellationToken)
    {
        using var response = await _httpClient.PostAsJsonAsync(
            "control/profile/export",
            new { masterKey, description },
            cancellationToken);

        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            throw new UnauthorizedAccessException("Invalid master key.");
        }

        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsByteArrayAsync(cancellationToken);
    }

    public async Task<string> PreviewProfileAsync(string masterKey, byte[] rapfBytes, CancellationToken cancellationToken)
    {
        using var response = await _httpClient.PostAsJsonAsync(
            "control/profile/preview",
            new { masterKey, fileBase64 = Convert.ToBase64String(rapfBytes) },
            cancellationToken);

        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            throw new UnauthorizedAccessException("Invalid master key for this file.");
        }

        response.EnsureSuccessStatusCode();
        return content;
    }

    public async Task<string> ImportProfileAsync(string masterKey, byte[] rapfBytes, bool mergeMode, CancellationToken cancellationToken)
    {
        using var response = await _httpClient.PostAsJsonAsync(
            "control/profile/import",
            new { masterKey, fileBase64 = Convert.ToBase64String(rapfBytes), mergeMode },
            cancellationToken);

        var content = await response.Content.ReadAsStringAsync(cancellationToken);
        if (response.StatusCode == HttpStatusCode.Unauthorized)
        {
            throw new UnauthorizedAccessException("Invalid master key.");
        }

        response.EnsureSuccessStatusCode();
        return content;
    }
}