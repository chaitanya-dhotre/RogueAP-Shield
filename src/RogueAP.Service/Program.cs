using RogueAP.Infrastructure.DependencyInjection;
using Microsoft.Extensions.Options;
using RogueAP.Core.Interfaces;
using RogueAP.Core.Models;
using RogueAP.Core.Options;
using RogueAP.Service;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

builder.Host.UseWindowsService(options =>
{
	options.ServiceName = "RogueAP Shield";
});

builder.Services.AddRogueApProtection(builder.Configuration);
builder.Services.AddHostedService<Worker>();
builder.Services.AddRateLimiter(options =>
{
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: context.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 60,
                Window = TimeSpan.FromSeconds(10),
                QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                QueueLimit = 2
            }));

    options.OnRejected = async (context, token) =>
    {
        context.HttpContext.Response.StatusCode = 429;
        await context.HttpContext.Response.WriteAsync(
            "{\"error\":\"Too many requests. Please slow down.\"}",
            token);
    };
});

var app = builder.Build();
app.UseRateLimiter();

var controlApiOptions = app.Services.GetRequiredService<IOptions<ControlApiOptions>>().Value;
if (controlApiOptions.Enabled)
{
	app.Urls.Clear();
	app.Urls.Add(controlApiOptions.Url);

	var control = app.MapGroup("/control");

	control.MapGet("/health", () => Results.Ok(new { status = "ok", utc = DateTimeOffset.UtcNow }));

	control.MapGet("/health/watchdog", (IAssessmentStateStore store) =>
	{
		var responsive = store.IsServiceResponsive();
		return responsive
			? Results.Ok(new { responsive = true, message = "Service heartbeat normal" })
			: Results.Ok(new { responsive = false, message = "Service may be unresponsive" });
	});

	control.MapGet("/assessment/latest", (IAssessmentStateStore stateStore) =>
	{
		var latest = stateStore.GetLatest();
		return latest is null ? Results.NotFound(new { message = "No assessment available yet." }) : Results.Ok(latest);
	});

	control.MapGet("/protection/profile", (IProtectionRuntimeConfigStore store) =>
		Results.Ok(new { deploymentProfile = store.GetDeploymentProfile() }));

	control.MapPost("/protection/profile", async (
		ProtectionProfileUpdateRequest request,
		IMasterKeyGate keyGate,
		IProtectionRuntimeConfigStore store,
		CancellationToken cancellationToken) =>
	{
		if (!await keyGate.VerifyMasterKeyAsync(request.MasterKey, cancellationToken))
		{
			return Results.Unauthorized();
		}

		store.SetDeploymentProfile(request.DeploymentProfile);
		return Results.Ok(new { deploymentProfile = store.GetDeploymentProfile() });
	});

	control.MapGet("/wifi/nearby", async (IWifiScanner scanner, CancellationToken cancellationToken) =>
	{
		var nearby = await scanner.ScanNearbyAsync(cancellationToken);
		var ordered = nearby.OrderByDescending(network => network.SignalStrength).ToArray();
		return Results.Ok(ordered);
	});

	control.MapGet("/wifi/connected", async (IWifiScanner scanner, CancellationToken cancellationToken) =>
	{
		var connected = await scanner.GetConnectedNetworkAsync(cancellationToken);
		return connected is null ? Results.NotFound(new { connected = false }) : Results.Ok(connected);
	});

	control.MapGet("/enforcement/status", async (IEnforcementController enforcementController, CancellationToken cancellationToken) =>
	{
		var status = await enforcementController.GetStatusAsync(cancellationToken);
		return Results.Ok(status);
	});

	control.MapPost("/enforcement/unblock", async (
		EnforcementUnblockRequest request,
		IMasterKeyGate keyGate,
		IEnforcementController enforcementController,
		IWifiScanner scanner,
		IVpnRuntimeConfigStore configStore,
		CancellationToken cancellationToken) =>
	{
		if (!await keyGate.VerifyMasterKeyAsync(request.MasterKey, cancellationToken))
		{
			return Results.Unauthorized();
		}

		await enforcementController.UnblockInternetAsync("Manual unblock requested from control panel.", cancellationToken);

		// FIX 3: Suppress auto-blocking until network changes
		var currentConnected = await scanner.GetConnectedNetworkAsync(cancellationToken);
		if (currentConnected != null)
		{
			configStore.SuppressBlockingUntilNetworkChange(currentConnected.Bssid);
		}

		var status = await enforcementController.GetStatusAsync(cancellationToken);
		return Results.Ok(new { reverted = !status.IsBlockingActive, status });
	});

	control.MapGet("/vpn/status", async (IVpnIntegrationService vpn, CancellationToken cancellationToken) =>
	{
		var status = await vpn.GetStatusAsync(cancellationToken);
		return Results.Ok(status);
	});

	control.MapGet("/vpn/config", (IVpnRuntimeConfigStore store) => Results.Ok(store.GetCurrent()));

	control.MapPost("/vpn/config", async (
		VpnConfigUpdateRequest request,
		IMasterKeyGate masterKeyGate,
		IVpnRuntimeConfigStore store,
		CancellationToken cancellationToken) =>
	{
		if (!await masterKeyGate.VerifyMasterKeyAsync(request.MasterKey, cancellationToken))
		{
			return Results.Unauthorized();
		}

		store.Update(new VpnRuntimeConfigUpdate(
			request.Mode,
			request.WireGuardConnectCommand,
			request.WireGuardDisconnectCommand,
			request.OpenVpnConnectCommand,
			request.OpenVpnDisconnectCommand,
			null));

		return Results.Ok(store.GetCurrent());
	});

	control.MapPost("/vpn/connect", async (
		IVpnIntegrationService vpn,
		IVpnRuntimeConfigStore store,
		IAssessmentStateStore stateStore,
		IAuditLogger auditLogger,
		CancellationToken cancellationToken) =>
	{
		await auditLogger.LogAsync(
			"VPN_MANUAL_CONNECT_REQUESTED",
			"VPN",
			"User requested VPN connect via UI",
			ct: cancellationToken);

		// FIX 1: Mark VPN as user-connected
		stateStore.SetVpnUserConnected(true);

		var success = await vpn.TryConnectAsync(cancellationToken);

		await auditLogger.LogAsync(
			success ? "VPN_CONNECTED" : "VPN_CONNECT_FAILED",
			"VPN",
			success
				? "VPN connection established successfully"
				: "VPN connection attempt failed",
			ct: cancellationToken);

		if (success)
		{
			store.SetAutoConnectSuppressedUntil(null);
			return Results.Ok(new { connected = true });
		}

		return Results.BadRequest(new { connected = false });
	});

	control.MapPost("/vpn/disconnect", async (
		IVpnIntegrationService vpn,
		IVpnRuntimeConfigStore store,
		IAssessmentStateStore stateStore,
		IAuditLogger auditLogger,
		CancellationToken cancellationToken) =>
	{
		await auditLogger.LogAsync(
			"VPN_MANUAL_DISCONNECT_REQUESTED",
			"VPN",
			"User requested VPN disconnect via UI",
			ct: cancellationToken);

		// FIX 1: Clear user-connected flag
		stateStore.SetVpnUserConnected(false);

		var success = await vpn.TryDisconnectAsync(cancellationToken);

		await auditLogger.LogAsync(
			success
				? "VPN_DISCONNECTED"
				: "VPN_DISCONNECT_FAILED",
			"VPN",
			success
				? "VPN disconnected successfully"
				: "VPN disconnect attempt failed",
			ct: cancellationToken);

		if (success)
		{
			var suppressedUntil = DateTimeOffset.UtcNow.AddMinutes(5);
			store.SetAutoConnectSuppressedUntil(suppressedUntil);
			return Results.Ok(new { disconnected = true, autoConnectSuppressedUntilUtc = suppressedUntil });
		}

		return Results.BadRequest(new { disconnected = false });
	});

	control.MapGet("/trusted-networks", async (ITrustedNetworkRepository repository, CancellationToken cancellationToken) =>
	{
		var trusted = await repository.GetAllAsync(cancellationToken);
		return Results.Ok(trusted);
	});

	control.MapPost("/trusted-networks", async (
		TrustedNetworkUpsertRequest request,
		IWifiScanner scanner,
		ITrustedNetworkRepository repository,
		IMasterKeyGate masterKeyGate,
		IBeaconFrameService beaconFrameService,
		INetworkLearningService learningService,
		IAuditLogger auditLogger,
		CancellationToken cancellationToken) =>
	{
		if (!await masterKeyGate.VerifyMasterKeyAsync(request.MasterKey, cancellationToken))
		{
			return Results.Unauthorized();
		}

		string? vendorOui = null;
		double? bandGHz = null;
		int? channel = null;
		string? gatewayIp = null;
		string? dhcpServerIp = null;
		int? gatewayTtl = null;
		var securityProtocol = request.SecurityProtocol;

		var connected = await scanner.GetConnectedNetworkAsync(cancellationToken);
		if (connected is not null
			&& string.Equals(connected.Bssid, request.Bssid, StringComparison.OrdinalIgnoreCase))
		{
			vendorOui = connected.VendorOui;
			bandGHz = connected.BandGHz;
			channel = connected.Channel;
			gatewayIp = connected.GatewayIp;
			dhcpServerIp = connected.DhcpServerIp;
			gatewayTtl = connected.ObservedGatewayTtl ?? connected.GatewayTtl;
			securityProtocol = connected.SecurityProtocol;
		}

		if (string.IsNullOrWhiteSpace(vendorOui) && !string.IsNullOrWhiteSpace(request.Bssid))
		{
			var parts = request.Bssid.Split(':', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
			if (parts.Length >= 3)
			{
				vendorOui = $"{parts[0]}:{parts[1]}:{parts[2]}".ToUpperInvariant();
			}
		}

		string? beaconFingerprintHash = null;
		var fingerprint = beaconFrameService.GetLatestFingerprint(request.Bssid);
		if (fingerprint is not null)
		{
			beaconFingerprintHash = fingerprint.FingerprintHash;
		}

		var network = new TrustedNetwork(
			request.Ssid,
			request.Bssid,
			securityProtocol,
			DateTimeOffset.UtcNow,
			bandGHz,
			channel,
			vendorOui,
			gatewayIp,
			dhcpServerIp,
			gatewayTtl,
			BeaconFingerprintHash: beaconFingerprintHash);

		await repository.AddOrUpdateAsync(network, cancellationToken);

		// FIX 1: Stop learning when network is manually trusted
		var existingProfile = await learningService.GetProfileAsync(network.Ssid, cancellationToken);
		if (existingProfile != null && !existingProfile.LearningComplete)
		{
			await learningService.CompleteLearningAsync(network.Ssid, cancellationToken);

			await auditLogger.LogAsync(
				"LEARNING_COMPLETED_BY_TRUST",
				"LEARNING",
				$"Learning stopped for '{network.Ssid}' because network was manually trusted.",
				network.Ssid,
				cancellationToken);
		}

		return Results.Ok(network);
	});

	control.MapDelete("/trusted-networks/{bssid}", async (
		string bssid,
		string masterKey,
		ITrustedNetworkRepository repository,
		IMasterKeyGate masterKeyGate,
		CancellationToken cancellationToken) =>
	{
		if (!await masterKeyGate.VerifyMasterKeyAsync(masterKey, cancellationToken))
		{
			return Results.Unauthorized();
		}

		var removed = await repository.RemoveByBssidAsync(bssid, cancellationToken);
		return removed ? Results.Ok(new { removed = true }) : Results.NotFound(new { removed = false });
	});

	control.MapGet("/master-key/status", (IMasterKeyGate keyGate) => Results.Ok(new { initialized = keyGate.IsInitialized }));

	control.MapPost("/master-key/init", async (
		MasterKeyInitRequest request,
		IMasterKeyGate keyGate,
		IAuditLogger auditLogger,
		CancellationToken cancellationToken) =>
	{
		await keyGate.InitializeAsync(request.MasterKey, request.RecoveryKey, cancellationToken);
		await auditLogger.LogAsync(
			"MASTER_KEY_INITIALIZED",
			"AUTH",
			ct: cancellationToken);
		return Results.Ok(new { initialized = true });
	});

	control.MapPost("/master-key/verify", async (
		MasterKeyVerifyRequest request,
		IMasterKeyGate keyGate,
		IAuditLogger auditLogger,
		CancellationToken cancellationToken) =>
	{
		var valid = await keyGate.VerifyMasterKeyAsync(request.MasterKey, cancellationToken);
		if (valid)
		{
			await auditLogger.LogAsync(
				AuditActions.MasterKeyVerified,
				AuditCategories.Auth,
				ct: cancellationToken);
		}
		else
		{
			await auditLogger.LogAsync(
				AuditActions.MasterKeyWrongAttempt,
				AuditCategories.Auth,
				"Invalid master key submitted",
				ct: cancellationToken);
		}
		return Results.Ok(new { valid });
	});

	control.MapPost("/master-key/recover", async (
		MasterKeyRecoverRequest request,
		IMasterKeyGate keyGate,
		CancellationToken cancellationToken) =>
	{
		var recovered = await keyGate.RecoverWithRecoveryKeyAsync(
			request.RecoveryKey,
			request.NewMasterKey,
			request.NewRecoveryKey,
			cancellationToken);

		return recovered ? Results.Ok(new { recovered = true }) : Results.BadRequest(new { recovered = false });
	});

	control.MapPost("/system/reset", async (
		SystemResetRequest request,
		IMasterKeyGate keyGate,
		ISystemResetService resetService,
		IAuditLogger auditLogger,
		CancellationToken cancellationToken) =>
	{
		if (!await keyGate.VerifyMasterKeyAsync(request.MasterKey, cancellationToken))
		{
			return Results.Unauthorized();
		}

		await auditLogger.LogAsync(
			AuditActions.FactoryReset,
			AuditCategories.System,
			ct: cancellationToken);

		await resetService.ResetAllAsync(cancellationToken);
		return Results.Ok(new { reset = true, message = "System state has been reset." });
	});

	control.MapGet("/audit/recent", async (
		int? count,
		IAuditLogger auditLogger,
		CancellationToken cancellationToken) =>
	{
		var entries = await auditLogger.GetRecentAsync(count ?? 50, cancellationToken);
		return Results.Ok(entries);
	});

	control.MapGet("/audit/verify", async (
		IAuditLogger auditLogger,
		CancellationToken cancellationToken) =>
	{
		var status = await auditLogger.VerifyChainIntegrityAsync(cancellationToken);
		return Results.Ok(status);
	});

	control.MapGet("/learning/status/{ssid}", async (
		string ssid,
		INetworkLearningService learningService,
		CancellationToken cancellationToken) =>
	{
		var profile = await learningService.GetProfileAsync(ssid, cancellationToken);
		if (profile is null)
		{
			return Results.NotFound(new { ssid, exists = false });
		}

		var isLearning = learningService.IsLearning(ssid);
		double? hoursRemaining = null;
		if (isLearning && !profile.LearningComplete)
		{
			var elapsed = DateTimeOffset.UtcNow - profile.LearningStartedAt;
			var remaining = profile.LearningDurationHours - elapsed.TotalHours;
			hoursRemaining = Math.Max(0, remaining);
		}

		return Results.Ok(new
		{
			ssid = profile.Ssid,
			isLearning,
			learningComplete = profile.LearningComplete,
			hoursRemaining,
			knownBssidCount = profile.KnownBssids.Count,
			learnedFingerprintCount = profile.BeaconFingerprints.Count
		});
	});

	control.MapPost("/learning/start", async (
		LearningStartRequest request,
		IMasterKeyGate keyGate,
		INetworkLearningService learningService,
		CancellationToken cancellationToken) =>
	{
		if (!await keyGate.VerifyMasterKeyAsync(request.MasterKey, cancellationToken))
		{
			return Results.Unauthorized();
		}

		await learningService.StartLearningAsync(request.Ssid, request.DeploymentProfile, cancellationToken);
		return Results.Ok(new { started = true, ssid = request.Ssid, deploymentProfile = request.DeploymentProfile });
	});

	control.MapPost("/learning/complete/{ssid}", async (
		string ssid,
		LearningCompleteRequest request,
		IMasterKeyGate keyGate,
		INetworkLearningService learningService,
		CancellationToken cancellationToken) =>
	{
		if (!await keyGate.VerifyMasterKeyAsync(request.MasterKey, cancellationToken))
		{
			return Results.Unauthorized();
		}

		await learningService.CompleteLearningAsync(ssid, cancellationToken);
		var profile = await learningService.GetProfileAsync(ssid, cancellationToken);
		return Results.Ok(new
		{
			completed = profile?.LearningComplete ?? false,
			ssid,
			knownBssidCount = profile?.KnownBssids.Count ?? 0
		});
	});

	control.MapPost("/learning/reset/{ssid}", async (
		string ssid,
		LearningResetRequest request,
		IMasterKeyGate keyGate,
		INetworkLearningService learningService,
		IAuditLogger auditLogger,
		CancellationToken cancellationToken) =>
	{
		if (!await keyGate.VerifyMasterKeyAsync(request.MasterKey, cancellationToken))
		{
			return Results.Unauthorized();
		}

		await learningService.ResetLearningAsync(ssid, cancellationToken);

		await auditLogger.LogAsync(
			"LEARNING_RESET",
			"LEARNING",
			$"Learning profile for '{ssid}' was manually reset.",
			ssid,
			cancellationToken);

		return Results.Ok(new { reset = true, ssid });
	});

	control.MapPost("/profile/export", async (
		ProfileExportRequest request,
		IMasterKeyGate keyGate,
		IProfileExportService exportService,
		CancellationToken cancellationToken) =>
	{
		if (!await keyGate.VerifyMasterKeyAsync(request.MasterKey, cancellationToken))
		{
			return Results.Unauthorized();
		}

		var bytes = await exportService.ExportAsync(request.MasterKey, request.Description ?? "", cancellationToken);
		return Results.File(bytes, "application/octet-stream", "rogueap-profile.rapf");
	});

	control.MapPost("/profile/preview", async (
		ProfileFileRequest request,
		IProfileExportService exportService,
		CancellationToken cancellationToken) =>
	{
		try
		{
			var rapfBytes = Convert.FromBase64String(request.FileBase64);
			var preview = await exportService.PreviewAsync(rapfBytes, request.MasterKey, cancellationToken);
			return Results.Ok(preview);
		}
		catch (InvalidDataException ex)
		{
			return Results.BadRequest(new { error = ex.Message });
		}
		catch (UnauthorizedAccessException)
		{
			return Results.Unauthorized();
		}
	});

	control.MapPost("/profile/import", async (
		ProfileImportRequest request,
		IMasterKeyGate keyGate,
		IProfileExportService exportService,
		CancellationToken cancellationToken) =>
	{
		if (!await keyGate.VerifyMasterKeyAsync(request.MasterKey, cancellationToken))
		{
			return Results.Unauthorized();
		}

		try
		{
			var rapfBytes = Convert.FromBase64String(request.FileBase64);
			var result = await exportService.ImportAsync(rapfBytes, request.MasterKey, request.MergeMode, cancellationToken);
			return Results.Ok(result);
		}
		catch (InvalidDataException ex)
		{
			return Results.BadRequest(new { error = ex.Message });
		}
		catch (UnauthorizedAccessException)
		{
			return Results.Unauthorized();
		}
	});
}

app.Run();

internal sealed record MasterKeyInitRequest(string MasterKey, string RecoveryKey);

internal sealed record MasterKeyVerifyRequest(string MasterKey);

internal sealed record MasterKeyRecoverRequest(string RecoveryKey, string NewMasterKey, string NewRecoveryKey);

internal sealed record TrustedNetworkUpsertRequest(string MasterKey, string Ssid, string Bssid, string SecurityProtocol);

internal sealed record VpnConfigUpdateRequest(
	string MasterKey,
	string? Mode,
	string? WireGuardConnectCommand,
	string? WireGuardDisconnectCommand,
	string? OpenVpnConnectCommand,
	string? OpenVpnDisconnectCommand);

internal sealed record SystemResetRequest(string MasterKey);

internal sealed record EnforcementUnblockRequest(string MasterKey);

internal sealed record ProtectionProfileUpdateRequest(string MasterKey, string DeploymentProfile);

internal sealed record LearningStartRequest(string MasterKey, string Ssid, string DeploymentProfile);

internal sealed record LearningCompleteRequest(string MasterKey);

internal sealed record LearningResetRequest(string MasterKey);

internal sealed record ProfileExportRequest(string MasterKey, string? Description);

internal sealed record ProfileFileRequest(string MasterKey, string FileBase64);

internal sealed record ProfileImportRequest(string MasterKey, string FileBase64, bool MergeMode);
