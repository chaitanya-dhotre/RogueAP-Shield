using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using RogueAP.Core.Interfaces;
using RogueAP.Core.Models;

namespace RogueAP.Infrastructure.Services;

public sealed class NativeWifiBeaconService : IBeaconFrameService
{
    private readonly ILogger<NativeWifiBeaconService> _logger;
    private readonly ConcurrentDictionary<string, BeaconFingerprint> _fingerprints = new(StringComparer.OrdinalIgnoreCase);
    private CancellationTokenSource? _scanLoopCts;
    private Task? _scanLoopTask;
    private bool _isAvailable = true;
    private CancellationTokenSource? _rescanCts;

    public NativeWifiBeaconService(ILogger<NativeWifiBeaconService> logger)
    {
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        if (_scanLoopTask is not null)
        {
            _logger.LogWarning("Beacon frame service already started");
            return Task.CompletedTask;
        }

        _scanLoopCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _scanLoopTask = Task.Run(() => ScanLoopAsync(_scanLoopCts.Token), cancellationToken);
        _logger.LogInformation("Beacon frame service started");
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_scanLoopCts is null || _scanLoopTask is null)
        {
            return;
        }

        _rescanCts?.Cancel();
        _rescanCts?.Dispose();
        _rescanCts = null;

        _scanLoopCts.Cancel();
        try
        {
            await _scanLoopTask.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken);
        }
        catch (TimeoutException)
        {
            _logger.LogWarning("Beacon frame service scan loop did not stop within timeout");
        }
        catch (OperationCanceledException)
        {
        }

        _scanLoopCts.Dispose();
        _scanLoopCts = null;
        _scanLoopTask = null;
        _logger.LogInformation("Beacon frame service stopped");
    }

    public void ScheduleRescan(TimeSpan delay)
    {
        _rescanCts?.Cancel();
        _rescanCts?.Dispose();
        _rescanCts = new CancellationTokenSource();
        var token = _rescanCts.Token;

        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(delay, token);
                await PerformScanAsync();
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception exception)
            {
                _logger.LogWarning(exception, "Scheduled beacon rescan failed");
            }
        }, token);
    }

    public BeaconFingerprint? GetLatestFingerprint(string bssid)
    {
        if (string.IsNullOrWhiteSpace(bssid))
        {
            return null;
        }

        return _fingerprints.TryGetValue(bssid, out var fingerprint) ? fingerprint : null;
    }

    public IReadOnlyDictionary<string, BeaconFingerprint> GetAllFingerprints()
    {
        return _fingerprints;
    }

    private async Task ScanLoopAsync(CancellationToken cancellationToken)
    {
        await PerformScanAsync();

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(TimeSpan.FromSeconds(30), cancellationToken);
                await PerformScanAsync();
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception exception)
            {
                _logger.LogWarning(exception, "Error in beacon frame scan loop");
            }
        }
    }

    private Task PerformScanAsync()
    {
        if (!_isAvailable)
        {
            return Task.CompletedTask;
        }

        return Task.Run(() =>
        {
            if (!OperatingSystem.IsWindows())
            {
                _logger.LogWarning("Native WiFi IE scanning is only available on Windows");
                _isAvailable = false;
                return;
            }

            try
            {
                ScanBssNetworksWithIeData();
            }
            catch (Exception exception)
            {
                _logger.LogWarning(exception, "Native WiFi IE scanning unavailable: {Message}", exception.Message);
                _isAvailable = false;
            }
        });
    }

    private void ScanBssNetworksWithIeData()
    {
        var result = WlanOpenHandle(2, IntPtr.Zero, out _, out var clientHandle);
        if (result != 0)
        {
            _logger.LogDebug("WlanOpenHandle failed with error {Error}", result);
            return;
        }

        try
        {
            result = WlanEnumInterfaces(clientHandle, IntPtr.Zero, out var interfaceListPtr);
            if (result != 0 || interfaceListPtr == IntPtr.Zero)
            {
                _logger.LogDebug("WlanEnumInterfaces failed with error {Error}", result);
                return;
            }

            try
            {
                var interfaceList = Marshal.PtrToStructure<WLAN_INTERFACE_INFO_LIST>(interfaceListPtr);
                var interfaceInfoSize = Marshal.SizeOf<WLAN_INTERFACE_INFO>();

                for (var i = 0; i < interfaceList.dwNumberOfItems; i++)
                {
                    var interfaceInfoPtr = IntPtr.Add(interfaceListPtr, 8 + (i * interfaceInfoSize));
                    var interfaceInfo = Marshal.PtrToStructure<WLAN_INTERFACE_INFO>(interfaceInfoPtr);

                    ScanInterfaceBssNetworks(clientHandle, interfaceInfo.InterfaceGuid);
                }
            }
            finally
            {
                WlanFreeMemory(interfaceListPtr);
            }
        }
        finally
        {
            WlanCloseHandle(clientHandle, IntPtr.Zero);
        }
    }

    private void ScanInterfaceBssNetworks(IntPtr clientHandle, Guid interfaceGuid)
    {
        var result = WlanGetNetworkBssList(
            clientHandle,
            ref interfaceGuid,
            IntPtr.Zero,
            WLAN_BSS_TYPE.dot11_BSS_type_any,
            false,
            IntPtr.Zero,
            out var bssListPtr);

        if (result != 0 || bssListPtr == IntPtr.Zero)
        {
            return;
        }

        try
        {
            // Read header: dwTotalSize (4 bytes) + dwNumberOfItems (4 bytes)
            var totalSize = Marshal.ReadInt32(bssListPtr, 0);
            var count = Marshal.ReadInt32(bssListPtr, 4);

            if (count <= 0 || totalSize <= 8)
            {
                return;
            }

            _logger.LogDebug("Found {Count} BSS entries for interface", count);

            // WLAN_BSS_ENTRY fixed-size layout per Windows SDK (x86/x64, no packing):
            //   offset   0: DOT11_SSID.uSSIDLength (4)
            //   offset   4: DOT11_SSID.ucSSID[32] (32)
            //   offset  36: uPhyId (4)
            //   offset  40: dot11Bssid[6] (6)
            //   offset  46: (2 padding)
            //   offset  48: dot11BssType (4)
            //   offset  52: dot11BssPhyType (4)
            //   offset  56: lRssi (4)
            //   offset  60: uLinkQuality (4)
            //   offset  64: bInRegDomain (1 BOOLEAN)
            //   offset  65: (1 padding)
            //   offset  66: usBeaconPeriod (2)
            //   offset  68: (4 padding for 8-byte alignment)
            //   offset  72: ullTimestamp (8)
            //   offset  80: ullHostTimestamp (8)
            //   offset  88: usCapabilityInformation (2)
            //   offset  90: (2 padding)
            //   offset  92: ulChCenterFrequency (4)
            //   offset  96: WLAN_RATE_SET { uRateSetLength(4) + usRateSet[126](252) } (256)
            //   offset 352: ulIeOffset (4)   <- offset from start of THIS entry to IE bytes
            //   offset 356: ulIeSize (4)
            //   total: 360 bytes
            const int entryStride = 360;
            const int bssidOffset = 40;
            const int ieOffsetFieldOff = 352;
            const int ieSizeFieldOff = 356;
            const int listHeaderSize = 8;

            for (var i = 0; i < count; i++)
            {
                var entryBase = IntPtr.Add(bssListPtr, listHeaderSize + i * entryStride);

                // Sanity: don't read past the allocated buffer
                if (listHeaderSize + (long)(i + 1) * entryStride > totalSize)
                {
                    break;
                }

                ProcessBssEntry(entryBase, bssidOffset, ieOffsetFieldOff, ieSizeFieldOff, totalSize, bssListPtr);
            }
        }
        finally
        {
            WlanFreeMemory(bssListPtr);
        }
    }

    private void ProcessBssEntry(
        IntPtr entryBase,
        int bssidOffset,
        int ieOffsetFieldOff,
        int ieSizeFieldOff,
        int totalBufSize,
        IntPtr listBase)
    {
        var bssidBytes = new byte[6];
        Marshal.Copy(IntPtr.Add(entryBase, bssidOffset), bssidBytes, 0, 6);
        var bssid = FormatBssid(bssidBytes);
        if (string.IsNullOrWhiteSpace(bssid))
        {
            return;
        }

        // ulIeOffset is the byte offset FROM THE START OF THIS ENTRY to the IE data
        var ulIeOffset = (uint)Marshal.ReadInt32(entryBase, ieOffsetFieldOff);
        var ulIeSize = (uint)Marshal.ReadInt32(entryBase, ieSizeFieldOff);

        if (ulIeSize == 0 || ulIeSize > 4096 || ulIeOffset < 360 || ulIeOffset > 65536)
        {
            return;
        }

        // IE data immediately follows the fixed portion of this entry
        var entryOffsetInBuf = entryBase.ToInt64() - listBase.ToInt64();
        if (entryOffsetInBuf + (long)ulIeOffset + (long)ulIeSize > totalBufSize)
        {
            return;
        }

        var iePtr = IntPtr.Add(entryBase, (int)ulIeOffset);
        var ieBytes = new byte[ulIeSize];
        Marshal.Copy(iePtr, ieBytes, 0, (int)ulIeSize);

        var parsedIEs = ParseInformationElements(ieBytes);
        if (parsedIEs.Count == 0)
        {
            return;
        }

        var fingerprintHash = GenerateFingerprintHash(parsedIEs);
        if (string.IsNullOrWhiteSpace(fingerprintHash))
        {
            return;
        }

        var fingerprint = new BeaconFingerprint(
            bssid,
            fingerprintHash,
            parsedIEs,
            HasQbssLoad: parsedIEs.ContainsKey(11),
            HasVhtCapabilities: parsedIEs.ContainsKey(191),
            HasHeCapabilities: parsedIEs.ContainsKey(255),
            CapturedAt: DateTime.UtcNow);

        _fingerprints[bssid] = fingerprint;
    }

    private static string FormatBssid(byte[] bssidBytes)
    {
        if (bssidBytes is null || bssidBytes.Length < 6)
        {
            return string.Empty;
        }

        return string.Join(":", bssidBytes.Take(6).Select(b => b.ToString("X2")));
    }

    private static Dictionary<int, byte[]> ParseInformationElements(byte[] ieBytes)
    {
        var result = new Dictionary<int, byte[]>();
        var offset = 0;

        while (offset + 2 <= ieBytes.Length)
        {
            var tagNumber = ieBytes[offset];
            var tagLength = ieBytes[offset + 1];
            offset += 2;

            if (offset + tagLength > ieBytes.Length)
            {
                break;
            }

            var tagData = new byte[tagLength];
            Array.Copy(ieBytes, offset, tagData, 0, tagLength);
            result[tagNumber] = tagData;
            offset += tagLength;
        }

        return result;
    }

    private static string GenerateFingerprintHash(Dictionary<int, byte[]> parsedIEs)
    {
        var relevantTags = new[] { 48, 1, 45, 191, 7, 221 };
        var concatenated = new List<byte>();

        foreach (var tag in relevantTags)
        {
            if (parsedIEs.TryGetValue(tag, out var data))
            {
                concatenated.AddRange(data);
            }
        }

        if (concatenated.Count == 0)
        {
            return string.Empty;
        }

        var hash = SHA256.HashData(concatenated.ToArray());
        return Convert.ToHexString(hash);
    }

    #region Native WiFi P/Invoke

    private const string WLANAPI = "wlanapi.dll";

    [DllImport(WLANAPI)]
    private static extern int WlanOpenHandle(
        int dwClientVersion,
        IntPtr pReserved,
        out int pdwNegotiatedVersion,
        out IntPtr phClientHandle);

    [DllImport(WLANAPI)]
    private static extern int WlanCloseHandle(
        IntPtr hClientHandle,
        IntPtr pReserved);

    [DllImport(WLANAPI)]
    private static extern int WlanEnumInterfaces(
        IntPtr hClientHandle,
        IntPtr pReserved,
        out IntPtr ppInterfaceList);

    [DllImport(WLANAPI)]
    private static extern int WlanGetNetworkBssList(
        IntPtr hClientHandle,
        ref Guid pInterfaceGuid,
        IntPtr pDot11Ssid,
        WLAN_BSS_TYPE dot11BssType,
        bool bSecurityEnabled,
        IntPtr pReserved,
        out IntPtr ppWlanBssList);

    [DllImport(WLANAPI)]
    private static extern void WlanFreeMemory(IntPtr pMemory);

    private enum WLAN_BSS_TYPE
    {
        dot11_BSS_type_infrastructure = 1,
        dot11_BSS_type_independent = 2,
        dot11_BSS_type_any = 3
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WLAN_INTERFACE_INFO_LIST
    {
        public int dwNumberOfItems;
        public int dwIndex;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WLAN_INTERFACE_INFO
    {
        public Guid InterfaceGuid;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string strInterfaceDescription;
        public int isState;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WLAN_BSS_LIST
    {
        public int dwTotalSize;
        public int dwNumberOfItems;
    }

    #endregion
}
