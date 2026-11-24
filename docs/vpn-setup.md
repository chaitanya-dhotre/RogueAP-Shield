# VPN Setup For RogueAP (Windows)

This guide shows how to test both `WireGuard` and `OpenVpn` modes in RogueAP.

## Prerequisites

- Run RogueAP Service as Administrator (required for firewall enforcement and many VPN commands).
- Keep your master key ready (VPN config update in UI requires it).

## Option A: WireGuard (recommended first)

1. Install WireGuard for Windows.
2. Get a `.conf` profile from your VPN provider (or your own WireGuard server).
3. Save it to a stable path, example:
   - `C:\VPN\wg-test.conf`
4. Use tunnel name = file name without extension:
   - `wg-test`

In RogueAP > `VPN` tab:

- Mode: `WireGuard`
- WireGuard Connect Command:

```powershell
& "C:\Program Files\WireGuard\wireguard.exe" /installtunnelservice "C:\VPN\wg-test.conf"
```

- WireGuard Disconnect Command:

```powershell
& "C:\Program Files\WireGuard\wireguard.exe" /uninstalltunnelservice wg-test
```

Notes:
- `installtunnelservice` creates/starts the tunnel service.
- `uninstalltunnelservice` removes/stops it.
- You can test manually in elevated PowerShell first.

## Option B: OpenVPN GUI

1. Install OpenVPN GUI (Community) or OpenVPN Connect.
2. Put your profile in OpenVPN GUI config folder and name it, example:
   - `C:\Users\<your-user>\OpenVPN\config\lab.ovpn`
3. Profile name here is `lab` (file name without extension).

In RogueAP > `VPN` tab:

- Mode: `OpenVpn`
- OpenVPN Connect Command:

```powershell
Start-Process -FilePath "C:\Program Files\OpenVPN\bin\openvpn-gui.exe" -WindowStyle Hidden; Start-Sleep -Seconds 2; & "C:\Program Files\OpenVPN\bin\openvpn-gui.exe" --command connect lab
```

- OpenVPN Disconnect Command:

```powershell
& "C:\Program Files\OpenVPN\bin\openvpn-gui.exe" --command disconnect lab
```

If your install path is different, update the executable path in both commands.

## Quick Validation Checklist

1. Set mode and commands, click `Update VPN Config`.
2. Click `Get VPN Status` (baseline should be disconnected).
3. Click `Connect VPN`, then `Get VPN Status` (should show connected).
4. Click `Disconnect VPN`, then `Get VPN Status` (should return disconnected).
5. Trigger a high/critical network condition and confirm:
   - if VPN is connected, internet block is not enforced.

## Troubleshooting

- If commands fail silently, run each command in elevated PowerShell first.
- If status still shows disconnected, add your adapter/process hints in `appsettings.json` `Vpn` section.
- If enforcement is not active, verify dashboard line says admin privileges are present.
