# Next implementation steps

## 1) Harden Windows netsh scanner

Current scanner is implemented using `netsh`. Next hardening tasks:

- adapter-specific fallback behavior when netsh output is partial
- parser resilience against locale/output format differences
- explicit telemetry quality flags for low-confidence scans

## 2) Complete real policy side effects

Current status:

- firewall block/unblock controller is implemented with safe `DryRun` mode
- Windows notification service is implemented with toast-first and popup fallback

Remaining:

- add user-session aware delivery channel for Windows Service deployments (service-to-user bridge)
- tune notification throttling/deduplication for repeated scans

## 3) Harden VPN adapters

Current command-based integration supports connect/disconnect and vendor status detection. Next tasks:

- validate command templates before execution
- add provider-specific status heuristics beyond process-name matching
- add command timeout/retry/backoff policies

## 4) Persistent secure storage

Current status:

- trusted networks and master-key state now persist with protected payload + integrity hash

Remaining hardening:

- schema/version migration handling for persisted secure files
- backup/restore integration for secure storage artifacts

## 5) Master key UX + recovery

- setup flow for master key + one-time recovery key
- require master key for any settings change
- recovery flow to rotate keys and unlock modification capability

## 6) System startup behavior

- run protection service at startup before user login
- GUI client (later) connects to service for status and settings

## 8) Control-plane API (current)

Current status:

- localhost control API is available for master-key flows, trusted networks, VPN status, VPN runtime config, and connect/disconnect actions
- settings mutations are master-key gated

Remaining:

- add stricter authentication/authorization for production deployments
- add audit trail endpoint for config/security changes

## 9) Windows GUI shell (current)

Current status:

- WPF control panel added for health, master-key flows, trusted networks, and VPN controls
- GUI communicates with localhost control API

Remaining:

- improve UX validation/messages for input fields
- add secure session token flow instead of sending master key per protected action

## 7) Validation matrix

Run scenario tests for:

- trusted network high risk
- untrusted medium/high risk with VPN off
- critical risk immediate block
- VPN connect failure fallback block
- service restart/reboot continuity
