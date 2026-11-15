# Kali log connection

The simulation sender and journal bridge share optional local configuration in `work/kali-connection.json`; see [configuration and presentation steps](KALI-PRESENTATION-2026-11-14.md). Omitting this file retains the existing `kali@127.0.0.1:2222` connection. No key or host trust is transferred automatically between VMs.

Kali remains a genuine Linux log collector. The integrated GUI lab also runs bounded requests from Kali against a dedicated Windows decoy. These two functions are independent.

1. Start the existing Kali VM in VirtualBox.
2. Start `Start-Cyber-Black-Box.cmd` from D:\CloudBox.
3. Run `Start-Kali-Log-Bridge.cmd` and keep its terminal open. Do not run a second bridge while one already owns guest port 18765.
4. In Cloud Box, check the Kali collector heartbeat and incoming Linux events. The agent durably queues records during outages; leave it running while the backlog drains.

The VM's existing NAT SSH mapping is Windows localhost:2222 to guest SSH:22. The bridge exposes the Windows API only at Kali localhost:18765. Existing authentication and pinned SSH host checking remain enabled. The script retries interrupted connections every ten seconds; Ctrl+C stops it.

Private SSH keys and collector tokens are local configuration and are deliberately excluded from source releases. A fresh machine requires provisioning its own keys, host trust and collector enrollment. This is not a portable credential bundle.

## Verified 12 November 2026

Connected to the running Kali VM using its existing SSH key. Fixed overly broad permissions on the copied D: private key. The guest reached /health/ready with HTTP 200 through the bridge; its collector heartbeat resumed and queued events began moving into Windows receipts and sealed evidence. No collector was replaced and no attack was executed in this check.

The integrated Lab page now manages its own temporary decoy and SSH forwards on guest loopback ports 18888 and 18889. It uses the existing pinned SSH connection; the log bridge on port 18765 remains separate. See [the presentation walkthrough](FYP-PRESENTATION.md). Docker is not required for this workflow.
