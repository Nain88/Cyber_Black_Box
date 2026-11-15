# Kali simulation and signed reports

The Windows project is at `D:\CloudBox`. Its Kali VM is registered from `E:\VirtualMachines\kali\kali.vbox`; keep that SSD connected. Docker is not required for this workflow.

## Presentation sequence

1. Start the existing Kali VM and wait for SSH to respond. The current VirtualBox NAT rule maps Windows localhost port 2222 to Kali port 22.
2. Start `Start-Cyber-Black-Box.cmd`, open http://127.0.0.1:8765 and sign in with your administrator account.
3. For independent Linux journal collection, start `Start-Kali-Log-Bridge.cmd`. Leave its window open and check the collector heartbeat. This bridge is separate from simulation traffic.
4. Open **Lab**. Choose failed logins, web path probes or TCP connections, then select **Start simulation**. Only one exercise can run at a time; wait six seconds between starts.
5. Watch the observation count. **Stop simulation** cancels further sending while preserving observations already received. A stopped run with observations still queues its report. An empty run does not invent evidence or generate a misleading report.
6. Open the generated evidence case. Review the original event bytes, timestamps and custody trail. Wait for the report job to finish.
7. Download the signed evidence ZIP and PDF, Word or JSON report. Download the corresponding signature when sharing a standalone report.

The scenarios send at most six invalid logins to a test service, five fixed nonexistent web paths, or six connections to one dedicated TCP listener. They do not test personal accounts or scan a network. The temporary Windows listeners bind only to loopback. Pinned SSH forwards carry Kali requests to them. Raw observations explicitly identify lab activity and explain why the observed source IP is loopback.

## Verify a report independently

Retain the deployment public key separately from the downloaded files. A key supplied by an untrusted package does not establish the identity of its author.

```powershell
.\.venv\Scripts\python.exe -m cbb.cli verify-package evidence.zip --public-key "YOUR_TRUSTED_PUBLIC_KEY"
.\.venv\Scripts\python.exe -m cbb.cli verify-report report.pdf report.pdf.signature.json --public-key "YOUR_TRUSTED_PUBLIC_KEY"
```

The same command accepts Word or JSON with its matching signature. Reports have detached Ed25519 signatures; the ZIP also has a signed manifest covering report and raw evidence hashes. These are not embedded Adobe or Microsoft certificate signatures. Changing report bytes invalidates the original signature. Preserve the original signed files when editing a separate presentation copy.

## Verified on 13 November 2026

The actual running Kali VM sent all three scenarios through SSH to the Windows decoy. Failed logins produced 6 observations, web probes 5, and TCP probes 6. Each run completed, automatically exported its case, and passed offline package verification. All nine PDF/Word/JSON files passed detached signature and content hash verification. Test artifacts and results are local under `work/fyp-live-acceptance`; private data and SSH keys are excluded from the source ZIP.

The backend suite passed 98 tests; the existing separate lab suite passed 9 tests; frontend tests passed 3 tests and the production build passed. These checks establish the tested behavior, not a claim of zero defects or universal integration support.

The browser acceptance check also passed: selecting Start in the GUI produced a signed report from the actual Kali sender, with no JavaScript errors and no horizontal overflow at a 390-pixel mobile width. PDF and Word previews were inspected. The standalone verification command accepted the original report and rejected a changed copy.

## Deployment boundaries

- Existing Kali journal collection remains independent. Its backlog may take time to drain after reconnection.
- SSH keys and pinned host entries in `work/kali-ssh` and `work/kali-known-hosts` are local provisioning. A fresh machine requires its own trusted SSH configuration; the source ZIP contains no credentials.
- Reserve guest loopback ports 18888 and 18889 for simulations and 18765 for the journal bridge. A disconnected VM or occupied forward port produces a failed run instead of fabricated observations.
- The Windows decoy is the observation source. This does not demonstrate real account compromise, packet visibility inside encrypted SSH, or complete Suricata capture.
- External cloud storage, AI providers and other optional services need their own configuration and acceptance tests. Docker and Windows repair are separate from this working native lab path.
