# Kali sender presentation guide

## Architecture

```text
Browser: administrator clicks Check / Start / Stop
                    |
Windows Cloud Box API --- pinned SSH ---> Kali: fixed Python sender
                    ^                          |
                    |   loopback SSH forwards |
Windows temporary HTTP/TCP decoy <-------------+
                    |
Authenticated observation -> receipt -> sealing -> evidence case
                    |
Export job -> JSON + Word + PDF + detached signatures + signed ZIP
```

The application, its database and signing keys remain on Windows. Kali originates the simulation requests. An independent Kali journal agent can also collect Linux logs through the separate port-18765 bridge. Docker is not used in this path. The older `lab/` Docker add-on is retained as an optional legacy implementation and is not launched by the integrated Lab page.

## Present on this laptop

1. Connect the SSD and start the existing Kali VM. On 14 November the running VM was VirtualBox `kali`, with guest address `10.0.2.15` and host SSH forwarding `127.0.0.1:2222` to guest port 22.
2. Run `D:\CloudBox\Start-Cyber-Black-Box.cmd`. Keep the launcher open and sign in at http://127.0.0.1:8765 as an administrator.
3. Open **Attack simulation lab** and click **Check Kali connection**. A successful result confirms SSH authentication and Linux Python availability at that moment. It does not promise that all forwarding ports are available or that the VM will remain online.
4. Click **Start simulation** on one scenario. The fixed workloads are six failed decoy logins, five fixed web paths, or six connections to one test TCP listener.
5. Watch the received-observation count. **Stop simulation** stops further sending; already collected evidence remains. A stopped run with observations can still generate a report.
6. Open the evidence case and explain its original bytes, receipt times, hashes and custody history. Lab records are explicitly marked simulations. Passwords are not retained.
7. Wait for the export job to complete. Download PDF, Word, JSON or the signed ZIP. Show the signature verification procedure in [FYP-PRESENTATION.md](FYP-PRESENTATION.md).
8. Explain the trust limit: signatures detect modification relative to a trusted public key; they do not establish complete capture or prove real compromise. SSH encrypts the transport, so packet sensors need not see the internal decoy requests.

## Use Kali in VMware or another private VM

Configure the VM's SSH service, key-based authentication and trusted host entry first. Compare the SSH host fingerprint directly with the VM before trusting it. Preserve the existing setup until the replacement connection is verified.

Create `work/kali-connection.json` locally, using the actual reachable private IPv4 address, SSH port and Linux username. Example only:

```json
{"host":"192.168.56.12","port":22,"username":"kali"}
```

The application accepts only those three fields, a private/loopback IPv4 address, a valid port and a restricted Linux username. Public destinations, command fields and arbitrary scenario targets are rejected. Private credentials remain at `work/kali-ssh`; host trust remains at `work/kali-known-hosts`. Neither file is included in releases. Never disable SSH host verification to silence a mismatch.

The VM needs Python 3 and SSH reverse forwarding. Guest loopback ports 18888 and 18889 are reserved for temporary simulation forwards; 18765 is reserved for the optional journal bridge. HTTP and TCP targets are still the dedicated Windows decoys; changing the sender connection does not expose arbitrary target controls.

After changing the file, use **Check Kali connection**, then run a scenario. Restart the journal bridge to load its new settings. Do not run two bridges on the same guest port.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Connection not configured | Local key, known-hosts file, SSH client and valid JSON |
| SSH check fails | VM boot completed, SSH service, VM networking, key ACL and host fingerprint |
| Check passes but run fails | Reverse-forward permission and reserved ports; open run error |
| Zero observations | Treat as no captured requests, not evidence of success |
| Run finishes but report pending | Background jobs, sealing and export verification; large archives take longer |
| Another admin cannot see a case | Add the user through case membership; admin status alone is not case ownership |
| No Linux journal events | Check the separate journal agent and log bridge |

Optional cloud archives, AI services, native packet sensors and forensic acquisitions require their own configuration and tests. This guide does not certify those integrations or claim zero defects.

## Acceptance results — 14 November 2026

- Backend: 111 tests passed, with one upstream Starlette/httpx deprecation warning. Frontend: 3 tests and production build passed. Legacy lab: 9 tests passed.
- Actual Kali SSH/Python readiness check passed. Each full live scenario completed with 6, 5 and 6 observations respectively; all three evidence ZIPs verified VALID and all report formats passed detached signature/hash checks.
- Browser: connection check and Start-to-signed-report passed; no JavaScript errors or horizontal mobile overflow at 390 pixels.
- Live cancellation: stopped after one observation, preserved that observation, reported STOPPED and completed its report job.
- Windows launcher: fixed unnecessary ACL rewrites when signing keys already have the exact protected operator/SYSTEM permissions. Fresh-directory permissions were checked too. Real deployment readiness returned HTTP 200.
- Test evidence is isolated from the user's live cases under `work/fyp-live-acceptance`. This folder and its credentials are excluded from the release ZIP.

## Live backlog correction

A later run on the live archive exposed a load-dependent issue that the isolated acceptance database did not reproduce: more than 14,000 older staged receipts delayed the lab's six receipts beyond its 45-second finalization window. Lab finalization now seals only its own bounded set of receipts through the standard transactional archive/custody path. Normal FIFO collection continues independently; evidence is not fabricated or dropped. A regression test verifies that unrelated older receipts remain staged while the lab run finishes.

The affected presentation run's six received observations were sealed and an export was queued without replaying the sender. Its recovered state remains PARTIAL with an explanatory note, because successful sender termination was not independently reverified. Large-archive report verification can still take longer than a small isolated test; inspect Background jobs for progress.
