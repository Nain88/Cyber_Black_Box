# Cyber Black Box | Three-hour testing and panel guide

## What the project does

Cyber Black Box preserves digital observations so an investigator can later show what arrived, who handled it, and whether the preserved bytes still match their recorded hashes. Think of two separate screens in the demo. The Docker lab creates clearly labelled synthetic records. The Cyber Black Box dashboard receives them, seals them, links them to a case and exports the investigation.

```text
Docker lab or authorized endpoint
  -> collector queue on disk
  -> intake API and durable receipt
  -> original bytes in archive + searchable evidence summary
  -> case, timeline and custody entries
  -> signed checkpoint and portable case package
  -> offline verification using a separately trusted public key
```

**Staged** means the server durably received the event. **Sealed** means the original bytes and their evidence record have been committed to the archive. **SHA-256** is the fingerprint of exact bytes. The evidence chain links successive records. The custody chain records actions. A signed checkpoint commits to a recorded point in the chains. A separate witness or independently retained checkpoint helps detect a rollback beyond the available local state.

## Before the timer

- Use the existing signed-in [Cyber Black Box dashboard](http://127.0.0.1:8765/) in Chrome and the [Docker lab](http://127.0.0.1:8081/) in Edge or the Codex browser. Start Docker Desktop and keep the app and bridge running. On Windows the source checkout includes `Start-Cyber-Black-Box.cmd` and `Start-Docker-Evidence-Demo.cmd`. Reuse the existing deployment and enrolled collector. **Collectors → Configure → Automatic intake case** should point at **Docker Security Lab**.
- Start with your approved test case, synthetic fixtures and test accounts. For backup, recovery, configuration experiments and disconnection drills, use a separate disposable deployment. One local dashboard deployment can use port 8765 at a time. A disposable native instance can use a different data directory and port, such as 8766. The Docker demo launcher targets 8765 in this revision.
- For every check, record local time and UTC, case, source, expected and actual counts, status and a screenshot or evidence ID. Use **Pass**, **Fail** or **Blocked**. External dependencies may be blocked even when the automated version of a test passes.

## 00:00–00:15 | Startup, navigation and permissions

1. Open both URLs. On the dashboard open **Getting started**, **Overview** and **Tools & sensors**. Observe the deployment mode, connected collectors and available tools.
2. Open **Collectors**. Confirm the Docker demo collector has a recent heartbeat and the intended intake case. A heartbeat demonstrates that a collector can communicate. The **last evidence** time demonstrates that the selected source delivered a record.
3. In a separate profile with an authorized lower-privilege test account, check that assigned evidence opens and an unassigned case or administration controls are denied. Verify the keyboard can reach the menu, filters and dialog buttons. If the header offers a motion toggle, pause it and reload.
4. **Pass when** both pages are reachable, the intended deployment and case are visible, and role restrictions behave as expected. A port conflict should be resolved by checking which deployment owns 8765 and using the original data folder.

## 00:15–00:40 | Docker lab and real endpoint markers

1. On the **Docker lab page**, use each **Run scenario** button once. Copy the unique reference from **Latest run**. Expected counts are **6** for failed login, **5** for web path, and **6** for TCP connection. These buttons generate synthetic records with a fixed schema.
2. On the dashboard open **Evidence explorer**. Paste one reference into the search box, click **Search**, and check the expected count. If the results page says it is frozen at an earlier sequence, refresh or run a fresh search. Open an evidence item. Check source `lab.fixture`, event type, timestamps, marker and **Integrity**. Open **Case workspace** to confirm automatic intake.
3. For **Windows**, check the existing collector is online and configured for the **Application** log. In an Administrator PowerShell write a benign event. Change the marker for repeated runs.

   ```powershell
   eventcreate /T INFORMATION /ID 100 /L APPLICATION /SO CloudBoxTest /D "CBB-WINDOWS-LIVE-001"
   ```

4. For **Linux**, use an enrolled Linux or Kali collector with journal access. In the authorized VM terminal write a benign message. Check `journalctl -t cbb-check -n 5` for the local record before searching the dashboard.

   ```bash
   logger -t cbb-check "CBB-LINUX-LIVE-001"
   ```

5. **Pass when** the three Docker references return **6, 5, 6** sealed records and the Windows/Linux checks show their own independent markers under `windows.event` and `linux.journal`. If a marker is missing, check the local log first, then collector state and source permissions, queue/backpressure, automatic intake and case scope, then rerun the search. An offline collector or stale capture process is a separate check from the Docker lab.

## 00:40–01:05 | Live monitor, search and network sources

1. Open **Live monitor → Log volume** while generating one new benign marker. Select the corresponding source and wait for the next refresh. Confirm the same event appears under incoming preserved logs. Compare the source timestamp to server receipt time.
2. In **Evidence explorer**, try source and time filters, clear filters, and search a deliberately nonexistent reference. Open an item and use **Original bytes**. Compare a downloaded file with the **Raw SHA-256** in **Integrity** with `Get-FileHash -Algorithm SHA256 -LiteralPath 'path-to-download.raw'`.
3. For **Windows Firewall**, **Suricata** and **Zeek**, check the source status and most recent capture time. With an approved sample, use the import option for a small supported structured log or PCAP in the disposable case. For a live source, use ordinary authorized test traffic and confirm a fresh observation for the configured interface. If a parser is absent, record whether the original PCAP is retained and whether parser availability is reported.
4. **Pass when** graph, list and source filters agree for the same received window, and original bytes match the hash. Record each optional sensor separately as **Blocked** if its process, fixture, interface or permissions are unavailable.

## 01:05–01:30 | Cases, timeline, alerts and assistant

1. In **Case workspace**, inspect the auto-linked evidence. On a test case, manually add one unrelated approved fixture, save a short investigation note, reopen the case and confirm note and membership. Check an assigned reviewer can see the case within their role and cannot edit evidence.
2. In **Timeline**, filter to the test window. Compare ordering and link a candidate relationship to actual record IDs. Explain a correlation as a candidate association.
3. In **Alerts & anomalies**, review a rule-backed finding where available. Record the decision and reason, then confirm the audit trail. A synthetic run can be captured successfully even when it triggers no enabled rule. In **Models & rules**, check model status, baseline/holdout separation and the explanation for any scored item. The anomaly model ranks unusual windows for review.
4. In **Evidence assistant**, ask for a summary of the test case. Open cited evidence IDs and compare the answer to source records. If local Ollama is unavailable, record tool status and test the local analysis path available in the deployment.
5. **Pass when** evidence associations, notes and decisions persist, and the reportable claims can be traced to their evidence IDs.

## 01:30–01:55 | Integrity, custody and acquisition

1. Open **Integrity** and create a signed checkpoint after the fixture records arrive. Select **Run verification** and then inspect **Background jobs**. On the verification result look for **VALID**, **0 discrepancies**, and its assurance type. If an independently held checkpoint or witness is available, verify with that material and record which was used. Otherwise record `LOCAL_CHECK_ONLY` and the limitation that a whole-archive rollback may remain undetected.
2. In **Chain of custody**, look up the case or evidence ID. Record available actions and actor/time fields. Explain the difference between audit entries and preserved event content.
3. In **Acquisitions**, propose a **Selected files** acquisition of a harmless text file in a configured allowlisted test folder. Use separately authorized approval, let the collector fulfill it, and check the resulting artifact digest. Use the disposable test to confirm that paths outside the allowed folder are refused. Memory capture requires separately configured tools and authorization. Mark it blocked if unavailable.
4. **Pass when** verification findings are traceable, custody entries are visible and the approved acquisition preserves the expected fixture bytes.

## 01:55–02:20 | Signed reports and cloud archive

1. In **Reports & exports**, generate a package for the correct test case. In **Background jobs**, wait for the export to complete. Download **Signed ZIP**, PDF, Word and JSON from the same package row. Check its case ID, frozen version, note, evidence count, manifest and findings.
2. Verify the ZIP with the deployment public key obtained through a trusted channel. Run from the repository root and replace both placeholders. For the negative check, use the existing isolated automated package/tamper tests.

   ```powershell
   .\.venv\Scripts\python.exe -m cbb.cli verify-package 'C:\path\case.zip' --public-key 'TRUSTED_BASE64_PUBLIC_KEY'
   ```

3. In **Tools & sensors**, check MEGAcmd status. In an approved disposable cloud scope, open **Cloud archive** and verify **Back up now → Background jobs → Verified objects → Restore check**. The restored copy is staged and compared by SHA-256. Use the automated retention test for the five-day policy. The clock begins at successful verification of a new eligible remote log object. Active case holds protect linked segments. Eligible remote copies move to the MEGA Rubbish Bin. Local originals are preserved.
4. **Pass when** signed export verification succeeds and any enabled cloud test yields a verified backup and matching staged restore. Record S3 Object Lock and independent witness acceptance separately from MEGA.

## 02:20–02:50 | Recovery and a timed 30-minute observation

1. In the disposable deployment, note a baseline and start a stopwatch. Every five minutes write one unique benign Windows/Linux marker, or trigger a labelled fixture using an intake path configured for the disposable deployment. Record staged/sealed counts, latency, queue depth, process memory and available disk.
2. Temporarily interrupt one test collector/server connection. Keep collector spool files. Restore the connection, confirm the collector resumes, and check that each acknowledged marker is present once. Repeat an existing record only with supported fixture/retry tooling.
3. Refresh the case and graph while intake continues. Try a saved view, a read-only role action and one stale search result. Compare total expected with total sealed and record time until the backlog drains. Use the automated tests for malformed payloads, duplicates, altered evidence, signer failure, receipt restart recovery and backup/restore into an empty directory.
4. **Pass when** counts reconcile, data resumes after recovery and errors are visible. Record the actual test duration. A three-hour checklist includes this 30-minute observation. A continuous three-hour soak requires a separate timed run.

## 02:50–03:00 | Present to the panel

Show one Docker button → reference → six records → one exact raw hash → case and custody → signed ZIP. Then show one independent Windows or Linux marker if its test passed.

| Panel question | Short answer |
|---|---|
| What problem does it solve? | It keeps original observations and an audit trail so investigators can verify what was preserved and document their decisions. |
| Why two browsers? | The Docker page generates synthetic evidence and the dashboard independently receives, preserves and investigates it. |
| What makes an event tamper-evident? | Original-byte hashes, linked record hashes and signed checkpoints. A separately held checkpoint reduces the local rollback blind spot. |
| Is an alert proof of an attack? | An alert identifies material to review. This demo proves labelled input reached the archive, and an analyst must evaluate any real incident claim. |
| What happens while the laptop or server is unavailable? | A running collector retains unsent or unsealed work in its durable spool within capacity. Recovery is checked by reconciling IDs and counts. |
| Can MEGA be the only copy? | MEGA provides a hash-verified archive copy and staged restore. Application database and signing-key recovery use separately controlled backups. |

## Ten QA observations and review tasks

1. Confirm Docker and dashboard use port 8081 and 8765 respectively, with the intended case.
2. Use each run's reference to reconcile the expected counts of 6, 5 and 6.
3. Compare a downloaded original record's SHA-256 with its stored evidence hash.
4. Record Windows Application and Linux journal markers independently of Docker activity.
5. Distinguish collector connectivity, queue depth and actual source freshness.
6. Compare graph counts and search results using the same time window.
7. Check a reviewer, case owner and unrelated account against the same evidence.
8. Retain checkpoint and public key separately and record the verification assurance mode.
9. Verify a frozen case ZIP and use a fixture test to demonstrate tamper detection.
10. Test verified cloud restore and held-segment exclusion in a disposable scope.

These are review and evidence-recording tasks. Add your name and observed result to the tasks you personally run.

## Results verified for this revision

Both local HTTP endpoints responded simultaneously and the collector linked **17 of 17** synthetic records to the intended case. Each record had a sealed receipt and its archived raw bytes matched the stored SHA-256. The three capture-to-check samples were about 2.6, 6.4 and 6.4 seconds. They describe this laptop run and are not a throughput or SLA result.

The main backend suite passed **133 of 133**, frontend unit checks passed **13 of 13**, and the production frontend built successfully. The backend suite reported one Starlette test-client deprecation warning. It uses disposable data and simulated remote integrations where configured. Live Windows/Linux event acceptance, the 30-minute observation period, and destination-specific cloud/MEGA/S3 acceptance are separate from this run.
