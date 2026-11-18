# Docker sender — 18 November 2026

The integrated Lab page now runs its three fixed scenarios from Docker Desktop Linux containers. The Windows application, temporary loopback decoy, evidence database and report signing stay on Windows. Kali and its SSH keys are not needed for these simulations. Existing Kali journal collection is a separate optional source.

1. Start Docker Desktop and wait for the Linux engine to run.
2. Run `Setup-Docker-Lab.cmd` once to pull the pinned Python image.
3. Start `Start-Cyber-Black-Box.cmd` and sign in.
4. Open Attack simulation lab and click Check Docker connection.
5. Start one fixed scenario. Watch received and preserved counts separately.
6. Open the case and download the report when its job completes.

Each run creates a non-root, read-only container with dropped capabilities, no-new-privileges, 128 MB memory, 0.5 CPU and 32-process limits. No project directories, signing keys or Docker socket are mounted. The fixed runner connects through Docker Desktop's host.docker.internal gateway to temporary token-authenticated Windows loopback listeners. No user-supplied target or command is accepted. Containers are removed on completion or cancellation. Docker daemon loss can prevent cleanup; inspect containers with the cbb-sender- prefix after restoring Docker.

On this Windows machine, gateway-to-loopback connectivity was tested successfully. This is a Docker Desktop Windows workflow, not a claim of portability to arbitrary native Linux Docker networking. A ready engine/image check alone does not establish decoy connectivity.

All three live Docker runs completed with 6 login, 5 web and 6 TCP observations. Their signed packages and detached report hashes/signatures were checked by the acceptance script. These are controlled lab observations, not proof of account compromise. Historical Kali guides describe the earlier sender and remain for journal collection/reference.

Validation on 18 November 2026: 115 backend tests and 4 frontend tests passed; the production frontend build passed. A live cancellation stopped after one observation, preserved it, completed its report and left no sender container. Browser checks passed for the guide, evidence dialog, distinct same-name case labels, PDF download and mobile layout, with no JavaScript errors. The HTTP audit and offline backup/restore smoke test passed using isolated synthetic fixtures. Live simulation tests used separate test data and did not modify existing investigation evidence.

Docker Hub login is not required for the public sender image used here. The sender is a temporary container created by the GUI for each exercise, not a continuously running Kali replacement desktop. PDF, Word and JSON reports use detached signature files; this is not an embedded Adobe/Word certificate signature. Local verification does not provide independent external anchoring.

## Presentation walkthrough (Roman Urdu)

1. Docker Desktop open rakhein. Project launcher chalayein aur browser mein sign in karein.
2. Attack simulation lab mein **Check Docker connection** dabayein. Yeh engine aur image check hai; actual requests run start hone par test hoti hain.
3. **Failed login simulation** start karein. Is test mein dedicated decoy ko 6 invalid requests jati hain; kisi personal account ka password test nahi hota.
4. Received aur preserved counts alag dekhein. Received ka matlab request observe hui; preserved ka matlab evidence archive mein seal hua.
5. Report complete hone par **Open evidence case** kholein. Case ID note karein, kyun ke multiple cases ka naam same ho sakta hai.
6. Evidence record mein Original bytes aur Integrity dekhein. Sirf hash nazar aane ko verification pass na kahein; Integrity & checkpoints mein verification run karein aur uska result aur assurance parhein.
7. Case mein apna observation note save karein, phir naya report package generate karein taake note bhi us snapshot mein aaye. PDF/Word/JSON ke saath signature file aur signed ZIP sambhal kar rakhein.
8. Stop button demonstrate karne ke liye naya run start karein aur pehli observation ke baad stop karein. Collected evidence rehna chahiye; zero observations par evidence report expect na karein.

If a run reports pending sealing or a failed report, inspect **Background jobs** and the guide's pipeline health. Preserve the case and error details before retrying. A successful local integrity check does not by itself resolve an earlier sender failure or establish external anchoring.
