# Defect log

Defects in the stack that an automated test exposed during development, with the test that
caught each one and the fix. Defects found by the Verdict conformance harness are listed in
Verdict's own `DEFECTS.md` and cross-referenced here when the fix landed in NR-Lite.

| # | Found by | Symptom | Root cause | Fix |
|---|---|---|---|---|
| 1 | `UeNasTest.T3520ExpiryAbortsRegistration` (GoogleTest) | When an authentication failure and T3510 expiry overlapped, the UE aborted the RRC connection twice. In the worse case it aborted the *next* registration attempt | `handle_registration_failure()` stopped T3510 but left T3520 running, so the timer belonging to the aborted procedure fired later | Stop T3520 whenever the registration procedure ends (failure, reject, accept) |
| 2 | Verdict VD-RRC-004, VD-RRC-008 | After RRCReject/RRCRelease with waitTime, the UE counted the barred access attempt at T3511 expiry as a failed registration (attempt counter 2) and ignored the "barring alleviated" indication, retrying only at the next T3511/T3521 expiry | UeRrc refused the barred establishment without saying why, so UeNas treated it as a lower-layer failure; `on_barring_alleviated()` was a no-op | RRC reports `AccessBarred`; NAS postpones the registration or de-registration without counting it (TS 24.501 §5.5.1.2.7 b), §5.5.2.2.6) and starts it on barring alleviation |
| 3 | Verdict VD-MM-015 | The UE started T3346 with the value from an unprotected REGISTRATION REJECT #22, so a false base station could choose the UE's back-off time | The reject handler used the T3346 value IE without checking whether the message was integrity protected | Use the IE only from an integrity-protected reject, otherwise a random 15-30 min value (TS 24.501 §5.5.1.2.5) |

Issues found in review (not by a test) are fixed in the same commits but kept out of this table:

* gNB: UL integrity checking was enabled when SecurityModeCommand was sent, which would have
  discarded the UE's unprotected SecurityModeFailure (TS 38.331 §5.3.4.3). The gNB now verifies
  SecurityModeComplete explicitly and accepts an unprotected SecurityModeFailure.
