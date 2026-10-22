# Defect log

Defects in the stack that an automated test exposed during development, with the test that
caught each one and the fix. Defects found by the Verdict conformance harness are listed in
Verdict's own `DEFECTS.md` and cross-referenced here when the fix landed in NR-Lite.

| # | Found by | Symptom | Root cause | Fix |
|---|---|---|---|---|
| 1 | `UeNasTest.T3520ExpiryAbortsRegistration` (GoogleTest) | When an authentication failure and T3510 expiry overlapped, the UE aborted the RRC connection twice. In the worse case it aborted the *next* registration attempt | `handle_registration_failure()` stopped T3510 but left T3520 running, so the timer belonging to the aborted procedure fired later | Stop T3520 whenever the registration procedure ends (failure, reject, accept) |

Issues found in review (not by a test) are fixed in the same commits but kept out of this table:

* gNB: UL integrity checking was enabled when SecurityModeCommand was sent, which would have
  discarded the UE's unprotected SecurityModeFailure (TS 38.331 §5.3.4.3). The gNB now verifies
  SecurityModeComplete explicitly and accepts an unprotected SecurityModeFailure.
