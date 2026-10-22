# Specification coverage

Clause references are to the Release 17/18 versions of the specifications. "Simplified" entries
say exactly what differs from the specification.

## TS 38.331 (NR RRC)

| Clause | Topic | Status |
|---|---|---|
| 5.3.3 | RRC connection establishment | Implemented: RRCSetupRequest with random value or 5G-S-TMSI part 1, T300, RRCSetupComplete with selectedPLMN-Identity, S-NSSAI list and 5G-S-TMSI part 2 |
| 5.3.3.7 | T300 expiry | Implemented: upper layers informed, UE stays in RRC_IDLE |
| 5.3.4 | Initial AS security activation | Implemented: K_RRCint from K_gNB, SMC integrity verified before use, SecurityModeFailure sent unprotected, ciphering after SMC Complete |
| 5.3.8 | RRC release | Implemented: 60 ms delay, waitTime → T302. Simplified: suspendConfig / redirection not supported |
| 5.3.11 | Going to RRC_IDLE | Implemented for release, NAS abort and connection failure |
| 5.3.15 | RRC connection reject | Implemented: T302 started with waitTime, access barred except emergency / MT access |
| 5.3.7 | Re-establishment | Not implemented. Triggers (DCCH integrity failure, ASN.1 error) lead to RRC_IDLE with "RRC connection failure" |
| — | Reconfiguration, UE capability transfer, measurements, paging, system information | Not implemented |
| 10 | Protocol error handling | CCCH errors ignored. DCCH errors → connection failure (see 5.3.7 above) |
| 6.2.2 | Messages | UL-CCCH, DL-CCCH, UL-DCCH and DL-DCCH envelopes. The messages listed in the README are fully coded; other c1 alternatives decode to a named "not supported" error |

## TS 24.501 (5GS NAS)

| Clause | Topic | Status |
|---|---|---|
| 4.4.3 | NAS COUNT and SQN | Implemented: 24-bit COUNT, receive-side estimation from 8-bit SQN, replays rejected through the MAC |
| 4.4.4.2 / 4.4.4.3 | Message integrity rules (UE / AMF) | Implemented with the standard lists of messages allowed without integrity protection |
| 4.4.6 | Initial NAS message protection | Integrity protected with an existing context, not ciphered. Simplified: no cleartext-IE split, the full message is sent (RINMR container supported in SMC Complete) |
| 5.4.1.3 | 5G-AKA | Implemented both sides, including #20 MAC failure, #21 synch failure with AUTS, #26 non-5G authentication, #71 ngKSI already in use, T3520 |
| 5.4.2 | Security mode control | Implemented: new context, replayed capability check (#23), algorithm checks, integrity check failure → reject #24, IMEISV request, RINMR |
| 5.4.3 | Identification | Implemented for SUCI, 5G-GUTI, IMEISV. Network side uses T3570 |
| 5.5.1.2 | Initial registration | Implemented, including abnormal cases (T3510, lower-layer failure, attempt counter, T3511 / T3502) |
| 5.5.1.2.5 | Registration reject | #3/#6/#7 → NO-SUPI. #11/#27 → LIMITED-SERVICE (identity deleted). #12/#13/#15 → LIMITED-SERVICE. #22 → T3346. Others → abnormal case |
| 5.5.1.2.8 | Network abnormal cases | T3550 retransmission ×4, 5th expiry aborts and keeps the new 5G-GUTI |
| 5.5.1.3 | Mobility / periodic registration | Periodic registration on T3512 implemented. Simplified: a failed periodic registration is handled like a failed initial one |
| 5.5.2.2 | UE-initiated de-registration | Implemented: normal (T3521 ×5) and switch-off |
| 7 | Error handling | Message too short → ignored. Unknown type → STATUS #97. Missing/invalid mandatory IE → STATUS #96. Wrong state → STATUS #98. Missing conditional IE → STATUS #100. Unknown optional IEs skipped. Repeated IEs: first occurrence used |
| 8.2 | Messages | 16 5GMM messages (see `nas/messages.hpp`). 5GSM not implemented |

## TS 33.501 / TS 35.206 (security)

| Item | Status |
|---|---|
| MILENAGE f1–f5* | Implemented. Verified against TS 35.207 test sets 1–3 |
| KDF (TS 33.220 Annex B.2) and Annex A derivations A.2, A.4–A.9 | Implemented |
| 128-NIA2 / 128-NEA2 | Implemented. Verified against 128-EIA2 / 128-EEA2 test data (TS 33.401 Annex C) |
| 128-NIA1/NEA1 (SNOW 3G), NIA3/NEA3 (ZUC) | Not implemented. Not advertised in the UE security capability |
| SUCI protection (ECIES profiles A/B) | Not implemented. Null scheme only; non-null SUCIs are rejected with #9 |
| SQN management (TS 33.102 Annex C) | Simplified: SQN must increase, and by no more than Δ = 2^28 |

## TS 38.323 (PDCP)

SRB data PDUs with 12-bit SN, MAC-I always present (zero before integrity activation), COUNT
estimation with the window rule of §5.2.2.1, duplicate discard. BEARER input = SRB identity − 1.
No reordering timer, status reports or data radio bearers.

## Choices where the specifications leave room

* **NAS BEARER input** is 0 for 3GPP access.
* **UL NAS COUNT for K_gNB**: the COUNT of NAS SECURITY MODE COMPLETE (fresh AKA) or of the
  integrity-protected initial message (context reuse).
* **Unknown subscriber**: REGISTRATION REJECT #7 (configurable).
* **Release after registration**: the AMF releases the N2 connection 100 ms after REGISTRATION
  COMPLETE unless the follow-on-request bit is set (configurable).
