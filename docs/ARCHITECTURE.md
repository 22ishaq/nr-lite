# NR-Lite architecture

## Layers and ownership

```
Simulator
├── EventLoop            virtual time (ms), ordered by (time, sequence) → deterministic
├── Logger               per-simulation, stamped with virtual time and a component tag
├── std::mt19937_64      single seeded RNG (RAND, random UE identities, 5G-TMSIs)
├── GnbRrc               network RRC: one UeContext per C-RNTI (PDCP SRB1, guard timer, keys)
├── Amf                  network 5GMM + UDM/AUSF/SEAF roles: subscriber DB, UE contexts, timers
└── UeNode × N
    ├── UeRrc            UE RRC state machine + PDCP SRB1
    └── UeNas            UE 5GMM state machine + USIM (MILENAGE, 5G-AKA)
```

Layers inside a node talk through `std::function` callbacks rather than direct references. That is
why each state machine can be unit-tested against a scripted peer (see `tests/rrc/ue_rrc_test.cpp`,
`tests/nas/ue_nas_test.cpp`) without the rest of the stack:

```
UeNas  --establish(cause, nas, s_tmsi)-->  UeRrc  --send(channel, pdcp_pdu, rrc_pdu)-->  air
       --send(nas)----------------------->        <--on_pdu(channel, pdu)-------------  air
       --abort_connection()-------------->
       --set_kgnb(K_gNB)----------------->
       <--deliver_nas / connected / released / establishment_failed / barring_alleviated--
```

## Message path

1. **Encoding**: `rrc::encode_*` and `nas::encode` produce exact bytes. Encoders throw
   `asn1::EncodeError` / `std::invalid_argument` when a value violates its constraint. That is a
   programming error on the sending side, never something a peer can trigger.
2. **Protection**: NAS messages are protected by `nas::protect` (MAC over `SQN || payload`, COUNT
   from the context). RRC DCCH messages go through `pdcp::SrbEntity::transmit` (12-bit SN header,
   MAC-I, optional NEA2).
3. **Transport**: `Simulator::transmit` applies the interceptor, records a `TraceRecord` and
   schedules delivery after the configured latency.
4. **Reception**: decoders never throw. They return `Result<T>` with an `Error` whose `code` is
   protocol specific (for NAS, the 5GMM cause the receiver should report), and the state machines
   apply the spec's error handling (ignore / STATUS / discard / go to idle).

## State machines

### UE RRC (`rrc::UeRrc`)

| State | Event | Action | Next |
|---|---|---|---|
| IDLE | `establish()` (T302 not running, or emergency/MT) | send RRCSetupRequest, start T300 | IDLE (establishing) |
| establishing | RRCSetup with SRB1 | stop T300, reset PDCP, send RRCSetupComplete (NAS + 5G-S-TMSI part 2) | CONNECTED |
| establishing | RRCSetup without SRB1 | stop T300, report `InvalidSetup` | IDLE |
| establishing | RRCReject | stop T300, start T302 = waitTime, report `Rejected` | IDLE |
| establishing | T300 expiry | report `T300Expiry` | IDLE |
| CONNECTED | SecurityModeCommand verified with K_RRCint | integrity on, send SMC Complete, then ciphering on | CONNECTED (secured) |
| CONNECTED | SecurityModeCommand not acceptable | send SecurityModeFailure unprotected | CONNECTED |
| CONNECTED | DCCH integrity failure / ASN.1 error | go to IDLE, "RRC connection failure" | IDLE |
| CONNECTED | RRCRelease | after 60 ms: start T302 if waitTime, report release | IDLE |

### UE 5GMM (`nas::UeNas`)

```
 5GMM-NULL ──power_on──► DEREGISTERED.NORMAL-SERVICE ──register()──► REGISTERED-INITIATED (T3510)
                                   ▲                                   │
     T3511 / T3502 / T3346 expiry  │                                   ├─ AUTHENTICATION REQUEST ─► RES* / FAILURE #20 #21 #26 #71
     ┌─────────────────────────────┤                                   ├─ SECURITY MODE COMMAND ─► COMPLETE (new ctx) / REJECT #23 #24
     │ DEREGISTERED.ATTEMPTING-    │◄── T3510 expiry, lower-layer ─────┤
     │ REGISTRATION (attempt ctr)  │    failure, reject "other"        ├─ REGISTRATION REJECT #3/#6/#7 ─► DEREGISTERED.NO-SUPI
     └─────────────────────────────┘                                   ├─ REGISTRATION REJECT #11/#27 ─► DEREGISTERED.LIMITED-SERVICE
                                                                       └─ REGISTRATION ACCEPT ─► REGISTERED.NORMAL-SERVICE
 REGISTERED ──deregister()──► DEREGISTERED-INITIATED (T3521 ×5) ──DEREGISTRATION ACCEPT──► DEREGISTERED
 REGISTERED + 5GMM-IDLE ──T3512──► REGISTERED-INITIATED (periodic, integrity protected, no new AKA)
```

### AMF (`core::Amf`)

`DEREGISTERED → COMMON-PROCEDURE-INITIATED → REGISTERED`, with one active procedure at a time
(`Identification`, `Authentication`, `SecurityMode`, `RegistrationAccept`) and its
retransmission timer (T3570, T3560, T3560, T3550). On the fifth expiry the procedure is aborted.
For T3550 the UE is then considered registered, as TS 24.501 §5.5.1.2.8 allows.

## Security key flow

```
USIM / UDM:    MILENAGE(K, OPc, RAND, SQN, AMF) → RES, CK, IK, AK, MAC-A
AUSF:          K_AUSF = KDF(CK||IK, 0x6A, SNN, SQN⊕AK);  XRES* = KDF(CK||IK, 0x6B, SNN, RAND, RES)[128 LSB]
SEAF:          K_SEAF = KDF(K_AUSF, 0x6C, SNN);           HXRES* = SHA-256(RAND||XRES*)[128 LSB]
AMF:           K_AMF  = KDF(K_SEAF, 0x6D, SUPI, ABBA)
               K_NASint/enc = KDF(K_AMF, 0x69, 0x02/0x01, alg)[128 LSB]
               K_gNB  = KDF(K_AMF, 0x6E, UL NAS COUNT, 0x01)
gNB:           K_RRCint/enc = KDF(K_gNB, 0x69, 0x04/0x03, alg)[128 LSB]
```

The UL NAS COUNT that feeds K_gNB is the count of NAS SECURITY MODE COMPLETE after a fresh
authentication, or of the integrity-protected initial NAS message when an existing context is
reused (e.g. periodic registration). UE and AMF derive it independently, and the AS
SecurityModeCommand only verifies if they agree.

## Test-system hooks

* `Simulator::set_air_interceptor(fn)`: `fn(AirPdu&)` returns `deliver`, `drop` or
  `delay(ms)` and may rewrite `pdu.data`. The trace records the PDU as transmitted. A plaintext
  "RRC hint" from the sender keeps ciphered DCCH traffic readable in traces, and it is discarded
  if the interceptor changed the bytes.
* `Simulator::detach_gnb(handler)` + `inject_dl(...)`: the test system receives every uplink PDU
  and supplies the downlink itself. This is how Verdict tests the UE in isolation.
