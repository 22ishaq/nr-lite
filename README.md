# NR-Lite

**A simplified 5G NR protocol stack simulator in C++17.** A UE, a gNB and a minimal AMF run RRC
connection setup and 5GS registration as explicit state machines following TS 38.331 (RRC) and
TS 24.501 (NAS). Messages are encoded bit-exactly: RRC with a hand-written ASN.1 UPER codec, NAS with
the TS 24.501 TLV formats. Every trace can be opened in Wireshark.

```
  time(ms)  link   dir      message                                        bytes
         2  Uu     UE->gNB  rrcSetupRequest                                6
         4  Uu     gNB->UE  rrcSetup                                       8
         6  Uu     UE->gNB  rrcSetupComplete [RegistrationRequest]         41
         7  N2     gNB->AMF InitialUEMessage [RegistrationRequest]         30
        10  Uu     gNB->UE  dlInformationTransfer [AuthenticationRequest]  51
        12  Uu     UE->gNB  ulInformationTransfer [AuthenticationResponse] 30
        16  Uu     gNB->UE  dlInformationTransfer [SecurityModeCommand*]   24
        18  Uu     UE->gNB  ulInformationTransfer [SecurityModeComplete*]  19
        20  N2     AMF->gNB InitialContextSetupRequest [RegistrationAccept*] 42
        22  Uu     gNB->UE  securityModeCommand                            9
        24  Uu     UE->gNB  securityModeComplete                           8
        26  Uu     gNB->UE  dlInformationTransfer [RegistrationAccept*]    51
        28  Uu     UE->gNB  ulInformationTransfer [RegistrationComplete*]  19
       132  Uu     gNB->UE  rrcRelease                                     8
```
<sub>`nrlite-sim --scenario registration` (abridged). `*` marks an integrity-protected NAS message.</sub>

## What is implemented

| Area | Spec | What NR-Lite does |
|---|---|---|
| ASN.1 UPER runtime | ITU-T X.691 | Constrained/semi-constrained/unconstrained integers, length determinants incl. 16K fragmentation, normally-small numbers, ENUMERATED / CHOICE with extension markers, BIT/OCTET STRING, SEQUENCE preambles, extension additions as open types |
| RRC messages | TS 38.331 §6.2 | RRCSetupRequest, RRCSetup (RadioBearerConfig + CellGroupConfig container), RRCReject, RRCSetupComplete, SecurityModeCommand/Complete/Failure, DL/ULInformationTransfer, RRCRelease |
| UE RRC | TS 38.331 §5.3 | RRC_IDLE / RRC_CONNECTED, T300, T302 (access barring after RRCReject), 5G-S-TMSI part 1/part 2, AS security activation, 60 ms release delay, protocol-error handling |
| gNB RRC | TS 38.331 / 38.413 | Per-C-RNTI contexts, admission control, guard timers, SMC, NAS relay over a simplified N2 |
| PDCP (SRB) | TS 38.323 | 12-bit SN, COUNT/HFN window, MAC-I (128-NIA2), 128-NEA2 ciphering, duplicate discard |
| 5GMM messages | TS 24.501 §8.2, §9.11 | 16 messages: registration, authentication, identification, security mode, de-registration, 5GMM STATUS; SUCI/5G-GUTI/IMEISV identities, TAI lists, NSSAI, GPRS timers |
| NAS security | TS 24.501 §4.4, TS 33.501 §6.4 | NAS COUNT estimation, MAC with 128-NIA2, 5G-EA0 / 128-5G-EA2, replay protection, message-integrity acceptance rules |
| UE 5GMM | TS 24.501 §5 | DEREGISTERED / REGISTERED-INITIATED / REGISTERED / DEREGISTERED-INITIATED with substates; T3510, T3511, T3502, T3512, T3520, T3521, T3346; attempt counter; reject-cause handling; periodic registration |
| AMF | TS 24.501 §5 (network side) | 5G-AKA incl. SQN re-synchronisation, identification, NAS SMC, GUTI allocation, T3550/T3560/T3570 retransmission, UE-initiated de-registration |
| Security algorithms | FIPS-197, FIPS 180-4, RFC 2104/4493, TS 35.206, TS 33.501 Annex A | AES-128, SHA-256, HMAC-SHA-256, AES-CMAC, MILENAGE (f1–f5*), the 5G key hierarchy (K_AUSF → K_SEAF → K_AMF → K_NASint/K_gNB → K_RRCint) |
| Tracing | — | pcap with `LINKTYPE_WIRESHARK_UPPER_PDU`; Wireshark decodes RRC with its `nr-rrc` dissector and NAS with `nas-5gs` |

## Quick start

Requirements: a C++17 compiler and CMake ≥ 3.20. GoogleTest is fetched automatically. Wireshark
(`tshark`) is optional and enables the trace cross-check test.

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
./build/nrlite-sim --scenario registration --pcap registration.pcap
wireshark -o nas-5gs.null_decipher:TRUE registration.pcap
```

`nrlite-sim` scenarios: `registration`, `deregistration`, `reject` (congestion with T3346),
`t300` (no gNB answers), `periodic` (T3512 re-registration), `multi` (several UEs). Add `--nea2`
to run with real ciphering, `--log debug` to see every state transition, or `--json` for
machine-readable output. `nrlite-sim --decode ul-ccch 12468acf1346` decodes a single PDU.

A ready-made trace is in [`docs/sample_traces/`](docs/sample_traces), along with tshark's full
decode of it.

## Architecture

```
            Uu (simulated air: latency, interceptor)                 N2 (simulated)
  +---------------------------+        +----------------------+        +----------------------+
  | UeNode                    |        | GnbRrc               |        | Amf                  |
  |  UeNas  (5GMM, USIM/AKA)  |        |  per-RNTI contexts   |        |  UE contexts         |
  |    | establish/send/kgnb  |        |  PDCP SRB1           |  NAS   |  5G-AKA, SMC, GUTI   |
  |  UeRrc  (T300/T302, SMC)  | <----> |  admission, SMC      | <----> |  T3550/T3560/T3570   |
  |  PDCP SRB1                |  RRC   |  NAS relay           |        |  subscriber DB (UDM) |
  +---------------------------+        +----------------------+        +----------------------+
                 \__________________ EventLoop (virtual ms clock, seeded RNG) ____________/
                                    TraceSinks: MemoryTrace, PcapTrace
```

Everything runs on one deterministic virtual clock, so a 12-minute T3502 back-off takes
microseconds and the same seed always produces the same bytes. The `Simulator` exposes two hooks
for test systems:

* an **air interceptor** that can drop, delay (reorder) or rewrite any Uu PDU;
* **gNB detach**, where uplink PDUs go to a callback and the test system injects downlink PDUs.
  This is the TS 38.523 model, in which a system simulator plays the network and the UE is the
  device under test.

These are what [Verdict](https://github.com/22ishaq/verdict), the conformance harness built on
NR-Lite, uses. More detail is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), and the per-clause
coverage with every simplification is in [docs/SPEC_COVERAGE.md](docs/SPEC_COVERAGE.md).

## How correctness is checked

* **Bit-exact encodings, checked independently.** The CTest target `wireshark_decodes_trace` runs
  five scenarios (including 128-NEA2), decodes each pcap with `tshark`, and fails on any malformed
  frame or expert error. It also asserts specific decoded field values such as
  `establishmentCause: mo-Signalling`, the SUCI MSIN, the AUTN AMF field, `ng-5G-S-TMSI-Part2`, and
  T3346. Wireshark's NR RRC dissector is generated from the 3GPP ASN.1, so this is an independent
  implementation agreeing with NR-Lite's codec.
* **Golden encodings** for every RRC message (e.g. RRCSetupRequest is exactly 48 bits) and
  hand-derived NAS encodings from the TS 24.501 IE tables.
* **Published test vectors**: FIPS-197 AES, FIPS 180-4 SHA-256, RFC 4231 HMAC, RFC 4493 AES-CMAC,
  TS 33.401 Annex C 128-EIA2/EEA2 (same algorithms as NIA2/NEA2), and TS 35.207 MILENAGE test
  sets 1–3.
* **436 GoogleTest cases** (386 `TEST`/`TEST_F` plus parameterized suites). They cover the UPER
  primitives, every message round trip, truncation and random-input robustness, the UE RRC, gNB
  RRC, UE 5GMM and AMF state machines against scripted peers, and end-to-end fault-injection
  scenarios (lost RRCSetup, lost Registration Complete, corrupted SMC, reordering, admission
  control).
* **Sanitizers.** CI runs the full suite under AddressSanitizer and UndefinedBehaviorSanitizer
  with `-Werror`.

Defects found by tests during development are recorded in
[docs/DEFECT_LOG.md](docs/DEFECT_LOG.md).

## Scope and simplifications

NR-Lite is a teaching and testing stack, not a product. Deliberate simplifications:

* Only the RRC and NAS fields listed above are modelled. Receiving an unmodelled optional RRC
  component (e.g. `spCellConfig`) is reported as an "unsupported" decode error, because UPER root
  components carry no length and cannot be skipped safely.
* No PHY/MAC/RLC, no RRC_INACTIVE, reconfiguration, re-establishment or handover. Where the spec
  would start RRC re-establishment (DCCH integrity or ASN.1 failure), the UE goes to RRC_IDLE with
  cause "RRC connection failure".
* N2 is modelled as C++ structs, not encoded NGAP. The NAS PDUs inside are byte-exact.
* Only the null SUCI protection scheme. Only 5G-EA0 / 128-NEA2 / 128-NIA2 (no SNOW 3G or ZUC).
* The SQN freshness check is a simplified version of TS 33.102 Annex C (strictly increasing within
  a Δ window, no IND array).

## Layout

```
include/nrlite/   asn1/ common/ core/ nas/ pdcp/ rrc/ security/ sim/ trace/
src/              implementations, same structure
apps/             nrlite-sim command-line tool
tests/            GoogleTest suites + Wireshark cross-check (tests/wireshark)
docs/             architecture, spec coverage, defect log, sample traces
```

## License

MIT, see [LICENSE](LICENSE).
