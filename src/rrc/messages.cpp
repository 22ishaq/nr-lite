#include "nrlite/rrc/messages.hpp"

#include "nrlite/asn1/per.hpp"

namespace nrlite::rrc {

using namespace nrlite::asn1;

namespace {

// ASN.1 constants (TS 38.331 §6.4)
constexpr std::int64_t kMaxPlmn = 12;
constexpr std::size_t kMaxNrofSNssai = 8;
constexpr std::int64_t kMaxLcId = 32;
constexpr std::int64_t kMaxSecondaryCellGroups = 3;

// Alternative names of the c1 CHOICEs, used for "not supported" diagnostics.
const char* const kUlCcchNames[] = {"rrcSetupRequest", "rrcResumeRequest", "rrcReestablishmentRequest",
                                    "rrcSystemInfoRequest"};
const char* const kDlCcchNames[] = {"rrcReject", "rrcSetup", "spare2", "spare1"};
const char* const kUlDcchNames[] = {"measurementReport",
                                    "rrcReconfigurationComplete",
                                    "rrcSetupComplete",
                                    "rrcReestablishmentComplete",
                                    "rrcResumeComplete",
                                    "securityModeComplete",
                                    "securityModeFailure",
                                    "ulInformationTransfer",
                                    "locationMeasurementIndication",
                                    "ueCapabilityInformation",
                                    "counterCheckResponse",
                                    "ueAssistanceInformation",
                                    "failureInformation",
                                    "ulInformationTransferMRDC",
                                    "scgFailureInformation",
                                    "scgFailureInformationEUTRA"};
const char* const kDlDcchNames[] = {"rrcReconfiguration",
                                    "rrcResume",
                                    "rrcRelease",
                                    "rrcReestablishment",
                                    "securityModeCommand",
                                    "dlInformationTransfer",
                                    "ueCapabilityEnquiry",
                                    "counterCheck",
                                    "mobilityFromNRCommand",
                                    "dlDedicatedMessageSegment-r16",
                                    "ueInformationRequest-r16",
                                    "dlInformationTransferMRDC-r16",
                                    "loggedMeasurementConfiguration-r16",
                                    "spare3",
                                    "spare2",
                                    "spare1"};

[[noreturn]] void unsupported(const std::string& what) { throw DecodeError(what + " not supported by NR-Lite"); }

std::uint8_t u8(std::int64_t v) { return static_cast<std::uint8_t>(v); }

/// criticalExtensions ::= CHOICE { <ies>, criticalExtensionsFuture SEQUENCE {} }
void expect_critical_extensions_ies(BitReader& r, const char* msg) {
  if (decode_choice_index(r, 2).index != 0) unsupported(std::string(msg) + ".criticalExtensionsFuture");
}

void skip_late_non_critical_extension(BitReader& r) { (void)decode_octet_string(r, Size::unbounded()); }

/// Any octets beyond the final padding mean the PDU is longer than its content.
void expect_end(const BitReader& r) {
  if (!r.at_padding()) {
    throw DecodeError(std::to_string(r.remaining() / 8) + " trailing octet(s) after end of message");
  }
}

template <typename Fn>
auto guarded(const char* channel, Fn&& fn) -> decltype(fn()) {
  try {
    return fn();
  } catch (const DecodeError& e) {
    return Error{std::string(channel) + ": " + e.what()};
  }
}

std::string hex(const Bytes& b) { return to_hex(b); }

// ---- InitialUE-Identity -------------------------------------------------------------------------

void enc(BitWriter& w, const InitialUeIdentity& v) {
  encode_choice_index(w, v.type == InitialUeIdentity::Type::ng_5G_S_TMSI_Part1 ? 0 : 1, 2);
  encode_bit_string(w, BitString::from_uint(v.value, 39), Size::fixed(39));
}

InitialUeIdentity dec_initial_ue_identity(BitReader& r) {
  InitialUeIdentity v;
  v.type = decode_choice_index(r, 2).index == 0 ? InitialUeIdentity::Type::ng_5G_S_TMSI_Part1
                                                 : InitialUeIdentity::Type::randomValue;
  v.value = decode_bit_string(r, Size::fixed(39)).to_uint();
  return v;
}

// ---- RadioBearerConfig --------------------------------------------------------------------------

void enc(BitWriter& w, const SrbToAddMod& v) {
  // SEQUENCE { srb-Identity, reestablishPDCP OPT, discardOnPDCP OPT, pdcp-Config OPT, ..., [[...]] }
  encode_sequence_preamble(w, true, false, {v.reestablish_pdcp, v.discard_on_pdcp, false});
  encode_integer(w, v.srb_identity, 1, 3);
  if (v.reestablish_pdcp) encode_enumerated(w, 0, 1);
  if (v.discard_on_pdcp) encode_enumerated(w, 0, 1);
}

SrbToAddMod dec_srb_to_add_mod(BitReader& r) {
  const Preamble p = decode_sequence_preamble(r, true, 3);
  SrbToAddMod v;
  v.srb_identity = u8(decode_integer(r, 1, 3));
  if (p[0]) {
    (void)decode_enumerated(r, 1);
    v.reestablish_pdcp = true;
  }
  if (p[1]) {
    (void)decode_enumerated(r, 1);
    v.discard_on_pdcp = true;
  }
  if (p[2]) unsupported("SRB-ToAddMod.pdcp-Config");
  if (p.extensions_present) (void)decode_extension_additions(r);  // srb-Identity-v1700: ignored
  return v;
}

void enc(BitWriter& w, const RadioBearerConfig& v) {
  // SEQUENCE { srb-ToAddModList OPT, srb3-ToRelease OPT, drb-ToAddModList OPT, drb-ToReleaseList OPT,
  //            securityConfig OPT, ... }
  const bool has_srbs = !v.srb_to_add_mod_list.empty();
  encode_sequence_preamble(w, true, false, {has_srbs, v.srb3_to_release, false, false, false});
  if (has_srbs) {
    encode_length(w, v.srb_to_add_mod_list.size(), Size::range(1, 2));
    for (const auto& s : v.srb_to_add_mod_list) enc(w, s);
  }
  if (v.srb3_to_release) encode_enumerated(w, 0, 1);
}

RadioBearerConfig dec_radio_bearer_config(BitReader& r) {
  const Preamble p = decode_sequence_preamble(r, true, 5);
  RadioBearerConfig v;
  if (p[0]) {
    const std::size_t n = decode_length(r, Size::range(1, 2));
    for (std::size_t i = 0; i < n; ++i) v.srb_to_add_mod_list.push_back(dec_srb_to_add_mod(r));
  }
  if (p[1]) {
    (void)decode_enumerated(r, 1);
    v.srb3_to_release = true;
  }
  if (p[2]) unsupported("RadioBearerConfig.drb-ToAddModList");
  if (p[3]) unsupported("RadioBearerConfig.drb-ToReleaseList");
  if (p[4]) unsupported("RadioBearerConfig.securityConfig");
  if (p.extensions_present) (void)decode_extension_additions(r);
  return v;
}

// ---- CellGroupConfig ----------------------------------------------------------------------------

void enc(BitWriter& w, const RlcBearerConfig& v) {
  // SEQUENCE { logicalChannelIdentity, servedRadioBearer OPT, reestablishRLC OPT, rlc-Config OPT,
  //            mac-LogicalChannelConfig OPT, ..., [[...]] }
  encode_sequence_preamble(w, true, false, {v.served_radio_bearer.has_value(), v.reestablish_rlc, false, false});
  encode_integer(w, v.logical_channel_identity, 1, kMaxLcId);
  if (v.served_radio_bearer) {
    encode_choice_index(w, v.served_radio_bearer->is_srb ? 0 : 1, 2);
    if (v.served_radio_bearer->is_srb) {
      encode_integer(w, v.served_radio_bearer->identity, 1, 3);
    } else {
      encode_integer(w, v.served_radio_bearer->identity, 1, 32);
    }
  }
  if (v.reestablish_rlc) encode_enumerated(w, 0, 1);
}

RlcBearerConfig dec_rlc_bearer_config(BitReader& r) {
  const Preamble p = decode_sequence_preamble(r, true, 4);
  RlcBearerConfig v;
  v.logical_channel_identity = u8(decode_integer(r, 1, kMaxLcId));
  if (p[0]) {
    RlcBearerConfig::ServedRadioBearer srb;
    srb.is_srb = decode_choice_index(r, 2).index == 0;
    srb.identity = u8(srb.is_srb ? decode_integer(r, 1, 3) : decode_integer(r, 1, 32));
    v.served_radio_bearer = srb;
  }
  if (p[1]) {
    (void)decode_enumerated(r, 1);
    v.reestablish_rlc = true;
  }
  if (p[2]) unsupported("RLC-BearerConfig.rlc-Config");
  if (p[3]) unsupported("RLC-BearerConfig.mac-LogicalChannelConfig");
  if (p.extensions_present) (void)decode_extension_additions(r);
  return v;
}

void enc(BitWriter& w, const CellGroupConfig& v) {
  // SEQUENCE { cellGroupId, rlc-BearerToAddModList OPT, rlc-BearerToReleaseList OPT,
  //            mac-CellGroupConfig OPT, physicalCellGroupConfig OPT, spCellConfig OPT,
  //            sCellToAddModList OPT, sCellToReleaseList OPT, ..., [[...]] }
  const bool has_rlc = !v.rlc_bearer_to_add_mod_list.empty();
  encode_sequence_preamble(w, true, false, {has_rlc, false, false, false, false, false, false});
  encode_integer(w, v.cell_group_id, 0, kMaxSecondaryCellGroups);
  if (has_rlc) {
    encode_length(w, v.rlc_bearer_to_add_mod_list.size(), Size::range(1, kMaxLcId));
    for (const auto& b : v.rlc_bearer_to_add_mod_list) enc(w, b);
  }
}

CellGroupConfig dec_cell_group_config(BitReader& r) {
  static const char* const kNames[] = {"rlc-BearerToAddModList", "rlc-BearerToReleaseList", "mac-CellGroupConfig",
                                       "physicalCellGroupConfig", "spCellConfig",           "sCellToAddModList",
                                       "sCellToReleaseList"};
  const Preamble p = decode_sequence_preamble(r, true, 7);
  CellGroupConfig v;
  v.cell_group_id = u8(decode_integer(r, 0, kMaxSecondaryCellGroups));
  if (p[0]) {
    const std::size_t n = decode_length(r, Size::range(1, kMaxLcId));
    for (std::size_t i = 0; i < n; ++i) v.rlc_bearer_to_add_mod_list.push_back(dec_rlc_bearer_config(r));
  }
  for (std::size_t i = 1; i < 7; ++i) {
    if (p[i]) unsupported(std::string("CellGroupConfig.") + kNames[i]);
  }
  if (p.extensions_present) (void)decode_extension_additions(r);
  return v;
}

// ---- S-NSSAI, PLMN-Identity, RegisteredAMF ------------------------------------------------------

void enc(BitWriter& w, const SNssai& v) {
  if (v.sd) {
    encode_choice_index(w, 1, 2);
    encode_bit_string(w, BitString::from_uint((std::uint64_t{v.sst} << 24) | *v.sd, 32), Size::fixed(32));
  } else {
    encode_choice_index(w, 0, 2);
    encode_bit_string(w, BitString::from_uint(v.sst, 8), Size::fixed(8));
  }
}

SNssai dec_s_nssai(BitReader& r) {
  SNssai v;
  if (decode_choice_index(r, 2).index == 0) {
    v.sst = u8(static_cast<std::int64_t>(decode_bit_string(r, Size::fixed(8)).to_uint()));
  } else {
    const std::uint64_t x = decode_bit_string(r, Size::fixed(32)).to_uint();
    v.sst = static_cast<std::uint8_t>(x >> 24);
    v.sd = static_cast<std::uint32_t>(x & 0xFFFFFF);
  }
  return v;
}

void enc(BitWriter& w, const PlmnIdentity& v) {
  encode_sequence_preamble(w, false, false, {v.mcc.has_value()});
  if (v.mcc) {
    for (std::uint8_t d : *v.mcc) encode_integer(w, d, 0, 9);  // MCC ::= SEQUENCE (SIZE (3)) OF MCC-MNC-Digit
  }
  encode_length(w, v.mnc.size(), Size::range(2, 3));  // MNC ::= SEQUENCE (SIZE (2..3)) OF MCC-MNC-Digit
  for (std::uint8_t d : v.mnc) encode_integer(w, d, 0, 9);
}

PlmnIdentity dec_plmn_identity(BitReader& r) {
  const Preamble p = decode_sequence_preamble(r, false, 1);
  PlmnIdentity v;
  if (p[0]) {
    std::array<std::uint8_t, 3> mcc{};
    for (auto& d : mcc) d = u8(decode_integer(r, 0, 9));
    v.mcc = mcc;
  }
  const std::size_t n = decode_length(r, Size::range(2, 3));
  for (std::size_t i = 0; i < n; ++i) v.mnc.push_back(u8(decode_integer(r, 0, 9)));
  return v;
}

void enc(BitWriter& w, const RegisteredAmf& v) {
  encode_sequence_preamble(w, false, false, {v.plmn_identity.has_value()});
  if (v.plmn_identity) enc(w, *v.plmn_identity);
  encode_bit_string(w, BitString::from_uint(v.amf_identifier, 24), Size::fixed(24));
}

RegisteredAmf dec_registered_amf(BitReader& r) {
  const Preamble p = decode_sequence_preamble(r, false, 1);
  RegisteredAmf v;
  if (p[0]) v.plmn_identity = dec_plmn_identity(r);
  v.amf_identifier = static_cast<std::uint32_t>(decode_bit_string(r, Size::fixed(24)).to_uint());
  return v;
}

// ---- Message bodies -----------------------------------------------------------------------------

void enc(BitWriter& w, const RrcSetupRequest& m) {
  // RRCSetupRequest ::= SEQUENCE { rrcSetupRequest RRCSetupRequest-IEs }
  // RRCSetupRequest-IEs ::= SEQUENCE { ue-Identity, establishmentCause, spare BIT STRING (SIZE (1)) }
  enc(w, m.ue_identity);
  encode_enumerated(w, static_cast<unsigned>(m.establishment_cause), 16);
  encode_bit_string(w, BitString::from_uint(0, 1), Size::fixed(1));
}

RrcSetupRequest dec_rrc_setup_request(BitReader& r) {
  RrcSetupRequest m;
  m.ue_identity = dec_initial_ue_identity(r);
  m.establishment_cause = static_cast<EstablishmentCause>(decode_enumerated(r, 16));
  (void)decode_bit_string(r, Size::fixed(1));  // spare
  return m;
}

void enc(BitWriter& w, const RrcSetup& m) {
  encode_integer(w, m.rrc_transaction_identifier, 0, 3);
  encode_choice_index(w, 0, 2);  // criticalExtensions: rrcSetup
  // RRCSetup-IEs ::= SEQUENCE { radioBearerConfig, masterCellGroup, lateNonCriticalExtension OPT,
  //                             nonCriticalExtension OPT }
  encode_sequence_preamble(w, false, false, {false, false});
  enc(w, m.radio_bearer_config);
  encode_octet_string(w, encode_cell_group_config(m.master_cell_group), Size::unbounded());
}

RrcSetup dec_rrc_setup(BitReader& r) {
  RrcSetup m;
  m.rrc_transaction_identifier = u8(decode_integer(r, 0, 3));
  expect_critical_extensions_ies(r, "RRCSetup");
  const Preamble p = decode_sequence_preamble(r, false, 2);
  m.radio_bearer_config = dec_radio_bearer_config(r);
  const Bytes cg = decode_octet_string(r, Size::unbounded());
  BitReader cgr(cg);
  m.master_cell_group = dec_cell_group_config(cgr);
  expect_end(cgr);
  if (p[0]) skip_late_non_critical_extension(r);
  if (p[1]) unsupported("RRCSetup-IEs.nonCriticalExtension");
  return m;
}

void enc(BitWriter& w, const RrcReject& m) {
  encode_choice_index(w, 0, 2);  // criticalExtensions: rrcReject
  // RRCReject-IEs ::= SEQUENCE { waitTime OPT, lateNonCriticalExtension OPT, nonCriticalExtension OPT }
  encode_sequence_preamble(w, false, false, {m.wait_time.has_value(), false, false});
  if (m.wait_time) encode_integer(w, *m.wait_time, 1, 16);
}

RrcReject dec_rrc_reject(BitReader& r) {
  expect_critical_extensions_ies(r, "RRCReject");
  const Preamble p = decode_sequence_preamble(r, false, 3);
  RrcReject m;
  if (p[0]) m.wait_time = u8(decode_integer(r, 1, 16));
  if (p[1]) skip_late_non_critical_extension(r);
  // p[2]: nonCriticalExtension SEQUENCE {} has an empty encoding.
  return m;
}

void enc(BitWriter& w, const RrcSetupComplete& m) {
  encode_integer(w, m.rrc_transaction_identifier, 0, 3);
  encode_choice_index(w, 0, 2);  // criticalExtensions: rrcSetupComplete
  const bool has_nssai = !m.s_nssai_list.empty();
  encode_sequence_preamble(w, false, false,
                           {m.registered_amf.has_value(), m.guami_type.has_value(), has_nssai,
                            m.ng_5g_s_tmsi_value.has_value(), false, false});
  encode_integer(w, m.selected_plmn_identity, 1, kMaxPlmn);
  if (m.registered_amf) enc(w, *m.registered_amf);
  if (m.guami_type) encode_enumerated(w, static_cast<unsigned>(*m.guami_type), 2);
  if (has_nssai) {
    encode_length(w, m.s_nssai_list.size(), Size::range(1, kMaxNrofSNssai));
    for (const auto& s : m.s_nssai_list) enc(w, s);
  }
  encode_octet_string(w, m.dedicated_nas_message, Size::unbounded());
  if (m.ng_5g_s_tmsi_value) {
    if (m.ng_5g_s_tmsi_value->full) {
      encode_choice_index(w, 0, 2);
      encode_bit_string(w, BitString::from_uint(m.ng_5g_s_tmsi_value->value, 48), Size::fixed(48));
    } else {
      encode_choice_index(w, 1, 2);
      encode_bit_string(w, BitString::from_uint(m.ng_5g_s_tmsi_value->value, 9), Size::fixed(9));
    }
  }
}

RrcSetupComplete dec_rrc_setup_complete(BitReader& r) {
  RrcSetupComplete m;
  m.rrc_transaction_identifier = u8(decode_integer(r, 0, 3));
  expect_critical_extensions_ies(r, "RRCSetupComplete");
  const Preamble p = decode_sequence_preamble(r, false, 6);
  m.selected_plmn_identity = u8(decode_integer(r, 1, kMaxPlmn));
  if (p[0]) m.registered_amf = dec_registered_amf(r);
  if (p[1]) m.guami_type = static_cast<RrcSetupComplete::GuamiType>(decode_enumerated(r, 2));
  if (p[2]) {
    const std::size_t n = decode_length(r, Size::range(1, kMaxNrofSNssai));
    for (std::size_t i = 0; i < n; ++i) m.s_nssai_list.push_back(dec_s_nssai(r));
  }
  m.dedicated_nas_message = decode_octet_string(r, Size::unbounded());
  if (p[3]) {
    RrcSetupComplete::Ng5gSTmsiValue v;
    v.full = decode_choice_index(r, 2).index == 0;
    v.value = decode_bit_string(r, Size::fixed(v.full ? 48 : 9)).to_uint();
    m.ng_5g_s_tmsi_value = v;
  }
  if (p[4]) skip_late_non_critical_extension(r);
  if (p[5]) unsupported("RRCSetupComplete-IEs.nonCriticalExtension");
  return m;
}

void enc(BitWriter& w, const SecurityModeCommand& m) {
  encode_integer(w, m.rrc_transaction_identifier, 0, 3);
  encode_choice_index(w, 0, 2);  // criticalExtensions: securityModeCommand
  // SecurityModeCommand-IEs ::= SEQUENCE { securityConfigSMC, lateNonCriticalExtension OPT,
  //                                        nonCriticalExtension OPT }
  encode_sequence_preamble(w, false, false, {false, false});
  // SecurityConfigSMC ::= SEQUENCE { securityAlgorithmConfig, ... }
  encode_sequence_preamble(w, true, false, {});
  // SecurityAlgorithmConfig ::= SEQUENCE { cipheringAlgorithm, integrityProtAlgorithm OPT, ... }
  encode_sequence_preamble(w, true, false, {m.integrity_prot_algorithm.has_value()});
  encode_enumerated(w, static_cast<unsigned>(m.ciphering_algorithm), 8, true);
  if (m.integrity_prot_algorithm) encode_enumerated(w, static_cast<unsigned>(*m.integrity_prot_algorithm), 8, true);
}

SecurityModeCommand dec_security_mode_command(BitReader& r) {
  SecurityModeCommand m;
  m.rrc_transaction_identifier = u8(decode_integer(r, 0, 3));
  expect_critical_extensions_ies(r, "SecurityModeCommand");
  const Preamble ies = decode_sequence_preamble(r, false, 2);
  const Preamble smc = decode_sequence_preamble(r, true, 0);
  const Preamble alg = decode_sequence_preamble(r, true, 1);
  const unsigned cipher = decode_enumerated(r, 8, true);
  if (cipher >= 8) throw DecodeError("cipheringAlgorithm: unknown extension value");
  m.ciphering_algorithm = static_cast<CipheringAlgorithm>(cipher);
  if (alg[0]) {
    const unsigned integ = decode_enumerated(r, 8, true);
    if (integ >= 8) throw DecodeError("integrityProtAlgorithm: unknown extension value");
    m.integrity_prot_algorithm = static_cast<IntegrityProtAlgorithm>(integ);
  }
  if (alg.extensions_present) (void)decode_extension_additions(r);
  if (smc.extensions_present) (void)decode_extension_additions(r);
  if (ies[0]) skip_late_non_critical_extension(r);
  return m;
}

/// SecurityModeComplete / SecurityModeFailure share the same shape.
void enc_txid_only(BitWriter& w, std::uint8_t txid) {
  encode_integer(w, txid, 0, 3);
  encode_choice_index(w, 0, 2);
  encode_sequence_preamble(w, false, false, {false, false});
}

std::uint8_t dec_txid_only(BitReader& r, const char* name) {
  const std::uint8_t txid = u8(decode_integer(r, 0, 3));
  expect_critical_extensions_ies(r, name);
  const Preamble p = decode_sequence_preamble(r, false, 2);
  if (p[0]) skip_late_non_critical_extension(r);
  return txid;
}

void enc(BitWriter& w, const DlInformationTransfer& m) {
  encode_integer(w, m.rrc_transaction_identifier, 0, 3);
  encode_choice_index(w, 0, 2);
  encode_sequence_preamble(w, false, false, {m.dedicated_nas_message.has_value(), false, false});
  if (m.dedicated_nas_message) encode_octet_string(w, *m.dedicated_nas_message, Size::unbounded());
}

DlInformationTransfer dec_dl_information_transfer(BitReader& r) {
  DlInformationTransfer m;
  m.rrc_transaction_identifier = u8(decode_integer(r, 0, 3));
  expect_critical_extensions_ies(r, "DLInformationTransfer");
  const Preamble p = decode_sequence_preamble(r, false, 3);
  if (p[0]) m.dedicated_nas_message = decode_octet_string(r, Size::unbounded());
  if (p[1]) skip_late_non_critical_extension(r);
  if (p[2]) unsupported("DLInformationTransfer-IEs.nonCriticalExtension");
  return m;
}

void enc(BitWriter& w, const UlInformationTransfer& m) {
  encode_choice_index(w, 0, 2);
  encode_sequence_preamble(w, false, false, {m.dedicated_nas_message.has_value(), false, false});
  if (m.dedicated_nas_message) encode_octet_string(w, *m.dedicated_nas_message, Size::unbounded());
}

UlInformationTransfer dec_ul_information_transfer(BitReader& r) {
  UlInformationTransfer m;
  expect_critical_extensions_ies(r, "ULInformationTransfer");
  const Preamble p = decode_sequence_preamble(r, false, 3);
  if (p[0]) m.dedicated_nas_message = decode_octet_string(r, Size::unbounded());
  if (p[1]) skip_late_non_critical_extension(r);
  if (p[2]) unsupported("ULInformationTransfer-IEs.nonCriticalExtension");
  return m;
}

void enc(BitWriter& w, const RrcRelease& m) {
  encode_integer(w, m.rrc_transaction_identifier, 0, 3);
  encode_choice_index(w, 0, 2);
  // RRCRelease-IEs ::= SEQUENCE { redirectedCarrierInfo OPT, cellReselectionPriorities OPT,
  //   suspendConfig OPT, deprioritisationReq OPT, lateNonCriticalExtension OPT, nonCriticalExtension OPT }
  encode_sequence_preamble(w, false, false,
                           {false, false, false, m.deprioritisation_req.has_value(), false, m.wait_time.has_value()});
  if (m.deprioritisation_req) {
    encode_enumerated(w, static_cast<unsigned>(m.deprioritisation_req->type), 2);
    encode_enumerated(w, static_cast<unsigned>(m.deprioritisation_req->timer), 4);
  }
  if (m.wait_time) {
    // RRCRelease-v1540-IEs ::= SEQUENCE { waitTime RejectWaitTime OPT, nonCriticalExtension OPT }
    encode_sequence_preamble(w, false, false, {true, false});
    encode_integer(w, *m.wait_time, 1, 16);
  }
}

RrcRelease dec_rrc_release(BitReader& r) {
  RrcRelease m;
  m.rrc_transaction_identifier = u8(decode_integer(r, 0, 3));
  expect_critical_extensions_ies(r, "RRCRelease");
  const Preamble p = decode_sequence_preamble(r, false, 6);
  if (p[0]) unsupported("RRCRelease-IEs.redirectedCarrierInfo");
  if (p[1]) unsupported("RRCRelease-IEs.cellReselectionPriorities");
  if (p[2]) unsupported("RRCRelease-IEs.suspendConfig");
  if (p[3]) {
    RrcRelease::DeprioritisationReq d;
    d.type = static_cast<RrcRelease::DeprioritisationReq::Type>(decode_enumerated(r, 2));
    d.timer = static_cast<RrcRelease::DeprioritisationReq::Timer>(decode_enumerated(r, 4));
    m.deprioritisation_req = d;
  }
  if (p[4]) skip_late_non_critical_extension(r);
  if (p[5]) {
    const Preamble v1540 = decode_sequence_preamble(r, false, 2);
    if (v1540[0]) m.wait_time = u8(decode_integer(r, 1, 16));
    if (v1540[1]) unsupported("RRCRelease-v1540-IEs.nonCriticalExtension");
  }
  return m;
}

// ---- JSON helpers -------------------------------------------------------------------------------

Json json_srb(const SrbToAddMod& s) {
  Json j = Json::object().set("srb-Identity", s.srb_identity);
  if (s.reestablish_pdcp) j.set("reestablishPDCP", "true");
  if (s.discard_on_pdcp) j.set("discardOnPDCP", "true");
  return j;
}

Json json_cell_group(const CellGroupConfig& cg) {
  Json j = Json::object().set("cellGroupId", cg.cell_group_id);
  if (!cg.rlc_bearer_to_add_mod_list.empty()) {
    Json list = Json::array();
    for (const auto& b : cg.rlc_bearer_to_add_mod_list) {
      Json e = Json::object().set("logicalChannelIdentity", b.logical_channel_identity);
      if (b.served_radio_bearer) {
        e.set("servedRadioBearer", Json::object().set(b.served_radio_bearer->is_srb ? "srb-Identity" : "drb-Identity",
                                                      b.served_radio_bearer->identity));
      }
      if (b.reestablish_rlc) e.set("reestablishRLC", "true");
      list.push(std::move(e));
    }
    j.set("rlc-BearerToAddModList", std::move(list));
  }
  return j;
}

Json json_s_nssai(const SNssai& s) {
  if (s.sd) return Json::object().set("sst-SD", Json::object().set("sst", s.sst).set("sd", *s.sd));
  return Json::object().set("sst", s.sst);
}

Json body(const RrcSetupRequest& m) {
  return Json::object()
      .set("ue-Identity", Json::object().set(m.ue_identity.type == InitialUeIdentity::Type::randomValue
                                                 ? "randomValue"
                                                 : "ng-5G-S-TMSI-Part1",
                                             m.ue_identity.value))
      .set("establishmentCause", to_string(m.establishment_cause));
}

Json body(const RrcSetup& m) {
  Json rb = Json::object();
  if (!m.radio_bearer_config.srb_to_add_mod_list.empty()) {
    Json list = Json::array();
    for (const auto& s : m.radio_bearer_config.srb_to_add_mod_list) list.push(json_srb(s));
    rb.set("srb-ToAddModList", std::move(list));
  }
  if (m.radio_bearer_config.srb3_to_release) rb.set("srb3-ToRelease", "true");
  return Json::object()
      .set("rrc-TransactionIdentifier", m.rrc_transaction_identifier)
      .set("radioBearerConfig", std::move(rb))
      .set("masterCellGroup", json_cell_group(m.master_cell_group));
}

Json body(const RrcReject& m) {
  Json j = Json::object();
  if (m.wait_time) j.set("waitTime", *m.wait_time);
  return j;
}

Json body(const RrcSetupComplete& m) {
  Json j = Json::object()
               .set("rrc-TransactionIdentifier", m.rrc_transaction_identifier)
               .set("selectedPLMN-Identity", m.selected_plmn_identity);
  if (m.registered_amf) j.set("registeredAMF", Json::object().set("amf-Identifier", m.registered_amf->amf_identifier));
  if (m.guami_type) j.set("guami-Type", *m.guami_type == RrcSetupComplete::GuamiType::native ? "native" : "mapped");
  if (!m.s_nssai_list.empty()) {
    Json list = Json::array();
    for (const auto& s : m.s_nssai_list) list.push(json_s_nssai(s));
    j.set("s-NSSAI-List", std::move(list));
  }
  j.set("dedicatedNAS-Message", hex(m.dedicated_nas_message));
  if (m.ng_5g_s_tmsi_value) {
    j.set("ng-5G-S-TMSI-Value", Json::object().set(m.ng_5g_s_tmsi_value->full ? "ng-5G-S-TMSI" : "ng-5G-S-TMSI-Part2",
                                                   m.ng_5g_s_tmsi_value->value));
  }
  return j;
}

Json body(const SecurityModeCommand& m) {
  Json alg = Json::object().set("cipheringAlgorithm", to_string(m.ciphering_algorithm));
  if (m.integrity_prot_algorithm) alg.set("integrityProtAlgorithm", to_string(*m.integrity_prot_algorithm));
  return Json::object()
      .set("rrc-TransactionIdentifier", m.rrc_transaction_identifier)
      .set("securityConfigSMC", Json::object().set("securityAlgorithmConfig", std::move(alg)));
}

Json body(const SecurityModeComplete& m) {
  return Json::object().set("rrc-TransactionIdentifier", m.rrc_transaction_identifier);
}

Json body(const SecurityModeFailure& m) {
  return Json::object().set("rrc-TransactionIdentifier", m.rrc_transaction_identifier);
}

Json body(const DlInformationTransfer& m) {
  Json j = Json::object().set("rrc-TransactionIdentifier", m.rrc_transaction_identifier);
  if (m.dedicated_nas_message) j.set("dedicatedNAS-Message", hex(*m.dedicated_nas_message));
  return j;
}

Json body(const UlInformationTransfer& m) {
  Json j = Json::object();
  if (m.dedicated_nas_message) j.set("dedicatedNAS-Message", hex(*m.dedicated_nas_message));
  return j;
}

Json body(const RrcRelease& m) {
  static const char* const kTypes[] = {"frequency", "nr"};
  static const char* const kTimers[] = {"min5", "min10", "min15", "min30"};
  Json j = Json::object().set("rrc-TransactionIdentifier", m.rrc_transaction_identifier);
  if (m.deprioritisation_req) {
    j.set("deprioritisationReq",
          Json::object()
              .set("deprioritisationType", kTypes[static_cast<int>(m.deprioritisation_req->type)])
              .set("deprioritisationTimer", kTimers[static_cast<int>(m.deprioritisation_req->timer)]));
  }
  if (m.wait_time) j.set("waitTime", *m.wait_time);
  return j;
}

template <typename Variant>
Json variant_json(const Variant& v) {
  return std::visit(
      [&v](const auto& m) {
        Json j = Json::object().set("message", message_name(v));
        j.set("body", body(m));
        return j;
      },
      v);
}

}  // namespace

// ---- Enum names ---------------------------------------------------------------------------------

const char* to_string(EstablishmentCause c) {
  static const char* const kNames[] = {"emergency",          "highPriorityAccess", "mt-Access",   "mo-Signalling",
                                       "mo-Data",            "mo-VoiceCall",       "mo-VideoCall", "mo-SMS",
                                       "mps-PriorityAccess", "mcs-PriorityAccess", "spare6",      "spare5",
                                       "spare4",             "spare3",             "spare2",      "spare1"};
  return kNames[static_cast<int>(c) & 0x0F];
}

const char* to_string(CipheringAlgorithm a) {
  static const char* const kNames[] = {"nea0", "nea1", "nea2", "nea3", "spare4", "spare3", "spare2", "spare1"};
  return kNames[static_cast<int>(a) & 0x07];
}

const char* to_string(IntegrityProtAlgorithm a) {
  static const char* const kNames[] = {"nia0", "nia1", "nia2", "nia3", "spare4", "spare3", "spare2", "spare1"};
  return kNames[static_cast<int>(a) & 0x07];
}

// ---- Top-level codecs ---------------------------------------------------------------------------

Bytes encode_cell_group_config(const CellGroupConfig& cg) {
  BitWriter w;
  enc(w, cg);
  return w.complete();
}

Result<CellGroupConfig> decode_cell_group_config(const Bytes& bytes) {
  return guarded("CellGroupConfig", [&]() -> Result<CellGroupConfig> {
    BitReader r(bytes);
    CellGroupConfig cg = dec_cell_group_config(r);
    expect_end(r);
    return cg;
  });
}

Bytes encode_ul_ccch(const UlCcchMessage& msg) {
  BitWriter w;
  encode_choice_index(w, 0, 2);  // UL-CCCH-MessageType: c1
  std::visit(overloaded{[&](const RrcSetupRequest& m) {
               encode_choice_index(w, 0, 4);
               enc(w, m);
             }},
             msg);
  return w.complete();
}

Bytes encode_dl_ccch(const DlCcchMessage& msg) {
  BitWriter w;
  encode_choice_index(w, 0, 2);  // DL-CCCH-MessageType: c1
  std::visit(overloaded{[&](const RrcReject& m) {
                          encode_choice_index(w, 0, 4);
                          enc(w, m);
                        },
                        [&](const RrcSetup& m) {
                          encode_choice_index(w, 1, 4);
                          enc(w, m);
                        }},
             msg);
  return w.complete();
}

Bytes encode_ul_dcch(const UlDcchMessage& msg) {
  BitWriter w;
  encode_choice_index(w, 0, 2);  // UL-DCCH-MessageType: c1
  std::visit(overloaded{[&](const RrcSetupComplete& m) {
                          encode_choice_index(w, 2, 16);
                          enc(w, m);
                        },
                        [&](const SecurityModeComplete& m) {
                          encode_choice_index(w, 5, 16);
                          enc_txid_only(w, m.rrc_transaction_identifier);
                        },
                        [&](const SecurityModeFailure& m) {
                          encode_choice_index(w, 6, 16);
                          enc_txid_only(w, m.rrc_transaction_identifier);
                        },
                        [&](const UlInformationTransfer& m) {
                          encode_choice_index(w, 7, 16);
                          enc(w, m);
                        }},
             msg);
  return w.complete();
}

Bytes encode_dl_dcch(const DlDcchMessage& msg) {
  BitWriter w;
  encode_choice_index(w, 0, 2);  // DL-DCCH-MessageType: c1
  std::visit(overloaded{[&](const SecurityModeCommand& m) {
                          encode_choice_index(w, 4, 16);
                          enc(w, m);
                        },
                        [&](const DlInformationTransfer& m) {
                          encode_choice_index(w, 5, 16);
                          enc(w, m);
                        },
                        [&](const RrcRelease& m) {
                          encode_choice_index(w, 2, 16);
                          enc(w, m);
                        }},
             msg);
  return w.complete();
}

Result<UlCcchMessage> decode_ul_ccch(const Bytes& pdu) {
  return guarded("UL-CCCH", [&]() -> Result<UlCcchMessage> {
    BitReader r(pdu);
    if (decode_choice_index(r, 2).index != 0) unsupported("messageClassExtension");
    const unsigned c1 = decode_choice_index(r, 4).index;
    if (c1 != 0) unsupported(kUlCcchNames[c1]);
    UlCcchMessage m = dec_rrc_setup_request(r);
    expect_end(r);
    return m;
  });
}

Result<DlCcchMessage> decode_dl_ccch(const Bytes& pdu) {
  return guarded("DL-CCCH", [&]() -> Result<DlCcchMessage> {
    BitReader r(pdu);
    if (decode_choice_index(r, 2).index != 0) unsupported("messageClassExtension");
    const unsigned c1 = decode_choice_index(r, 4).index;
    DlCcchMessage m;
    switch (c1) {
      case 0: m = dec_rrc_reject(r); break;
      case 1: m = dec_rrc_setup(r); break;
      default: unsupported(kDlCcchNames[c1]);
    }
    expect_end(r);
    return m;
  });
}

Result<UlDcchMessage> decode_ul_dcch(const Bytes& pdu) {
  return guarded("UL-DCCH", [&]() -> Result<UlDcchMessage> {
    BitReader r(pdu);
    if (decode_choice_index(r, 2).index != 0) unsupported("messageClassExtension");
    const unsigned c1 = decode_choice_index(r, 16).index;
    UlDcchMessage m;
    switch (c1) {
      case 2: m = dec_rrc_setup_complete(r); break;
      case 5: m = SecurityModeComplete{dec_txid_only(r, "SecurityModeComplete")}; break;
      case 6: m = SecurityModeFailure{dec_txid_only(r, "SecurityModeFailure")}; break;
      case 7: m = dec_ul_information_transfer(r); break;
      default: unsupported(kUlDcchNames[c1]);
    }
    expect_end(r);
    return m;
  });
}

Result<DlDcchMessage> decode_dl_dcch(const Bytes& pdu) {
  return guarded("DL-DCCH", [&]() -> Result<DlDcchMessage> {
    BitReader r(pdu);
    if (decode_choice_index(r, 2).index != 0) unsupported("messageClassExtension");
    const unsigned c1 = decode_choice_index(r, 16).index;
    DlDcchMessage m;
    switch (c1) {
      case 2: m = dec_rrc_release(r); break;
      case 4: m = dec_security_mode_command(r); break;
      case 5: m = dec_dl_information_transfer(r); break;
      default: unsupported(kDlDcchNames[c1]);
    }
    expect_end(r);
    return m;
  });
}

std::string message_name(const UlCcchMessage&) { return "rrcSetupRequest"; }

std::string message_name(const DlCcchMessage& m) {
  return std::holds_alternative<RrcReject>(m) ? "rrcReject" : "rrcSetup";
}

std::string message_name(const UlDcchMessage& m) {
  return std::visit(overloaded{[](const RrcSetupComplete&) { return "rrcSetupComplete"; },
                               [](const SecurityModeComplete&) { return "securityModeComplete"; },
                               [](const SecurityModeFailure&) { return "securityModeFailure"; },
                               [](const UlInformationTransfer&) { return "ulInformationTransfer"; }},
                    m);
}

std::string message_name(const DlDcchMessage& m) {
  return std::visit(overloaded{[](const SecurityModeCommand&) { return "securityModeCommand"; },
                               [](const DlInformationTransfer&) { return "dlInformationTransfer"; },
                               [](const RrcRelease&) { return "rrcRelease"; }},
                    m);
}

Json to_json(const UlCcchMessage& m) { return variant_json(m); }
Json to_json(const DlCcchMessage& m) { return variant_json(m); }
Json to_json(const UlDcchMessage& m) { return variant_json(m); }
Json to_json(const DlDcchMessage& m) { return variant_json(m); }

}  // namespace nrlite::rrc
