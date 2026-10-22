#pragma once

// NR RRC messages (TS 38.331 §6.2) used for connection setup, AS security and NAS transport.
//
// Each struct mirrors the ASN.1 definition; the encoders and decoders in messages.cpp follow the
// definitions component by component and produce bit-exact UPER, so the output can be decoded by
// Wireshark's nr-rrc dissector. Fields that NR-Lite does not model (e.g. PDCP-Config, spCellConfig)
// are always encoded as absent; receiving one is reported as an "unsupported" decode error rather
// than silently mis-parsed, because UPER root components carry no length and cannot be skipped.
//
// Logical channel message classes:
//   UL-CCCH  rrcSetupRequest
//   DL-CCCH  rrcReject, rrcSetup
//   UL-DCCH  rrcSetupComplete, securityModeComplete, securityModeFailure, ulInformationTransfer
//   DL-DCCH  securityModeCommand, dlInformationTransfer, rrcRelease

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "nrlite/common/bytes.hpp"
#include "nrlite/common/json.hpp"
#include "nrlite/common/result.hpp"

namespace nrlite::rrc {

// ---- Information elements (TS 38.331 §6.3) ------------------------------------------------------

enum class EstablishmentCause : std::uint8_t {
  emergency,
  highPriorityAccess,
  mt_Access,
  mo_Signalling,
  mo_Data,
  mo_VoiceCall,
  mo_VideoCall,
  mo_SMS,
  mps_PriorityAccess,
  mcs_PriorityAccess,
  spare6,
  spare5,
  spare4,
  spare3,
  spare2,
  spare1,
};
const char* to_string(EstablishmentCause c);

/// InitialUE-Identity ::= CHOICE { ng-5G-S-TMSI-Part1 BIT STRING (SIZE (39)), randomValue BIT STRING (SIZE (39)) }
struct InitialUeIdentity {
  enum class Type : std::uint8_t { ng_5G_S_TMSI_Part1, randomValue };
  Type type = Type::randomValue;
  std::uint64_t value = 0;  ///< 39 bits

  bool operator==(const InitialUeIdentity& o) const { return type == o.type && value == o.value; }
};

enum class CipheringAlgorithm : std::uint8_t { nea0, nea1, nea2, nea3, spare4, spare3, spare2, spare1 };
enum class IntegrityProtAlgorithm : std::uint8_t { nia0, nia1, nia2, nia3, spare4, spare3, spare2, spare1 };
const char* to_string(CipheringAlgorithm a);
const char* to_string(IntegrityProtAlgorithm a);

/// SRB-ToAddMod (pdcp-Config not modelled: the UE uses the default SRB PDCP configuration).
struct SrbToAddMod {
  std::uint8_t srb_identity = 1;  ///< SRB-Identity ::= INTEGER (1..3)
  bool reestablish_pdcp = false;
  bool discard_on_pdcp = false;

  bool operator==(const SrbToAddMod& o) const {
    return srb_identity == o.srb_identity && reestablish_pdcp == o.reestablish_pdcp &&
           discard_on_pdcp == o.discard_on_pdcp;
  }
};

/// RadioBearerConfig (DRBs and securityConfig not modelled).
struct RadioBearerConfig {
  std::vector<SrbToAddMod> srb_to_add_mod_list;  ///< SIZE (1..2); empty = absent
  bool srb3_to_release = false;

  bool operator==(const RadioBearerConfig& o) const {
    return srb_to_add_mod_list == o.srb_to_add_mod_list && srb3_to_release == o.srb3_to_release;
  }
};

/// RLC-BearerConfig (rlc-Config / mac-LogicalChannelConfig not modelled).
struct RlcBearerConfig {
  struct ServedRadioBearer {
    bool is_srb = true;
    std::uint8_t identity = 1;  ///< SRB-Identity (1..3) or DRB-Identity (1..32)
    bool operator==(const ServedRadioBearer& o) const { return is_srb == o.is_srb && identity == o.identity; }
  };
  std::uint8_t logical_channel_identity = 1;  ///< LogicalChannelIdentity ::= INTEGER (1..maxLC-ID=32)
  std::optional<ServedRadioBearer> served_radio_bearer;
  bool reestablish_rlc = false;

  bool operator==(const RlcBearerConfig& o) const {
    return logical_channel_identity == o.logical_channel_identity && served_radio_bearer == o.served_radio_bearer &&
           reestablish_rlc == o.reestablish_rlc;
  }
};

/// CellGroupConfig, carried in RRCSetup.masterCellGroup as OCTET STRING (CONTAINING CellGroupConfig).
struct CellGroupConfig {
  std::uint8_t cell_group_id = 0;  ///< CellGroupId ::= INTEGER (0..maxSecondaryCellGroups=3)
  std::vector<RlcBearerConfig> rlc_bearer_to_add_mod_list;

  bool operator==(const CellGroupConfig& o) const {
    return cell_group_id == o.cell_group_id && rlc_bearer_to_add_mod_list == o.rlc_bearer_to_add_mod_list;
  }
};

/// S-NSSAI ::= CHOICE { sst BIT STRING (SIZE (8)), sst-SD BIT STRING (SIZE (32)) }
struct SNssai {
  std::uint8_t sst = 1;
  std::optional<std::uint32_t> sd;  ///< 24 bits
  bool operator==(const SNssai& o) const { return sst == o.sst && sd == o.sd; }
};

/// PLMN-Identity ::= SEQUENCE { mcc MCC OPTIONAL, mnc MNC }
struct PlmnIdentity {
  std::optional<std::array<std::uint8_t, 3>> mcc;
  std::vector<std::uint8_t> mnc;  ///< 2 or 3 digits
  bool operator==(const PlmnIdentity& o) const { return mcc == o.mcc && mnc == o.mnc; }
};

/// RegisteredAMF ::= SEQUENCE { plmn-Identity PLMN-Identity OPTIONAL, amf-Identifier BIT STRING (SIZE (24)) }
struct RegisteredAmf {
  std::optional<PlmnIdentity> plmn_identity;
  std::uint32_t amf_identifier = 0;  ///< AMF Region ID (8) | AMF Set ID (10) | AMF Pointer (6)
  bool operator==(const RegisteredAmf& o) const {
    return plmn_identity == o.plmn_identity && amf_identifier == o.amf_identifier;
  }
};

// ---- Messages ---------------------------------------------------------------------------------

struct RrcSetupRequest {
  InitialUeIdentity ue_identity;
  EstablishmentCause establishment_cause = EstablishmentCause::mo_Signalling;
  bool operator==(const RrcSetupRequest& o) const {
    return ue_identity == o.ue_identity && establishment_cause == o.establishment_cause;
  }
};

struct RrcSetup {
  std::uint8_t rrc_transaction_identifier = 0;  ///< RRC-TransactionIdentifier ::= INTEGER (0..3)
  RadioBearerConfig radio_bearer_config;
  CellGroupConfig master_cell_group;
  bool operator==(const RrcSetup& o) const {
    return rrc_transaction_identifier == o.rrc_transaction_identifier &&
           radio_bearer_config == o.radio_bearer_config && master_cell_group == o.master_cell_group;
  }
};

struct RrcReject {
  std::optional<std::uint8_t> wait_time;  ///< RejectWaitTime ::= INTEGER (1..16) seconds
  bool operator==(const RrcReject& o) const { return wait_time == o.wait_time; }
};

struct RrcSetupComplete {
  enum class GuamiType : std::uint8_t { native, mapped };
  /// ng-5G-S-TMSI-Value ::= CHOICE { ng-5G-S-TMSI (48 bits), ng-5G-S-TMSI-Part2 (9 bits) }
  struct Ng5gSTmsiValue {
    bool full = false;
    std::uint64_t value = 0;
    bool operator==(const Ng5gSTmsiValue& o) const { return full == o.full && value == o.value; }
  };

  std::uint8_t rrc_transaction_identifier = 0;
  std::uint8_t selected_plmn_identity = 1;  ///< INTEGER (1..maxPLMN=12)
  std::optional<RegisteredAmf> registered_amf;
  std::optional<GuamiType> guami_type;
  std::vector<SNssai> s_nssai_list;  ///< SIZE (1..maxNrofS-NSSAI=8); empty = absent
  Bytes dedicated_nas_message;
  std::optional<Ng5gSTmsiValue> ng_5g_s_tmsi_value;

  bool operator==(const RrcSetupComplete& o) const {
    return rrc_transaction_identifier == o.rrc_transaction_identifier &&
           selected_plmn_identity == o.selected_plmn_identity && registered_amf == o.registered_amf &&
           guami_type == o.guami_type && s_nssai_list == o.s_nssai_list &&
           dedicated_nas_message == o.dedicated_nas_message && ng_5g_s_tmsi_value == o.ng_5g_s_tmsi_value;
  }
};

struct SecurityModeCommand {
  std::uint8_t rrc_transaction_identifier = 0;
  CipheringAlgorithm ciphering_algorithm = CipheringAlgorithm::nea0;
  std::optional<IntegrityProtAlgorithm> integrity_prot_algorithm;
  bool operator==(const SecurityModeCommand& o) const {
    return rrc_transaction_identifier == o.rrc_transaction_identifier &&
           ciphering_algorithm == o.ciphering_algorithm && integrity_prot_algorithm == o.integrity_prot_algorithm;
  }
};

struct SecurityModeComplete {
  std::uint8_t rrc_transaction_identifier = 0;
  bool operator==(const SecurityModeComplete& o) const {
    return rrc_transaction_identifier == o.rrc_transaction_identifier;
  }
};

struct SecurityModeFailure {
  std::uint8_t rrc_transaction_identifier = 0;
  bool operator==(const SecurityModeFailure& o) const {
    return rrc_transaction_identifier == o.rrc_transaction_identifier;
  }
};

struct DlInformationTransfer {
  std::uint8_t rrc_transaction_identifier = 0;
  std::optional<Bytes> dedicated_nas_message;
  bool operator==(const DlInformationTransfer& o) const {
    return rrc_transaction_identifier == o.rrc_transaction_identifier &&
           dedicated_nas_message == o.dedicated_nas_message;
  }
};

struct UlInformationTransfer {
  std::optional<Bytes> dedicated_nas_message;
  bool operator==(const UlInformationTransfer& o) const { return dedicated_nas_message == o.dedicated_nas_message; }
};

struct RrcRelease {
  struct DeprioritisationReq {
    enum class Type : std::uint8_t { frequency, nr };
    enum class Timer : std::uint8_t { min5, min10, min15, min30 };
    Type type = Type::frequency;
    Timer timer = Timer::min5;
    bool operator==(const DeprioritisationReq& o) const { return type == o.type && timer == o.timer; }
  };
  std::uint8_t rrc_transaction_identifier = 0;
  std::optional<DeprioritisationReq> deprioritisation_req;
  std::optional<std::uint8_t> wait_time;  ///< RRCRelease-v1540-IEs.waitTime, 1..16 s

  bool operator==(const RrcRelease& o) const {
    return rrc_transaction_identifier == o.rrc_transaction_identifier &&
           deprioritisation_req == o.deprioritisation_req && wait_time == o.wait_time;
  }
};

using UlCcchMessage = std::variant<RrcSetupRequest>;
using DlCcchMessage = std::variant<RrcReject, RrcSetup>;
using UlDcchMessage = std::variant<RrcSetupComplete, SecurityModeComplete, SecurityModeFailure, UlInformationTransfer>;
using DlDcchMessage = std::variant<SecurityModeCommand, DlInformationTransfer, RrcRelease>;

// ---- Codec ------------------------------------------------------------------------------------

/// Encoders throw asn1::EncodeError if a field violates its ASN.1 constraint.
Bytes encode_ul_ccch(const UlCcchMessage& msg);
Bytes encode_dl_ccch(const DlCcchMessage& msg);
Bytes encode_ul_dcch(const UlDcchMessage& msg);
Bytes encode_dl_dcch(const DlDcchMessage& msg);

/// Decoders never throw on malformed input; they return an Error describing the first problem.
Result<UlCcchMessage> decode_ul_ccch(const Bytes& pdu);
Result<DlCcchMessage> decode_dl_ccch(const Bytes& pdu);
Result<UlDcchMessage> decode_ul_dcch(const Bytes& pdu);
Result<DlDcchMessage> decode_dl_dcch(const Bytes& pdu);

/// Stand-alone codec for the container carried in RRCSetup.masterCellGroup.
Bytes encode_cell_group_config(const CellGroupConfig& cg);
Result<CellGroupConfig> decode_cell_group_config(const Bytes& bytes);

/// ASN.1 name of the message alternative, e.g. "rrcSetupRequest".
std::string message_name(const UlCcchMessage& m);
std::string message_name(const DlCcchMessage& m);
std::string message_name(const UlDcchMessage& m);
std::string message_name(const DlDcchMessage& m);

/// JSON rendering with ASN.1 field names (bit strings as integers, octet strings as hex).
Json to_json(const UlCcchMessage& m);
Json to_json(const DlCcchMessage& m);
Json to_json(const UlDcchMessage& m);
Json to_json(const DlDcchMessage& m);

}  // namespace nrlite::rrc
