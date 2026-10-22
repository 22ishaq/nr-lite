#pragma once

// Simplified N2 (NGAP, TS 38.413) between gNB and AMF. Only the procedures the registration flow
// needs are modelled, as plain C++ structs rather than an encoded NGAP PDU: NR-Lite's focus is the
// UE-facing RRC and NAS layers, and NAS PDUs inside these messages are byte-exact.

#include <cstdint>
#include <optional>
#include <string>
#include <variant>

#include "nrlite/common/bytes.hpp"
#include "nrlite/nas/ies.hpp"
#include "nrlite/rrc/messages.hpp"
#include "nrlite/security/crypto.hpp"

namespace nrlite::n2 {

struct InitialUeMessage {
  std::uint32_t ran_ue_id = 0;
  Bytes nas_pdu;
  rrc::EstablishmentCause establishment_cause = rrc::EstablishmentCause::mo_Signalling;
  std::optional<std::uint64_t> five_g_s_tmsi;
};

struct UplinkNasTransport {
  std::uint32_t ran_ue_id = 0;
  std::uint32_t amf_ue_id = 0;
  Bytes nas_pdu;
};

struct DownlinkNasTransport {
  std::uint32_t ran_ue_id = 0;
  std::uint32_t amf_ue_id = 0;
  Bytes nas_pdu;
};

struct InitialContextSetupRequest {
  std::uint32_t ran_ue_id = 0;
  std::uint32_t amf_ue_id = 0;
  sec::Key256 kgnb{};
  nas::UeSecurityCapability ue_security_capability;
  std::optional<Bytes> nas_pdu;
};

struct InitialContextSetupResponse {
  std::uint32_t ran_ue_id = 0;
  std::uint32_t amf_ue_id = 0;
};

struct InitialContextSetupFailure {
  std::uint32_t ran_ue_id = 0;
  std::uint32_t amf_ue_id = 0;
  std::string cause;
};

struct UeContextReleaseRequest {
  std::uint32_t ran_ue_id = 0;
  std::uint32_t amf_ue_id = 0;
  std::string cause;
};

struct UeContextReleaseCommand {
  std::uint32_t ran_ue_id = 0;
  std::uint32_t amf_ue_id = 0;
  std::string cause;
};

struct UeContextReleaseComplete {
  std::uint32_t ran_ue_id = 0;
  std::uint32_t amf_ue_id = 0;
};

using Message = std::variant<InitialUeMessage, UplinkNasTransport, DownlinkNasTransport, InitialContextSetupRequest,
                             InitialContextSetupResponse, InitialContextSetupFailure, UeContextReleaseRequest,
                             UeContextReleaseCommand, UeContextReleaseComplete>;

std::string name(const Message& m);
std::uint32_t ran_ue_id(const Message& m);
/// NAS PDU carried by the message, if any.
const Bytes* nas_pdu(const Message& m);
/// True for messages sent by the gNB towards the AMF.
bool is_uplink(const Message& m);

}  // namespace nrlite::n2
