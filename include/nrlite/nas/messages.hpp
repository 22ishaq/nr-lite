#pragma once

// 5GS mobility management (5GMM) messages, TS 24.501 §8.2.
//
// Plain 5GMM message:      EPD (0x7E) | spare + security header type (0) | message type | IEs
// Security protected 5GMM: EPD (0x7E) | spare + security header type (1-4) | MAC (4) | SQN (1) | plain message
//
// Decoding follows the error-handling rules of TS 24.501 §7: a truncated header is ignored, an
// unknown message type yields cause #97, a missing or invalid mandatory IE yields cause #96, and
// unknown optional IEs are skipped using the IEI format rules of TS 24.007 §11.2.4.

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "nrlite/common/bytes.hpp"
#include "nrlite/common/json.hpp"
#include "nrlite/common/result.hpp"
#include "nrlite/nas/ies.hpp"

namespace nrlite::nas {

constexpr std::uint8_t kEpd5gmm = 0x7E;
constexpr std::uint8_t kEpd5gsm = 0x2E;

enum class SecurityHeaderType : std::uint8_t {
  Plain = 0,
  IntegrityProtected = 1,
  IntegrityProtectedAndCiphered = 2,
  IntegrityProtectedWithNewContext = 3,
  IntegrityProtectedAndCipheredWithNewContext = 4,
};
const char* to_string(SecurityHeaderType t);

enum class MessageType : std::uint8_t {
  RegistrationRequest = 0x41,
  RegistrationAccept = 0x42,
  RegistrationComplete = 0x43,
  RegistrationReject = 0x44,
  DeregistrationRequestUeOriginating = 0x45,
  DeregistrationAcceptUeOriginating = 0x46,
  AuthenticationRequest = 0x56,
  AuthenticationResponse = 0x57,
  AuthenticationReject = 0x58,
  AuthenticationFailure = 0x59,
  IdentityRequest = 0x5B,
  IdentityResponse = 0x5C,
  SecurityModeCommand = 0x5D,
  SecurityModeComplete = 0x5E,
  SecurityModeReject = 0x5F,
  Status5gmm = 0x64,
};
const char* to_string(MessageType t);

using Rand = std::array<std::uint8_t, 16>;
using Autn = std::array<std::uint8_t, 16>;
using ResStar = std::array<std::uint8_t, 16>;
using Auts = std::array<std::uint8_t, 14>;

struct RegistrationRequest {
  RegistrationType registration_type;
  Ngksi ngksi;
  MobileIdentity mobile_identity;
  std::optional<Bytes> mm_capability;                         ///< 0x10 5GMM capability (raw)
  std::optional<UeSecurityCapability> ue_security_capability;  ///< 0x2E
  std::optional<std::vector<SNssai>> requested_nssai;         ///< 0x2F
  std::optional<Tai> last_visited_registered_tai;             ///< 0x52
  std::optional<Bytes> nas_message_container;                 ///< 0x71
  bool operator==(const RegistrationRequest& o) const {
    return registration_type == o.registration_type && ngksi == o.ngksi && mobile_identity == o.mobile_identity &&
           mm_capability == o.mm_capability && ue_security_capability == o.ue_security_capability &&
           requested_nssai == o.requested_nssai && last_visited_registered_tai == o.last_visited_registered_tai &&
           nas_message_container == o.nas_message_container;
  }
};

struct RegistrationAccept {
  std::uint8_t registration_result = 0x01;  ///< 5GS registration result value: 3GPP access
  std::optional<Guti5g> guti;                ///< 0x77
  std::optional<TaiList> tai_list;           ///< 0x54
  std::optional<std::vector<SNssai>> allowed_nssai;  ///< 0x15
  std::optional<GprsTimer> t3512;            ///< 0x5E (GPRS timer 3)
  std::optional<GprsTimer> t3502;            ///< 0x16 (GPRS timer 2)
  bool operator==(const RegistrationAccept& o) const {
    return registration_result == o.registration_result && guti == o.guti && tai_list == o.tai_list &&
           allowed_nssai == o.allowed_nssai && t3512 == o.t3512 && t3502 == o.t3502;
  }
};

struct RegistrationComplete {
  bool operator==(const RegistrationComplete&) const { return true; }
};

struct RegistrationReject {
  Cause cause = Cause::ProtocolErrorUnspecified;
  std::optional<GprsTimer> t3346;  ///< 0x5F (GPRS timer 2)
  std::optional<GprsTimer> t3502;  ///< 0x16 (GPRS timer 2)
  bool operator==(const RegistrationReject& o) const {
    return cause == o.cause && t3346 == o.t3346 && t3502 == o.t3502;
  }
};

struct DeregistrationRequestUeOriginating {
  DeregistrationType deregistration_type;
  Ngksi ngksi;
  MobileIdentity mobile_identity;
  bool operator==(const DeregistrationRequestUeOriginating& o) const {
    return deregistration_type == o.deregistration_type && ngksi == o.ngksi && mobile_identity == o.mobile_identity;
  }
};

struct DeregistrationAcceptUeOriginating {
  bool operator==(const DeregistrationAcceptUeOriginating&) const { return true; }
};

struct AuthenticationRequest {
  Ngksi ngksi;
  Bytes abba{0x00, 0x00};
  std::optional<Rand> rand;  ///< 0x21 (TV)
  std::optional<Autn> autn;  ///< 0x20 (TLV)
  bool operator==(const AuthenticationRequest& o) const {
    return ngksi == o.ngksi && abba == o.abba && rand == o.rand && autn == o.autn;
  }
};

struct AuthenticationResponse {
  std::optional<ResStar> res_star;  ///< 0x2D
  bool operator==(const AuthenticationResponse& o) const { return res_star == o.res_star; }
};

struct AuthenticationReject {
  bool operator==(const AuthenticationReject&) const { return true; }
};

struct AuthenticationFailure {
  Cause cause = Cause::MacFailure;
  std::optional<Auts> auts;  ///< 0x30, present with cause #21
  bool operator==(const AuthenticationFailure& o) const { return cause == o.cause && auts == o.auts; }
};

struct IdentityRequest {
  IdentityType identity_type = IdentityType::Suci;
  bool operator==(const IdentityRequest& o) const { return identity_type == o.identity_type; }
};

struct IdentityResponse {
  MobileIdentity mobile_identity;
  bool operator==(const IdentityResponse& o) const { return mobile_identity == o.mobile_identity; }
};

struct SecurityModeCommand {
  NasSecurityAlgorithms selected_algorithms;
  Ngksi ngksi;
  UeSecurityCapability replayed_ue_security_capability;
  std::optional<bool> imeisv_request;                       ///< 0xE- (TV, half octet)
  std::optional<std::uint8_t> additional_security_information;  ///< 0x36 (RINMR bit 2, HDP bit 1)
  std::optional<Bytes> abba;                                ///< 0x38
  bool operator==(const SecurityModeCommand& o) const {
    return selected_algorithms == o.selected_algorithms && ngksi == o.ngksi &&
           replayed_ue_security_capability == o.replayed_ue_security_capability &&
           imeisv_request == o.imeisv_request &&
           additional_security_information == o.additional_security_information && abba == o.abba;
  }
};

struct SecurityModeComplete {
  std::optional<MobileIdentity> imeisv;        ///< 0x77
  std::optional<Bytes> nas_message_container;  ///< 0x71
  bool operator==(const SecurityModeComplete& o) const {
    return imeisv == o.imeisv && nas_message_container == o.nas_message_container;
  }
};

struct SecurityModeReject {
  Cause cause = Cause::SecurityModeRejectedUnspecified;
  bool operator==(const SecurityModeReject& o) const { return cause == o.cause; }
};

struct Status5gmm {
  Cause cause = Cause::ProtocolErrorUnspecified;
  bool operator==(const Status5gmm& o) const { return cause == o.cause; }
};

using PlainMessage =
    std::variant<RegistrationRequest, RegistrationAccept, RegistrationComplete, RegistrationReject,
                 DeregistrationRequestUeOriginating, DeregistrationAcceptUeOriginating, AuthenticationRequest,
                 AuthenticationResponse, AuthenticationReject, AuthenticationFailure, IdentityRequest,
                 IdentityResponse, SecurityModeCommand, SecurityModeComplete, SecurityModeReject, Status5gmm>;

MessageType message_type(const PlainMessage& m);
std::string message_name(const PlainMessage& m);

/// Encodes a plain 5GMM message including the 3-octet header.
Bytes encode(const PlainMessage& m);
/// Decodes a plain 5GMM message. Error::code carries the 5GMM cause for a status report.
Result<PlainMessage> decode_plain(const Bytes& pdu);

/// Security protected header fields (TS 24.501 §9.1.1).
struct SecuredPdu {
  SecurityHeaderType security_header_type = SecurityHeaderType::Plain;
  std::array<std::uint8_t, 4> mac{};
  std::uint8_t sqn = 0;
  Bytes payload;  ///< the (possibly ciphered) plain NAS message
};

/// Returns the security header type of any 5GMM PDU (error if the header is malformed).
Result<SecurityHeaderType> peek_security_header_type(const Bytes& pdu);
/// Splits a security protected PDU into its header fields and payload.
Result<SecuredPdu> parse_secured(const Bytes& pdu);
Bytes build_secured(const SecuredPdu& s);

Json to_json(const PlainMessage& m);

}  // namespace nrlite::nas
