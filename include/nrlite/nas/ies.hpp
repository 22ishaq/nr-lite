#pragma once

// 5GS NAS information elements (TS 24.501 §9.11) used by the 5GMM procedures in NR-Lite.
// Encoders produce the IE *value* (no IEI / length); framing is done by the message codec.

#include <array>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

#include "nrlite/common/bytes.hpp"
#include "nrlite/common/json.hpp"

namespace nrlite::nas {

/// Thrown inside the NAS codec; converted to Result<>/Error with `cause` as the 5GMM cause a
/// receiver should report (TS 24.501 §7).
class NasDecodeError : public std::runtime_error {
 public:
  NasDecodeError(const std::string& what, std::uint8_t cause) : std::runtime_error(what), cause_(cause) {}
  std::uint8_t cause() const { return cause_; }

 private:
  std::uint8_t cause_;
};

/// 5GMM cause values (TS 24.501 §9.11.3.2). Stored as the raw octet so unknown values survive.
enum class Cause : std::uint8_t {
  IllegalUe = 3,
  PeiNotAccepted = 5,
  IllegalMe = 6,
  FiveGsServicesNotAllowed = 7,
  UeIdentityCannotBeDerived = 9,
  ImplicitlyDeregistered = 10,
  PlmnNotAllowed = 11,
  TrackingAreaNotAllowed = 12,
  RoamingNotAllowedInTrackingArea = 13,
  NoSuitableCellsInTrackingArea = 15,
  MacFailure = 20,
  SynchFailure = 21,
  Congestion = 22,
  UeSecurityCapabilitiesMismatch = 23,
  SecurityModeRejectedUnspecified = 24,
  Non5gAuthenticationUnacceptable = 26,
  N1ModeNotAllowed = 27,
  RestrictedServiceArea = 28,
  NoNetworkSlicesAvailable = 62,
  NgksiAlreadyInUse = 71,
  SemanticallyIncorrectMessage = 95,
  InvalidMandatoryInformation = 96,
  MessageTypeNonExistent = 97,
  MessageTypeNotCompatibleWithProtocolState = 98,
  InformationElementNonExistent = 99,
  ConditionalIeError = 100,
  MessageNotCompatibleWithProtocolState = 101,
  ProtocolErrorUnspecified = 111,
};
const char* to_string(Cause c);

/// PLMN identity as digit strings: MCC is 3 digits, MNC 2 or 3.
struct Plmn {
  std::string mcc = "001";
  std::string mnc = "01";
  bool operator==(const Plmn& o) const { return mcc == o.mcc && mnc == o.mnc; }
};
/// 3-octet BCD encoding (TS 24.501 Figure 9.11.3.4.1 octets 5-7).
Bytes encode_plmn(const Plmn& p);
Plmn decode_plmn(const std::uint8_t* p);

/// Packs decimal digits as BCD, low nibble first, padding an odd count with 0xF.
Bytes encode_bcd(const std::string& digits);
std::string decode_bcd(const std::uint8_t* p, std::size_t len);

// ---- 5GS mobile identity (§9.11.3.4) -----------------------------------------------------------

/// SUCI with SUPI format IMSI. NR-Lite uses the null protection scheme, so the scheme output is
/// the MSIN in BCD; other schemes are carried opaquely in `scheme_output`.
struct Suci {
  Plmn plmn;
  std::string routing_indicator = "0000";
  std::uint8_t protection_scheme_id = 0;
  std::uint8_t home_network_public_key_id = 0;
  std::string msin;     ///< null scheme
  Bytes scheme_output;  ///< non-null schemes
  bool operator==(const Suci& o) const {
    return plmn == o.plmn && routing_indicator == o.routing_indicator &&
           protection_scheme_id == o.protection_scheme_id &&
           home_network_public_key_id == o.home_network_public_key_id && msin == o.msin &&
           scheme_output == o.scheme_output;
  }
  /// SUPI (IMSI digits) for the null scheme.
  std::string supi() const { return plmn.mcc + plmn.mnc + msin; }
};

struct Guti5g {
  Plmn plmn;
  std::uint8_t amf_region_id = 0;
  std::uint16_t amf_set_id = 0;  ///< 10 bits
  std::uint8_t amf_pointer = 0;  ///< 6 bits
  std::uint32_t tmsi = 0;
  bool operator==(const Guti5g& o) const {
    return plmn == o.plmn && amf_region_id == o.amf_region_id && amf_set_id == o.amf_set_id &&
           amf_pointer == o.amf_pointer && tmsi == o.tmsi;
  }
  /// 5G-S-TMSI = AMF Set ID (10) | AMF Pointer (6) | 5G-TMSI (32): 48 bits.
  std::uint64_t s_tmsi() const {
    return (std::uint64_t{amf_set_id} << 38) | (std::uint64_t{amf_pointer} << 32) | tmsi;
  }
  /// AMF Identifier = AMF Region ID (8) | AMF Set ID (10) | AMF Pointer (6): 24 bits.
  std::uint32_t amf_identifier() const {
    return (std::uint32_t{amf_region_id} << 16) | (std::uint32_t{amf_set_id} << 6) | amf_pointer;
  }
};

struct STmsi5g {
  std::uint16_t amf_set_id = 0;
  std::uint8_t amf_pointer = 0;
  std::uint32_t tmsi = 0;
  bool operator==(const STmsi5g& o) const {
    return amf_set_id == o.amf_set_id && amf_pointer == o.amf_pointer && tmsi == o.tmsi;
  }
};

struct Imei {
  std::string digits;  ///< 15 digits
  bool operator==(const Imei& o) const { return digits == o.digits; }
};

struct Imeisv {
  std::string digits;  ///< 16 digits
  bool operator==(const Imeisv& o) const { return digits == o.digits; }
};

struct NoIdentity {
  bool operator==(const NoIdentity&) const { return true; }
};

using MobileIdentity = std::variant<NoIdentity, Suci, Guti5g, Imei, Imeisv, STmsi5g>;

enum class IdentityType : std::uint8_t { NoIdentity = 0, Suci = 1, Guti = 2, Imei = 3, STmsi = 4, Imeisv = 5 };
const char* to_string(IdentityType t);

Bytes encode_mobile_identity(const MobileIdentity& id);
MobileIdentity decode_mobile_identity(const Bytes& value);
IdentityType identity_type(const MobileIdentity& id);

// ---- Security related IEs ---------------------------------------------------------------------

/// NAS key set identifier (§9.11.3.32): TSC bit and 3-bit KSI; KSI 7 = "no key is available".
struct Ngksi {
  bool mapped = false;
  std::uint8_t ksi = 7;
  bool operator==(const Ngksi& o) const { return mapped == o.mapped && ksi == o.ksi; }
  std::uint8_t nibble() const { return static_cast<std::uint8_t>((mapped ? 0x08 : 0x00) | (ksi & 0x07)); }
  static Ngksi from_nibble(std::uint8_t n) { return Ngksi{(n & 0x08) != 0, static_cast<std::uint8_t>(n & 0x07)}; }
  static constexpr std::uint8_t kNoKey = 7;
};

/// UE security capability (§9.11.3.54). Bit 8 of each octet is algorithm 0 (EA0 / IA0).
struct UeSecurityCapability {
  std::uint8_t nr_ea = 0;
  std::uint8_t nr_ia = 0;
  std::optional<std::uint8_t> eutra_ea;
  std::optional<std::uint8_t> eutra_ia;

  bool supports_ea(unsigned alg) const { return alg < 8 && (nr_ea & (0x80u >> alg)) != 0; }
  bool supports_ia(unsigned alg) const { return alg < 8 && (nr_ia & (0x80u >> alg)) != 0; }
  static std::uint8_t bit(unsigned alg) { return static_cast<std::uint8_t>(0x80u >> alg); }
  bool operator==(const UeSecurityCapability& o) const {
    return nr_ea == o.nr_ea && nr_ia == o.nr_ia && eutra_ea == o.eutra_ea && eutra_ia == o.eutra_ia;
  }
  bool operator!=(const UeSecurityCapability& o) const { return !(*this == o); }
};
Bytes encode_ue_security_capability(const UeSecurityCapability& c);
UeSecurityCapability decode_ue_security_capability(const Bytes& v);

/// NAS security algorithms (§9.11.3.34): ciphering in bits 8-5, integrity in bits 4-1.
struct NasSecurityAlgorithms {
  std::uint8_t ciphering = 0;  ///< 0 = 5G-EA0, 2 = 128-5G-EA2
  std::uint8_t integrity = 2;  ///< 0 = 5G-IA0, 2 = 128-5G-IA2
  bool operator==(const NasSecurityAlgorithms& o) const {
    return ciphering == o.ciphering && integrity == o.integrity;
  }
  std::uint8_t octet() const { return static_cast<std::uint8_t>(((ciphering & 0x0F) << 4) | (integrity & 0x0F)); }
  static NasSecurityAlgorithms from_octet(std::uint8_t o) {
    return {static_cast<std::uint8_t>(o >> 4), static_cast<std::uint8_t>(o & 0x0F)};
  }
};

// ---- Registration related IEs -------------------------------------------------------------------

/// 5GS registration type (§9.11.3.7).
struct RegistrationType {
  enum Value : std::uint8_t { Initial = 1, MobilityUpdating = 2, PeriodicUpdating = 3, Emergency = 4 };
  bool follow_on_request = false;
  std::uint8_t value = Initial;
  bool operator==(const RegistrationType& o) const {
    return follow_on_request == o.follow_on_request && value == o.value;
  }
  std::uint8_t nibble() const { return static_cast<std::uint8_t>((follow_on_request ? 0x08 : 0) | (value & 0x07)); }
};

/// De-registration type (§9.11.3.20).
struct DeregistrationType {
  bool switch_off = false;
  bool reregistration_required = false;
  std::uint8_t access_type = 1;  ///< 1 = 3GPP access
  bool operator==(const DeregistrationType& o) const {
    return switch_off == o.switch_off && reregistration_required == o.reregistration_required &&
           access_type == o.access_type;
  }
  std::uint8_t nibble() const {
    return static_cast<std::uint8_t>((switch_off ? 0x08 : 0) | (reregistration_required ? 0x04 : 0) |
                                     (access_type & 0x03));
  }
};

/// S-NSSAI (§9.11.2.8), without the mapped HPLMN values.
struct SNssai {
  std::uint8_t sst = 1;
  std::optional<std::uint32_t> sd;  ///< 24 bits
  bool operator==(const SNssai& o) const { return sst == o.sst && sd == o.sd; }
};
/// NSSAI (§9.11.3.37): a list of length-prefixed S-NSSAI values.
Bytes encode_nssai(const std::vector<SNssai>& list);
std::vector<SNssai> decode_nssai(const Bytes& v);

/// 5GS tracking area identity (§9.11.3.8).
struct Tai {
  Plmn plmn;
  std::uint32_t tac = 1;  ///< 24 bits
  bool operator==(const Tai& o) const { return plmn == o.plmn && tac == o.tac; }
};

/// 5GS tracking area identity list (§9.11.3.9), using type-00 partial lists.
struct TaiList {
  std::vector<Tai> tais;
  bool operator==(const TaiList& o) const { return tais == o.tais; }
};
Bytes encode_tai_list(const TaiList& l);
TaiList decode_tai_list(const Bytes& v);

/// GPRS timer 2 / GPRS timer 3 (TS 24.008 §10.5.7.4 / §10.5.7.4a): 3-bit unit, 5-bit value.
struct GprsTimer {
  std::uint8_t unit = 0;
  std::uint8_t value = 0;
  bool operator==(const GprsTimer& o) const { return unit == o.unit && value == o.value; }
  std::uint8_t octet() const { return static_cast<std::uint8_t>(((unit & 0x07) << 5) | (value & 0x1F)); }
  static GprsTimer from_octet(std::uint8_t o) {
    return {static_cast<std::uint8_t>(o >> 5), static_cast<std::uint8_t>(o & 0x1F)};
  }
  /// Duration in seconds; nullopt if the timer is deactivated.
  std::optional<std::uint32_t> seconds_timer2() const;
  std::optional<std::uint32_t> seconds_timer3() const;
};

Json to_json(const MobileIdentity& id);

}  // namespace nrlite::nas
