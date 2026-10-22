#include "nrlite/nas/ies.hpp"

#include <cctype>

namespace nrlite::nas {

namespace {

constexpr std::uint8_t kInvalidMandatory = static_cast<std::uint8_t>(Cause::InvalidMandatoryInformation);

[[noreturn]] void bad(const std::string& what) { throw NasDecodeError(what, kInvalidMandatory); }

void check_digits(const std::string& s, const char* what) {
  for (char c : s) {
    if (!std::isdigit(static_cast<unsigned char>(c))) throw std::invalid_argument(std::string(what) + ": not a digit");
  }
}

std::uint8_t digit(const std::string& s, std::size_t i) { return static_cast<std::uint8_t>(s.at(i) - '0'); }

}  // namespace

const char* to_string(Cause c) {
  switch (c) {
    case Cause::IllegalUe: return "Illegal UE";
    case Cause::PeiNotAccepted: return "PEI not accepted";
    case Cause::IllegalMe: return "Illegal ME";
    case Cause::FiveGsServicesNotAllowed: return "5GS services not allowed";
    case Cause::UeIdentityCannotBeDerived: return "UE identity cannot be derived by the network";
    case Cause::ImplicitlyDeregistered: return "Implicitly de-registered";
    case Cause::PlmnNotAllowed: return "PLMN not allowed";
    case Cause::TrackingAreaNotAllowed: return "Tracking area not allowed";
    case Cause::RoamingNotAllowedInTrackingArea: return "Roaming not allowed in this tracking area";
    case Cause::NoSuitableCellsInTrackingArea: return "No suitable cells in tracking area";
    case Cause::MacFailure: return "MAC failure";
    case Cause::SynchFailure: return "Synch failure";
    case Cause::Congestion: return "Congestion";
    case Cause::UeSecurityCapabilitiesMismatch: return "UE security capabilities mismatch";
    case Cause::SecurityModeRejectedUnspecified: return "Security mode rejected, unspecified";
    case Cause::Non5gAuthenticationUnacceptable: return "Non-5G authentication unacceptable";
    case Cause::N1ModeNotAllowed: return "N1 mode not allowed";
    case Cause::RestrictedServiceArea: return "Restricted service area";
    case Cause::NoNetworkSlicesAvailable: return "No network slices available";
    case Cause::NgksiAlreadyInUse: return "ngKSI already in use";
    case Cause::SemanticallyIncorrectMessage: return "Semantically incorrect message";
    case Cause::InvalidMandatoryInformation: return "Invalid mandatory information";
    case Cause::MessageTypeNonExistent: return "Message type non-existent or not implemented";
    case Cause::MessageTypeNotCompatibleWithProtocolState: return "Message type not compatible with the protocol state";
    case Cause::InformationElementNonExistent: return "Information element non-existent or not implemented";
    case Cause::ConditionalIeError: return "Conditional IE error";
    case Cause::MessageNotCompatibleWithProtocolState: return "Message not compatible with the protocol state";
    case Cause::ProtocolErrorUnspecified: return "Protocol error, unspecified";
  }
  return "unknown cause";
}

const char* to_string(IdentityType t) {
  switch (t) {
    case IdentityType::NoIdentity: return "no identity";
    case IdentityType::Suci: return "SUCI";
    case IdentityType::Guti: return "5G-GUTI";
    case IdentityType::Imei: return "IMEI";
    case IdentityType::STmsi: return "5G-S-TMSI";
    case IdentityType::Imeisv: return "IMEISV";
  }
  return "unknown";
}

// ---- BCD and PLMN -------------------------------------------------------------------------------

Bytes encode_bcd(const std::string& digits) {
  check_digits(digits, "encode_bcd");
  Bytes out;
  for (std::size_t i = 0; i < digits.size(); i += 2) {
    const std::uint8_t lo = digit(digits, i);
    const std::uint8_t hi = i + 1 < digits.size() ? digit(digits, i + 1) : 0x0F;
    out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
  }
  return out;
}

std::string decode_bcd(const std::uint8_t* p, std::size_t len) {
  std::string s;
  for (std::size_t i = 0; i < len; ++i) {
    const std::uint8_t lo = p[i] & 0x0F;
    const std::uint8_t hi = p[i] >> 4;
    if (lo > 9) bad("BCD digit out of range");
    s.push_back(static_cast<char>('0' + lo));
    if (hi == 0x0F) {
      if (i + 1 != len) bad("BCD filler before the last octet");
      break;
    }
    if (hi > 9) bad("BCD digit out of range");
    s.push_back(static_cast<char>('0' + hi));
  }
  return s;
}

Bytes encode_plmn(const Plmn& p) {
  if (p.mcc.size() != 3 || (p.mnc.size() != 2 && p.mnc.size() != 3)) throw std::invalid_argument("encode_plmn: bad length");
  check_digits(p.mcc, "MCC");
  check_digits(p.mnc, "MNC");
  const std::uint8_t mnc3 = p.mnc.size() == 3 ? digit(p.mnc, 2) : 0x0F;
  return Bytes{static_cast<std::uint8_t>((digit(p.mcc, 1) << 4) | digit(p.mcc, 0)),
               static_cast<std::uint8_t>((mnc3 << 4) | digit(p.mcc, 2)),
               static_cast<std::uint8_t>((digit(p.mnc, 1) << 4) | digit(p.mnc, 0))};
}

Plmn decode_plmn(const std::uint8_t* p) {
  auto d = [](std::uint8_t v) {
    if (v > 9) bad("PLMN digit out of range");
    return static_cast<char>('0' + v);
  };
  Plmn out;
  out.mcc = {d(p[0] & 0x0F), d(p[0] >> 4), d(p[1] & 0x0F)};
  out.mnc = {d(p[2] & 0x0F), d(p[2] >> 4)};
  if ((p[1] >> 4) != 0x0F) out.mnc.push_back(d(p[1] >> 4));
  return out;
}

// ---- Mobile identity ----------------------------------------------------------------------------

IdentityType identity_type(const MobileIdentity& id) {
  // Variant order: NoIdentity, Suci, Guti5g, Imei, Imeisv, STmsi5g
  static constexpr IdentityType kTypes[] = {IdentityType::NoIdentity, IdentityType::Suci,   IdentityType::Guti,
                                            IdentityType::Imei,       IdentityType::Imeisv, IdentityType::STmsi};
  return kTypes[id.index()];
}

Bytes encode_mobile_identity(const MobileIdentity& id) {
  Bytes out;
  std::visit(
      [&out](const auto& v) {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, NoIdentity>) {
          out.push_back(0x00);
        } else if constexpr (std::is_same_v<T, Suci>) {
          out.push_back(0x01);  // SUPI format IMSI, type SUCI
          const Bytes plmn = encode_plmn(v.plmn);
          out.insert(out.end(), plmn.begin(), plmn.end());
          if (v.routing_indicator.empty() || v.routing_indicator.size() > 4) {
            throw std::invalid_argument("SUCI routing indicator must be 1-4 digits");
          }
          std::string ri = v.routing_indicator;
          check_digits(ri, "routing indicator");
          std::uint8_t d[4] = {0x0F, 0x0F, 0x0F, 0x0F};
          for (std::size_t i = 0; i < ri.size(); ++i) d[i] = digit(ri, i);
          out.push_back(static_cast<std::uint8_t>((d[1] << 4) | d[0]));
          out.push_back(static_cast<std::uint8_t>((d[3] << 4) | d[2]));
          out.push_back(v.protection_scheme_id & 0x0F);
          out.push_back(v.home_network_public_key_id);
          const Bytes so = v.protection_scheme_id == 0 ? encode_bcd(v.msin) : v.scheme_output;
          out.insert(out.end(), so.begin(), so.end());
        } else if constexpr (std::is_same_v<T, Guti5g>) {
          if (v.amf_set_id > 0x3FF || v.amf_pointer > 0x3F) throw std::invalid_argument("5G-GUTI field overflow");
          out.push_back(0xF2);
          const Bytes plmn = encode_plmn(v.plmn);
          out.insert(out.end(), plmn.begin(), plmn.end());
          out.push_back(v.amf_region_id);
          out.push_back(static_cast<std::uint8_t>(v.amf_set_id >> 2));
          out.push_back(static_cast<std::uint8_t>(((v.amf_set_id & 0x03) << 6) | v.amf_pointer));
          put_u32(out, v.tmsi);
        } else if constexpr (std::is_same_v<T, STmsi5g>) {
          if (v.amf_set_id > 0x3FF || v.amf_pointer > 0x3F) throw std::invalid_argument("5G-S-TMSI field overflow");
          out.push_back(0xF4);
          out.push_back(static_cast<std::uint8_t>(v.amf_set_id >> 2));
          out.push_back(static_cast<std::uint8_t>(((v.amf_set_id & 0x03) << 6) | v.amf_pointer));
          put_u32(out, v.tmsi);
        } else {  // Imei / Imeisv
          constexpr std::uint8_t type = std::is_same_v<T, Imei> ? 0x03 : 0x05;
          check_digits(v.digits, "IMEI");
          if (v.digits.empty()) throw std::invalid_argument("IMEI digits empty");
          const bool odd = v.digits.size() % 2 == 1;
          out.push_back(static_cast<std::uint8_t>((digit(v.digits, 0) << 4) | (odd ? 0x08 : 0x00) | type));
          const Bytes rest = encode_bcd(v.digits.substr(1));
          out.insert(out.end(), rest.begin(), rest.end());
        }
      },
      id);
  return out;
}

MobileIdentity decode_mobile_identity(const Bytes& v) {
  if (v.empty()) bad("5GS mobile identity: empty");
  const std::uint8_t type = v[0] & 0x07;
  switch (type) {
    case 0: return NoIdentity{};
    case 1: {
      if (((v[0] >> 4) & 0x07) != 0) bad("SUCI: only SUPI format IMSI is supported");
      if (v.size() < 8) bad("SUCI: too short");
      Suci s;
      s.plmn = decode_plmn(&v[1]);
      std::string ri;
      const std::uint8_t d[4] = {static_cast<std::uint8_t>(v[4] & 0x0F), static_cast<std::uint8_t>(v[4] >> 4),
                                 static_cast<std::uint8_t>(v[5] & 0x0F), static_cast<std::uint8_t>(v[5] >> 4)};
      for (std::uint8_t x : d) {
        if (x == 0x0F) break;
        if (x > 9) bad("SUCI: bad routing indicator digit");
        ri.push_back(static_cast<char>('0' + x));
      }
      s.routing_indicator = ri;
      s.protection_scheme_id = v[6] & 0x0F;
      s.home_network_public_key_id = v[7];
      if (s.protection_scheme_id == 0) {
        s.msin = decode_bcd(v.data() + 8, v.size() - 8);
      } else {
        s.scheme_output.assign(v.begin() + 8, v.end());
      }
      return s;
    }
    case 2: {
      if (v.size() != 11) bad("5G-GUTI: length must be 11");
      Guti5g g;
      g.plmn = decode_plmn(&v[1]);
      g.amf_region_id = v[4];
      g.amf_set_id = static_cast<std::uint16_t>((v[5] << 2) | (v[6] >> 6));
      g.amf_pointer = v[6] & 0x3F;
      g.tmsi = (std::uint32_t{v[7]} << 24) | (std::uint32_t{v[8]} << 16) | (std::uint32_t{v[9]} << 8) | v[10];
      return g;
    }
    case 3:
    case 5: {
      const bool odd = (v[0] & 0x08) != 0;
      std::string digits(1, static_cast<char>('0' + (v[0] >> 4)));
      if ((v[0] >> 4) > 9) bad("IMEI: bad digit");
      digits += decode_bcd(v.data() + 1, v.size() - 1);
      if ((digits.size() % 2 == 1) != odd) bad("IMEI: odd/even indicator mismatch");
      if (type == 3) return Imei{digits};
      return Imeisv{digits};
    }
    case 4: {
      if (v.size() != 7) bad("5G-S-TMSI: length must be 7");
      STmsi5g s;
      s.amf_set_id = static_cast<std::uint16_t>((v[1] << 2) | (v[2] >> 6));
      s.amf_pointer = v[2] & 0x3F;
      s.tmsi = (std::uint32_t{v[3]} << 24) | (std::uint32_t{v[4]} << 16) | (std::uint32_t{v[5]} << 8) | v[6];
      return s;
    }
    default: bad("5GS mobile identity: unsupported type of identity " + std::to_string(type));
  }
}

Json to_json(const MobileIdentity& id) {
  return std::visit(
      [](const auto& v) -> Json {
        using T = std::decay_t<decltype(v)>;
        if constexpr (std::is_same_v<T, NoIdentity>) {
          return Json::object().set("type", "no identity");
        } else if constexpr (std::is_same_v<T, Suci>) {
          Json j = Json::object()
                       .set("type", "SUCI")
                       .set("mcc", v.plmn.mcc)
                       .set("mnc", v.plmn.mnc)
                       .set("routingIndicator", v.routing_indicator)
                       .set("protectionSchemeId", v.protection_scheme_id)
                       .set("homeNetworkPublicKeyId", v.home_network_public_key_id);
          if (v.protection_scheme_id == 0) {
            j.set("msin", v.msin);
          } else {
            j.set("schemeOutput", to_hex(v.scheme_output));
          }
          return j;
        } else if constexpr (std::is_same_v<T, Guti5g>) {
          return Json::object()
              .set("type", "5G-GUTI")
              .set("mcc", v.plmn.mcc)
              .set("mnc", v.plmn.mnc)
              .set("amfRegionId", v.amf_region_id)
              .set("amfSetId", v.amf_set_id)
              .set("amfPointer", v.amf_pointer)
              .set("tmsi", v.tmsi);
        } else if constexpr (std::is_same_v<T, STmsi5g>) {
          return Json::object()
              .set("type", "5G-S-TMSI")
              .set("amfSetId", v.amf_set_id)
              .set("amfPointer", v.amf_pointer)
              .set("tmsi", v.tmsi);
        } else if constexpr (std::is_same_v<T, Imei>) {
          return Json::object().set("type", "IMEI").set("digits", v.digits);
        } else {
          return Json::object().set("type", "IMEISV").set("digits", v.digits);
        }
      },
      id);
}

// ---- Security capability ------------------------------------------------------------------------

Bytes encode_ue_security_capability(const UeSecurityCapability& c) {
  Bytes out{c.nr_ea, c.nr_ia};
  if (c.eutra_ea || c.eutra_ia) {
    out.push_back(c.eutra_ea.value_or(0));
    out.push_back(c.eutra_ia.value_or(0));
  }
  return out;
}

UeSecurityCapability decode_ue_security_capability(const Bytes& v) {
  if (v.size() < 2 || v.size() > 8) bad("UE security capability: length must be 2..8");
  UeSecurityCapability c;
  c.nr_ea = v[0];
  c.nr_ia = v[1];
  if (v.size() >= 3) c.eutra_ea = v[2];
  if (v.size() >= 4) c.eutra_ia = v[3];
  return c;
}

// ---- NSSAI, TAI list, timers --------------------------------------------------------------------

Bytes encode_nssai(const std::vector<SNssai>& list) {
  Bytes out;
  for (const SNssai& s : list) {
    if (s.sd) {
      if (*s.sd > 0xFFFFFF) throw std::invalid_argument("S-NSSAI SD is 24 bits");
      out.push_back(4);
      out.push_back(s.sst);
      out.push_back(static_cast<std::uint8_t>(*s.sd >> 16));
      out.push_back(static_cast<std::uint8_t>(*s.sd >> 8));
      out.push_back(static_cast<std::uint8_t>(*s.sd));
    } else {
      out.push_back(1);
      out.push_back(s.sst);
    }
  }
  return out;
}

std::vector<SNssai> decode_nssai(const Bytes& v) {
  std::vector<SNssai> out;
  std::size_t i = 0;
  while (i < v.size()) {
    const std::size_t len = v[i++];
    if (i + len > v.size()) bad("NSSAI: S-NSSAI overruns IE");
    if (len != 1 && len != 2 && len != 4 && len != 5 && len != 8) bad("NSSAI: invalid S-NSSAI length");
    SNssai s;
    s.sst = v[i];
    if (len >= 4) s.sd = (std::uint32_t{v[i + 1]} << 16) | (std::uint32_t{v[i + 2]} << 8) | v[i + 3];
    out.push_back(s);
    i += len;
  }
  return out;
}

Bytes encode_tai_list(const TaiList& l) {
  if (l.tais.empty()) throw std::invalid_argument("TAI list must not be empty");
  Bytes out;
  // One type-00 partial list per PLMN run (list of non-consecutive TACs, 1..16 elements).
  std::size_t i = 0;
  while (i < l.tais.size()) {
    std::size_t j = i;
    while (j < l.tais.size() && l.tais[j].plmn == l.tais[i].plmn && j - i < 16) ++j;
    out.push_back(static_cast<std::uint8_t>((0u << 5) | (j - i - 1)));
    const Bytes plmn = encode_plmn(l.tais[i].plmn);
    out.insert(out.end(), plmn.begin(), plmn.end());
    for (std::size_t k = i; k < j; ++k) {
      out.push_back(static_cast<std::uint8_t>(l.tais[k].tac >> 16));
      out.push_back(static_cast<std::uint8_t>(l.tais[k].tac >> 8));
      out.push_back(static_cast<std::uint8_t>(l.tais[k].tac));
    }
    i = j;
  }
  return out;
}

TaiList decode_tai_list(const Bytes& v) {
  TaiList l;
  std::size_t i = 0;
  auto tac_at = [&](std::size_t p) { return (std::uint32_t{v[p]} << 16) | (std::uint32_t{v[p + 1]} << 8) | v[p + 2]; };
  while (i < v.size()) {
    const std::uint8_t hdr = v[i++];
    const std::uint8_t type = (hdr >> 5) & 0x03;
    const std::size_t n = (hdr & 0x1F) + 1u;
    if (type == 0) {
      if (i + 3 + 3 * n > v.size()) bad("TAI list: type 00 partial list truncated");
      const Plmn plmn = decode_plmn(&v[i]);
      i += 3;
      for (std::size_t k = 0; k < n; ++k, i += 3) l.tais.push_back(Tai{plmn, tac_at(i)});
    } else if (type == 1) {
      if (i + 6 > v.size()) bad("TAI list: type 01 partial list truncated");
      const Plmn plmn = decode_plmn(&v[i]);
      const std::uint32_t first = tac_at(i + 3);
      for (std::size_t k = 0; k < n; ++k) l.tais.push_back(Tai{plmn, (first + static_cast<std::uint32_t>(k)) & 0xFFFFFF});
      i += 6;
    } else if (type == 2) {
      if (i + 6 * n > v.size()) bad("TAI list: type 10 partial list truncated");
      for (std::size_t k = 0; k < n; ++k, i += 6) l.tais.push_back(Tai{decode_plmn(&v[i]), tac_at(i + 3)});
    } else {
      bad("TAI list: reserved partial list type");
    }
  }
  if (l.tais.empty()) bad("TAI list: empty");
  return l;
}

std::optional<std::uint32_t> GprsTimer::seconds_timer2() const {
  switch (unit) {
    case 0: return value * 2u;
    case 1: return value * 60u;
    case 2: return value * 360u;
    case 7: return std::nullopt;
    default: return value * 60u;  // other values are interpreted as minutes (TS 24.008)
  }
}

std::optional<std::uint32_t> GprsTimer::seconds_timer3() const {
  switch (unit) {
    case 0: return value * 600u;
    case 1: return value * 3600u;
    case 2: return value * 36000u;
    case 3: return value * 2u;
    case 4: return value * 30u;
    case 5: return value * 60u;
    case 6: return value * 1152000u;
    default: return std::nullopt;
  }
}

}  // namespace nrlite::nas
