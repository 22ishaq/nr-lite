#include "nrlite/nas/messages.hpp"

#include <algorithm>
#include <set>

namespace nrlite::nas {

namespace {

constexpr std::uint8_t kCause96 = static_cast<std::uint8_t>(Cause::InvalidMandatoryInformation);
constexpr std::uint8_t kCause97 = static_cast<std::uint8_t>(Cause::MessageTypeNonExistent);
constexpr std::uint8_t kCause111 = static_cast<std::uint8_t>(Cause::ProtocolErrorUnspecified);

[[noreturn]] void missing(const std::string& what) { throw NasDecodeError(what, kCause96); }

// ---- Byte-level reader / writer -----------------------------------------------------------------

class Reader {
 public:
  Reader(const Bytes& b, std::size_t pos) : b_(b), pos_(pos) {}
  bool empty() const { return pos_ >= b_.size(); }
  std::size_t pos() const { return pos_; }
  void seek(std::size_t pos) { pos_ = pos; }
  std::size_t remaining() const { return b_.size() - pos_; }
  std::uint8_t peek() const {
    if (empty()) missing("unexpected end of message");
    return b_[pos_];
  }
  std::uint8_t u8(const char* what) {
    if (empty()) missing(std::string(what) + ": message truncated");
    return b_[pos_++];
  }
  Bytes take(std::size_t n, const char* what) {
    if (remaining() < n) missing(std::string(what) + ": IE overruns message");
    Bytes out(b_.begin() + static_cast<std::ptrdiff_t>(pos_), b_.begin() + static_cast<std::ptrdiff_t>(pos_ + n));
    pos_ += n;
    return out;
  }
  Bytes lv(const char* what) { return take(u8(what), what); }
  Bytes lve(const char* what) {
    const std::size_t hi = u8(what);
    const std::size_t lo = u8(what);
    return take((hi << 8) | lo, what);
  }

 private:
  const Bytes& b_;
  std::size_t pos_;
};

void put_lv(Bytes& out, const Bytes& v) {
  if (v.size() > 255) throw std::invalid_argument("LV IE longer than 255 octets");
  out.push_back(static_cast<std::uint8_t>(v.size()));
  out.insert(out.end(), v.begin(), v.end());
}

void put_lve(Bytes& out, const Bytes& v) {
  if (v.size() > 0xFFFF) throw std::invalid_argument("LV-E IE longer than 65535 octets");
  put_u16(out, static_cast<std::uint16_t>(v.size()));
  out.insert(out.end(), v.begin(), v.end());
}

void put_tlv(Bytes& out, std::uint8_t iei, const Bytes& v) {
  out.push_back(iei);
  put_lv(out, v);
}

void put_tlve(Bytes& out, std::uint8_t iei, const Bytes& v) {
  out.push_back(iei);
  put_lve(out, v);
}

/// Iterates the optional IE part of a message. `handler(iei, reader)` returns true if it consumed
/// the IE; otherwise the IE is skipped according to its format. Repeated IEs after the first are
/// ignored (TS 24.007 §8.6.3), and an optional IE whose contents are syntactically incorrect is
/// treated as not present (TS 24.501 §7.7.2). A truncated message is still an error.
template <typename Handler>
void for_each_optional(Reader& r, Handler&& handler) {
  std::set<std::uint8_t> seen;
  while (!r.empty()) {
    const std::size_t start = r.pos();
    const std::uint8_t first = r.peek();
    const bool half_octet = (first & 0x80) != 0;
    const std::uint8_t key = half_octet ? static_cast<std::uint8_t>(first & 0xF0) : first;
    const bool repeat = !seen.insert(key).second;
    if (!repeat) {
      try {
        if (handler(key, r)) continue;
      } catch (const NasDecodeError&) {
        r.seek(start);  // ignore the IE: fall through and skip it by its length
      }
    }
    // Skip: type 1/2 IEs are one octet; 0x7X IEIs are TLV-E; everything else TLV (TS 24.007 §11.2.4).
    r.u8("IEI");
    if (half_octet) continue;
    if ((first & 0xF0) == 0x70) {
      (void)r.lve("unknown TLV-E IE");
    } else {
      (void)r.lv("unknown TLV IE");
    }
  }
}

template <std::size_t N>
std::array<std::uint8_t, N> fixed(const Bytes& v, const char* what) {
  if (v.size() != N) missing(std::string(what) + ": wrong length " + std::to_string(v.size()));
  std::array<std::uint8_t, N> a{};
  std::copy(v.begin(), v.end(), a.begin());
  return a;
}

Tai decode_tai_value(const Bytes& v) {
  if (v.size() != 6) missing("5GS TAI: wrong length");
  return Tai{decode_plmn(v.data()), (std::uint32_t{v[3]} << 16) | (std::uint32_t{v[4]} << 8) | v[5]};
}

Bytes encode_tai_value(const Tai& t) {
  Bytes out = encode_plmn(t.plmn);
  out.push_back(static_cast<std::uint8_t>(t.tac >> 16));
  out.push_back(static_cast<std::uint8_t>(t.tac >> 8));
  out.push_back(static_cast<std::uint8_t>(t.tac));
  return out;
}

// ---- Per-message encoders -----------------------------------------------------------------------

void enc(Bytes& out, const RegistrationRequest& m) {
  out.push_back(static_cast<std::uint8_t>((m.ngksi.nibble() << 4) | m.registration_type.nibble()));
  put_lve(out, encode_mobile_identity(m.mobile_identity));
  if (m.mm_capability) put_tlv(out, 0x10, *m.mm_capability);
  if (m.ue_security_capability) put_tlv(out, 0x2E, encode_ue_security_capability(*m.ue_security_capability));
  if (m.requested_nssai) put_tlv(out, 0x2F, encode_nssai(*m.requested_nssai));
  if (m.last_visited_registered_tai) {
    out.push_back(0x52);
    const Bytes t = encode_tai_value(*m.last_visited_registered_tai);
    out.insert(out.end(), t.begin(), t.end());
  }
  if (m.nas_message_container) put_tlve(out, 0x71, *m.nas_message_container);
}

void enc(Bytes& out, const RegistrationAccept& m) {
  put_lv(out, Bytes{m.registration_result});
  if (m.guti) put_tlve(out, 0x77, encode_mobile_identity(*m.guti));
  if (m.tai_list) put_tlv(out, 0x54, encode_tai_list(*m.tai_list));
  if (m.allowed_nssai) put_tlv(out, 0x15, encode_nssai(*m.allowed_nssai));
  if (m.t3512) put_tlv(out, 0x5E, Bytes{m.t3512->octet()});
  if (m.t3502) put_tlv(out, 0x16, Bytes{m.t3502->octet()});
}

void enc(Bytes&, const RegistrationComplete&) {}

void enc(Bytes& out, const RegistrationReject& m) {
  out.push_back(static_cast<std::uint8_t>(m.cause));
  if (m.t3346) put_tlv(out, 0x5F, Bytes{m.t3346->octet()});
  if (m.t3502) put_tlv(out, 0x16, Bytes{m.t3502->octet()});
}

void enc(Bytes& out, const DeregistrationRequestUeOriginating& m) {
  out.push_back(static_cast<std::uint8_t>((m.ngksi.nibble() << 4) | m.deregistration_type.nibble()));
  put_lve(out, encode_mobile_identity(m.mobile_identity));
}

void enc(Bytes&, const DeregistrationAcceptUeOriginating&) {}

void enc(Bytes& out, const AuthenticationRequest& m) {
  out.push_back(m.ngksi.nibble());  // spare half octet in bits 8-5
  put_lv(out, m.abba);
  if (m.rand) {
    out.push_back(0x21);
    out.insert(out.end(), m.rand->begin(), m.rand->end());
  }
  if (m.autn) put_tlv(out, 0x20, Bytes(m.autn->begin(), m.autn->end()));
}

void enc(Bytes& out, const AuthenticationResponse& m) {
  if (m.res_star) put_tlv(out, 0x2D, Bytes(m.res_star->begin(), m.res_star->end()));
}

void enc(Bytes&, const AuthenticationReject&) {}

void enc(Bytes& out, const AuthenticationFailure& m) {
  out.push_back(static_cast<std::uint8_t>(m.cause));
  if (m.auts) put_tlv(out, 0x30, Bytes(m.auts->begin(), m.auts->end()));
}

void enc(Bytes& out, const IdentityRequest& m) { out.push_back(static_cast<std::uint8_t>(m.identity_type) & 0x07); }

void enc(Bytes& out, const IdentityResponse& m) { put_lve(out, encode_mobile_identity(m.mobile_identity)); }

void enc(Bytes& out, const SecurityModeCommand& m) {
  out.push_back(m.selected_algorithms.octet());
  out.push_back(m.ngksi.nibble());  // spare half octet in bits 8-5
  put_lv(out, encode_ue_security_capability(m.replayed_ue_security_capability));
  if (m.imeisv_request) out.push_back(static_cast<std::uint8_t>(0xE0 | (*m.imeisv_request ? 0x01 : 0x00)));
  if (m.additional_security_information) put_tlv(out, 0x36, Bytes{*m.additional_security_information});
  if (m.abba) put_tlv(out, 0x38, *m.abba);
}

void enc(Bytes& out, const SecurityModeComplete& m) {
  if (m.imeisv) put_tlve(out, 0x77, encode_mobile_identity(*m.imeisv));
  if (m.nas_message_container) put_tlve(out, 0x71, *m.nas_message_container);
}

void enc(Bytes& out, const SecurityModeReject& m) { out.push_back(static_cast<std::uint8_t>(m.cause)); }

void enc(Bytes& out, const Status5gmm& m) { out.push_back(static_cast<std::uint8_t>(m.cause)); }

// ---- Per-message decoders -----------------------------------------------------------------------

RegistrationRequest dec_registration_request(Reader& r) {
  RegistrationRequest m;
  const std::uint8_t o = r.u8("5GS registration type / ngKSI");
  m.registration_type.follow_on_request = (o & 0x08) != 0;
  m.registration_type.value = o & 0x07;
  if (m.registration_type.value == 0 || m.registration_type.value == 7) missing("5GS registration type: reserved value");
  m.ngksi = Ngksi::from_nibble(static_cast<std::uint8_t>(o >> 4));
  m.mobile_identity = decode_mobile_identity(r.lve("5GS mobile identity"));
  for_each_optional(r, [&](std::uint8_t iei, Reader& rr) {
    switch (iei) {
      case 0x10:
        rr.u8("IEI");
        m.mm_capability = rr.lv("5GMM capability");
        return true;
      case 0x2E:
        rr.u8("IEI");
        m.ue_security_capability = decode_ue_security_capability(rr.lv("UE security capability"));
        return true;
      case 0x2F:
        rr.u8("IEI");
        m.requested_nssai = decode_nssai(rr.lv("Requested NSSAI"));
        return true;
      case 0x52:
        rr.u8("IEI");
        m.last_visited_registered_tai = decode_tai_value(rr.take(6, "Last visited registered TAI"));
        return true;
      case 0x71:
        rr.u8("IEI");
        m.nas_message_container = rr.lve("NAS message container");
        return true;
      default: return false;
    }
  });
  return m;
}

RegistrationAccept dec_registration_accept(Reader& r) {
  RegistrationAccept m;
  const Bytes result = r.lv("5GS registration result");
  if (result.size() != 1) missing("5GS registration result: length must be 1");
  m.registration_result = result[0];
  for_each_optional(r, [&](std::uint8_t iei, Reader& rr) {
    switch (iei) {
      case 0x77: {
        rr.u8("IEI");
        const MobileIdentity id = decode_mobile_identity(rr.lve("5G-GUTI"));
        if (!std::holds_alternative<Guti5g>(id)) missing("5G-GUTI IE does not carry a 5G-GUTI");
        m.guti = std::get<Guti5g>(id);
        return true;
      }
      case 0x54:
        rr.u8("IEI");
        m.tai_list = decode_tai_list(rr.lv("TAI list"));
        return true;
      case 0x15:
        rr.u8("IEI");
        m.allowed_nssai = decode_nssai(rr.lv("Allowed NSSAI"));
        return true;
      case 0x5E:
        rr.u8("IEI");
        m.t3512 = GprsTimer::from_octet(fixed<1>(rr.lv("T3512 value"), "T3512 value")[0]);
        return true;
      case 0x16:
        rr.u8("IEI");
        m.t3502 = GprsTimer::from_octet(fixed<1>(rr.lv("T3502 value"), "T3502 value")[0]);
        return true;
      default: return false;
    }
  });
  return m;
}

RegistrationReject dec_registration_reject(Reader& r) {
  RegistrationReject m;
  m.cause = static_cast<Cause>(r.u8("5GMM cause"));
  for_each_optional(r, [&](std::uint8_t iei, Reader& rr) {
    if (iei == 0x5F || iei == 0x16) {
      rr.u8("IEI");
      const GprsTimer t = GprsTimer::from_octet(fixed<1>(rr.lv("GPRS timer 2"), "GPRS timer 2")[0]);
      (iei == 0x5F ? m.t3346 : m.t3502) = t;
      return true;
    }
    return false;
  });
  return m;
}

DeregistrationRequestUeOriginating dec_deregistration_request(Reader& r) {
  DeregistrationRequestUeOriginating m;
  const std::uint8_t o = r.u8("De-registration type / ngKSI");
  m.deregistration_type.switch_off = (o & 0x08) != 0;
  m.deregistration_type.reregistration_required = (o & 0x04) != 0;
  m.deregistration_type.access_type = o & 0x03;
  if (m.deregistration_type.access_type == 0) missing("De-registration type: reserved access type");
  m.ngksi = Ngksi::from_nibble(static_cast<std::uint8_t>(o >> 4));
  m.mobile_identity = decode_mobile_identity(r.lve("5GS mobile identity"));
  for_each_optional(r, [](std::uint8_t, Reader&) { return false; });
  return m;
}

AuthenticationRequest dec_authentication_request(Reader& r) {
  AuthenticationRequest m;
  m.ngksi = Ngksi::from_nibble(r.u8("ngKSI") & 0x0F);
  m.abba = r.lv("ABBA");
  if (m.abba.size() < 2) missing("ABBA: length must be at least 2");
  for_each_optional(r, [&](std::uint8_t iei, Reader& rr) {
    switch (iei) {
      case 0x21:
        rr.u8("IEI");
        m.rand = fixed<16>(rr.take(16, "RAND"), "RAND");
        return true;
      case 0x20:
        rr.u8("IEI");
        m.autn = fixed<16>(rr.lv("AUTN"), "AUTN");
        return true;
      default: return false;
    }
  });
  return m;
}

AuthenticationResponse dec_authentication_response(Reader& r) {
  AuthenticationResponse m;
  for_each_optional(r, [&](std::uint8_t iei, Reader& rr) {
    if (iei != 0x2D) return false;
    rr.u8("IEI");
    m.res_star = fixed<16>(rr.lv("Authentication response parameter"), "RES*");
    return true;
  });
  return m;
}

AuthenticationFailure dec_authentication_failure(Reader& r) {
  AuthenticationFailure m;
  m.cause = static_cast<Cause>(r.u8("5GMM cause"));
  for_each_optional(r, [&](std::uint8_t iei, Reader& rr) {
    if (iei != 0x30) return false;
    rr.u8("IEI");
    m.auts = fixed<14>(rr.lv("Authentication failure parameter"), "AUTS");
    return true;
  });
  return m;
}

IdentityRequest dec_identity_request(Reader& r) {
  IdentityRequest m;
  const std::uint8_t t = r.u8("5GS identity type") & 0x07;
  if (t > 5) missing("5GS identity type: unsupported value " + std::to_string(t));
  m.identity_type = static_cast<IdentityType>(t);
  return m;
}

IdentityResponse dec_identity_response(Reader& r) {
  IdentityResponse m;
  m.mobile_identity = decode_mobile_identity(r.lve("Mobile identity"));
  return m;
}

SecurityModeCommand dec_security_mode_command(Reader& r) {
  SecurityModeCommand m;
  m.selected_algorithms = NasSecurityAlgorithms::from_octet(r.u8("Selected NAS security algorithms"));
  m.ngksi = Ngksi::from_nibble(r.u8("ngKSI") & 0x0F);
  m.replayed_ue_security_capability = decode_ue_security_capability(r.lv("Replayed UE security capabilities"));
  for_each_optional(r, [&](std::uint8_t iei, Reader& rr) {
    switch (iei) {
      case 0xE0:
        m.imeisv_request = (rr.u8("IMEISV request") & 0x07) == 1;
        return true;
      case 0x36: {
        rr.u8("IEI");
        m.additional_security_information = fixed<1>(rr.lv("Additional 5G security information"), "Additional 5G security information")[0];
        return true;
      }
      case 0x38:
        rr.u8("IEI");
        m.abba = rr.lv("ABBA");
        return true;
      case 0x57:  // Selected EPS NAS security algorithms: TV, 2 octets
        rr.take(2, "Selected EPS NAS security algorithms");
        return true;
      default: return false;
    }
  });
  return m;
}

SecurityModeComplete dec_security_mode_complete(Reader& r) {
  SecurityModeComplete m;
  for_each_optional(r, [&](std::uint8_t iei, Reader& rr) {
    switch (iei) {
      case 0x77:
        rr.u8("IEI");
        m.imeisv = decode_mobile_identity(rr.lve("IMEISV"));
        return true;
      case 0x71:
        rr.u8("IEI");
        m.nas_message_container = rr.lve("NAS message container");
        return true;
      default: return false;
    }
  });
  return m;
}

template <typename T>
struct TypeOf;
#define NRLITE_NAS_TYPE(T, V)                          \
  template <>                                          \
  struct TypeOf<T> {                                   \
    static constexpr MessageType value = MessageType::V; \
  };
NRLITE_NAS_TYPE(RegistrationRequest, RegistrationRequest)
NRLITE_NAS_TYPE(RegistrationAccept, RegistrationAccept)
NRLITE_NAS_TYPE(RegistrationComplete, RegistrationComplete)
NRLITE_NAS_TYPE(RegistrationReject, RegistrationReject)
NRLITE_NAS_TYPE(DeregistrationRequestUeOriginating, DeregistrationRequestUeOriginating)
NRLITE_NAS_TYPE(DeregistrationAcceptUeOriginating, DeregistrationAcceptUeOriginating)
NRLITE_NAS_TYPE(AuthenticationRequest, AuthenticationRequest)
NRLITE_NAS_TYPE(AuthenticationResponse, AuthenticationResponse)
NRLITE_NAS_TYPE(AuthenticationReject, AuthenticationReject)
NRLITE_NAS_TYPE(AuthenticationFailure, AuthenticationFailure)
NRLITE_NAS_TYPE(IdentityRequest, IdentityRequest)
NRLITE_NAS_TYPE(IdentityResponse, IdentityResponse)
NRLITE_NAS_TYPE(SecurityModeCommand, SecurityModeCommand)
NRLITE_NAS_TYPE(SecurityModeComplete, SecurityModeComplete)
NRLITE_NAS_TYPE(SecurityModeReject, SecurityModeReject)
NRLITE_NAS_TYPE(Status5gmm, Status5gmm)
#undef NRLITE_NAS_TYPE

std::string hex(const Bytes& b) { return to_hex(b); }

Json gprs_timer_json(const GprsTimer& t) { return Json::object().set("unit", t.unit).set("value", t.value); }

Json nssai_json(const std::vector<SNssai>& list) {
  Json a = Json::array();
  for (const auto& s : list) {
    Json e = Json::object().set("sst", s.sst);
    if (s.sd) e.set("sd", *s.sd);
    a.push(std::move(e));
  }
  return a;
}

Json ue_sec_cap_json(const UeSecurityCapability& c) {
  return Json::object().set("5G-EA", c.nr_ea).set("5G-IA", c.nr_ia);
}

Json ngksi_json(const Ngksi& k) { return Json::object().set("tsc", k.mapped ? 1 : 0).set("ksi", k.ksi); }

}  // namespace

// ---- Names --------------------------------------------------------------------------------------

const char* to_string(SecurityHeaderType t) {
  switch (t) {
    case SecurityHeaderType::Plain: return "Plain NAS message";
    case SecurityHeaderType::IntegrityProtected: return "Integrity protected";
    case SecurityHeaderType::IntegrityProtectedAndCiphered: return "Integrity protected and ciphered";
    case SecurityHeaderType::IntegrityProtectedWithNewContext: return "Integrity protected with new 5G NAS security context";
    case SecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext:
      return "Integrity protected and ciphered with new 5G NAS security context";
  }
  return "Reserved";
}

const char* to_string(MessageType t) {
  switch (t) {
    case MessageType::RegistrationRequest: return "RegistrationRequest";
    case MessageType::RegistrationAccept: return "RegistrationAccept";
    case MessageType::RegistrationComplete: return "RegistrationComplete";
    case MessageType::RegistrationReject: return "RegistrationReject";
    case MessageType::DeregistrationRequestUeOriginating: return "DeregistrationRequest(UE originating)";
    case MessageType::DeregistrationAcceptUeOriginating: return "DeregistrationAccept(UE originating)";
    case MessageType::AuthenticationRequest: return "AuthenticationRequest";
    case MessageType::AuthenticationResponse: return "AuthenticationResponse";
    case MessageType::AuthenticationReject: return "AuthenticationReject";
    case MessageType::AuthenticationFailure: return "AuthenticationFailure";
    case MessageType::IdentityRequest: return "IdentityRequest";
    case MessageType::IdentityResponse: return "IdentityResponse";
    case MessageType::SecurityModeCommand: return "SecurityModeCommand";
    case MessageType::SecurityModeComplete: return "SecurityModeComplete";
    case MessageType::SecurityModeReject: return "SecurityModeReject";
    case MessageType::Status5gmm: return "5GMMStatus";
  }
  return "Unknown";
}

MessageType message_type(const PlainMessage& m) {
  return std::visit([](const auto& v) { return TypeOf<std::decay_t<decltype(v)>>::value; }, m);
}

std::string message_name(const PlainMessage& m) { return to_string(message_type(m)); }

// ---- Codec --------------------------------------------------------------------------------------

Bytes encode(const PlainMessage& m) {
  Bytes out{kEpd5gmm, 0x00, static_cast<std::uint8_t>(message_type(m))};
  std::visit([&out](const auto& v) { enc(out, v); }, m);
  return out;
}

Result<PlainMessage> decode_plain(const Bytes& pdu) {
  if (pdu.size() < 3) return Error{"NAS: message too short (" + std::to_string(pdu.size()) + " octets)", kCause111};
  if (pdu[0] != kEpd5gmm) return Error{"NAS: unsupported extended protocol discriminator", kCause97};
  if ((pdu[1] & 0x0F) != 0) return Error{"NAS: not a plain 5GMM message", kCause111};
  try {
    Reader r(pdu, 3);
    switch (static_cast<MessageType>(pdu[2])) {
      case MessageType::RegistrationRequest: return PlainMessage{dec_registration_request(r)};
      case MessageType::RegistrationAccept: return PlainMessage{dec_registration_accept(r)};
      case MessageType::RegistrationComplete:
        for_each_optional(r, [](std::uint8_t, Reader&) { return false; });
        return PlainMessage{RegistrationComplete{}};
      case MessageType::RegistrationReject: return PlainMessage{dec_registration_reject(r)};
      case MessageType::DeregistrationRequestUeOriginating: return PlainMessage{dec_deregistration_request(r)};
      case MessageType::DeregistrationAcceptUeOriginating: return PlainMessage{DeregistrationAcceptUeOriginating{}};
      case MessageType::AuthenticationRequest: return PlainMessage{dec_authentication_request(r)};
      case MessageType::AuthenticationResponse: return PlainMessage{dec_authentication_response(r)};
      case MessageType::AuthenticationReject:
        for_each_optional(r, [](std::uint8_t, Reader&) { return false; });
        return PlainMessage{AuthenticationReject{}};
      case MessageType::AuthenticationFailure: return PlainMessage{dec_authentication_failure(r)};
      case MessageType::IdentityRequest: return PlainMessage{dec_identity_request(r)};
      case MessageType::IdentityResponse: return PlainMessage{dec_identity_response(r)};
      case MessageType::SecurityModeCommand: return PlainMessage{dec_security_mode_command(r)};
      case MessageType::SecurityModeComplete: return PlainMessage{dec_security_mode_complete(r)};
      case MessageType::SecurityModeReject:
        return PlainMessage{SecurityModeReject{static_cast<Cause>(r.u8("5GMM cause"))}};
      case MessageType::Status5gmm: return PlainMessage{Status5gmm{static_cast<Cause>(r.u8("5GMM cause"))}};
    }
    return Error{"NAS: message type 0x" + to_hex(&pdu[2], 1) + " non-existent or not implemented", kCause97};
  } catch (const NasDecodeError& e) {
    return Error{std::string("NAS ") + to_string(static_cast<MessageType>(pdu[2])) + ": " + e.what(), e.cause()};
  } catch (const std::invalid_argument& e) {
    return Error{std::string("NAS: ") + e.what(), kCause96};
  }
}

Result<SecurityHeaderType> peek_security_header_type(const Bytes& pdu) {
  if (pdu.size() < 3) return Error{"NAS: message too short", kCause111};
  if (pdu[0] != kEpd5gmm) return Error{"NAS: unsupported extended protocol discriminator", kCause97};
  const std::uint8_t sht = pdu[1] & 0x0F;
  if (sht > 4) return Error{"NAS: reserved security header type " + std::to_string(sht), kCause111};
  return static_cast<SecurityHeaderType>(sht);
}

Result<SecuredPdu> parse_secured(const Bytes& pdu) {
  const auto sht = peek_security_header_type(pdu);
  if (!sht) return sht.error();
  if (*sht == SecurityHeaderType::Plain) return Error{"NAS: message is not security protected", kCause111};
  if (pdu.size() < 7 + 3) return Error{"NAS: security protected message too short", kCause111};
  SecuredPdu s;
  s.security_header_type = *sht;
  std::copy(pdu.begin() + 2, pdu.begin() + 6, s.mac.begin());
  s.sqn = pdu[6];
  s.payload.assign(pdu.begin() + 7, pdu.end());
  return s;
}

Bytes build_secured(const SecuredPdu& s) {
  Bytes out{kEpd5gmm, static_cast<std::uint8_t>(s.security_header_type)};
  out.insert(out.end(), s.mac.begin(), s.mac.end());
  out.push_back(s.sqn);
  out.insert(out.end(), s.payload.begin(), s.payload.end());
  return out;
}

// ---- JSON ---------------------------------------------------------------------------------------

Json to_json(const PlainMessage& msg) {
  Json body = Json::object();
  std::visit(
      [&body](const auto& m) {
        using T = std::decay_t<decltype(m)>;
        if constexpr (std::is_same_v<T, RegistrationRequest>) {
          body.set("5gsRegistrationType", Json::object()
                                              .set("for", m.registration_type.follow_on_request ? 1 : 0)
                                              .set("value", m.registration_type.value));
          body.set("ngKSI", ngksi_json(m.ngksi));
          body.set("mobileIdentity", to_json(m.mobile_identity));
          if (m.ue_security_capability) body.set("ueSecurityCapability", ue_sec_cap_json(*m.ue_security_capability));
          if (m.requested_nssai) body.set("requestedNSSAI", nssai_json(*m.requested_nssai));
          if (m.mm_capability) body.set("5gmmCapability", hex(*m.mm_capability));
          if (m.nas_message_container) body.set("nasMessageContainer", hex(*m.nas_message_container));
        } else if constexpr (std::is_same_v<T, RegistrationAccept>) {
          body.set("5gsRegistrationResult", m.registration_result);
          if (m.guti) body.set("5gGuti", to_json(MobileIdentity{*m.guti}));
          if (m.tai_list) {
            Json tais = Json::array();
            for (const auto& t : m.tai_list->tais) {
              tais.push(Json::object().set("mcc", t.plmn.mcc).set("mnc", t.plmn.mnc).set("tac", t.tac));
            }
            body.set("taiList", std::move(tais));
          }
          if (m.allowed_nssai) body.set("allowedNSSAI", nssai_json(*m.allowed_nssai));
          if (m.t3512) body.set("t3512", gprs_timer_json(*m.t3512));
          if (m.t3502) body.set("t3502", gprs_timer_json(*m.t3502));
        } else if constexpr (std::is_same_v<T, RegistrationReject>) {
          body.set("5gmmCause", static_cast<int>(m.cause));
          if (m.t3346) body.set("t3346", gprs_timer_json(*m.t3346));
          if (m.t3502) body.set("t3502", gprs_timer_json(*m.t3502));
        } else if constexpr (std::is_same_v<T, DeregistrationRequestUeOriginating>) {
          body.set("switchOff", m.deregistration_type.switch_off ? 1 : 0);
          body.set("accessType", m.deregistration_type.access_type);
          body.set("ngKSI", ngksi_json(m.ngksi));
          body.set("mobileIdentity", to_json(m.mobile_identity));
        } else if constexpr (std::is_same_v<T, AuthenticationRequest>) {
          body.set("ngKSI", ngksi_json(m.ngksi));
          body.set("abba", hex(m.abba));
          if (m.rand) body.set("rand", to_hex(*m.rand));
          if (m.autn) body.set("autn", to_hex(*m.autn));
        } else if constexpr (std::is_same_v<T, AuthenticationResponse>) {
          if (m.res_star) body.set("resStar", to_hex(*m.res_star));
        } else if constexpr (std::is_same_v<T, AuthenticationFailure>) {
          body.set("5gmmCause", static_cast<int>(m.cause));
          if (m.auts) body.set("auts", to_hex(*m.auts));
        } else if constexpr (std::is_same_v<T, IdentityRequest>) {
          body.set("identityType", static_cast<int>(m.identity_type));
        } else if constexpr (std::is_same_v<T, IdentityResponse>) {
          body.set("mobileIdentity", to_json(m.mobile_identity));
        } else if constexpr (std::is_same_v<T, SecurityModeCommand>) {
          body.set("selectedNasSecurityAlgorithms", Json::object()
                                                        .set("ciphering", m.selected_algorithms.ciphering)
                                                        .set("integrity", m.selected_algorithms.integrity));
          body.set("ngKSI", ngksi_json(m.ngksi));
          body.set("replayedUeSecurityCapabilities", ue_sec_cap_json(m.replayed_ue_security_capability));
          if (m.imeisv_request) body.set("imeisvRequest", *m.imeisv_request);
          if (m.additional_security_information) body.set("additional5gSecurityInformation", *m.additional_security_information);
        } else if constexpr (std::is_same_v<T, SecurityModeComplete>) {
          if (m.imeisv) body.set("imeisv", to_json(*m.imeisv));
          if (m.nas_message_container) body.set("nasMessageContainer", hex(*m.nas_message_container));
        } else if constexpr (std::is_same_v<T, SecurityModeReject> || std::is_same_v<T, Status5gmm>) {
          body.set("5gmmCause", static_cast<int>(m.cause));
        }
      },
      msg);
  return Json::object().set("message", message_name(msg)).set("body", std::move(body));
}

}  // namespace nrlite::nas
