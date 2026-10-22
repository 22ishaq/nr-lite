#pragma once

// Shared test helpers: subscriber data and small "peer" emulators that build correctly protected
// messages so that one side of a protocol can be tested in isolation.

#include <algorithm>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "nrlite/nas/messages.hpp"
#include "nrlite/nas/security.hpp"
#include "nrlite/security/aka.hpp"
#include "nrlite/security/kdf.hpp"

namespace nrlite::testing {

inline sec::Subscription test_subscription(std::size_t index = 0) {
  sec::Subscription s;
  std::string msin = std::to_string(index + 1);
  s.supi = "00101" + std::string(10 - msin.size(), '0') + msin;
  s.k = array_from_hex<16>("465b5ce8b199b49faa5f0a2ee238a6bc");
  s.opc = array_from_hex<16>("cd63cb71954a9f4e48a5994e37a02baf");
  return s;
}

inline std::string test_snn() { return sec::serving_network_name("001", "01"); }

inline nas::Suci test_suci(std::size_t index = 0) {
  nas::Suci s;
  s.plmn = nas::Plmn{"001", "01"};
  s.msin = test_subscription(index).supi.substr(5);
  return s;
}

inline nas::UeSecurityCapability test_caps() { return nas::UeSecurityCapability{0xA0, 0x20, std::nullopt, std::nullopt}; }

/// Plays the AMF towards a UE NAS entity under test.
struct NetworkPeer {
  sec::Subscription sub = test_subscription();
  std::uint64_t sqn = 0;
  std::optional<sec::HeAuthVector> av;
  nas::Ngksi ngksi{false, 0};
  nas::NasSecurityContext ctx;

  nas::AuthenticationRequest auth_request(std::uint8_t rand_seed = 1) {
    sec::Block rand{};
    for (std::size_t i = 0; i < rand.size(); ++i) rand[i] = static_cast<std::uint8_t>(rand_seed * 31 + i);
    ++sqn;
    av = sec::generate_he_av(sub, rand, sqn, test_snn());
    nas::AuthenticationRequest r;
    r.ngksi = ngksi;
    r.rand = av->rand;
    r.autn = av->autn;
    return r;
  }

  sec::Key256 kamf() const { return sec::derive_kamf(av->kseaf, sub.supi, Bytes{0, 0}); }

  /// SECURITY MODE COMMAND protected with a fresh context derived from the last AV.
  Bytes security_mode_command(nas::NasSecurityAlgorithms algs = {0, 2},
                              nas::UeSecurityCapability caps = test_caps(),
                              std::optional<std::uint8_t> additional = std::nullopt) {
    ctx.activate(kamf(), algs, ngksi);
    nas::SecurityModeCommand smc;
    smc.selected_algorithms = algs;
    smc.ngksi = ngksi;
    smc.replayed_ue_security_capability = caps;
    smc.additional_security_information = additional;
    return nas::protect(ctx, nas::encode(smc), nas::SecurityHeaderType::IntegrityProtectedWithNewContext,
                        sec::Direction::Downlink);
  }

  Bytes protect_dl(const nas::PlainMessage& m) {
    return nas::protect(ctx, nas::encode(m), nas::SecurityHeaderType::IntegrityProtectedAndCiphered,
                        sec::Direction::Downlink);
  }

  /// Decodes an uplink PDU, verifying it with `ctx` if it is protected.
  std::optional<nas::PlainMessage> open_ul(const Bytes& pdu) {
    auto sht = nas::peek_security_header_type(pdu);
    if (!sht) return std::nullopt;
    Bytes plain = pdu;
    if (*sht != nas::SecurityHeaderType::Plain) {
      auto un = nas::unprotect(ctx, pdu, sec::Direction::Uplink);
      if (!un) return std::nullopt;
      plain = un->plain;
    }
    auto m = nas::decode_plain(plain);
    if (!m) return std::nullopt;
    return *m;
  }
};

/// Plays the UE towards the AMF under test.
struct UePeer {
  sec::Usim usim{test_subscription(), 0};
  std::optional<nas::Ngksi> ngksi;
  std::optional<sec::Key256> kamf;
  nas::NasSecurityContext ctx;

  nas::RegistrationRequest registration_request(bool with_caps = true) const {
    nas::RegistrationRequest rr;
    rr.mobile_identity = test_suci();
    if (with_caps) rr.ue_security_capability = test_caps();
    rr.requested_nssai = std::vector<nas::SNssai>{nas::SNssai{1, std::nullopt}};
    return rr;
  }

  /// Answers an AUTHENTICATION REQUEST with the USIM; returns the plain response PDU.
  Bytes answer_auth(const nas::AuthenticationRequest& req) {
    sec::Autn16 autn{};
    std::copy(req.autn->begin(), req.autn->end(), autn.begin());
    const auto res = usim.authenticate(*req.rand, autn, test_snn());
    if (res.status != sec::Usim::AuthStatus::Ok) {
      return nas::encode(nas::AuthenticationFailure{nas::Cause::MacFailure, std::nullopt});
    }
    ngksi = req.ngksi;
    kamf = sec::derive_kamf(res.kseaf, usim.subscription().supi, req.abba);
    nas::ResStar rs{};
    std::copy(res.res_star.begin(), res.res_star.end(), rs.begin());
    return nas::encode(nas::AuthenticationResponse{rs});
  }

  /// Verifies an SMC with the context from the last authentication and returns SMC COMPLETE.
  std::optional<Bytes> answer_smc(const Bytes& smc_pdu) {
    auto s = nas::parse_secured(smc_pdu);
    if (!s) return std::nullopt;
    auto inner = nas::decode_plain(s->payload);
    if (!inner || !std::holds_alternative<nas::SecurityModeCommand>(*inner)) return std::nullopt;
    const auto& smc = std::get<nas::SecurityModeCommand>(*inner);
    ctx.activate(*kamf, smc.selected_algorithms, smc.ngksi);
    if (!nas::unprotect(ctx, smc_pdu, sec::Direction::Downlink)) return std::nullopt;
    return nas::protect(ctx, nas::encode(nas::SecurityModeComplete{}),
                        nas::SecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext, sec::Direction::Uplink);
  }

  Bytes protect_ul(const nas::PlainMessage& m) {
    return nas::protect(ctx, nas::encode(m), nas::SecurityHeaderType::IntegrityProtectedAndCiphered,
                        sec::Direction::Uplink);
  }

  std::optional<nas::PlainMessage> open_dl(const Bytes& pdu) {
    auto sht = nas::peek_security_header_type(pdu);
    if (!sht) return std::nullopt;
    Bytes plain = pdu;
    if (*sht == nas::SecurityHeaderType::IntegrityProtectedWithNewContext) {
      auto s = nas::parse_secured(pdu);
      plain = s->payload;
    } else if (*sht != nas::SecurityHeaderType::Plain) {
      auto un = nas::unprotect(ctx, pdu, sec::Direction::Downlink);
      if (!un) return std::nullopt;
      plain = un->plain;
    }
    auto m = nas::decode_plain(plain);
    if (!m) return std::nullopt;
    return *m;
  }
};

}  // namespace nrlite::testing
