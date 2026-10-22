#pragma once

// 5G-AKA (TS 33.501 §6.1.3.2) built on MILENAGE:
//   home network: RAND, AUTN = (SQN xor AK) || AMF || MAC-A, XRES*, K_AUSF, HXRES*, K_SEAF
//   USIM:         verify MAC-A, AMF separation bit and SQN freshness, then RES*, K_AUSF, K_SEAF;
//                 on a stale SQN return AUTS = (SQN_MS xor AK*) || MAC-S for re-synchronisation.

#include <array>
#include <cstdint>
#include <optional>
#include <string>

#include "nrlite/security/kdf.hpp"
#include "nrlite/security/milenage.hpp"

namespace nrlite::sec {

using Autn16 = std::array<std::uint8_t, 16>;
using Auts14 = std::array<std::uint8_t, 14>;

/// Subscription data held by the home network (UDM/ARPF) and the USIM.
struct Subscription {
  std::string supi;  ///< IMSI digits, e.g. "001010000000001"
  Key128 k{};
  Key128 opc{};
  Amf amf{0x80, 0x00};  ///< AMF field with the separation bit (bit 0) set, as 5G requires
};

/// 5G home-environment authentication vector plus the keys the SEAF/AMF derive from it.
struct HeAuthVector {
  Block rand{};
  Autn16 autn{};
  Key128 xres_star{};
  Key128 hxres_star{};
  Key256 kausf{};
  Key256 kseaf{};
  Sqn sqn{};
};

HeAuthVector generate_he_av(const Subscription& sub, const Block& rand, std::uint64_t sqn, const std::string& snn);

/// Recovers SQN_MS from AUTS if MAC-S verifies (resync AMF is 0x0000, TS 33.102 §6.3.5).
std::optional<std::uint64_t> verify_auts(const Subscription& sub, const Block& rand, const Auts14& auts);

class Usim {
 public:
  enum class AuthStatus {
    Ok,
    MacFailure,              ///< reported with 5GMM cause #20
    SynchFailure,            ///< reported with 5GMM cause #21 and AUTS
    Non5gAuthUnacceptable,   ///< AMF separation bit not set: cause #26
  };

  struct AuthResult {
    AuthStatus status = AuthStatus::MacFailure;
    Key128 res_star{};
    Key256 kausf{};
    Key256 kseaf{};
    Auts14 auts{};
  };

  Usim(Subscription sub, std::uint64_t sqn_ms = 0);

  AuthResult authenticate(const Block& rand, const Autn16& autn, const std::string& snn);

  const Subscription& subscription() const { return sub_; }
  std::uint64_t sqn_ms() const { return sqn_ms_; }
  void set_sqn_ms(std::uint64_t v) { sqn_ms_ = v; }
  /// Maximum accepted SQN jump ("delta" in TS 33.102 Annex C.2.1).
  static constexpr std::uint64_t kDelta = std::uint64_t{1} << 28;

 private:
  Subscription sub_;
  std::uint64_t sqn_ms_;
};

}  // namespace nrlite::sec
