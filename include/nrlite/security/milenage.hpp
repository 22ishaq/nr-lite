#pragma once

// MILENAGE authentication and key generation functions f1, f1*, f2, f3, f4, f5, f5*
// (TS 35.205 / TS 35.206), with the default rotation and constant values.

#include <array>
#include <cstdint>

#include "nrlite/security/crypto.hpp"

namespace nrlite::sec {

using Sqn = std::array<std::uint8_t, 6>;
using Amf = std::array<std::uint8_t, 2>;
using Mac64 = std::array<std::uint8_t, 8>;
using Res64 = std::array<std::uint8_t, 8>;
using Ak48 = std::array<std::uint8_t, 6>;

class Milenage {
 public:
  /// Constructs from K and OPc (the operator variant already combined with K).
  Milenage(const Key128& k, const Key128& opc);
  static Key128 compute_opc(const Key128& k, const Key128& op);

  struct F1Out {
    Mac64 mac_a;  ///< f1
    Mac64 mac_s;  ///< f1*
  };
  F1Out f1(const Block& rand, const Sqn& sqn, const Amf& amf) const;

  struct F2345Out {
    Res64 res;   ///< f2
    Key128 ck;   ///< f3
    Key128 ik;   ///< f4
    Ak48 ak;     ///< f5
  };
  F2345Out f2345(const Block& rand) const;

  /// f5* (anonymity key used for re-synchronisation).
  Ak48 f5_star(const Block& rand) const;

 private:
  Block temp(const Block& rand) const;
  Block out_n(const Block& temp, unsigned rotate_bits, std::uint8_t constant) const;

  Aes128 aes_;
  Key128 opc_;
};

std::uint64_t sqn_to_u64(const Sqn& sqn);
Sqn sqn_from_u64(std::uint64_t v);

}  // namespace nrlite::sec
