#pragma once

// 5G key hierarchy (TS 33.501 Annex A) on top of the generic KDF of TS 33.220 Annex B.2:
//   derived key = HMAC-SHA-256(Key, S),  S = FC || P0 || L0 || P1 || L1 || ...
//
//   CK||IK --(FC 0x6A)--> K_AUSF --(0x6C)--> K_SEAF --(0x6D)--> K_AMF --(0x69)--> K_NASint/K_NASenc
//                                                                    \--(0x6E)--> K_gNB --(0x69)--> K_RRCint/...
//   RES* / XRES*  (FC 0x6B),  HRES* / HXRES* = SHA-256(RAND || RES*)

#include <cstdint>
#include <string>
#include <vector>

#include "nrlite/security/crypto.hpp"
#include "nrlite/security/milenage.hpp"

namespace nrlite::sec {

/// Generic KDF: HMAC-SHA-256(key, FC || P0 || L0 || ...).
Key256 kdf(const Bytes& key, std::uint8_t fc, const std::vector<Bytes>& params);

/// "5G:mnc<MNC>.mcc<MCC>.3gppnetwork.org" with a three-digit MNC (TS 24.501 §9.12.1).
std::string serving_network_name(const std::string& mcc, const std::string& mnc);

/// Algorithm type distinguishers (TS 33.501 Table A.8-1).
enum class AlgorithmDistinguisher : std::uint8_t {
  NasEnc = 0x01,
  NasInt = 0x02,
  RrcEnc = 0x03,
  RrcInt = 0x04,
  UpEnc = 0x05,
  UpInt = 0x06,
};

Key256 derive_kausf(const Key128& ck, const Key128& ik, const std::string& snn, const Ak48& sqn_xor_ak);
/// RES* / XRES*: the 128 least significant bits of the KDF output (A.4).
Key128 derive_res_star(const Key128& ck, const Key128& ik, const std::string& snn, const Block& rand,
                       const Res64& res);
/// HRES* / HXRES*: the 128 least significant bits of SHA-256(RAND || RES*) (A.5).
Key128 derive_hres_star(const Block& rand, const Key128& res_star);
Key256 derive_kseaf(const Key256& kausf, const std::string& snn);
/// SUPI is the IMSI as a digit string; ABBA defaults to 0x0000 (A.7).
Key256 derive_kamf(const Key256& kseaf, const std::string& supi_digits, const Bytes& abba);
/// Algorithm key: 128 least significant bits of KDF(parent, 0x69, distinguisher, algorithm id) (A.8).
Key128 derive_algorithm_key(const Key256& parent, AlgorithmDistinguisher type, std::uint8_t algorithm_id);
/// K_gNB from K_AMF and the uplink NAS COUNT, access type 3GPP (A.9).
Key256 derive_kgnb(const Key256& kamf, std::uint32_t ul_nas_count);

}  // namespace nrlite::sec
