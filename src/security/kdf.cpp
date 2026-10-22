#include "nrlite/security/kdf.hpp"

#include <cstring>
#include <stdexcept>

namespace nrlite::sec {

namespace {

Bytes str_bytes(const std::string& s) { return Bytes(s.begin(), s.end()); }

Key128 low128(const Key256& k) {
  Key128 out;
  std::memcpy(out.data(), k.data() + 16, 16);
  return out;
}

}  // namespace

Key256 kdf(const Bytes& key, std::uint8_t fc, const std::vector<Bytes>& params) {
  Bytes s;
  s.push_back(fc);
  for (const Bytes& p : params) {
    if (p.size() > 0xFFFF) throw std::invalid_argument("kdf: parameter longer than 65535 octets");
    s.insert(s.end(), p.begin(), p.end());
    put_u16(s, static_cast<std::uint16_t>(p.size()));
  }
  return hmac_sha256(key, s);
}

std::string serving_network_name(const std::string& mcc, const std::string& mnc) {
  if (mcc.size() != 3 || (mnc.size() != 2 && mnc.size() != 3)) {
    throw std::invalid_argument("serving_network_name: MCC must be 3 digits and MNC 2 or 3 digits");
  }
  const std::string mnc3 = mnc.size() == 2 ? "0" + mnc : mnc;
  return "5G:mnc" + mnc3 + ".mcc" + mcc + ".3gppnetwork.org";
}

Key256 derive_kausf(const Key128& ck, const Key128& ik, const std::string& snn, const Ak48& sqn_xor_ak) {
  Bytes key(ck.begin(), ck.end());
  key.insert(key.end(), ik.begin(), ik.end());
  return kdf(key, 0x6A, {str_bytes(snn), Bytes(sqn_xor_ak.begin(), sqn_xor_ak.end())});
}

Key128 derive_res_star(const Key128& ck, const Key128& ik, const std::string& snn, const Block& rand,
                       const Res64& res) {
  Bytes key(ck.begin(), ck.end());
  key.insert(key.end(), ik.begin(), ik.end());
  return low128(kdf(key, 0x6B, {str_bytes(snn), Bytes(rand.begin(), rand.end()), Bytes(res.begin(), res.end())}));
}

Key128 derive_hres_star(const Block& rand, const Key128& res_star) {
  Bytes s(rand.begin(), rand.end());
  s.insert(s.end(), res_star.begin(), res_star.end());
  return low128(sha256(s));
}

Key256 derive_kseaf(const Key256& kausf, const std::string& snn) {
  return kdf(Bytes(kausf.begin(), kausf.end()), 0x6C, {str_bytes(snn)});
}

Key256 derive_kamf(const Key256& kseaf, const std::string& supi_digits, const Bytes& abba) {
  return kdf(Bytes(kseaf.begin(), kseaf.end()), 0x6D, {str_bytes(supi_digits), abba});
}

Key128 derive_algorithm_key(const Key256& parent, AlgorithmDistinguisher type, std::uint8_t algorithm_id) {
  return low128(kdf(Bytes(parent.begin(), parent.end()), 0x69,
                    {Bytes{static_cast<std::uint8_t>(type)}, Bytes{algorithm_id}}));
}

Key256 derive_kgnb(const Key256& kamf, std::uint32_t ul_nas_count) {
  Bytes count;
  put_u32(count, ul_nas_count);
  return kdf(Bytes(kamf.begin(), kamf.end()), 0x6E, {count, Bytes{0x01}});
}

}  // namespace nrlite::sec
