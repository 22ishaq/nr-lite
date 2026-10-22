#include "nrlite/security/aka.hpp"

#include <cstring>

namespace nrlite::sec {

namespace {

Ak48 xor48(const Sqn& a, const Ak48& b) {
  Ak48 out;
  for (int i = 0; i < 6; ++i) out[i] = static_cast<std::uint8_t>(a[i] ^ b[i]);
  return out;
}

}  // namespace

HeAuthVector generate_he_av(const Subscription& sub, const Block& rand, std::uint64_t sqn, const std::string& snn) {
  const Milenage m(sub.k, sub.opc);
  HeAuthVector av;
  av.rand = rand;
  av.sqn = sqn_from_u64(sqn);
  const auto f1 = m.f1(rand, av.sqn, sub.amf);
  const auto f25 = m.f2345(rand);
  const Ak48 sqn_xor_ak = xor48(av.sqn, f25.ak);

  std::memcpy(av.autn.data(), sqn_xor_ak.data(), 6);
  std::memcpy(av.autn.data() + 6, sub.amf.data(), 2);
  std::memcpy(av.autn.data() + 8, f1.mac_a.data(), 8);

  av.xres_star = derive_res_star(f25.ck, f25.ik, snn, rand, f25.res);
  av.hxres_star = derive_hres_star(rand, av.xres_star);
  av.kausf = derive_kausf(f25.ck, f25.ik, snn, sqn_xor_ak);
  av.kseaf = derive_kseaf(av.kausf, snn);
  return av;
}

std::optional<std::uint64_t> verify_auts(const Subscription& sub, const Block& rand, const Auts14& auts) {
  const Milenage m(sub.k, sub.opc);
  const Ak48 ak_star = m.f5_star(rand);
  Sqn sqn_ms;
  for (int i = 0; i < 6; ++i) sqn_ms[i] = static_cast<std::uint8_t>(auts[i] ^ ak_star[i]);
  const auto f1 = m.f1(rand, sqn_ms, Amf{0x00, 0x00});
  if (!equal_ct(f1.mac_s.data(), auts.data() + 6, 8)) return std::nullopt;
  return sqn_to_u64(sqn_ms);
}

Usim::Usim(Subscription sub, std::uint64_t sqn_ms) : sub_(std::move(sub)), sqn_ms_(sqn_ms) {}

Usim::AuthResult Usim::authenticate(const Block& rand, const Autn16& autn, const std::string& snn) {
  const Milenage m(sub_.k, sub_.opc);
  const auto f25 = m.f2345(rand);

  Sqn sqn;
  for (int i = 0; i < 6; ++i) sqn[i] = static_cast<std::uint8_t>(autn[i] ^ f25.ak[i]);
  const Amf amf{autn[6], autn[7]};
  const auto f1 = m.f1(rand, sqn, amf);

  AuthResult r;
  if (!equal_ct(f1.mac_a.data(), autn.data() + 8, 8)) {
    r.status = AuthStatus::MacFailure;
    return r;
  }
  if ((amf[0] & 0x80) == 0) {  // TS 33.501 §6.1.3.2.0: the AMF separation bit must be 1
    r.status = AuthStatus::Non5gAuthUnacceptable;
    return r;
  }
  const std::uint64_t sqn_he = sqn_to_u64(sqn);
  if (sqn_he <= sqn_ms_ || sqn_he - sqn_ms_ > kDelta) {
    const Ak48 ak_star = m.f5_star(rand);
    const Sqn ms = sqn_from_u64(sqn_ms_);
    const auto f1s = m.f1(rand, ms, Amf{0x00, 0x00});
    for (int i = 0; i < 6; ++i) r.auts[i] = static_cast<std::uint8_t>(ms[i] ^ ak_star[i]);
    std::memcpy(r.auts.data() + 6, f1s.mac_s.data(), 8);
    r.status = AuthStatus::SynchFailure;
    return r;
  }

  sqn_ms_ = sqn_he;
  Ak48 sqn_xor_ak;
  std::memcpy(sqn_xor_ak.data(), autn.data(), 6);
  r.status = AuthStatus::Ok;
  r.res_star = derive_res_star(f25.ck, f25.ik, snn, rand, f25.res);
  r.kausf = derive_kausf(f25.ck, f25.ik, snn, sqn_xor_ak);
  r.kseaf = derive_kseaf(r.kausf, snn);
  return r;
}

}  // namespace nrlite::sec
