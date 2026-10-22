#include "nrlite/security/milenage.hpp"

#include <cstring>

namespace nrlite::sec {

namespace {

Block xor_block(const Block& a, const Block& b) {
  Block out;
  for (int i = 0; i < 16; ++i) out[i] = static_cast<std::uint8_t>(a[i] ^ b[i]);
  return out;
}

/// Cyclic left rotation of a 128-bit value by `bits` (multiple of 8 for MILENAGE defaults).
Block rotate_left(const Block& in, unsigned bits) {
  const unsigned bytes = (bits / 8) % 16;
  Block out;
  for (unsigned i = 0; i < 16; ++i) out[i] = in[(i + bytes) % 16];
  return out;
}

}  // namespace

Milenage::Milenage(const Key128& k, const Key128& opc) : aes_(k), opc_(opc) {}

Key128 Milenage::compute_opc(const Key128& k, const Key128& op) {
  const Aes128 aes(k);
  return xor_block(aes.encrypt(op), op);
}

Block Milenage::temp(const Block& rand) const { return aes_.encrypt(xor_block(rand, opc_)); }

Block Milenage::out_n(const Block& t, unsigned rotate_bits, std::uint8_t constant) const {
  Block in = rotate_left(xor_block(t, opc_), rotate_bits);
  in[15] ^= constant;  // c2..c5 = 1, 2, 4, 8 in the least significant bits
  return xor_block(aes_.encrypt(in), opc_);
}

Milenage::F1Out Milenage::f1(const Block& rand, const Sqn& sqn, const Amf& amf) const {
  const Block t = temp(rand);
  Block in1;
  std::memcpy(in1.data(), sqn.data(), 6);
  std::memcpy(in1.data() + 6, amf.data(), 2);
  std::memcpy(in1.data() + 8, sqn.data(), 6);
  std::memcpy(in1.data() + 14, amf.data(), 2);

  // OUT1 = E_K(TEMP xor rot(IN1 xor OPc, r1) xor c1) xor OPc, r1 = 64, c1 = 0
  const Block rotated = rotate_left(xor_block(in1, opc_), 64);
  const Block out1 = xor_block(aes_.encrypt(xor_block(t, rotated)), opc_);
  F1Out o;
  std::memcpy(o.mac_a.data(), out1.data(), 8);
  std::memcpy(o.mac_s.data(), out1.data() + 8, 8);
  return o;
}

Milenage::F2345Out Milenage::f2345(const Block& rand) const {
  const Block t = temp(rand);
  const Block out2 = out_n(t, 0, 1);
  const Block out3 = out_n(t, 32, 2);
  const Block out4 = out_n(t, 64, 4);
  F2345Out o;
  std::memcpy(o.ak.data(), out2.data(), 6);
  std::memcpy(o.res.data(), out2.data() + 8, 8);
  std::memcpy(o.ck.data(), out3.data(), 16);
  std::memcpy(o.ik.data(), out4.data(), 16);
  return o;
}

Ak48 Milenage::f5_star(const Block& rand) const {
  const Block out5 = out_n(temp(rand), 96, 8);
  Ak48 ak;
  std::memcpy(ak.data(), out5.data(), 6);
  return ak;
}

std::uint64_t sqn_to_u64(const Sqn& sqn) {
  std::uint64_t v = 0;
  for (std::uint8_t b : sqn) v = (v << 8) | b;
  return v;
}

Sqn sqn_from_u64(std::uint64_t v) {
  Sqn s;
  for (int i = 5; i >= 0; --i) {
    s[static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(v);
    v >>= 8;
  }
  return s;
}

}  // namespace nrlite::sec
