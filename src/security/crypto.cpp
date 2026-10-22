#include "nrlite/security/crypto.hpp"

#include <cstring>
#include <stdexcept>

namespace nrlite::sec {

// ------------------------------------------------------------------------------------------
// AES-128 (FIPS-197), encryption direction only.

namespace {

constexpr std::uint8_t kSbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9,
    0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f,
    0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07,
    0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3,
    0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58,
    0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3,
    0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f,
    0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac,
    0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a,
    0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
    0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42,
    0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

constexpr std::uint8_t kRcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

inline std::uint8_t xtime(std::uint8_t x) {
  return static_cast<std::uint8_t>((x << 1) ^ ((x & 0x80) != 0 ? 0x1b : 0x00));
}

}  // namespace

Aes128::Aes128(const Key128& key) {
  std::memcpy(round_keys_.data(), key.data(), 16);
  for (int i = 4; i < 44; ++i) {
    std::uint8_t t[4];
    std::memcpy(t, &round_keys_[(i - 1) * 4], 4);
    if (i % 4 == 0) {
      const std::uint8_t first = t[0];
      t[0] = static_cast<std::uint8_t>(kSbox[t[1]] ^ kRcon[i / 4 - 1]);
      t[1] = kSbox[t[2]];
      t[2] = kSbox[t[3]];
      t[3] = kSbox[first];
    }
    for (int j = 0; j < 4; ++j) {
      round_keys_[i * 4 + j] = static_cast<std::uint8_t>(round_keys_[(i - 4) * 4 + j] ^ t[j]);
    }
  }
}

Block Aes128::encrypt(const Block& in) const {
  std::uint8_t s[16];
  for (int i = 0; i < 16; ++i) s[i] = static_cast<std::uint8_t>(in[i] ^ round_keys_[i]);
  for (int round = 1; round <= 10; ++round) {
    // SubBytes + ShiftRows (state is column-major: s[col*4 + row]).
    std::uint8_t t[16];
    for (int c = 0; c < 4; ++c) {
      for (int r = 0; r < 4; ++r) t[c * 4 + r] = kSbox[s[((c + r) % 4) * 4 + r]];
    }
    if (round != 10) {  // MixColumns
      for (int c = 0; c < 4; ++c) {
        std::uint8_t* col = &t[c * 4];
        const std::uint8_t a0 = col[0], a1 = col[1], a2 = col[2], a3 = col[3];
        const std::uint8_t all = static_cast<std::uint8_t>(a0 ^ a1 ^ a2 ^ a3);
        col[0] = static_cast<std::uint8_t>(a0 ^ all ^ xtime(static_cast<std::uint8_t>(a0 ^ a1)));
        col[1] = static_cast<std::uint8_t>(a1 ^ all ^ xtime(static_cast<std::uint8_t>(a1 ^ a2)));
        col[2] = static_cast<std::uint8_t>(a2 ^ all ^ xtime(static_cast<std::uint8_t>(a2 ^ a3)));
        col[3] = static_cast<std::uint8_t>(a3 ^ all ^ xtime(static_cast<std::uint8_t>(a3 ^ a0)));
      }
    }
    for (int i = 0; i < 16; ++i) s[i] = static_cast<std::uint8_t>(t[i] ^ round_keys_[round * 16 + i]);
  }
  Block out;
  std::memcpy(out.data(), s, 16);
  return out;
}

// ------------------------------------------------------------------------------------------
// SHA-256 (FIPS 180-4)

namespace {

constexpr std::uint32_t kK[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline std::uint32_t rotr(std::uint32_t x, unsigned n) { return (x >> n) | (x << (32 - n)); }

void sha256_block(std::uint32_t h[8], const std::uint8_t* p) {
  std::uint32_t w[64];
  for (int i = 0; i < 16; ++i) {
    w[i] = (std::uint32_t{p[4 * i]} << 24) | (std::uint32_t{p[4 * i + 1]} << 16) |
           (std::uint32_t{p[4 * i + 2]} << 8) | std::uint32_t{p[4 * i + 3]};
  }
  for (int i = 16; i < 64; ++i) {
    const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
    const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
  for (int i = 0; i < 64; ++i) {
    const std::uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
    const std::uint32_t ch = (e & f) ^ (~e & g);
    const std::uint32_t t1 = hh + S1 + ch + kK[i] + w[i];
    const std::uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
    const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    const std::uint32_t t2 = S0 + maj;
    hh = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  h[0] += a;
  h[1] += b;
  h[2] += c;
  h[3] += d;
  h[4] += e;
  h[5] += f;
  h[6] += g;
  h[7] += hh;
}

}  // namespace

Digest256 sha256(const std::uint8_t* data, std::size_t len) {
  std::uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  std::size_t full = len / 64;
  for (std::size_t i = 0; i < full; ++i) sha256_block(h, data + 64 * i);

  std::uint8_t tail[128] = {};
  const std::size_t rem = len % 64;
  if (rem != 0) std::memcpy(tail, data + 64 * full, rem);
  tail[rem] = 0x80;
  const std::size_t tail_len = (rem < 56) ? 64 : 128;
  const std::uint64_t bit_len = static_cast<std::uint64_t>(len) * 8;
  for (int i = 0; i < 8; ++i) tail[tail_len - 1 - i] = static_cast<std::uint8_t>(bit_len >> (8 * i));
  sha256_block(h, tail);
  if (tail_len == 128) sha256_block(h, tail + 64);

  Digest256 out;
  for (int i = 0; i < 8; ++i) {
    out[4 * i] = static_cast<std::uint8_t>(h[i] >> 24);
    out[4 * i + 1] = static_cast<std::uint8_t>(h[i] >> 16);
    out[4 * i + 2] = static_cast<std::uint8_t>(h[i] >> 8);
    out[4 * i + 3] = static_cast<std::uint8_t>(h[i]);
  }
  return out;
}

Digest256 hmac_sha256(const std::uint8_t* key, std::size_t key_len, const std::uint8_t* data, std::size_t len) {
  std::uint8_t k0[64] = {};
  if (key_len > 64) {
    const Digest256 kh = sha256(key, key_len);
    std::memcpy(k0, kh.data(), kh.size());
  } else if (key_len != 0) {
    std::memcpy(k0, key, key_len);
  }
  Bytes inner(64 + len);
  for (int i = 0; i < 64; ++i) inner[i] = static_cast<std::uint8_t>(k0[i] ^ 0x36);
  if (len != 0) std::memcpy(inner.data() + 64, data, len);
  const Digest256 ih = sha256(inner);

  Bytes outer(64 + 32);
  for (int i = 0; i < 64; ++i) outer[i] = static_cast<std::uint8_t>(k0[i] ^ 0x5c);
  std::memcpy(outer.data() + 64, ih.data(), 32);
  return sha256(outer);
}

// ------------------------------------------------------------------------------------------
// AES-CMAC (NIST SP 800-38B) over a bit string

namespace {

Block left_shift_xor(const Block& in) {
  Block out{};
  for (int i = 0; i < 16; ++i) {
    out[i] = static_cast<std::uint8_t>(in[i] << 1);
    if (i < 15 && (in[i + 1] & 0x80) != 0) out[i] |= 1;
  }
  if ((in[0] & 0x80) != 0) out[15] ^= 0x87;
  return out;
}

}  // namespace

Block aes_cmac(const Key128& key, const Bytes& message, std::size_t bit_len) {
  if (bit_len > message.size() * 8) throw std::invalid_argument("aes_cmac: bit length exceeds message");
  const Aes128 aes(key);
  const Block l = aes.encrypt(Block{});
  const Block k1 = left_shift_xor(l);
  const Block k2 = left_shift_xor(k1);

  const std::size_t n_blocks = bit_len == 0 ? 1 : (bit_len + 127) / 128;
  const bool last_complete = bit_len != 0 && bit_len % 128 == 0;

  Block x{};
  for (std::size_t b = 0; b + 1 < n_blocks; ++b) {
    Block y;
    for (int i = 0; i < 16; ++i) y[i] = static_cast<std::uint8_t>(x[i] ^ message[b * 16 + i]);
    x = aes.encrypt(y);
  }

  // Last block: either complete (xor K1) or padded with 1 0* (xor K2).
  Block last{};
  const std::size_t start_bit = (n_blocks - 1) * 128;
  const std::size_t last_bits = bit_len - start_bit;
  for (std::size_t i = 0; i < last_bits; ++i) {
    const std::size_t bit = start_bit + i;
    if (((message[bit / 8] >> (7 - bit % 8)) & 1u) != 0) last[i / 8] |= static_cast<std::uint8_t>(0x80u >> (i % 8));
  }
  if (!last_complete) last[last_bits / 8] |= static_cast<std::uint8_t>(0x80u >> (last_bits % 8));
  const Block& sub = last_complete ? k1 : k2;
  Block y;
  for (int i = 0; i < 16; ++i) y[i] = static_cast<std::uint8_t>(x[i] ^ last[i] ^ sub[i]);
  return aes.encrypt(y);
}

// ------------------------------------------------------------------------------------------
// 128-NIA2 / 128-NEA2

Mac32 nia2(const Key128& key, std::uint32_t count, std::uint8_t bearer, Direction dir, const Bytes& message,
           std::size_t bit_len) {
  if (bearer > 31) throw std::invalid_argument("nia2: BEARER is 5 bits");
  if (bit_len > message.size() * 8) throw std::invalid_argument("nia2: bit length exceeds message");
  Bytes m;
  m.reserve(8 + message.size());
  put_u32(m, count);
  m.push_back(static_cast<std::uint8_t>((bearer << 3) | (static_cast<std::uint8_t>(dir) << 2)));
  m.insert(m.end(), {0, 0, 0});
  m.insert(m.end(), message.begin(), message.end());
  const Block t = aes_cmac(key, m, 64 + bit_len);
  return Mac32{t[0], t[1], t[2], t[3]};
}

Bytes nea2(const Key128& key, std::uint32_t count, std::uint8_t bearer, Direction dir, const Bytes& data,
           std::size_t bit_len) {
  if (bearer > 31) throw std::invalid_argument("nea2: BEARER is 5 bits");
  if (bit_len > data.size() * 8) throw std::invalid_argument("nea2: bit length exceeds data");
  const Aes128 aes(key);
  Block ctr{};
  ctr[0] = static_cast<std::uint8_t>(count >> 24);
  ctr[1] = static_cast<std::uint8_t>(count >> 16);
  ctr[2] = static_cast<std::uint8_t>(count >> 8);
  ctr[3] = static_cast<std::uint8_t>(count);
  ctr[4] = static_cast<std::uint8_t>((bearer << 3) | (static_cast<std::uint8_t>(dir) << 2));

  const std::size_t n_bytes = (bit_len + 7) / 8;
  Bytes out(data.begin(), data.begin() + static_cast<std::ptrdiff_t>(n_bytes));
  for (std::size_t off = 0; off < n_bytes; off += 16) {
    const Block ks = aes.encrypt(ctr);
    for (std::size_t i = 0; i < 16 && off + i < n_bytes; ++i) out[off + i] ^= ks[i];
    for (int i = 15; i >= 0; --i) {  // 128-bit big-endian counter increment
      if (++ctr[i] != 0) break;
    }
  }
  if (bit_len % 8 != 0) out.back() &= static_cast<std::uint8_t>(0xFF00u >> (bit_len % 8));
  return out;
}

bool equal_ct(const std::uint8_t* a, const std::uint8_t* b, std::size_t len) {
  std::uint8_t diff = 0;
  for (std::size_t i = 0; i < len; ++i) diff = static_cast<std::uint8_t>(diff | (a[i] ^ b[i]));
  return diff == 0;
}

}  // namespace nrlite::sec
