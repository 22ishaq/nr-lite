#pragma once

// Cryptographic primitives needed by 5G security (TS 33.501), implemented from the public
// specifications so the stack has no third-party dependencies:
//   * AES-128 block encryption (FIPS-197)
//   * SHA-256 (FIPS 180-4) and HMAC-SHA-256 (RFC 2104)
//   * AES-CMAC over bit strings (NIST SP 800-38B, RFC 4493)
//   * 128-NIA2 integrity and 128-NEA2 ciphering (TS 33.501 Annex D, identical to 128-EIA2/EEA2)
//
// These are written for clarity and protocol testing, not for side-channel resistance.

#include <array>
#include <cstddef>
#include <cstdint>

#include "nrlite/common/bytes.hpp"

namespace nrlite::sec {

using Key128 = std::array<std::uint8_t, 16>;
using Key256 = std::array<std::uint8_t, 32>;
using Block = std::array<std::uint8_t, 16>;
using Digest256 = std::array<std::uint8_t, 32>;
using Mac32 = std::array<std::uint8_t, 4>;

class Aes128 {
 public:
  explicit Aes128(const Key128& key);
  Block encrypt(const Block& in) const;

 private:
  std::array<std::uint8_t, 176> round_keys_{};
};

Digest256 sha256(const std::uint8_t* data, std::size_t len);
inline Digest256 sha256(const Bytes& b) { return sha256(b.data(), b.size()); }

Digest256 hmac_sha256(const std::uint8_t* key, std::size_t key_len, const std::uint8_t* data, std::size_t len);
inline Digest256 hmac_sha256(const Bytes& key, const Bytes& data) {
  return hmac_sha256(key.data(), key.size(), data.data(), data.size());
}

/// AES-CMAC of the first `bit_len` bits of `message` (bit-oriented input as required by NIA2).
Block aes_cmac(const Key128& key, const Bytes& message, std::size_t bit_len);
inline Block aes_cmac(const Key128& key, const Bytes& message) { return aes_cmac(key, message, message.size() * 8); }

enum class Direction : std::uint8_t { Uplink = 0, Downlink = 1 };

/// 128-NIA2: MAC = first 32 bits of CMAC(KEY, COUNT || BEARER || DIRECTION || 0^26 || MESSAGE).
Mac32 nia2(const Key128& key, std::uint32_t count, std::uint8_t bearer, Direction dir, const Bytes& message,
           std::size_t bit_len);
inline Mac32 nia2(const Key128& key, std::uint32_t count, std::uint8_t bearer, Direction dir, const Bytes& message) {
  return nia2(key, count, bearer, dir, message, message.size() * 8);
}

/// 128-NEA2: AES-CTR keystream with IV = COUNT || BEARER || DIRECTION || 0^26 || 0^64.
/// Encryption and decryption are the same operation. Bits beyond `bit_len` are zeroed.
Bytes nea2(const Key128& key, std::uint32_t count, std::uint8_t bearer, Direction dir, const Bytes& data,
           std::size_t bit_len);
inline Bytes nea2(const Key128& key, std::uint32_t count, std::uint8_t bearer, Direction dir, const Bytes& data) {
  return nea2(key, count, bearer, dir, data, data.size() * 8);
}

/// Constant-time comparison for MACs.
bool equal_ct(const std::uint8_t* a, const std::uint8_t* b, std::size_t len);

}  // namespace nrlite::sec
