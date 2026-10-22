#pragma once

// 5G NAS security context and message protection (TS 24.501 §4.4, TS 33.501 §6.4).
//
//   NAS COUNT = 0x00 | NAS overflow (16 bits) | NAS sequence number (8 bits)
//   MAC       = NIA(K_NASint, COUNT, BEARER = 0 (3GPP access), DIRECTION, SQN || payload)
//   payload   = plain NAS message, ciphered with NEA(K_NASenc, ...) for header types 2 and 4
//
// The receiver estimates the full COUNT from the 8-bit SQN and the next expected COUNT; a
// replayed or stale SQN therefore maps onto a different COUNT and fails the MAC check.

#include <cstdint>
#include <string>

#include "nrlite/common/bytes.hpp"
#include "nrlite/common/result.hpp"
#include "nrlite/nas/ies.hpp"
#include "nrlite/nas/messages.hpp"
#include "nrlite/security/crypto.hpp"

namespace nrlite::nas {

constexpr std::uint8_t kNasBearer3gpp = 0;

/// Integrity algorithms NR-Lite implements (5G-IA0 is only accepted when explicitly allowed).
bool integrity_algorithm_supported(std::uint8_t ia);
/// Ciphering algorithms NR-Lite implements (5G-EA0 and 128-5G-EA2).
bool ciphering_algorithm_supported(std::uint8_t ea);

struct NasSecurityContext {
  bool valid = false;
  Ngksi ngksi;
  sec::Key256 kamf{};
  NasSecurityAlgorithms algorithms;
  sec::Key128 knas_int{};
  sec::Key128 knas_enc{};
  std::uint32_t ul_count = 0;  ///< next UL NAS COUNT (sender: UE, receiver: AMF)
  std::uint32_t dl_count = 0;  ///< next DL NAS COUNT (sender: AMF, receiver: UE)

  /// Derives K_NASint / K_NASenc from K_AMF for the selected algorithms and resets the counts.
  void activate(const sec::Key256& k_amf, const NasSecurityAlgorithms& algs, const Ngksi& ksi);
  void clear() { *this = NasSecurityContext{}; }
};

/// Builds a security protected NAS PDU using (and then incrementing) the context's COUNT for
/// direction `dir`. `sht` must be one of the protected header types.
Bytes protect(NasSecurityContext& ctx, const Bytes& plain, SecurityHeaderType sht, sec::Direction dir);

struct Unprotected {
  Bytes plain;
  SecurityHeaderType security_header_type = SecurityHeaderType::Plain;
  std::uint32_t count = 0;
};

enum class UnprotectError { Malformed = 1, IntegrityFailure = 2, UnsupportedAlgorithm = 3 };

/// Verifies and deciphers a protected PDU received in direction `dir`. On success the receive
/// COUNT is advanced past the estimated value. Error::code holds an UnprotectError.
Result<Unprotected> unprotect(NasSecurityContext& ctx, const Bytes& pdu, sec::Direction dir);

/// The 32-bit COUNT a receiver estimates for `sqn` given the next expected COUNT.
std::uint32_t estimate_count(std::uint32_t expected_next, std::uint8_t sqn);

}  // namespace nrlite::nas
