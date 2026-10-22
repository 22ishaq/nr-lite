#include "nrlite/nas/security.hpp"

#include "nrlite/security/kdf.hpp"

namespace nrlite::nas {

namespace {

Bytes mac_input(std::uint8_t sqn, const Bytes& payload) {
  Bytes m;
  m.reserve(1 + payload.size());
  m.push_back(sqn);
  m.insert(m.end(), payload.begin(), payload.end());
  return m;
}

sec::Mac32 compute_mac(const NasSecurityContext& ctx, std::uint32_t count, sec::Direction dir, std::uint8_t sqn,
                       const Bytes& payload) {
  if (ctx.algorithms.integrity == 0) return sec::Mac32{0, 0, 0, 0};  // 5G-IA0
  return sec::nia2(ctx.knas_int, count, kNasBearer3gpp, dir, mac_input(sqn, payload));
}

bool ciphered(SecurityHeaderType sht) {
  return sht == SecurityHeaderType::IntegrityProtectedAndCiphered ||
         sht == SecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext;
}

Bytes cipher(const NasSecurityContext& ctx, std::uint32_t count, sec::Direction dir, const Bytes& data) {
  if (ctx.algorithms.ciphering == 0 || data.empty()) return data;  // 5G-EA0
  return sec::nea2(ctx.knas_enc, count, kNasBearer3gpp, dir, data);
}

}  // namespace

bool integrity_algorithm_supported(std::uint8_t ia) { return ia == 0 || ia == 2; }
bool ciphering_algorithm_supported(std::uint8_t ea) { return ea == 0 || ea == 2; }

void NasSecurityContext::activate(const sec::Key256& k_amf, const NasSecurityAlgorithms& algs, const Ngksi& ksi) {
  valid = true;
  ngksi = ksi;
  kamf = k_amf;
  algorithms = algs;
  knas_int = sec::derive_algorithm_key(k_amf, sec::AlgorithmDistinguisher::NasInt, algs.integrity);
  knas_enc = sec::derive_algorithm_key(k_amf, sec::AlgorithmDistinguisher::NasEnc, algs.ciphering);
  ul_count = 0;
  dl_count = 0;
}

std::uint32_t estimate_count(std::uint32_t expected_next, std::uint8_t sqn) {
  std::uint32_t overflow = (expected_next >> 8) & 0xFFFF;
  if (sqn < (expected_next & 0xFF)) overflow = (overflow + 1) & 0xFFFF;
  return (overflow << 8) | sqn;
}

Bytes protect(NasSecurityContext& ctx, const Bytes& plain, SecurityHeaderType sht, sec::Direction dir) {
  if (sht == SecurityHeaderType::Plain) throw std::invalid_argument("protect: plain security header type");
  std::uint32_t& counter = dir == sec::Direction::Uplink ? ctx.ul_count : ctx.dl_count;
  const std::uint32_t count = counter;
  counter = (counter + 1) & 0x00FFFFFF;

  SecuredPdu s;
  s.security_header_type = sht;
  s.sqn = static_cast<std::uint8_t>(count & 0xFF);
  s.payload = ciphered(sht) ? cipher(ctx, count, dir, plain) : plain;
  s.mac = compute_mac(ctx, count, dir, s.sqn, s.payload);
  return build_secured(s);
}

Result<Unprotected> unprotect(NasSecurityContext& ctx, const Bytes& pdu, sec::Direction dir) {
  auto parsed = parse_secured(pdu);
  if (!parsed) return Error{parsed.error().message, static_cast<int>(UnprotectError::Malformed)};
  if (!ctx.valid) return Error{"no NAS security context", static_cast<int>(UnprotectError::IntegrityFailure)};
  if (!integrity_algorithm_supported(ctx.algorithms.integrity) ||
      !ciphering_algorithm_supported(ctx.algorithms.ciphering)) {
    return Error{"unsupported NAS security algorithm", static_cast<int>(UnprotectError::UnsupportedAlgorithm)};
  }
  std::uint32_t& expected = dir == sec::Direction::Uplink ? ctx.ul_count : ctx.dl_count;
  const std::uint32_t count = estimate_count(expected, parsed->sqn);
  const sec::Mac32 mac = compute_mac(ctx, count, dir, parsed->sqn, parsed->payload);
  if (!sec::equal_ct(mac.data(), parsed->mac.data(), 4)) {
    return Error{"NAS MAC verification failed (COUNT " + std::to_string(count) + ")",
                 static_cast<int>(UnprotectError::IntegrityFailure)};
  }
  expected = (count + 1) & 0x00FFFFFF;
  Unprotected out;
  out.security_header_type = parsed->security_header_type;
  out.count = count;
  out.plain = ciphered(parsed->security_header_type) ? cipher(ctx, count, dir, parsed->payload) : parsed->payload;
  return out;
}

}  // namespace nrlite::nas
