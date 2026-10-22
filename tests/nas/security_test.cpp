#include "nrlite/nas/security.hpp"

#include <gtest/gtest.h>

#include "nrlite/security/kdf.hpp"

using namespace nrlite;
using namespace nrlite::nas;

namespace {

NasSecurityContext make_ctx(std::uint8_t ea = 0, std::uint8_t ia = 2) {
  NasSecurityContext ctx;
  sec::Key256 kamf{};
  for (std::size_t i = 0; i < kamf.size(); ++i) kamf[i] = static_cast<std::uint8_t>(i);
  ctx.activate(kamf, NasSecurityAlgorithms{ea, ia}, Ngksi{false, 0});
  return ctx;
}

const Bytes kPlain = encode(RegistrationComplete{});

}  // namespace

TEST(NasSecurity, ActivateDerivesDistinctKeysAndResetsCounts) {
  NasSecurityContext ctx = make_ctx(2, 2);
  EXPECT_TRUE(ctx.valid);
  EXPECT_NE(ctx.knas_int, ctx.knas_enc);
  EXPECT_EQ(ctx.knas_int, sec::derive_algorithm_key(ctx.kamf, sec::AlgorithmDistinguisher::NasInt, 2));
  EXPECT_EQ(ctx.ul_count, 0u);
}

TEST(NasSecurity, ProtectThenUnprotect) {
  NasSecurityContext ue = make_ctx();
  NasSecurityContext amf = make_ctx();
  const Bytes pdu = protect(ue, kPlain, SecurityHeaderType::IntegrityProtected, sec::Direction::Uplink);
  EXPECT_EQ(pdu[1], 0x01);
  EXPECT_EQ(pdu[6], 0x00);  // SQN of COUNT 0
  auto un = unprotect(amf, pdu, sec::Direction::Uplink);
  ASSERT_TRUE(un) << un.error().message;
  EXPECT_EQ(un->plain, kPlain);
  EXPECT_EQ(un->count, 0u);
  EXPECT_EQ(amf.ul_count, 1u);
  EXPECT_EQ(ue.ul_count, 1u);
}

TEST(NasSecurity, TamperedPayloadFailsIntegrity) {
  NasSecurityContext ue = make_ctx();
  NasSecurityContext amf = make_ctx();
  Bytes pdu = protect(ue, kPlain, SecurityHeaderType::IntegrityProtected, sec::Direction::Uplink);
  pdu.back() ^= 0x01;
  auto un = unprotect(amf, pdu, sec::Direction::Uplink);
  ASSERT_FALSE(un);
  EXPECT_EQ(un.error().code, static_cast<int>(UnprotectError::IntegrityFailure));
  EXPECT_EQ(amf.ul_count, 0u);  // a failed check does not advance the receive COUNT
}

TEST(NasSecurity, TamperedMacFails) {
  NasSecurityContext ue = make_ctx();
  NasSecurityContext amf = make_ctx();
  Bytes pdu = protect(ue, kPlain, SecurityHeaderType::IntegrityProtected, sec::Direction::Uplink);
  pdu[2] ^= 0x80;
  EXPECT_FALSE(unprotect(amf, pdu, sec::Direction::Uplink));
}

TEST(NasSecurity, DirectionIsBoundIntoMac) {
  NasSecurityContext a = make_ctx();
  NasSecurityContext b = make_ctx();
  const Bytes pdu = protect(a, kPlain, SecurityHeaderType::IntegrityProtected, sec::Direction::Uplink);
  EXPECT_FALSE(unprotect(b, pdu, sec::Direction::Downlink));
}

TEST(NasSecurity, ReplayedMessageIsRejected) {
  NasSecurityContext ue = make_ctx();
  NasSecurityContext amf = make_ctx();
  const Bytes pdu = protect(ue, kPlain, SecurityHeaderType::IntegrityProtected, sec::Direction::Uplink);
  ASSERT_TRUE(unprotect(amf, pdu, sec::Direction::Uplink));
  EXPECT_FALSE(unprotect(amf, pdu, sec::Direction::Uplink));
}

TEST(NasSecurity, DifferentKeyFails) {
  NasSecurityContext ue = make_ctx();
  NasSecurityContext other;
  other.activate(sec::Key256{}, NasSecurityAlgorithms{0, 2}, Ngksi{false, 0});
  const Bytes pdu = protect(ue, kPlain, SecurityHeaderType::IntegrityProtected, sec::Direction::Uplink);
  EXPECT_FALSE(unprotect(other, pdu, sec::Direction::Uplink));
}

TEST(NasSecurity, Ea2CiphersPayloadAndRoundTrips) {
  NasSecurityContext ue = make_ctx(2, 2);
  NasSecurityContext amf = make_ctx(2, 2);
  const Bytes plain = encode(RegistrationReject{Cause::Congestion});
  const Bytes pdu = protect(ue, plain, SecurityHeaderType::IntegrityProtectedAndCiphered, sec::Direction::Uplink);
  EXPECT_NE(Bytes(pdu.begin() + 7, pdu.end()), plain);
  auto un = unprotect(amf, pdu, sec::Direction::Uplink);
  ASSERT_TRUE(un);
  EXPECT_EQ(un->plain, plain);
}

TEST(NasSecurity, Ea0LeavesPayloadReadable) {
  NasSecurityContext ue = make_ctx(0, 2);
  const Bytes pdu = protect(ue, kPlain, SecurityHeaderType::IntegrityProtectedAndCiphered, sec::Direction::Uplink);
  EXPECT_EQ(Bytes(pdu.begin() + 7, pdu.end()), kPlain);
}

TEST(NasSecurity, CountEstimationAcrossSqnWrap) {
  EXPECT_EQ(estimate_count(0x000005, 5), 0x000005u);
  EXPECT_EQ(estimate_count(0x000005, 9), 0x000009u);
  EXPECT_EQ(estimate_count(0x0000FF, 0x00), 0x000100u);  // SQN wrapped: overflow incremented
  EXPECT_EQ(estimate_count(0x000106, 0x05), 0x000205u);  // stale SQN maps to the next overflow
}

TEST(NasSecurity, ManyMessagesAcrossOverflow) {
  NasSecurityContext ue = make_ctx();
  NasSecurityContext amf = make_ctx();
  for (int i = 0; i < 600; ++i) {
    const Bytes pdu = protect(ue, kPlain, SecurityHeaderType::IntegrityProtectedAndCiphered, sec::Direction::Uplink);
    auto un = unprotect(amf, pdu, sec::Direction::Uplink);
    ASSERT_TRUE(un) << "message " << i;
    EXPECT_EQ(un->count, static_cast<std::uint32_t>(i));
  }
}

TEST(NasSecurity, LostMessagesAreTolerated) {
  NasSecurityContext ue = make_ctx();
  NasSecurityContext amf = make_ctx();
  for (int i = 0; i < 3; ++i) (void)protect(ue, kPlain, SecurityHeaderType::IntegrityProtected, sec::Direction::Uplink);
  auto un = unprotect(amf, protect(ue, kPlain, SecurityHeaderType::IntegrityProtected, sec::Direction::Uplink),
                      sec::Direction::Uplink);
  ASSERT_TRUE(un);
  EXPECT_EQ(un->count, 3u);
}

TEST(NasSecurity, NullIntegrityProducesZeroMac) {
  NasSecurityContext ctx = make_ctx(0, 0);
  const Bytes pdu = protect(ctx, kPlain, SecurityHeaderType::IntegrityProtected, sec::Direction::Uplink);
  EXPECT_EQ(to_hex(Bytes(pdu.begin() + 2, pdu.begin() + 6)), "00000000");
}

TEST(NasSecurity, InvalidContextOrMalformedPduRejected) {
  NasSecurityContext empty;
  NasSecurityContext ue = make_ctx();
  const Bytes pdu = protect(ue, kPlain, SecurityHeaderType::IntegrityProtected, sec::Direction::Uplink);
  EXPECT_FALSE(unprotect(empty, pdu, sec::Direction::Uplink));
  auto bad = unprotect(ue, Bytes{0x7e, 0x01}, sec::Direction::Uplink);
  ASSERT_FALSE(bad);
  EXPECT_EQ(bad.error().code, static_cast<int>(UnprotectError::Malformed));
  EXPECT_THROW(protect(ue, kPlain, SecurityHeaderType::Plain, sec::Direction::Uplink), std::invalid_argument);
}

TEST(NasSecurity, UnsupportedAlgorithmReported) {
  NasSecurityContext ctx = make_ctx(1, 1);  // 128-5G-EA1 / IA1 (SNOW 3G) are not implemented
  auto r = unprotect(ctx, Bytes{0x7e, 0x01, 0, 0, 0, 0, 0, 0x7e, 0x00, 0x43}, sec::Direction::Uplink);
  ASSERT_FALSE(r);
  EXPECT_EQ(r.error().code, static_cast<int>(UnprotectError::UnsupportedAlgorithm));
  EXPECT_TRUE(integrity_algorithm_supported(2));
  EXPECT_FALSE(ciphering_algorithm_supported(3));
}
