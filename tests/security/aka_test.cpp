#include "nrlite/security/aka.hpp"

#include <gtest/gtest.h>

#include "support/fixtures.hpp"

using namespace nrlite;
using namespace nrlite::sec;
using nrlite::testing::test_snn;
using nrlite::testing::test_subscription;

namespace {

Block rand_of(std::uint8_t v) {
  Block b{};
  b.fill(v);
  return b;
}

}  // namespace

TEST(Aka, UsimAcceptsFreshVectorAndAgreesOnKeys) {
  const Subscription sub = test_subscription();
  const HeAuthVector av = generate_he_av(sub, rand_of(1), 1, test_snn());
  Usim usim(sub, 0);
  const auto r = usim.authenticate(av.rand, av.autn, test_snn());
  ASSERT_EQ(r.status, Usim::AuthStatus::Ok);
  EXPECT_EQ(r.res_star, av.xres_star);
  EXPECT_EQ(r.kausf, av.kausf);
  EXPECT_EQ(r.kseaf, av.kseaf);
  EXPECT_EQ(derive_hres_star(av.rand, r.res_star), av.hxres_star);
  EXPECT_EQ(usim.sqn_ms(), 1u);
}

TEST(Aka, AutnCarriesConcealedSqnAndAmf) {
  const Subscription sub = test_subscription();
  const HeAuthVector av = generate_he_av(sub, rand_of(7), 0x123456, test_snn());
  EXPECT_EQ(av.autn[6], 0x80);  // AMF separation bit
  EXPECT_EQ(av.autn[7], 0x00);
  const Milenage m(sub.k, sub.opc);
  const auto ak = m.f2345(av.rand).ak;
  std::uint64_t sqn = 0;
  for (int i = 0; i < 6; ++i) sqn = (sqn << 8) | static_cast<std::uint8_t>(av.autn[static_cast<std::size_t>(i)] ^ ak[static_cast<std::size_t>(i)]);
  EXPECT_EQ(sqn, 0x123456u);
}

TEST(Aka, TamperedMacIsMacFailure) {
  const Subscription sub = test_subscription();
  HeAuthVector av = generate_he_av(sub, rand_of(2), 5, test_snn());
  av.autn[15] ^= 1;
  Usim usim(sub, 0);
  EXPECT_EQ(usim.authenticate(av.rand, av.autn, test_snn()).status, Usim::AuthStatus::MacFailure);
  EXPECT_EQ(usim.sqn_ms(), 0u);
}

TEST(Aka, WrongKeyIsMacFailure) {
  Subscription other = test_subscription();
  other.k[0] ^= 0xFF;
  const HeAuthVector av = generate_he_av(other, rand_of(3), 1, test_snn());
  Usim usim(test_subscription(), 0);
  EXPECT_EQ(usim.authenticate(av.rand, av.autn, test_snn()).status, Usim::AuthStatus::MacFailure);
}

TEST(Aka, MissingSeparationBitIsNon5g) {
  Subscription sub = test_subscription();
  sub.amf = Amf{0x00, 0x00};
  const HeAuthVector av = generate_he_av(sub, rand_of(4), 1, test_snn());
  Usim usim(test_subscription(), 0);
  EXPECT_EQ(usim.authenticate(av.rand, av.autn, test_snn()).status, Usim::AuthStatus::Non5gAuthUnacceptable);
}

TEST(Aka, StaleSqnTriggersResyncWithVerifiableAuts) {
  const Subscription sub = test_subscription();
  Usim usim(sub, 100);
  const HeAuthVector av = generate_he_av(sub, rand_of(5), 50, test_snn());  // SQN 50 <= SQN_MS 100
  const auto r = usim.authenticate(av.rand, av.autn, test_snn());
  ASSERT_EQ(r.status, Usim::AuthStatus::SynchFailure);
  const auto sqn_ms = verify_auts(sub, av.rand, r.auts);
  ASSERT_TRUE(sqn_ms);
  EXPECT_EQ(*sqn_ms, 100u);
  // A vector built from the recovered SQN is then accepted.
  const HeAuthVector next = generate_he_av(sub, rand_of(6), *sqn_ms + 1, test_snn());
  EXPECT_EQ(usim.authenticate(next.rand, next.autn, test_snn()).status, Usim::AuthStatus::Ok);
}

TEST(Aka, ReplayedVectorIsSynchFailure) {
  const Subscription sub = test_subscription();
  Usim usim(sub, 0);
  const HeAuthVector av = generate_he_av(sub, rand_of(8), 1, test_snn());
  ASSERT_EQ(usim.authenticate(av.rand, av.autn, test_snn()).status, Usim::AuthStatus::Ok);
  EXPECT_EQ(usim.authenticate(av.rand, av.autn, test_snn()).status, Usim::AuthStatus::SynchFailure);
}

TEST(Aka, SqnJumpBeyondDeltaIsSynchFailure) {
  const Subscription sub = test_subscription();
  Usim usim(sub, 0);
  const HeAuthVector av = generate_he_av(sub, rand_of(9), Usim::kDelta + 1, test_snn());
  EXPECT_EQ(usim.authenticate(av.rand, av.autn, test_snn()).status, Usim::AuthStatus::SynchFailure);
}

TEST(Aka, TamperedAutsIsRejected) {
  const Subscription sub = test_subscription();
  Usim usim(sub, 10);
  const HeAuthVector av = generate_he_av(sub, rand_of(10), 3, test_snn());
  auto r = usim.authenticate(av.rand, av.autn, test_snn());
  ASSERT_EQ(r.status, Usim::AuthStatus::SynchFailure);
  r.auts[13] ^= 1;
  EXPECT_FALSE(verify_auts(sub, av.rand, r.auts));
}

TEST(Aka, ServingNetworkNameBindsResStar) {
  const Subscription sub = test_subscription();
  const HeAuthVector av = generate_he_av(sub, rand_of(11), 1, test_snn());
  Usim usim(sub, 0);
  const auto r = usim.authenticate(av.rand, av.autn, serving_network_name("208", "93"));
  ASSERT_EQ(r.status, Usim::AuthStatus::Ok);  // MILENAGE does not see the SNN...
  EXPECT_NE(r.res_star, av.xres_star);         // ...but RES* does, so a false network is detected
}
