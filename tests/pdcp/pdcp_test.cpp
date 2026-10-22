#include "nrlite/pdcp/pdcp.hpp"

#include <gtest/gtest.h>

using namespace nrlite;
using namespace nrlite::pdcp;

namespace {

sec::Key128 key(std::uint8_t v) {
  sec::Key128 k{};
  k.fill(v);
  return k;
}

const Bytes kSdu{0x2a, 0x00};

}  // namespace

TEST(Pdcp, HeaderCarries12BitSnAndZeroMacWithoutIntegrity) {
  SrbEntity tx(1, sec::Direction::Uplink);
  const Bytes p0 = tx.transmit(kSdu);
  EXPECT_EQ(to_hex(p0), "0000" "2a00" "00000000");
  const Bytes p1 = tx.transmit(kSdu);
  EXPECT_EQ(p1[1], 0x01);
  EXPECT_EQ(tx.tx_next(), 2u);
}

TEST(Pdcp, RoundTripWithoutSecurity) {
  SrbEntity ue(1, sec::Direction::Uplink);
  SrbEntity gnb(1, sec::Direction::Downlink);
  auto rx = gnb.receive(ue.transmit(kSdu));
  ASSERT_TRUE(rx);
  EXPECT_EQ(rx->sdu, kSdu);
  EXPECT_FALSE(rx->integrity_verified);
}

TEST(Pdcp, IntegrityProtectedRoundTrip) {
  SrbEntity ue(1, sec::Direction::Uplink);
  SrbEntity gnb(1, sec::Direction::Downlink);
  ue.enable_tx_integrity(key(1));
  gnb.enable_rx_integrity(key(1));
  for (int i = 0; i < 5; ++i) {
    auto rx = gnb.receive(ue.transmit(kSdu));
    ASSERT_TRUE(rx);
    EXPECT_TRUE(rx->integrity_verified);
    EXPECT_EQ(rx->count, static_cast<std::uint32_t>(i));
  }
}

TEST(Pdcp, CorruptedPduFailsIntegrity) {
  SrbEntity ue(1, sec::Direction::Uplink);
  SrbEntity gnb(1, sec::Direction::Downlink);
  ue.enable_tx_integrity(key(1));
  gnb.enable_rx_integrity(key(1));
  Bytes pdu = ue.transmit(kSdu);
  pdu[2] ^= 0x01;
  auto rx = gnb.receive(pdu);
  ASSERT_FALSE(rx);
  EXPECT_EQ(rx.error().code, static_cast<int>(RxError::IntegrityFailure));
}

TEST(Pdcp, WrongKeyFailsIntegrity) {
  SrbEntity ue(1, sec::Direction::Uplink);
  SrbEntity gnb(1, sec::Direction::Downlink);
  ue.enable_tx_integrity(key(1));
  gnb.enable_rx_integrity(key(2));
  EXPECT_FALSE(gnb.receive(ue.transmit(kSdu)));
}

TEST(Pdcp, CipheringHidesSduAndRoundTrips) {
  SrbEntity ue(1, sec::Direction::Uplink);
  SrbEntity gnb(1, sec::Direction::Downlink);
  ue.enable_tx_integrity(key(1));
  ue.enable_tx_ciphering(key(3));
  gnb.enable_rx_integrity(key(1));
  gnb.enable_rx_ciphering(key(3));
  const Bytes sdu(20, 0x55);
  const Bytes pdu = ue.transmit(sdu);
  EXPECT_NE(Bytes(pdu.begin() + 2, pdu.begin() + 22), sdu);
  auto rx = gnb.receive(pdu);
  ASSERT_TRUE(rx);
  EXPECT_EQ(rx->sdu, sdu);
}

TEST(Pdcp, DuplicateIsDiscarded) {
  SrbEntity ue(1, sec::Direction::Uplink);
  SrbEntity gnb(1, sec::Direction::Downlink);
  const Bytes pdu = ue.transmit(kSdu);
  ASSERT_TRUE(gnb.receive(pdu));
  auto again = gnb.receive(pdu);
  ASSERT_FALSE(again);
  EXPECT_EQ(again.error().code, static_cast<int>(RxError::Duplicate));
}

TEST(Pdcp, DeferredVerificationForSecurityModeCommand) {
  SrbEntity gnb(1, sec::Direction::Downlink);
  SrbEntity ue(1, sec::Direction::Uplink);
  gnb.enable_tx_integrity(key(9));
  auto rx = ue.receive(gnb.transmit(kSdu));  // UE has no key yet: delivered unverified
  ASSERT_TRUE(rx);
  EXPECT_FALSE(rx->integrity_verified);
  EXPECT_TRUE(ue.verify(*rx, key(9)));
  EXPECT_FALSE(ue.verify(*rx, key(8)));
}

TEST(Pdcp, HfnAdvancesAcrossSnWrap) {
  SrbEntity ue(1, sec::Direction::Uplink);
  SrbEntity gnb(1, sec::Direction::Downlink);
  ue.enable_tx_integrity(key(1));
  gnb.enable_rx_integrity(key(1));
  for (std::uint32_t i = 0; i < kSnModulus + 10; ++i) {
    auto rx = gnb.receive(ue.transmit(kSdu));
    ASSERT_TRUE(rx) << "COUNT " << i;
    ASSERT_EQ(rx->count, i);
  }
}

TEST(Pdcp, ShortPduAndBadSrbRejected) {
  SrbEntity gnb(1, sec::Direction::Downlink);
  auto rx = gnb.receive(Bytes{0x00, 0x00, 0x00});
  ASSERT_FALSE(rx);
  EXPECT_EQ(rx.error().code, static_cast<int>(RxError::Malformed));
  EXPECT_THROW(SrbEntity(0, sec::Direction::Uplink), std::invalid_argument);
  EXPECT_THROW(SrbEntity(4, sec::Direction::Uplink), std::invalid_argument);
}

TEST(Pdcp, ResetAndDisableSecurity) {
  SrbEntity ue(1, sec::Direction::Uplink);
  ue.enable_tx_integrity(key(1));
  (void)ue.transmit(kSdu);
  ue.disable_security();
  EXPECT_FALSE(ue.tx_integrity_active());
  EXPECT_EQ(ue.tx_next(), 1u);  // COUNT state kept
  ue.reset();
  EXPECT_EQ(ue.tx_next(), 0u);
}

TEST(Pdcp, BearerIdIsBoundIntoMac) {
  SrbEntity srb1(1, sec::Direction::Uplink);
  SrbEntity srb2(2, sec::Direction::Uplink);
  srb1.enable_tx_integrity(key(1));
  srb2.enable_tx_integrity(key(1));
  EXPECT_NE(srb1.transmit(kSdu), srb2.transmit(kSdu));
}
