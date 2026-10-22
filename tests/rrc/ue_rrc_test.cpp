// UE RRC state machine driven by a scripted gNB peer (TS 38.331 §5.3).

#include "nrlite/rrc/ue_rrc.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <random>
#include <utility>
#include <vector>

#include "nrlite/security/kdf.hpp"

using namespace nrlite;
using namespace nrlite::rrc;

namespace {

class UeRrcTest : public ::testing::Test {
 protected:
  void SetUp() override {
    config_.s_nssai_list = {SNssai{1, std::nullopt}};
    rrc_ = std::make_unique<UeRrc>(loop_, log_, "UE1", config_, rng_);
    rrc_->set_callbacks(UeRrc::Callbacks{
        [this](Channel ch, const Bytes& pdu, const Bytes&) { sent_.emplace_back(ch, pdu); },
        [this](const Bytes& nas) { nas_.push_back(nas); },
        [this] { ++connected_; },
        [this](EstablishmentFailure f) { failures_.push_back(f); },
        [this](ReleaseCause c) { releases_.push_back(c); },
        [this] { ++alleviated_; },
    });
  }

  RrcSetup setup(std::uint8_t txid = 0, bool with_srb1 = true) {
    RrcSetup s;
    s.rrc_transaction_identifier = txid;
    if (with_srb1) s.radio_bearer_config.srb_to_add_mod_list = {SrbToAddMod{1}};
    return s;
  }

  void deliver_ccch(const DlCcchMessage& m) { rrc_->on_pdu(Channel::Ccch, encode_dl_ccch(m)); }
  void deliver_dcch(const DlDcchMessage& m) { rrc_->on_pdu(Channel::Dcch, gnb_pdcp_.transmit(encode_dl_dcch(m))); }

  RrcSetupRequest last_setup_request() {
    EXPECT_EQ(sent_.back().first, Channel::Ccch);
    return std::get<RrcSetupRequest>(*decode_ul_ccch(sent_.back().second));
  }

  pdcp::RxPdu last_ul_pdcp() {
    EXPECT_EQ(sent_.back().first, Channel::Dcch);
    auto rx = gnb_pdcp_.receive(sent_.back().second);
    EXPECT_TRUE(rx) << rx.error().message;
    return *rx;
  }

  UlDcchMessage last_ul_dcch() { return *decode_ul_dcch(last_ul_pdcp().sdu); }

  void connect(std::optional<std::uint64_t> s_tmsi = std::nullopt) {
    ASSERT_TRUE(rrc_->establish(EstablishmentCause::mo_Signalling, Bytes{0x7e, 0x00, 0x41}, s_tmsi));
    deliver_ccch(setup());
    ASSERT_EQ(rrc_->state(), UeState::Connected);
  }

  sec::Key256 kgnb() const {
    sec::Key256 k{};
    k.fill(0x42);
    return k;
  }
  sec::Key128 k_rrc_int() const { return sec::derive_algorithm_key(kgnb(), sec::AlgorithmDistinguisher::RrcInt, 2); }
  sec::Key128 k_rrc_enc() const { return sec::derive_algorithm_key(kgnb(), sec::AlgorithmDistinguisher::RrcEnc, 2); }

  EventLoop loop_;
  Logger log_{&loop_, LogLevel::Off};
  std::mt19937_64 rng_{7};
  UeRrcConfig config_;
  std::unique_ptr<UeRrc> rrc_;
  pdcp::SrbEntity gnb_pdcp_{1, sec::Direction::Downlink};

  std::vector<std::pair<Channel, Bytes>> sent_;
  std::vector<Bytes> nas_;
  int connected_ = 0;
  int alleviated_ = 0;
  std::vector<EstablishmentFailure> failures_;
  std::vector<ReleaseCause> releases_;
};

}  // namespace

TEST_F(UeRrcTest, EstablishSendsSetupRequestAndStartsT300) {
  ASSERT_TRUE(rrc_->establish(EstablishmentCause::mo_Signalling, Bytes{1}, std::nullopt));
  ASSERT_EQ(sent_.size(), 1u);
  const RrcSetupRequest req = last_setup_request();
  EXPECT_EQ(req.ue_identity.type, InitialUeIdentity::Type::randomValue);
  EXPECT_LT(req.ue_identity.value, 1ull << 39);
  EXPECT_EQ(req.establishment_cause, EstablishmentCause::mo_Signalling);
  EXPECT_TRUE(rrc_->t300().running());
  EXPECT_EQ(rrc_->t300().remaining(), 1000);
  EXPECT_EQ(rrc_->state(), UeState::Idle);
}

TEST_F(UeRrcTest, EstablishWith5gSTmsiSendsPart1) {
  const std::uint64_t s_tmsi = 0xABCDEF123456ull;
  ASSERT_TRUE(rrc_->establish(EstablishmentCause::mt_Access, Bytes{1}, s_tmsi));
  const RrcSetupRequest req = last_setup_request();
  EXPECT_EQ(req.ue_identity.type, InitialUeIdentity::Type::ng_5G_S_TMSI_Part1);
  EXPECT_EQ(req.ue_identity.value, s_tmsi & ((1ull << 39) - 1));
}

TEST_F(UeRrcTest, T300ExpiryReportsEstablishmentFailure) {
  rrc_->establish(EstablishmentCause::mo_Signalling, Bytes{1}, std::nullopt);
  loop_.advance(999);
  EXPECT_TRUE(failures_.empty());
  loop_.advance(1);
  ASSERT_EQ(failures_.size(), 1u);
  EXPECT_EQ(failures_[0], EstablishmentFailure::T300Expiry);
  EXPECT_EQ(rrc_->state(), UeState::Idle);
}

TEST_F(UeRrcTest, RrcSetupConnectsAndCarriesNasInSetupComplete) {
  const Bytes nas{0x7e, 0x00, 0x41, 0x71};
  rrc_->establish(EstablishmentCause::mo_Signalling, nas, std::nullopt);
  deliver_ccch(setup(2));
  EXPECT_EQ(rrc_->state(), UeState::Connected);
  EXPECT_FALSE(rrc_->t300().running());
  EXPECT_EQ(connected_, 1);
  const auto c = std::get<RrcSetupComplete>(last_ul_dcch());
  EXPECT_EQ(c.rrc_transaction_identifier, 2);
  EXPECT_EQ(c.selected_plmn_identity, 1);
  EXPECT_EQ(c.dedicated_nas_message, nas);
  EXPECT_EQ(c.s_nssai_list, config_.s_nssai_list);
  EXPECT_FALSE(c.ng_5g_s_tmsi_value);
}

TEST_F(UeRrcTest, SetupCompleteCarries5gSTmsiPart2) {
  const std::uint64_t s_tmsi = 0xABCDEF123456ull;
  rrc_->establish(EstablishmentCause::mo_Signalling, Bytes{1}, s_tmsi);
  deliver_ccch(setup());
  const auto c = std::get<RrcSetupComplete>(last_ul_dcch());
  ASSERT_TRUE(c.ng_5g_s_tmsi_value);
  EXPECT_FALSE(c.ng_5g_s_tmsi_value->full);
  EXPECT_EQ(c.ng_5g_s_tmsi_value->value, s_tmsi >> 39);
}

TEST_F(UeRrcTest, RrcRejectStartsT302AndBarsAccess) {
  rrc_->establish(EstablishmentCause::mo_Signalling, Bytes{1}, std::nullopt);
  deliver_ccch(RrcReject{3});
  ASSERT_EQ(failures_.size(), 1u);
  EXPECT_EQ(failures_[0], EstablishmentFailure::Rejected);
  EXPECT_TRUE(rrc_->t302().running());
  EXPECT_EQ(rrc_->t302().remaining(), 3000);
  EXPECT_FALSE(rrc_->establish(EstablishmentCause::mo_Signalling, Bytes{1}, std::nullopt));
  EXPECT_FALSE(rrc_->establish(EstablishmentCause::mo_Data, Bytes{1}, std::nullopt));
  loop_.advance(3000);
  EXPECT_EQ(alleviated_, 1);
  EXPECT_TRUE(rrc_->establish(EstablishmentCause::mo_Signalling, Bytes{1}, std::nullopt));
}

TEST_F(UeRrcTest, EmergencyAccessIsNotBarredByT302) {
  rrc_->establish(EstablishmentCause::mo_Signalling, Bytes{1}, std::nullopt);
  deliver_ccch(RrcReject{10});
  EXPECT_TRUE(rrc_->establish(EstablishmentCause::emergency, Bytes{1}, std::nullopt));
}

TEST_F(UeRrcTest, RejectWithoutWaitTimeDoesNotBar) {
  rrc_->establish(EstablishmentCause::mo_Signalling, Bytes{1}, std::nullopt);
  deliver_ccch(RrcReject{});
  EXPECT_FALSE(rrc_->t302().running());
  EXPECT_TRUE(rrc_->establish(EstablishmentCause::mo_Signalling, Bytes{1}, std::nullopt));
}

TEST_F(UeRrcTest, UnsolicitedRrcSetupAndRejectAreIgnored) {
  deliver_ccch(setup());
  deliver_ccch(RrcReject{5});
  EXPECT_EQ(rrc_->state(), UeState::Idle);
  EXPECT_FALSE(rrc_->t302().running());
  EXPECT_EQ(rrc_->counters().ignored_messages, 2u);
  EXPECT_TRUE(sent_.empty());
}

TEST_F(UeRrcTest, RrcSetupWithoutSrb1FailsEstablishment) {
  rrc_->establish(EstablishmentCause::mo_Signalling, Bytes{1}, std::nullopt);
  deliver_ccch(setup(0, false));
  EXPECT_EQ(rrc_->state(), UeState::Idle);
  ASSERT_EQ(failures_.size(), 1u);
  EXPECT_EQ(failures_[0], EstablishmentFailure::InvalidSetup);
}

TEST_F(UeRrcTest, UndecodableCcchIsIgnoredAndT300KeepsRunning) {
  rrc_->establish(EstablishmentCause::mo_Signalling, Bytes{1}, std::nullopt);
  rrc_->on_pdu(Channel::Ccch, Bytes{0xFF});
  EXPECT_EQ(rrc_->counters().decode_errors, 1u);
  EXPECT_TRUE(rrc_->t300().running());
}

TEST_F(UeRrcTest, SecondEstablishmentIsRefused) {
  rrc_->establish(EstablishmentCause::mo_Signalling, Bytes{1}, std::nullopt);
  EXPECT_FALSE(rrc_->establish(EstablishmentCause::mo_Signalling, Bytes{1}, std::nullopt));
  deliver_ccch(setup());
  EXPECT_FALSE(rrc_->establish(EstablishmentCause::mo_Signalling, Bytes{1}, std::nullopt));
}

TEST_F(UeRrcTest, DlInformationTransferDeliversNas) {
  connect();
  deliver_dcch(DlInformationTransfer{1, Bytes{0x7e, 0x00, 0x56}});
  ASSERT_EQ(nas_.size(), 1u);
  EXPECT_EQ(nas_[0], (Bytes{0x7e, 0x00, 0x56}));
  deliver_dcch(DlInformationTransfer{2, std::nullopt});
  EXPECT_EQ(nas_.size(), 1u);
}

TEST_F(UeRrcTest, SendNasUsesUlInformationTransfer) {
  EXPECT_FALSE(rrc_->send_nas(Bytes{1}));
  connect();
  ASSERT_TRUE(rrc_->send_nas(Bytes{0x7e, 0x00, 0x57}));
  const auto m = std::get<UlInformationTransfer>(last_ul_dcch());
  EXPECT_EQ(m.dedicated_nas_message, (Bytes{0x7e, 0x00, 0x57}));
}

TEST_F(UeRrcTest, SecurityModeCommandActivatesAsSecurity) {
  connect();
  rrc_->set_kgnb(kgnb());
  gnb_pdcp_.enable_tx_integrity(k_rrc_int());
  deliver_dcch(SecurityModeCommand{1, CipheringAlgorithm::nea0, IntegrityProtAlgorithm::nia2});
  EXPECT_TRUE(rrc_->as_security_active());
  // SecurityModeComplete is integrity protected with K_RRCint.
  pdcp::RxPdu rx = last_ul_pdcp();
  EXPECT_TRUE(gnb_pdcp_.verify(rx, k_rrc_int()));
  EXPECT_EQ(std::get<SecurityModeComplete>(*decode_ul_dcch(rx.sdu)).rrc_transaction_identifier, 1);
  // From now on unprotected downlink PDUs fail the integrity check.
  pdcp::SrbEntity rogue(1, sec::Direction::Downlink);
  for (std::uint32_t i = 0; i < gnb_pdcp_.tx_next(); ++i) (void)rogue.transmit(Bytes{0});
  rrc_->on_pdu(Channel::Dcch, rogue.transmit(encode_dl_dcch(DlInformationTransfer{2, Bytes{1}})));
  EXPECT_EQ(rrc_->state(), UeState::Idle);
  ASSERT_EQ(releases_.size(), 1u);
  EXPECT_EQ(releases_[0], ReleaseCause::ConnectionFailure);
  EXPECT_TRUE(nas_.empty());
}

TEST_F(UeRrcTest, SecurityModeCommandWithNea2CiphersAfterComplete) {
  connect();
  rrc_->set_kgnb(kgnb());
  gnb_pdcp_.enable_tx_integrity(k_rrc_int());
  deliver_dcch(SecurityModeCommand{0, CipheringAlgorithm::nea2, IntegrityProtAlgorithm::nia2});
  pdcp::RxPdu complete = last_ul_pdcp();  // SMC complete itself is not ciphered
  ASSERT_TRUE(decode_ul_dcch(complete.sdu));
  gnb_pdcp_.enable_rx_integrity(k_rrc_int());
  gnb_pdcp_.enable_tx_ciphering(k_rrc_enc());
  gnb_pdcp_.enable_rx_ciphering(k_rrc_enc());
  deliver_dcch(DlInformationTransfer{1, Bytes{0x7e, 0x00, 0x42}});
  ASSERT_EQ(nas_.size(), 1u);
  rrc_->send_nas(Bytes{0x7e, 0x00, 0x43});
  EXPECT_EQ(std::get<UlInformationTransfer>(last_ul_dcch()).dedicated_nas_message, (Bytes{0x7e, 0x00, 0x43}));
}

TEST_F(UeRrcTest, SecurityModeCommandWithoutKgnbFails) {
  connect();
  deliver_dcch(SecurityModeCommand{3, CipheringAlgorithm::nea0, IntegrityProtAlgorithm::nia2});
  EXPECT_FALSE(rrc_->as_security_active());
  pdcp::RxPdu rx = last_ul_pdcp();
  EXPECT_EQ(to_hex(rx.mac_i), "00000000");  // SecurityModeFailure is sent unprotected
  EXPECT_EQ(std::get<SecurityModeFailure>(*decode_ul_dcch(rx.sdu)).rrc_transaction_identifier, 3);
  EXPECT_EQ(rrc_->counters().security_mode_failures, 1u);
}

TEST_F(UeRrcTest, SecurityModeCommandWithBadMacFails) {
  connect();
  rrc_->set_kgnb(kgnb());
  sec::Key128 wrong{};
  gnb_pdcp_.enable_tx_integrity(wrong);
  deliver_dcch(SecurityModeCommand{1, CipheringAlgorithm::nea0, IntegrityProtAlgorithm::nia2});
  EXPECT_FALSE(rrc_->as_security_active());
  EXPECT_TRUE(std::holds_alternative<SecurityModeFailure>(last_ul_dcch()));
  EXPECT_EQ(rrc_->counters().integrity_failures, 1u);
  EXPECT_EQ(rrc_->state(), UeState::Connected);
}

TEST_F(UeRrcTest, SecurityModeCommandWithUnsupportedAlgorithmsFails) {
  connect();
  rrc_->set_kgnb(kgnb());
  gnb_pdcp_.enable_tx_integrity(k_rrc_int());
  deliver_dcch(SecurityModeCommand{1, CipheringAlgorithm::nea0, IntegrityProtAlgorithm::nia1});
  EXPECT_TRUE(std::holds_alternative<SecurityModeFailure>(last_ul_dcch()));
  deliver_dcch(SecurityModeCommand{2, CipheringAlgorithm::nea3, IntegrityProtAlgorithm::nia2});
  EXPECT_TRUE(std::holds_alternative<SecurityModeFailure>(last_ul_dcch()));
  deliver_dcch(SecurityModeCommand{3, CipheringAlgorithm::nea0, std::nullopt});
  EXPECT_TRUE(std::holds_alternative<SecurityModeFailure>(last_ul_dcch()));
  EXPECT_FALSE(rrc_->as_security_active());
}

TEST_F(UeRrcTest, SecondSecurityModeCommandIsIgnored) {
  connect();
  rrc_->set_kgnb(kgnb());
  gnb_pdcp_.enable_tx_integrity(k_rrc_int());
  deliver_dcch(SecurityModeCommand{1, CipheringAlgorithm::nea0, IntegrityProtAlgorithm::nia2});
  const std::size_t n = sent_.size();
  deliver_dcch(SecurityModeCommand{2, CipheringAlgorithm::nea0, IntegrityProtAlgorithm::nia2});
  EXPECT_EQ(sent_.size(), n);
  EXPECT_EQ(rrc_->counters().ignored_messages, 1u);
}

TEST_F(UeRrcTest, RrcReleaseTakesEffectAfter60ms) {
  connect();
  deliver_dcch(RrcRelease{1, std::nullopt, std::nullopt});
  loop_.advance(59);
  EXPECT_EQ(rrc_->state(), UeState::Connected);
  loop_.advance(1);
  EXPECT_EQ(rrc_->state(), UeState::Idle);
  ASSERT_EQ(releases_.size(), 1u);
  EXPECT_EQ(releases_[0], ReleaseCause::RrcRelease);
  EXPECT_FALSE(rrc_->t302().running());
}

TEST_F(UeRrcTest, RrcReleaseWithWaitTimeStartsT302) {
  connect();
  deliver_dcch(RrcRelease{1, std::nullopt, 4});
  loop_.advance(60);
  EXPECT_TRUE(rrc_->t302().running());
  EXPECT_EQ(rrc_->t302().remaining(), 4000);
}

TEST_F(UeRrcTest, MessagesDuringReleaseDelayAreIgnored) {
  connect();
  deliver_dcch(RrcRelease{1, std::nullopt, std::nullopt});
  deliver_dcch(DlInformationTransfer{2, Bytes{1}});
  EXPECT_TRUE(nas_.empty());
  EXPECT_FALSE(rrc_->send_nas(Bytes{1}));
}

TEST_F(UeRrcTest, DcchAbstractSyntaxErrorLeadsToIdle) {
  connect();
  rrc_->on_pdu(Channel::Dcch, gnb_pdcp_.transmit(Bytes{0x00, 0x00}));  // rrcReconfiguration: unsupported
  EXPECT_EQ(rrc_->state(), UeState::Idle);
  EXPECT_EQ(rrc_->counters().decode_errors, 1u);
  ASSERT_EQ(releases_.size(), 1u);
  EXPECT_EQ(releases_[0], ReleaseCause::ConnectionFailure);
}

TEST_F(UeRrcTest, DcchWhileIdleIsIgnored) {
  rrc_->on_pdu(Channel::Dcch, gnb_pdcp_.transmit(encode_dl_dcch(DlInformationTransfer{0, Bytes{1}})));
  EXPECT_TRUE(nas_.empty());
  EXPECT_EQ(rrc_->counters().ignored_messages, 1u);
}

TEST_F(UeRrcTest, AbortConnectionReleasesLocally) {
  connect();
  rrc_->abort_connection();
  EXPECT_EQ(rrc_->state(), UeState::Idle);
  ASSERT_EQ(releases_.size(), 1u);
  EXPECT_EQ(releases_[0], ReleaseCause::LocalRelease);
}

TEST_F(UeRrcTest, AbortDuringEstablishmentStopsT300Silently) {
  rrc_->establish(EstablishmentCause::mo_Signalling, Bytes{1}, std::nullopt);
  rrc_->abort_connection();
  EXPECT_FALSE(rrc_->t300().running());
  loop_.advance(2000);
  EXPECT_TRUE(failures_.empty());
  EXPECT_TRUE(releases_.empty());
}

TEST_F(UeRrcTest, ReconnectAfterReleaseResetsPdcp) {
  connect();
  rrc_->send_nas(Bytes{1});
  deliver_dcch(RrcRelease{1, std::nullopt, std::nullopt});
  loop_.advance(60);
  gnb_pdcp_ = pdcp::SrbEntity(1, sec::Direction::Downlink);
  connect();
  EXPECT_EQ(last_ul_pdcp().count, 0u);
}

TEST(UeRrcNames, ToString) {
  EXPECT_STREQ(to_string(UeState::Connected), "RRC_CONNECTED");
  EXPECT_STREQ(to_string(Channel::Dcch), "DCCH");
  EXPECT_STREQ(to_string(EstablishmentFailure::T300Expiry), "T300 expiry");
  EXPECT_STREQ(to_string(ReleaseCause::ConnectionFailure), "RRC connection failure");
}
