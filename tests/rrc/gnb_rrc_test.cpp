// gNB RRC driven by a scripted UE on the air side and a scripted AMF on N2.

#include "nrlite/rrc/gnb_rrc.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <vector>

#include "nrlite/security/kdf.hpp"

using namespace nrlite;
using namespace nrlite::rrc;

namespace {

constexpr std::uint16_t kRnti = 0x4601;

class GnbRrcTest : public ::testing::Test {
 protected:
  void SetUp() override { make(GnbConfig{}); }

  void make(GnbConfig cfg) {
    gnb_ = std::make_unique<GnbRrc>(loop_, log_, cfg);
    gnb_->set_callbacks(GnbRrc::Callbacks{
        [this](std::uint16_t rnti, Channel ch, const Bytes& pdu, const Bytes&) { air_.push_back({rnti, ch, pdu}); },
        [this](const n2::Message& m) { n2_.push_back(m); },
    });
  }

  void setup_request(std::uint16_t rnti = kRnti, std::optional<std::uint64_t> part1 = std::nullopt) {
    RrcSetupRequest req;
    if (part1) req.ue_identity = InitialUeIdentity{InitialUeIdentity::Type::ng_5G_S_TMSI_Part1, *part1};
    gnb_->on_air(rnti, Channel::Ccch, encode_ul_ccch(req));
  }

  void ul_dcch(const UlDcchMessage& m, std::uint16_t rnti = kRnti) {
    gnb_->on_air(rnti, Channel::Dcch, ue_pdcp_.transmit(encode_ul_dcch(m)));
  }

  DlCcchMessage last_dl_ccch() { return *decode_dl_ccch(air_.back().pdu); }

  pdcp::RxPdu last_dl_pdcp() {
    auto rx = ue_pdcp_.receive(air_.back().pdu);
    EXPECT_TRUE(rx) << rx.error().message;
    return *rx;
  }

  DlDcchMessage last_dl_dcch() { return *decode_dl_dcch(last_dl_pdcp().sdu); }

  /// Brings the UE context to CONNECTED with InitialUEMessage sent.
  void connect() {
    setup_request();
    const auto setup = std::get<RrcSetup>(last_dl_ccch());
    RrcSetupComplete c;
    c.rrc_transaction_identifier = setup.rrc_transaction_identifier;
    c.dedicated_nas_message = Bytes{0x7e, 0x00, 0x41};
    ul_dcch(c);
    ASSERT_EQ(gnb_->state_of(kRnti), GnbUeState::Connected);
  }

  n2::InitialContextSetupRequest ics(bool with_nas = true) {
    n2::InitialContextSetupRequest r;
    r.ran_ue_id = *gnb_->ran_ue_id_of(kRnti);
    r.amf_ue_id = 77;
    r.kgnb.fill(0x24);
    r.ue_security_capability = nas::UeSecurityCapability{0xA0, 0x20, std::nullopt, std::nullopt};
    if (with_nas) r.nas_pdu = Bytes{0x7e, 0x02, 1, 2, 3, 4, 0, 0x7e, 0x00, 0x42};
    return r;
  }

  sec::Key128 k_int() const {
    sec::Key256 k{};
    k.fill(0x24);
    return sec::derive_algorithm_key(k, sec::AlgorithmDistinguisher::RrcInt, 2);
  }

  struct Air {
    std::uint16_t rnti;
    Channel ch;
    Bytes pdu;
  };

  EventLoop loop_;
  Logger log_{&loop_, LogLevel::Off};
  std::unique_ptr<GnbRrc> gnb_;
  pdcp::SrbEntity ue_pdcp_{1, sec::Direction::Uplink};
  std::vector<Air> air_;
  std::vector<n2::Message> n2_;
};

}  // namespace

TEST_F(GnbRrcTest, SetupRequestCreatesContextAndSendsRrcSetup) {
  setup_request();
  ASSERT_EQ(air_.size(), 1u);
  EXPECT_EQ(air_[0].ch, Channel::Ccch);
  const auto setup = std::get<RrcSetup>(last_dl_ccch());
  ASSERT_EQ(setup.radio_bearer_config.srb_to_add_mod_list.size(), 1u);
  EXPECT_EQ(setup.radio_bearer_config.srb_to_add_mod_list[0].srb_identity, 1);
  EXPECT_EQ(setup.master_cell_group.rlc_bearer_to_add_mod_list.at(0).logical_channel_identity, 1);
  EXPECT_EQ(gnb_->ue_count(), 1u);
  EXPECT_EQ(gnb_->state_of(kRnti), GnbUeState::WaitSetupComplete);
}

TEST_F(GnbRrcTest, AdmissionControlRejectsBeyondMaxUes) {
  GnbConfig cfg;
  cfg.max_ues = 1;
  cfg.reject_wait_time_s = 9;
  make(cfg);
  setup_request(1);
  setup_request(2);
  EXPECT_EQ(gnb_->ue_count(), 1u);
  const auto reject = std::get<RrcReject>(last_dl_ccch());
  EXPECT_EQ(reject.wait_time, 9);
  EXPECT_EQ(air_.back().rnti, 2);
  EXPECT_EQ(gnb_->counters().rejects, 1u);
}

TEST_F(GnbRrcTest, RejectAllKnob) {
  GnbConfig cfg;
  cfg.reject_all = true;
  make(cfg);
  setup_request();
  EXPECT_TRUE(std::holds_alternative<RrcReject>(last_dl_ccch()));
  EXPECT_EQ(gnb_->ue_count(), 0u);
}

TEST_F(GnbRrcTest, SetupCompleteForwardsInitialUeMessage) {
  connect();
  ASSERT_EQ(n2_.size(), 1u);
  const auto& ini = std::get<n2::InitialUeMessage>(n2_[0]);
  EXPECT_EQ(ini.nas_pdu, (Bytes{0x7e, 0x00, 0x41}));
  EXPECT_EQ(ini.establishment_cause, EstablishmentCause::mo_Signalling);
  EXPECT_FALSE(ini.five_g_s_tmsi);
}

TEST_F(GnbRrcTest, InitialUeMessageReassembles5gSTmsi) {
  const std::uint64_t s_tmsi = 0x123456789ABCull;
  setup_request(kRnti, s_tmsi & ((1ull << 39) - 1));
  RrcSetupComplete c;
  c.rrc_transaction_identifier = std::get<RrcSetup>(last_dl_ccch()).rrc_transaction_identifier;
  c.dedicated_nas_message = Bytes{1};
  c.ng_5g_s_tmsi_value = RrcSetupComplete::Ng5gSTmsiValue{false, s_tmsi >> 39};
  ul_dcch(c);
  EXPECT_EQ(std::get<n2::InitialUeMessage>(n2_.back()).five_g_s_tmsi, s_tmsi);
}

TEST_F(GnbRrcTest, SetupCompleteWithWrongTransactionIdIgnored) {
  setup_request();
  RrcSetupComplete c;
  c.rrc_transaction_identifier = 3;
  c.dedicated_nas_message = Bytes{1};
  ul_dcch(c);
  EXPECT_TRUE(n2_.empty());
  EXPECT_EQ(gnb_->counters().ignored_messages, 1u);
}

TEST_F(GnbRrcTest, GuardTimerDropsContextWithoutSetupComplete) {
  setup_request();
  loop_.advance(2000);
  EXPECT_EQ(gnb_->ue_count(), 0u);
  EXPECT_EQ(gnb_->counters().guard_expiries, 1u);
}

TEST_F(GnbRrcTest, NasRelayInBothDirections) {
  connect();
  gnb_->on_n2(n2::DownlinkNasTransport{*gnb_->ran_ue_id_of(kRnti), 77, Bytes{0x7e, 0x00, 0x56}});
  const auto dl = std::get<DlInformationTransfer>(last_dl_dcch());
  EXPECT_EQ(dl.dedicated_nas_message, (Bytes{0x7e, 0x00, 0x56}));
  ul_dcch(UlInformationTransfer{Bytes{0x7e, 0x00, 0x57}});
  const auto& up = std::get<n2::UplinkNasTransport>(n2_.back());
  EXPECT_EQ(up.amf_ue_id, 77u);
  EXPECT_EQ(up.nas_pdu, (Bytes{0x7e, 0x00, 0x57}));
}

TEST_F(GnbRrcTest, InitialContextSetupStartsProtectedSecurityModeCommand) {
  connect();
  gnb_->on_n2(ics());
  pdcp::RxPdu rx = last_dl_pdcp();
  EXPECT_TRUE(ue_pdcp_.verify(rx, k_int()));
  const auto smc = std::get<SecurityModeCommand>(*decode_dl_dcch(rx.sdu));
  EXPECT_EQ(smc.integrity_prot_algorithm, IntegrityProtAlgorithm::nia2);
  EXPECT_EQ(smc.ciphering_algorithm, CipheringAlgorithm::nea0);
  EXPECT_EQ(gnb_->state_of(kRnti), GnbUeState::WaitSecurityModeComplete);
}

TEST_F(GnbRrcTest, SecurityModeCompleteDeliversPendingNasAndAnswersAmf) {
  connect();
  gnb_->on_n2(ics());
  const auto txid = std::get<SecurityModeCommand>(*decode_dl_dcch(last_dl_pdcp().sdu)).rrc_transaction_identifier;
  ue_pdcp_.enable_tx_integrity(k_int());
  ue_pdcp_.enable_rx_integrity(k_int());
  ul_dcch(SecurityModeComplete{txid});
  EXPECT_EQ(gnb_->state_of(kRnti), GnbUeState::Secured);
  const auto dl = std::get<DlInformationTransfer>(last_dl_dcch());
  EXPECT_EQ(dl.dedicated_nas_message, ics().nas_pdu);
  EXPECT_TRUE(std::holds_alternative<n2::InitialContextSetupResponse>(n2_.back()));
}

TEST_F(GnbRrcTest, SecurityModeCompleteWithBadMacIgnored) {
  connect();
  gnb_->on_n2(ics());
  const auto txid = std::get<SecurityModeCommand>(*decode_dl_dcch(last_dl_pdcp().sdu)).rrc_transaction_identifier;
  ul_dcch(SecurityModeComplete{txid});  // not integrity protected
  EXPECT_EQ(gnb_->state_of(kRnti), GnbUeState::WaitSecurityModeComplete);
  EXPECT_EQ(gnb_->counters().integrity_failures, 1u);
}

TEST_F(GnbRrcTest, SecurityModeFailureReportsInitialContextSetupFailure) {
  connect();
  gnb_->on_n2(ics());
  const auto txid = std::get<SecurityModeCommand>(*decode_dl_dcch(last_dl_pdcp().sdu)).rrc_transaction_identifier;
  ul_dcch(SecurityModeFailure{txid});  // unprotected, as the UE sends it
  EXPECT_TRUE(std::holds_alternative<n2::InitialContextSetupFailure>(n2_.back()));
  EXPECT_EQ(gnb_->state_of(kRnti), GnbUeState::Connected);
  // Downlink falls back to no integrity protection.
  gnb_->on_n2(n2::DownlinkNasTransport{*gnb_->ran_ue_id_of(kRnti), 77, Bytes{1}});
  EXPECT_EQ(to_hex(last_dl_pdcp().mac_i), "00000000");
}

TEST_F(GnbRrcTest, InitialContextSetupFailsWithoutCommonAlgorithm) {
  connect();
  auto req = ics();
  req.ue_security_capability.nr_ia = 0x40;  // IA1 only
  gnb_->on_n2(req);
  EXPECT_TRUE(std::holds_alternative<n2::InitialContextSetupFailure>(n2_.back()));
}

TEST_F(GnbRrcTest, SecurityModeGuardRequestsRelease) {
  connect();
  gnb_->on_n2(ics());
  loop_.advance(2000);
  EXPECT_TRUE(std::holds_alternative<n2::UeContextReleaseRequest>(n2_.back()));
}

TEST_F(GnbRrcTest, ReleaseCommandSendsRrcReleaseAndFreesContext) {
  connect();
  const std::uint32_t ran = *gnb_->ran_ue_id_of(kRnti);
  gnb_->on_n2(n2::UeContextReleaseCommand{ran, 77, "test"});
  EXPECT_TRUE(std::holds_alternative<RrcRelease>(last_dl_dcch()));
  EXPECT_EQ(gnb_->ue_count(), 0u);
  const auto& done = std::get<n2::UeContextReleaseComplete>(n2_.back());
  EXPECT_EQ(done.ran_ue_id, ran);
  EXPECT_EQ(gnb_->counters().releases, 1u);
}

TEST_F(GnbRrcTest, ReleaseCommandForUnknownUeIsStillAcknowledged) {
  gnb_->on_n2(n2::UeContextReleaseCommand{999, 5, "stale"});
  EXPECT_TRUE(std::holds_alternative<n2::UeContextReleaseComplete>(n2_.back()));
}

TEST_F(GnbRrcTest, DcchFromUnknownRntiAndGarbageIgnored) {
  ul_dcch(UlInformationTransfer{Bytes{1}}, 0x9999);
  EXPECT_EQ(gnb_->counters().ignored_messages, 1u);
  gnb_->on_air(kRnti, Channel::Ccch, Bytes{0xFF, 0xFF});
  EXPECT_EQ(gnb_->counters().decode_errors, 1u);
  EXPECT_TRUE(n2_.empty());
}

TEST_F(GnbRrcTest, RepeatedSetupRequestReplacesStaleContext) {
  connect();
  gnb_->on_n2(n2::DownlinkNasTransport{*gnb_->ran_ue_id_of(kRnti), 77, Bytes{1}});
  const std::uint32_t old_ran = *gnb_->ran_ue_id_of(kRnti);
  setup_request();
  const auto& req = std::get<n2::UeContextReleaseRequest>(n2_.back());
  EXPECT_EQ(req.ran_ue_id, old_ran);
  EXPECT_NE(*gnb_->ran_ue_id_of(kRnti), old_ran);
  EXPECT_EQ(gnb_->state_of(kRnti), GnbUeState::WaitSetupComplete);
}

TEST_F(GnbRrcTest, UplinkInformationTransferBeforeSetupCompleteIgnored) {
  setup_request();
  ul_dcch(UlInformationTransfer{Bytes{1}});
  EXPECT_TRUE(n2_.empty());
}
