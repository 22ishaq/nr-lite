// UE 5GMM state machine driven by a scripted AMF (NetworkPeer) — TS 24.501 §4.4, §5.4, §5.5.

#include "nrlite/nas/ue_nas.hpp"

#include <gtest/gtest.h>
#include <memory>
#include <vector>

#include "support/fixtures.hpp"

using namespace nrlite;
using namespace nrlite::nas;
using nrlite::testing::NetworkPeer;

namespace {

class UeNasTest : public ::testing::Test {
 protected:
  void SetUp() override { make(UeNasConfig{}); }

  void make(UeNasConfig cfg) {
    cfg.subscription = nrlite::testing::test_subscription();
    cfg.plmn = Plmn{"001", "01"};
    config_ = cfg;
    nas_ = std::make_unique<UeNas>(loop_, log_, "UE1", cfg);
    nas_->set_callbacks(UeNas::Callbacks{
        [this](rrc::EstablishmentCause c, const Bytes& pdu, std::optional<std::uint64_t> s_tmsi) {
          if (barred_) {
            nas_->on_establishment_failure(rrc::EstablishmentFailure::AccessBarred);
            return false;
          }
          established_.push_back({c, pdu, s_tmsi});
          sent_.push_back(pdu);
          return establish_ok_;
        },
        [this](const Bytes& pdu) {
          sent_.push_back(pdu);
          return true;
        },
        [this] { ++aborts_; },
        [this](const sec::Key256& k) { kgnb_.push_back(k); },
    });
  }

  std::optional<PlainMessage> last_ul() { return peer_.open_ul(sent_.back()); }

  template <typename T>
  T last_ul_as() {
    auto m = last_ul();
    EXPECT_TRUE(m) << "last uplink PDU could not be opened";
    EXPECT_TRUE(m && std::holds_alternative<T>(*m)) << (m ? message_name(*m) : "none");
    return std::get<T>(*m);
  }

  void start_registration() {
    nas_->power_on();
    ASSERT_TRUE(nas_->register_ue());
    nas_->on_rrc_connected();
  }

  void authenticate() {
    nas_->on_dl_nas(encode(peer_.auth_request()));
    ASSERT_TRUE(std::holds_alternative<AuthenticationResponse>(*last_ul()));
  }

  void secure() {
    nas_->on_dl_nas(peer_.security_mode_command());
    ASSERT_TRUE(std::holds_alternative<SecurityModeComplete>(*last_ul()));
  }

  RegistrationAccept accept() {
    RegistrationAccept acc;
    Guti5g g;
    g.plmn = Plmn{"001", "01"};
    g.amf_region_id = 1;
    g.amf_set_id = 1;
    g.amf_pointer = 1;
    g.tmsi = 0x01020304;
    acc.guti = g;
    acc.tai_list = TaiList{{Tai{Plmn{"001", "01"}, 1}}};
    acc.t3512 = GprsTimer{3, 5};  // 10 s
    return acc;
  }

  void register_fully() {
    start_registration();
    authenticate();
    secure();
    nas_->on_dl_nas(peer_.protect_dl(accept()));
    ASSERT_EQ(nas_->state(), MmState::Registered);
  }

  struct Established {
    rrc::EstablishmentCause cause;
    Bytes pdu;
    std::optional<std::uint64_t> s_tmsi;
  };

  EventLoop loop_;
  Logger log_{&loop_, LogLevel::Off};
  UeNasConfig config_;
  std::unique_ptr<UeNas> nas_;
  NetworkPeer peer_;
  bool establish_ok_ = true;
  bool barred_ = false;  // the stub RRC reports AccessBarred, as UeRrc does while T302 runs
  std::vector<Established> established_;
  std::vector<Bytes> sent_;
  std::vector<sec::Key256> kgnb_;
  int aborts_ = 0;
};

}  // namespace

// ---- Registration initiation ----------------------------------------------------------------------

TEST_F(UeNasTest, PowerOnEntersDeregisteredNormalService) {
  EXPECT_EQ(nas_->state(), MmState::Null);
  nas_->power_on();
  EXPECT_EQ(nas_->state(), MmState::Deregistered);
  EXPECT_EQ(nas_->sub_state(), MmSubState::NormalService);
}

TEST_F(UeNasTest, RegisterSendsPlainRegistrationRequestOverNewConnection) {
  nas_->power_on();
  ASSERT_TRUE(nas_->register_ue());
  ASSERT_EQ(established_.size(), 1u);
  EXPECT_EQ(established_[0].cause, rrc::EstablishmentCause::mo_Signalling);
  EXPECT_FALSE(established_[0].s_tmsi);
  const auto rr = last_ul_as<RegistrationRequest>();
  EXPECT_EQ(rr.registration_type.value, RegistrationType::Initial);
  EXPECT_EQ(rr.ngksi.ksi, Ngksi::kNoKey);
  EXPECT_TRUE(std::holds_alternative<Suci>(rr.mobile_identity));
  EXPECT_EQ(std::get<Suci>(rr.mobile_identity).msin, "0000000001");
  EXPECT_EQ(rr.ue_security_capability, config_.security_capability);
  EXPECT_EQ(nas_->state(), MmState::RegisteredInitiated);
  EXPECT_TRUE(nas_->t3510().running());
}

TEST_F(UeNasTest, RegisterRefusedOutsideDeregistered) {
  EXPECT_FALSE(nas_->register_ue());  // 5GMM-NULL
  start_registration();
  EXPECT_FALSE(nas_->register_ue());
}

// ---- Authentication -------------------------------------------------------------------------------

TEST_F(UeNasTest, AuthenticationRequestAnsweredWithResStar) {
  start_registration();
  nas_->on_dl_nas(encode(peer_.auth_request()));
  const auto resp = last_ul_as<AuthenticationResponse>();
  ASSERT_TRUE(resp.res_star);
  EXPECT_TRUE(std::equal(resp.res_star->begin(), resp.res_star->end(), peer_.av->xres_star.begin()));
}

TEST_F(UeNasTest, AuthenticationMacFailureSendsCause20AndStartsT3520) {
  start_registration();
  auto req = peer_.auth_request();
  (*req.autn)[15] ^= 1;
  nas_->on_dl_nas(encode(req));
  const auto f = last_ul_as<AuthenticationFailure>();
  EXPECT_EQ(f.cause, Cause::MacFailure);
  EXPECT_FALSE(f.auts);
  EXPECT_TRUE(nas_->t3520().running());
}

TEST_F(UeNasTest, T3520ExpiryAbortsRegistration) {
  start_registration();
  auto req = peer_.auth_request();
  (*req.autn)[15] ^= 1;
  nas_->on_dl_nas(encode(req));
  loop_.advance(15000);
  EXPECT_EQ(aborts_, 1);
  EXPECT_EQ(nas_->state(), MmState::Deregistered);
  EXPECT_EQ(nas_->attempt_counter(), 1u);
}

TEST_F(UeNasTest, SynchFailureSendsCause21WithVerifiableAuts) {
  nas_->usim().set_sqn_ms(500);
  start_registration();
  nas_->on_dl_nas(encode(peer_.auth_request()));  // network SQN 1 is stale
  const auto f = last_ul_as<AuthenticationFailure>();
  EXPECT_EQ(f.cause, Cause::SynchFailure);
  ASSERT_TRUE(f.auts);
  sec::Auts14 auts{};
  std::copy(f.auts->begin(), f.auts->end(), auts.begin());
  EXPECT_EQ(sec::verify_auts(peer_.sub, peer_.av->rand, auts), 500u);
}

TEST_F(UeNasTest, Non5gAuthenticationVectorRejectedWithCause26) {
  start_registration();
  peer_.sub.amf = sec::Amf{0x00, 0x00};
  nas_->on_dl_nas(encode(peer_.auth_request()));
  EXPECT_EQ(last_ul_as<AuthenticationFailure>().cause, Cause::Non5gAuthenticationUnacceptable);
}

TEST_F(UeNasTest, AuthenticationRequestWithoutChallengeGetsStatus100) {
  start_registration();
  AuthenticationRequest req;
  req.ngksi = Ngksi{false, 0};
  nas_->on_dl_nas(encode(req));
  EXPECT_EQ(last_ul_as<Status5gmm>().cause, Cause::ConditionalIeError);
}

TEST_F(UeNasTest, NgksiAlreadyInUseGetsCause71) {
  register_fully();
  // Re-authentication reusing the ngKSI of the current context.
  nas_->on_dl_nas(peer_.protect_dl(peer_.auth_request()));
  EXPECT_EQ(last_ul_as<AuthenticationFailure>().cause, Cause::NgksiAlreadyInUse);
}

TEST_F(UeNasTest, AuthenticationRejectInvalidatesUsim) {
  start_registration();
  nas_->on_dl_nas(encode(AuthenticationReject{}));
  EXPECT_EQ(nas_->state(), MmState::Deregistered);
  EXPECT_EQ(nas_->sub_state(), MmSubState::NoSupi);
  EXPECT_FALSE(nas_->t3510().running());
  loop_.advance(1);
  EXPECT_EQ(aborts_, 1);
  EXPECT_FALSE(nas_->register_ue());
}

// ---- Security mode control ------------------------------------------------------------------------

TEST_F(UeNasTest, SecurityModeCommandTakesNewContextIntoUse) {
  start_registration();
  authenticate();
  nas_->on_dl_nas(peer_.security_mode_command());
  const Bytes complete = sent_.back();
  EXPECT_EQ(complete[1], static_cast<std::uint8_t>(SecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext));
  EXPECT_TRUE(std::holds_alternative<SecurityModeComplete>(*last_ul()));
  EXPECT_TRUE(nas_->security_context().valid);
  EXPECT_EQ(nas_->security_context().algorithms, (NasSecurityAlgorithms{0, 2}));
  ASSERT_EQ(kgnb_.size(), 1u);
  EXPECT_EQ(kgnb_[0], sec::derive_kgnb(peer_.kamf(), 0));
}

TEST_F(UeNasTest, SecurityModeCommandWithNea2) {
  start_registration();
  authenticate();
  nas_->on_dl_nas(peer_.security_mode_command(NasSecurityAlgorithms{2, 2}));
  EXPECT_TRUE(std::holds_alternative<SecurityModeComplete>(*last_ul()));
  EXPECT_EQ(nas_->security_context().algorithms.ciphering, 2);
}

TEST_F(UeNasTest, ImeisvRequestAndRinmrAreHonoured) {
  start_registration();
  authenticate();
  peer_.ctx.activate(peer_.kamf(), NasSecurityAlgorithms{0, 2}, peer_.ngksi);
  SecurityModeCommand smc;
  smc.selected_algorithms = NasSecurityAlgorithms{0, 2};
  smc.ngksi = peer_.ngksi;
  smc.replayed_ue_security_capability = nrlite::testing::test_caps();
  smc.imeisv_request = true;
  smc.additional_security_information = 0x02;
  nas_->on_dl_nas(protect(peer_.ctx, encode(smc), SecurityHeaderType::IntegrityProtectedWithNewContext,
                          sec::Direction::Downlink));
  const auto c = last_ul_as<SecurityModeComplete>();
  ASSERT_TRUE(c.imeisv);
  EXPECT_EQ(std::get<Imeisv>(*c.imeisv).digits, config_.imeisv);
  ASSERT_TRUE(c.nas_message_container);
  EXPECT_TRUE(std::holds_alternative<RegistrationRequest>(*decode_plain(*c.nas_message_container)));
}

TEST_F(UeNasTest, ReplayedCapabilityMismatchRejectedWithCause23) {
  start_registration();
  authenticate();
  nas_->on_dl_nas(peer_.security_mode_command({0, 2}, UeSecurityCapability{0xE0, 0x60, std::nullopt, std::nullopt}));
  EXPECT_EQ(last_ul_as<SecurityModeReject>().cause, Cause::UeSecurityCapabilitiesMismatch);
  EXPECT_FALSE(nas_->security_context().valid);
}

TEST_F(UeNasTest, SecurityModeCommandWithBadMacRejectedWithCause24) {
  start_registration();
  authenticate();
  Bytes smc = peer_.security_mode_command();
  smc[3] ^= 0xFF;
  nas_->on_dl_nas(smc);
  EXPECT_EQ(last_ul_as<SecurityModeReject>().cause, Cause::SecurityModeRejectedUnspecified);
  EXPECT_EQ(nas_->counters().integrity_failures, 1u);
}

TEST_F(UeNasTest, SecurityModeCommandWithoutAuthenticationRejected) {
  start_registration();
  peer_.auth_request();  // the UE never sees it
  nas_->on_dl_nas(peer_.security_mode_command());
  EXPECT_EQ(last_ul_as<SecurityModeReject>().cause, Cause::SecurityModeRejectedUnspecified);
}

TEST_F(UeNasTest, NullIntegrityAlgorithmRejected) {
  start_registration();
  authenticate();
  nas_->on_dl_nas(peer_.security_mode_command(NasSecurityAlgorithms{0, 0}));
  EXPECT_TRUE(std::holds_alternative<SecurityModeReject>(*last_ul()));
}

TEST_F(UeNasTest, UnsupportedSelectedAlgorithmRejected) {
  start_registration();
  authenticate();
  nas_->on_dl_nas(peer_.security_mode_command(NasSecurityAlgorithms{1, 2}));
  EXPECT_EQ(last_ul_as<SecurityModeReject>().cause, Cause::UeSecurityCapabilitiesMismatch);
}

// ---- Registration accept / reject -----------------------------------------------------------------

TEST_F(UeNasTest, RegistrationAcceptCompletesRegistration) {
  start_registration();
  authenticate();
  secure();
  nas_->on_dl_nas(peer_.protect_dl(accept()));
  EXPECT_EQ(nas_->state(), MmState::Registered);
  EXPECT_EQ(nas_->sub_state(), MmSubState::NormalService);
  ASSERT_TRUE(nas_->guti());
  EXPECT_EQ(nas_->guti()->tmsi, 0x01020304u);
  EXPECT_FALSE(nas_->t3510().running());
  EXPECT_EQ(sent_.back()[1], static_cast<std::uint8_t>(SecurityHeaderType::IntegrityProtectedAndCiphered));
  EXPECT_TRUE(std::holds_alternative<RegistrationComplete>(*last_ul()));
}

TEST_F(UeNasTest, PlainRegistrationAcceptIsDiscarded) {
  start_registration();
  nas_->on_dl_nas(encode(accept()));
  EXPECT_EQ(nas_->state(), MmState::RegisteredInitiated);
  EXPECT_EQ(nas_->counters().discarded_plain, 1u);
}

TEST_F(UeNasTest, RegistrationAcceptWithBadMacIsDiscarded) {
  start_registration();
  authenticate();
  secure();
  Bytes pdu = peer_.protect_dl(accept());
  pdu.back() ^= 1;
  nas_->on_dl_nas(pdu);
  EXPECT_EQ(nas_->state(), MmState::RegisteredInitiated);
  EXPECT_EQ(nas_->counters().integrity_failures, 1u);
}

TEST_F(UeNasTest, ReplayedRegistrationAcceptIsDiscarded) {
  start_registration();
  authenticate();
  secure();
  const Bytes pdu = peer_.protect_dl(accept());
  nas_->on_dl_nas(pdu);
  const std::size_t n = sent_.size();
  nas_->on_dl_nas(pdu);
  EXPECT_EQ(sent_.size(), n);
  EXPECT_EQ(nas_->counters().integrity_failures, 1u);
}

TEST_F(UeNasTest, RetransmittedRegistrationAcceptIsAcknowledgedAgain) {
  register_fully();
  const std::size_t n = sent_.size();
  nas_->on_dl_nas(peer_.protect_dl(accept()));
  ASSERT_EQ(sent_.size(), n + 1);
  EXPECT_TRUE(std::holds_alternative<RegistrationComplete>(*last_ul()));
  EXPECT_EQ(nas_->state(), MmState::Registered);
}

TEST_F(UeNasTest, RegistrationRejectIllegalUeInvalidatesUsim) {
  start_registration();
  nas_->on_dl_nas(encode(RegistrationReject{Cause::IllegalUe}));
  EXPECT_EQ(nas_->state(), MmState::Deregistered);
  EXPECT_EQ(nas_->sub_state(), MmSubState::NoSupi);
  EXPECT_FALSE(nas_->register_ue());
}

TEST_F(UeNasTest, RegistrationRejectPlmnNotAllowedGivesLimitedService) {
  start_registration();
  nas_->on_dl_nas(encode(RegistrationReject{Cause::PlmnNotAllowed}));
  EXPECT_EQ(nas_->sub_state(), MmSubState::LimitedService);
  EXPECT_EQ(nas_->attempt_counter(), 0u);
}

TEST_F(UeNasTest, RegistrationRejectCongestionStartsT3346) {
  start_registration();
  nas_->on_dl_nas(encode(RegistrationReject{Cause::Congestion, GprsTimer{0, 10}, std::nullopt}));  // 20 s
  EXPECT_EQ(nas_->sub_state(), MmSubState::AttemptingRegistration);
  EXPECT_TRUE(nas_->t3346().running());
  EXPECT_EQ(nas_->t3346().remaining(), 20000);
  EXPECT_FALSE(nas_->register_ue());
  nas_->on_rrc_released(rrc::ReleaseCause::RrcRelease);
  loop_.advance(20000);
  EXPECT_EQ(nas_->state(), MmState::RegisteredInitiated);  // retried when T3346 expired
  EXPECT_EQ(established_.size(), 2u);
}

TEST_F(UeNasTest, RegistrationRejectOtherCauseUsesAttemptCounter) {
  start_registration();
  nas_->on_dl_nas(encode(RegistrationReject{Cause::SemanticallyIncorrectMessage}));
  EXPECT_EQ(nas_->attempt_counter(), 1u);
  EXPECT_TRUE(nas_->t3511().running());
  EXPECT_EQ(nas_->sub_state(), MmSubState::AttemptingRegistration);
}

TEST_F(UeNasTest, RegistrationRejectWhenNotRegisteringGetsStatus98) {
  nas_->power_on();
  nas_->on_rrc_connected();
  nas_->on_dl_nas(encode(RegistrationReject{Cause::Congestion}));
  EXPECT_EQ(last_ul_as<Status5gmm>().cause, Cause::MessageTypeNotCompatibleWithProtocolState);
}

// ---- Abnormal cases (§5.5.1.2.7) ------------------------------------------------------------------

TEST_F(UeNasTest, T3510ExpiryAbortsAndT3511Retries) {
  start_registration();
  loop_.advance(15000);
  EXPECT_EQ(aborts_, 1);
  EXPECT_EQ(nas_->attempt_counter(), 1u);
  EXPECT_EQ(nas_->sub_state(), MmSubState::AttemptingRegistration);
  EXPECT_TRUE(nas_->t3511().running());
  nas_->on_rrc_released(rrc::ReleaseCause::LocalRelease);
  loop_.advance(10000);
  EXPECT_EQ(established_.size(), 2u);
  EXPECT_EQ(nas_->state(), MmState::RegisteredInitiated);
}

TEST_F(UeNasTest, FifthFailureStartsT3502AndDeletesIdentity) {
  register_fully();
  nas_->on_rrc_released(rrc::ReleaseCause::RrcRelease);
  // Force repeated failures: from now on every establishment fails with T300.
  nas_->deregister(true);
  nas_->on_rrc_released(rrc::ReleaseCause::RrcRelease);
  ASSERT_TRUE(nas_->register_ue());
  for (int i = 0; i < 5; ++i) {
    nas_->on_establishment_failure(rrc::EstablishmentFailure::T300Expiry);
    if (i < 4) {
      EXPECT_TRUE(nas_->t3511().running());
      loop_.advance(10000);
    }
  }
  EXPECT_EQ(nas_->attempt_counter(), 5u);
  EXPECT_TRUE(nas_->t3502().running());
  EXPECT_FALSE(nas_->t3511().running());
  EXPECT_FALSE(nas_->guti());
  EXPECT_FALSE(nas_->security_context().valid);
  loop_.advance(720000);
  EXPECT_EQ(nas_->state(), MmState::RegisteredInitiated);
  EXPECT_EQ(nas_->attempt_counter(), 0u);
}

TEST_F(UeNasTest, RefusedEstablishmentWithoutReasonCountsAsFailedAttempt) {
  establish_ok_ = false;
  nas_->power_on();
  nas_->register_ue();
  loop_.advance(1);
  EXPECT_EQ(nas_->attempt_counter(), 1u);
  EXPECT_EQ(nas_->state(), MmState::Deregistered);
}

// Regression for Verdict VD-RRC-004 (DEFECT_LOG #2): a barred access attempt is postponed, not failed.
TEST_F(UeNasTest, BarredRegistrationIsPostponedNotCountedAsFailure) {
  nas_->power_on();
  barred_ = true;
  ASSERT_TRUE(nas_->register_ue());
  EXPECT_EQ(nas_->state(), MmState::Deregistered);
  EXPECT_EQ(nas_->sub_state(), MmSubState::NormalService);
  EXPECT_EQ(nas_->attempt_counter(), 0u);
  EXPECT_FALSE(nas_->t3510().running());
  EXPECT_TRUE(nas_->waiting_for_barring_alleviation());
  loop_.advance(60000);
  EXPECT_TRUE(established_.empty());
  barred_ = false;
  nas_->on_barring_alleviated();
  EXPECT_EQ(nas_->state(), MmState::RegisteredInitiated);
  ASSERT_EQ(established_.size(), 1u);
  EXPECT_FALSE(nas_->waiting_for_barring_alleviation());
}

// Regression for Verdict VD-RRC-008 (DEFECT_LOG #2): de-registration starts when barring ends.
TEST_F(UeNasTest, BarredDeregistrationStartsWhenBarringIsAlleviated) {
  register_fully();
  nas_->on_rrc_released(rrc::ReleaseCause::RrcRelease);
  barred_ = true;
  const std::size_t before = established_.size();
  ASSERT_TRUE(nas_->deregister(false));
  EXPECT_EQ(established_.size(), before);
  barred_ = false;
  loop_.advance(1000);
  nas_->on_barring_alleviated();
  ASSERT_EQ(established_.size(), before + 1);
  EXPECT_TRUE(std::holds_alternative<DeregistrationRequestUeOriginating>(*last_ul()));
  EXPECT_EQ(nas_->t3521().remaining(), 15000);
}

TEST_F(UeNasTest, ConnectionReleaseBeforeAcceptCountsAsFailure) {
  start_registration();
  authenticate();
  nas_->on_rrc_released(rrc::ReleaseCause::ConnectionFailure);
  EXPECT_EQ(nas_->attempt_counter(), 1u);
  EXPECT_EQ(nas_->state(), MmState::Deregistered);
}

// ---- Message integrity rules (§4.4.4.2) and error handling (§7) -----------------------------------

TEST_F(UeNasTest, PlainIdentityRequestForSuciAnswered) {
  start_registration();
  nas_->on_dl_nas(encode(IdentityRequest{IdentityType::Suci}));
  const auto r = last_ul_as<IdentityResponse>();
  EXPECT_TRUE(std::holds_alternative<Suci>(r.mobile_identity));
}

TEST_F(UeNasTest, PlainIdentityRequestForImeisvDiscarded) {
  start_registration();
  const std::size_t n = sent_.size();
  nas_->on_dl_nas(encode(IdentityRequest{IdentityType::Imeisv}));
  EXPECT_EQ(sent_.size(), n);
  EXPECT_EQ(nas_->counters().discarded_plain, 1u);
}

TEST_F(UeNasTest, ProtectedIdentityRequestForImeisvAnswered) {
  register_fully();
  nas_->on_dl_nas(peer_.protect_dl(IdentityRequest{IdentityType::Imeisv}));
  EXPECT_EQ(std::get<Imeisv>(last_ul_as<IdentityResponse>().mobile_identity).digits, config_.imeisv);
}

TEST_F(UeNasTest, UnknownMessageTypeGetsStatus97) {
  start_registration();
  nas_->on_dl_nas(Bytes{0x7e, 0x00, 0x99});
  EXPECT_EQ(last_ul_as<Status5gmm>().cause, Cause::MessageTypeNonExistent);
}

TEST_F(UeNasTest, MissingMandatoryIeGetsStatus96) {
  start_registration();
  nas_->on_dl_nas(from_hex("7e005600"));  // AUTHENTICATION REQUEST without ABBA
  EXPECT_EQ(last_ul_as<Status5gmm>().cause, Cause::InvalidMandatoryInformation);
}

TEST_F(UeNasTest, UplinkOnlyMessageFromNetworkGetsStatus97) {
  register_fully();
  nas_->on_dl_nas(peer_.protect_dl(RegistrationComplete{}));
  EXPECT_EQ(last_ul_as<Status5gmm>().cause, Cause::MessageTypeNonExistent);
}

TEST_F(UeNasTest, TruncatedPduIsIgnored) {
  start_registration();
  const std::size_t n = sent_.size();
  nas_->on_dl_nas(Bytes{0x7e});
  nas_->on_dl_nas(Bytes{0x2e, 0x00, 0x41});  // 5GSM EPD
  EXPECT_EQ(sent_.size(), n);
  EXPECT_EQ(nas_->counters().decode_errors, 2u);
}

TEST_F(UeNasTest, ProtectedMessageWithoutContextIsDiscarded) {
  start_registration();
  NasSecurityContext rogue;
  rogue.activate(sec::Key256{}, NasSecurityAlgorithms{0, 2}, Ngksi{false, 0});
  nas_->on_dl_nas(protect(rogue, encode(accept()), SecurityHeaderType::IntegrityProtectedAndCiphered,
                          sec::Direction::Downlink));
  EXPECT_EQ(nas_->state(), MmState::RegisteredInitiated);
  EXPECT_EQ(nas_->counters().integrity_failures, 1u);
}

// ---- De-registration, periodic registration, re-registration --------------------------------------

TEST_F(UeNasTest, NormalDeregistrationWhileConnected) {
  register_fully();
  ASSERT_TRUE(nas_->deregister(false));
  EXPECT_EQ(nas_->state(), MmState::DeregisteredInitiated);
  EXPECT_TRUE(nas_->t3521().running());
  const auto d = last_ul_as<DeregistrationRequestUeOriginating>();
  EXPECT_FALSE(d.deregistration_type.switch_off);
  EXPECT_TRUE(std::holds_alternative<Guti5g>(d.mobile_identity));
  nas_->on_dl_nas(peer_.protect_dl(DeregistrationAcceptUeOriginating{}));
  EXPECT_EQ(nas_->state(), MmState::Deregistered);
  EXPECT_FALSE(nas_->t3521().running());
}

TEST_F(UeNasTest, DeregistrationFromIdleUsesIntegrityProtectedInitialMessage) {
  register_fully();
  nas_->on_rrc_released(rrc::ReleaseCause::RrcRelease);
  const std::size_t established = established_.size();
  nas_->deregister(false);
  ASSERT_EQ(established_.size(), established + 1);
  EXPECT_EQ(established_.back().s_tmsi, nas_->guti()->s_tmsi());
  EXPECT_EQ(established_.back().pdu[1], static_cast<std::uint8_t>(SecurityHeaderType::IntegrityProtected));
  EXPECT_TRUE(std::holds_alternative<DeregistrationRequestUeOriginating>(*last_ul()));
}

TEST_F(UeNasTest, SwitchOffDeregistrationDoesNotWaitForAccept) {
  register_fully();
  nas_->deregister(true);
  EXPECT_EQ(nas_->state(), MmState::Deregistered);
  EXPECT_TRUE(last_ul_as<DeregistrationRequestUeOriginating>().deregistration_type.switch_off);
}

TEST_F(UeNasTest, T3521RetransmitsThenAbortsLocally) {
  register_fully();
  nas_->deregister(false);
  const std::size_t n = sent_.size();
  for (int i = 0; i < 4; ++i) loop_.advance(15000);
  EXPECT_EQ(sent_.size(), n + 4);  // four retransmissions
  EXPECT_EQ(nas_->state(), MmState::DeregisteredInitiated);
  loop_.advance(15000);
  EXPECT_EQ(nas_->state(), MmState::Deregistered);
  EXPECT_EQ(aborts_, 1);
}

TEST_F(UeNasTest, DeregisterRefusedWhenNotRegistered) {
  nas_->power_on();
  EXPECT_FALSE(nas_->deregister(false));
}

TEST_F(UeNasTest, PeriodicRegistrationOnT3512Expiry) {
  register_fully();
  nas_->on_rrc_released(rrc::ReleaseCause::RrcRelease);
  EXPECT_TRUE(nas_->t3512().running());
  EXPECT_EQ(nas_->t3512().remaining(), 10000);
  loop_.advance(10000);
  EXPECT_EQ(nas_->state(), MmState::RegisteredInitiated);
  const auto rr = last_ul_as<RegistrationRequest>();
  EXPECT_EQ(rr.registration_type.value, RegistrationType::PeriodicUpdating);
  EXPECT_TRUE(std::holds_alternative<Guti5g>(rr.mobile_identity));
  EXPECT_EQ(established_.back().pdu[1], static_cast<std::uint8_t>(SecurityHeaderType::IntegrityProtected));
}

TEST_F(UeNasTest, InitialMessageWithStoredContextDerivesKgnbFromItsCount) {
  register_fully();
  nas_->on_rrc_released(rrc::ReleaseCause::RrcRelease);
  const std::uint32_t count = nas_->security_context().ul_count;
  loop_.advance(10000);  // periodic registration
  EXPECT_EQ(kgnb_.back(), sec::derive_kgnb(peer_.kamf(), count));
}

TEST_F(UeNasTest, PowerOffWhileRegisteredSendsSwitchOff) {
  register_fully();
  nas_->power_off();
  EXPECT_EQ(nas_->state(), MmState::Null);
  EXPECT_TRUE(last_ul_as<DeregistrationRequestUeOriginating>().deregistration_type.switch_off);
}

TEST(UeNasNames, StateNames) {
  EXPECT_STREQ(to_string(MmState::RegisteredInitiated), "5GMM-REGISTERED-INITIATED");
  EXPECT_STREQ(to_string(MmSubState::AttemptingRegistration), "ATTEMPTING-REGISTRATION");
  EXPECT_STREQ(to_string(MmMode::Connected), "5GMM-CONNECTED");
}
