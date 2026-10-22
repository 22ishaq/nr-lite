// AMF (network side of 5GMM) driven over N2 by a scripted UE (UePeer).

#include "nrlite/core/amf.hpp"

#include <gtest/gtest.h>
#include <algorithm>
#include <memory>
#include <random>
#include <vector>

#include "support/fixtures.hpp"

using namespace nrlite;
using namespace nrlite::nas;
using nrlite::testing::UePeer;

namespace {

constexpr std::uint32_t kRan = 11;

class AmfTest : public ::testing::Test {
 protected:
  void SetUp() override { make(core::AmfConfig{}); }

  void make(core::AmfConfig cfg) {
    cfg.plmn = Plmn{"001", "01"};
    amf_ = std::make_unique<core::Amf>(loop_, log_, cfg, rng_);
    amf_->add_subscriber(nrlite::testing::test_subscription(), 0);
    amf_->set_n2_sender([this](const n2::Message& m) { out_.push_back(m); });
  }

  void initial(const Bytes& nas, std::optional<std::uint64_t> s_tmsi = std::nullopt) {
    n2::InitialUeMessage m;
    m.ran_ue_id = kRan;
    m.nas_pdu = nas;
    m.five_g_s_tmsi = s_tmsi;
    amf_->on_n2(m);
  }

  void uplink(const Bytes& nas) { amf_->on_n2(n2::UplinkNasTransport{kRan, amf_ue_id(), nas}); }

  std::uint32_t amf_ue_id() const {
    for (auto it = out_.rbegin(); it != out_.rend(); ++it) {
      if (const auto* d = std::get_if<n2::DownlinkNasTransport>(&*it)) return d->amf_ue_id;
      if (const auto* i = std::get_if<n2::InitialContextSetupRequest>(&*it)) return i->amf_ue_id;
    }
    return 0;
  }

  /// The NAS PDU of the most recent downlink N2 message carrying one.
  Bytes last_dl_pdu() const {
    for (auto it = out_.rbegin(); it != out_.rend(); ++it) {
      if (const Bytes* nas = n2::nas_pdu(*it)) return *nas;
    }
    ADD_FAILURE() << "no downlink NAS PDU";
    return {};
  }

  std::optional<PlainMessage> last_dl() { return peer_.open_dl(last_dl_pdu()); }

  template <typename T>
  T last_dl_as() {
    auto m = last_dl();
    EXPECT_TRUE(m && std::holds_alternative<T>(*m)) << (m ? message_name(*m) : "unopenable");
    return std::get<T>(*m);
  }

  template <typename T>
  std::size_t count_n2() const {
    return static_cast<std::size_t>(std::count_if(out_.begin(), out_.end(), [](const n2::Message& m) { return std::holds_alternative<T>(m); }));
  }

  /// Runs registration up to (and including) the SECURITY MODE COMPLETE.
  void authenticate_and_secure() {
    initial(encode(peer_.registration_request()));
    uplink(peer_.answer_auth(last_dl_as<AuthenticationRequest>()));
    auto complete = peer_.answer_smc(last_dl_pdu());
    ASSERT_TRUE(complete);
    uplink(*complete);
    ASSERT_TRUE(std::holds_alternative<n2::InitialContextSetupRequest>(out_.back()));
  }

  void register_fully() {
    authenticate_and_secure();
    ASSERT_TRUE(std::holds_alternative<RegistrationAccept>(*last_dl()));
    uplink(peer_.protect_ul(RegistrationComplete{}));
    ASSERT_EQ(state(), core::AmfUeState::Registered);
  }

  void release() {
    loop_.advance(100);
    amf_->on_n2(n2::UeContextReleaseComplete{kRan, amf_ue_id()});
  }

  core::AmfUeState state() const { return amf_->ue(peer_.usim.subscription().supi)->state; }

  EventLoop loop_;
  Logger log_{&loop_, LogLevel::Off};
  std::mt19937_64 rng_{3};
  std::unique_ptr<core::Amf> amf_;
  UePeer peer_;
  std::vector<n2::Message> out_;
};

}  // namespace

TEST_F(AmfTest, FullInitialRegistration) {
  initial(encode(peer_.registration_request()));
  const auto auth = last_dl_as<AuthenticationRequest>();
  EXPECT_EQ(auth.ngksi.ksi, 0);
  ASSERT_TRUE(auth.rand && auth.autn);
  EXPECT_EQ(state(), core::AmfUeState::CommonProcedureInitiated);

  uplink(peer_.answer_auth(auth));
  const Bytes smc_pdu = last_dl_pdu();
  EXPECT_EQ(smc_pdu[1], static_cast<std::uint8_t>(SecurityHeaderType::IntegrityProtectedWithNewContext));
  auto complete = peer_.answer_smc(smc_pdu);
  ASSERT_TRUE(complete) << "SMC failed verification at the UE";

  uplink(*complete);
  const auto& ics = std::get<n2::InitialContextSetupRequest>(out_.back());
  EXPECT_EQ(ics.kgnb, sec::derive_kgnb(*peer_.kamf, 0));
  EXPECT_EQ(ics.ue_security_capability, nrlite::testing::test_caps());
  const auto acc = last_dl_as<RegistrationAccept>();
  ASSERT_TRUE(acc.guti);
  EXPECT_EQ(acc.guti->amf_region_id, 1);
  ASSERT_TRUE(acc.allowed_nssai);
  EXPECT_EQ(acc.allowed_nssai->size(), 1u);

  uplink(peer_.protect_ul(RegistrationComplete{}));
  EXPECT_EQ(state(), core::AmfUeState::Registered);
  EXPECT_EQ(amf_->counters().registrations_completed, 1u);
  EXPECT_EQ(amf_->ue(peer_.usim.subscription().supi)->guti, acc.guti);

  loop_.advance(100);
  EXPECT_TRUE(std::holds_alternative<n2::UeContextReleaseCommand>(out_.back()));
}

TEST_F(AmfTest, UnknownSubscriberRejected) {
  UePeer stranger;
  RegistrationRequest rr = stranger.registration_request();
  rr.mobile_identity = nrlite::testing::test_suci(41);
  initial(encode(rr));
  EXPECT_EQ(last_dl_as<RegistrationReject>().cause, Cause::FiveGsServicesNotAllowed);
  EXPECT_EQ(amf_->counters().registration_rejects, 1u);
}

TEST_F(AmfTest, MissingUeSecurityCapabilityRejectedWithCause96) {
  initial(encode(peer_.registration_request(false)));
  EXPECT_EQ(last_dl_as<RegistrationReject>().cause, Cause::InvalidMandatoryInformation);
}

TEST_F(AmfTest, NonNullSuciSchemeRejectedWithCause9) {
  RegistrationRequest rr = peer_.registration_request();
  Suci s = nrlite::testing::test_suci();
  s.protection_scheme_id = 1;
  s.scheme_output = Bytes(32, 1);
  rr.mobile_identity = s;
  initial(encode(rr));
  EXPECT_EQ(last_dl_as<RegistrationReject>().cause, Cause::UeIdentityCannotBeDerived);
}

TEST_F(AmfTest, WrongResStarGetsAuthenticationReject) {
  initial(encode(peer_.registration_request()));
  ResStar wrong{};
  uplink(encode(AuthenticationResponse{wrong}));
  last_dl_as<AuthenticationReject>();
  EXPECT_EQ(state(), core::AmfUeState::Deregistered);
  EXPECT_EQ(amf_->counters().auth_failures, 1u);
  loop_.advance(100);
  EXPECT_TRUE(std::holds_alternative<n2::UeContextReleaseCommand>(out_.back()));
}

TEST_F(AmfTest, SynchFailureResynchronisesSqnAndReauthenticates) {
  peer_.usim.set_sqn_ms(1000);
  initial(encode(peer_.registration_request()));
  const auto first = last_dl_as<AuthenticationRequest>();
  sec::Autn16 autn{};
  std::copy(first.autn->begin(), first.autn->end(), autn.begin());
  const auto r = peer_.usim.authenticate(*first.rand, autn, nrlite::testing::test_snn());
  ASSERT_EQ(r.status, sec::Usim::AuthStatus::SynchFailure);
  Auts auts{};
  std::copy(r.auts.begin(), r.auts.end(), auts.begin());
  uplink(encode(AuthenticationFailure{Cause::SynchFailure, auts}));
  EXPECT_EQ(amf_->counters().resyncs, 1u);
  EXPECT_EQ(amf_->subscriber_sqn(peer_.usim.subscription().supi), 1001u);
  // The new challenge uses a fresh SQN and is accepted.
  const Bytes resp = peer_.answer_auth(last_dl_as<AuthenticationRequest>());
  EXPECT_TRUE(std::holds_alternative<AuthenticationResponse>(*decode_plain(resp)));
}

TEST_F(AmfTest, SynchFailureWithForgedAutsRejected) {
  initial(encode(peer_.registration_request()));
  Auts forged{};
  uplink(encode(AuthenticationFailure{Cause::SynchFailure, forged}));
  last_dl_as<AuthenticationReject>();
}

TEST_F(AmfTest, MacFailureAbortsProcedure) {
  initial(encode(peer_.registration_request()));
  uplink(encode(AuthenticationFailure{Cause::MacFailure, std::nullopt}));
  EXPECT_EQ(state(), core::AmfUeState::Deregistered);
  loop_.advance(100);
  EXPECT_TRUE(std::holds_alternative<n2::UeContextReleaseCommand>(out_.back()));
}

TEST_F(AmfTest, NgksiAlreadyInUsePicksAnotherKsi) {
  initial(encode(peer_.registration_request()));
  const std::uint8_t first = last_dl_as<AuthenticationRequest>().ngksi.ksi;
  uplink(encode(AuthenticationFailure{Cause::NgksiAlreadyInUse, std::nullopt}));
  EXPECT_NE(last_dl_as<AuthenticationRequest>().ngksi.ksi, first);
}

TEST_F(AmfTest, T3560RetransmitsAuthenticationRequestThenAborts) {
  initial(encode(peer_.registration_request()));
  const std::size_t before = count_n2<n2::DownlinkNasTransport>();
  for (int i = 0; i < 4; ++i) loop_.advance(6000);
  EXPECT_EQ(count_n2<n2::DownlinkNasTransport>(), before + 4);
  EXPECT_EQ(amf_->counters().retransmissions, 4u);
  loop_.advance(6000);  // 5th expiry
  EXPECT_EQ(state(), core::AmfUeState::Deregistered);
  loop_.advance(100);
  EXPECT_TRUE(std::holds_alternative<n2::UeContextReleaseCommand>(out_.back()));
}

TEST_F(AmfTest, T3560RetransmitsSecurityModeCommandWithFreshCount) {
  initial(encode(peer_.registration_request()));
  uplink(peer_.answer_auth(last_dl_as<AuthenticationRequest>()));
  const Bytes first = last_dl_pdu();
  loop_.advance(6000);
  const Bytes second = last_dl_pdu();
  EXPECT_NE(first, second);
  EXPECT_EQ(second[6], 1);  // NAS sequence number advanced
  EXPECT_TRUE(peer_.answer_smc(second));
}

TEST_F(AmfTest, T3550RetransmitsRegistrationAccept) {
  authenticate_and_secure();
  const auto first = last_dl_as<RegistrationAccept>();
  loop_.advance(6000);
  ASSERT_TRUE(std::holds_alternative<n2::DownlinkNasTransport>(out_.back()));
  EXPECT_EQ(last_dl_as<RegistrationAccept>().guti, first.guti);
  uplink(peer_.protect_ul(RegistrationComplete{}));
  EXPECT_EQ(state(), core::AmfUeState::Registered);
}

TEST_F(AmfTest, FifthT3550ExpiryConsidersUeRegistered) {
  authenticate_and_secure();
  for (int i = 0; i < 5; ++i) loop_.advance(6000);
  EXPECT_EQ(state(), core::AmfUeState::Registered);
}

TEST_F(AmfTest, UnknownGutiTriggersIdentification) {
  RegistrationRequest rr = peer_.registration_request();
  Guti5g g;
  g.plmn = Plmn{"001", "01"};
  g.tmsi = 0xDEAD;
  rr.mobile_identity = g;
  initial(encode(rr));
  EXPECT_EQ(last_dl_as<IdentityRequest>().identity_type, IdentityType::Suci);
  uplink(encode(IdentityResponse{nrlite::testing::test_suci()}));
  last_dl_as<AuthenticationRequest>();
}

TEST_F(AmfTest, T3570RetransmitsIdentityRequest) {
  RegistrationRequest rr = peer_.registration_request();
  rr.mobile_identity = Guti5g{};
  initial(encode(rr));
  loop_.advance(6000);
  EXPECT_EQ(amf_->counters().retransmissions, 1u);
  last_dl_as<IdentityRequest>();
}

TEST_F(AmfTest, PlainMessageAfterSecurityIsDiscarded) {
  authenticate_and_secure();
  uplink(encode(RegistrationComplete{}));
  EXPECT_EQ(amf_->counters().discarded_plain, 1u);
  EXPECT_EQ(state(), core::AmfUeState::CommonProcedureInitiated);
}

TEST_F(AmfTest, ProtectedMessageWithBadMacIsDiscarded) {
  authenticate_and_secure();
  Bytes pdu = peer_.protect_ul(RegistrationComplete{});
  pdu[2] ^= 0xFF;
  uplink(pdu);
  EXPECT_EQ(amf_->counters().integrity_failures, 1u);
  EXPECT_NE(state(), core::AmfUeState::Registered);
}

TEST_F(AmfTest, SecurityModeCompleteWithBadMacIsDiscarded) {
  initial(encode(peer_.registration_request()));
  uplink(peer_.answer_auth(last_dl_as<AuthenticationRequest>()));
  auto complete = peer_.answer_smc(last_dl_pdu());
  ASSERT_TRUE(complete);
  (*complete)[3] ^= 1;
  uplink(*complete);
  EXPECT_EQ(amf_->counters().integrity_failures, 1u);
  EXPECT_EQ(count_n2<n2::InitialContextSetupRequest>(), 0u);
}

TEST_F(AmfTest, SecurityModeRejectAbortsRegistration) {
  initial(encode(peer_.registration_request()));
  uplink(peer_.answer_auth(last_dl_as<AuthenticationRequest>()));
  uplink(encode(SecurityModeReject{Cause::UeSecurityCapabilitiesMismatch}));
  EXPECT_EQ(state(), core::AmfUeState::Deregistered);
}

TEST_F(AmfTest, NoCommonNasAlgorithmRejectedWithCause23) {
  RegistrationRequest rr = peer_.registration_request();
  rr.ue_security_capability = UeSecurityCapability{0x40, 0x40, std::nullopt, std::nullopt};  // EA1/IA1 only
  initial(encode(rr));
  uplink(peer_.answer_auth(last_dl_as<AuthenticationRequest>()));
  EXPECT_EQ(last_dl_as<RegistrationReject>().cause, Cause::UeSecurityCapabilitiesMismatch);
}

TEST_F(AmfTest, UnexpectedAuthenticationResponseIgnored) {
  register_fully();
  const std::size_t n = out_.size();
  uplink(peer_.protect_ul(AuthenticationResponse{ResStar{}}));
  EXPECT_EQ(out_.size(), n);
}

TEST_F(AmfTest, ReRegistrationWithStoredContextSkipsAuthentication) {
  register_fully();
  release();
  const Guti5g guti = *amf_->ue(peer_.usim.subscription().supi)->guti;
  RegistrationRequest rr = peer_.registration_request();
  rr.registration_type.value = RegistrationType::PeriodicUpdating;
  rr.mobile_identity = guti;
  rr.ngksi = *peer_.ngksi;
  const std::uint32_t count = peer_.ctx.ul_count;
  const Bytes pdu = protect(peer_.ctx, encode(rr), SecurityHeaderType::IntegrityProtected, sec::Direction::Uplink);
  initial(pdu, guti.s_tmsi());
  ASSERT_TRUE(std::holds_alternative<n2::InitialContextSetupRequest>(out_.back()));
  EXPECT_EQ(std::get<n2::InitialContextSetupRequest>(out_.back()).kgnb, sec::derive_kgnb(*peer_.kamf, count));
  EXPECT_EQ(amf_->counters().authentications, 1u);
  uplink(peer_.protect_ul(RegistrationComplete{}));
  EXPECT_EQ(state(), core::AmfUeState::Registered);
}

TEST_F(AmfTest, ReRegistrationWithBadMacReauthenticates) {
  register_fully();
  release();
  RegistrationRequest rr = peer_.registration_request();
  rr.mobile_identity = *amf_->ue(peer_.usim.subscription().supi)->guti;
  Bytes pdu = protect(peer_.ctx, encode(rr), SecurityHeaderType::IntegrityProtected, sec::Direction::Uplink);
  pdu[2] ^= 1;
  initial(pdu);
  last_dl_as<AuthenticationRequest>();
  EXPECT_EQ(amf_->counters().authentications, 2u);
  EXPECT_EQ(amf_->counters().integrity_failures, 1u);
}

TEST_F(AmfTest, DeregistrationIsAcceptedAndReleased) {
  register_fully();
  DeregistrationRequestUeOriginating d;
  d.mobile_identity = *amf_->ue(peer_.usim.subscription().supi)->guti;
  uplink(peer_.protect_ul(d));
  last_dl_as<DeregistrationAcceptUeOriginating>();
  EXPECT_EQ(state(), core::AmfUeState::Deregistered);
  EXPECT_EQ(amf_->counters().deregistrations, 1u);
}

TEST_F(AmfTest, SwitchOffDeregistrationGetsNoAccept) {
  register_fully();
  release();
  DeregistrationRequestUeOriginating d;
  d.deregistration_type.switch_off = true;
  d.mobile_identity = *amf_->ue(peer_.usim.subscription().supi)->guti;
  const std::size_t n = count_n2<n2::DownlinkNasTransport>();
  initial(protect(peer_.ctx, encode(d), SecurityHeaderType::IntegrityProtected, sec::Direction::Uplink));
  EXPECT_EQ(count_n2<n2::DownlinkNasTransport>(), n);
  EXPECT_EQ(state(), core::AmfUeState::Deregistered);
}

TEST_F(AmfTest, RejectKnobSendsCongestionWithT3346) {
  core::AmfConfig cfg;
  cfg.reject_registrations_with = Cause::Congestion;
  cfg.reject_t3346 = GprsTimer{1, 3};
  make(cfg);
  initial(encode(peer_.registration_request()));
  const auto rej = last_dl_as<RegistrationReject>();
  EXPECT_EQ(rej.cause, Cause::Congestion);
  EXPECT_EQ(rej.t3346, (GprsTimer{1, 3}));
}

TEST_F(AmfTest, MalformedInitialRegistrationRequestRejected) {
  initial(from_hex("7e004171"));  // no mobile identity
  EXPECT_EQ(last_dl_as<RegistrationReject>().cause, Cause::InvalidMandatoryInformation);
}

TEST_F(AmfTest, NonInitialMessageAsInitialIsRefused) {
  initial(encode(RegistrationComplete{}));
  EXPECT_EQ(last_dl_as<Status5gmm>().cause, Cause::MessageNotCompatibleWithProtocolState);
}

TEST_F(AmfTest, GarbageInitialMessageIsReleased) {
  initial(Bytes{0x01, 0x02});
  EXPECT_EQ(amf_->counters().decode_errors, 1u);
  loop_.advance(100);
  EXPECT_TRUE(std::holds_alternative<n2::UeContextReleaseCommand>(out_.back()));
}

TEST_F(AmfTest, UeContextReleaseRequestAbortsOngoingProcedure) {
  initial(encode(peer_.registration_request()));
  amf_->on_n2(n2::UeContextReleaseRequest{kRan, amf_ue_id(), "radio link failure"});
  EXPECT_EQ(state(), core::AmfUeState::Deregistered);
  loop_.advance(100);
  EXPECT_TRUE(std::holds_alternative<n2::UeContextReleaseCommand>(out_.back()));
}

TEST_F(AmfTest, ReleaseStopsRetransmissions) {
  initial(encode(peer_.registration_request()));
  amf_->on_n2(n2::UeContextReleaseComplete{kRan, amf_ue_id()});
  const std::size_t n = out_.size();
  loop_.advance(60000);
  EXPECT_EQ(out_.size(), n);
}
