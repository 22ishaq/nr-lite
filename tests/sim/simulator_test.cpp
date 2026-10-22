// End-to-end tests: UE + gNB + AMF over the simulated air interface and N2 link, including fault
// injection through the air interceptor.

#include "nrlite/sim/simulator.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <set>
#include <string>
#include <vector>

using namespace nrlite;
using namespace nrlite::sim;

namespace {

bool registered(Simulator& sim, std::size_t i) {
  return sim.ue(i).nas().state() == nas::MmState::Registered &&
         sim.amf().ue(sim.ue(i).config().nas.subscription.supi)->state == core::AmfUeState::Registered;
}

void register_all(Simulator& sim) {
  for (std::size_t i = 0; i < sim.ue_count(); ++i) {
    sim.ue(i).nas().power_on();
    sim.ue(i).nas().register_ue();
  }
}

/// Drops the first PDU whose decoded summary contains `needle`.
AirInterceptor drop_first(const std::string& needle, int* dropped) {
  return [needle, dropped](AirPdu& pdu) {
    const Bytes rrc = pdu.channel == rrc::Channel::Dcch ? strip_pdcp(pdu.data) : pdu.data;
    if (*dropped == 0 && summarize_uu(pdu.direction, pdu.channel, rrc).find(needle) != std::string::npos) {
      ++*dropped;
      return InterceptDecision::drop();
    }
    return InterceptDecision::deliver();
  };
}

}  // namespace

TEST(Simulator, SingleUeRegistersWithExpectedMessageSequence) {
  Simulator sim;
  MemoryTrace trace;
  sim.add_trace_sink(&trace);
  sim.add_ue();
  register_all(sim);
  sim.advance(1000);
  ASSERT_TRUE(registered(sim, 0));
  EXPECT_EQ(sim.ue(0).rrc().state(), rrc::UeState::Idle);  // released after registration
  const std::vector<std::string> expected{
      "rrcSetupRequest",
      "rrcSetup",
      "rrcSetupComplete [RegistrationRequest]",
      "dlInformationTransfer [AuthenticationRequest]",
      "ulInformationTransfer [AuthenticationResponse]",
      "dlInformationTransfer [SecurityModeCommand*]",
      "ulInformationTransfer [SecurityModeComplete*]",
      "securityModeCommand",
      "securityModeComplete",
      "dlInformationTransfer [RegistrationAccept*]",
      "ulInformationTransfer [RegistrationComplete*]",
      "rrcRelease",
  };
  EXPECT_EQ(trace.uu_messages(), expected);
}

TEST(Simulator, EightUesRegisterConcurrently) {
  Simulator sim;
  for (int i = 0; i < 8; ++i) sim.add_ue();
  register_all(sim);
  sim.advance(2000);
  for (std::size_t i = 0; i < 8; ++i) EXPECT_TRUE(registered(sim, i)) << "UE" << i + 1;
  EXPECT_EQ(sim.amf().counters().registrations_completed, 8u);
  // Every UE got a distinct 5G-TMSI.
  std::set<std::uint32_t> tmsis;
  for (std::size_t i = 0; i < 8; ++i) tmsis.insert(sim.ue(i).nas().guti()->tmsi);
  EXPECT_EQ(tmsis.size(), 8u);
}

TEST(Simulator, AdmissionControlRejectsThenUeRetries) {
  SimConfig cfg;
  cfg.gnb.max_ues = 2;
  cfg.gnb.reject_wait_time_s = 2;
  Simulator sim(cfg);
  for (int i = 0; i < 3; ++i) sim.add_ue();
  register_all(sim);
  sim.advance(500);
  EXPECT_EQ(sim.gnb().counters().rejects, 1u);
  EXPECT_EQ(sim.ue(2).nas().sub_state(), nas::MmSubState::AttemptingRegistration);
  EXPECT_TRUE(sim.ue(2).rrc().t302().running());
  sim.advance(15000);  // T3511 retry after the others were released
  for (std::size_t i = 0; i < 3; ++i) EXPECT_TRUE(registered(sim, i)) << "UE" << i + 1;
}

TEST(Simulator, LostRrcSetupRecoveredByT300AndT3511) {
  Simulator sim;
  int dropped = 0;
  sim.set_air_interceptor(drop_first("rrcSetup", &dropped));
  sim.add_ue();
  register_all(sim);
  sim.advance(1500);
  EXPECT_EQ(dropped, 1);
  EXPECT_EQ(sim.ue(0).nas().attempt_counter(), 1u);
  EXPECT_FALSE(registered(sim, 0));
  sim.advance(10000);
  EXPECT_TRUE(registered(sim, 0));
  EXPECT_EQ(sim.ue(0).nas().attempt_counter(), 0u);
}

TEST(Simulator, LostRegistrationCompleteRecoveredByT3550) {
  SimConfig cfg;
  cfg.amf.release_after_registration = false;
  Simulator sim(cfg);
  int dropped = 0;
  sim.set_air_interceptor(drop_first("RegistrationComplete", &dropped));
  sim.add_ue();
  register_all(sim);
  sim.advance(1000);
  EXPECT_EQ(sim.ue(0).nas().state(), nas::MmState::Registered);
  EXPECT_EQ(sim.amf().ue(sim.ue(0).config().nas.subscription.supi)->state, core::AmfUeState::CommonProcedureInitiated);
  sim.advance(6000);  // T3550 retransmits REGISTRATION ACCEPT, the UE acknowledges again
  EXPECT_TRUE(registered(sim, 0));
  EXPECT_EQ(sim.amf().counters().retransmissions, 1u);
}

TEST(Simulator, LostAuthenticationResponseRecoveredByT3560) {
  Simulator sim;
  int dropped = 0;
  sim.set_air_interceptor(drop_first("AuthenticationResponse", &dropped));
  sim.add_ue();
  register_all(sim);
  sim.advance(7000);
  // The retransmitted AUTHENTICATION REQUEST replays the SQN, which the USIM rejects: the AMF
  // re-synchronises and the registration still completes.
  EXPECT_TRUE(registered(sim, 0));
  EXPECT_EQ(sim.amf().counters().retransmissions, 1u);
  EXPECT_EQ(sim.amf().counters().resyncs, 1u);
}

TEST(Simulator, CorruptedSecurityModeCommandFailsThenRecovers) {
  Simulator sim;
  int corrupted = 0;
  sim.set_air_interceptor([&](AirPdu& pdu) {
    if (corrupted == 0 && pdu.direction == Direction::Downlink && pdu.channel == rrc::Channel::Dcch &&
        summarize_uu(pdu.direction, pdu.channel, strip_pdcp(pdu.data)) == "securityModeCommand") {
      ++corrupted;
      pdu.data.back() ^= 0x01;  // flip a MAC-I bit
    }
    return InterceptDecision::deliver();
  });
  sim.add_ue();
  register_all(sim);
  sim.advance(1000);
  EXPECT_EQ(corrupted, 1);
  EXPECT_EQ(sim.ue(0).rrc().counters().security_mode_failures, 1u);
  EXPECT_FALSE(registered(sim, 0));
  sim.advance(11000);
  EXPECT_TRUE(registered(sim, 0));
}

TEST(Simulator, ReorderedDownlinkIsHandled) {
  Simulator sim;
  bool delayed = false;
  sim.set_air_interceptor([&](AirPdu& pdu) {
    // Delay the RRC SecurityModeCommand behind the NAS message that follows it.
    if (!delayed && pdu.direction == Direction::Downlink && pdu.channel == rrc::Channel::Dcch &&
        summarize_uu(pdu.direction, pdu.channel, strip_pdcp(pdu.data)) == "securityModeCommand") {
      delayed = true;
      return InterceptDecision::delay(50);
    }
    return InterceptDecision::deliver();
  });
  sim.add_ue();
  register_all(sim);
  sim.advance(2000);
  EXPECT_TRUE(delayed);
  EXPECT_TRUE(registered(sim, 0));
}

TEST(Simulator, PeriodicRegistrationReusesContextWithoutAuthentication) {
  SimConfig cfg;
  cfg.amf.t3512 = nas::GprsTimer{3, 5};  // 10 s
  Simulator sim(cfg);
  MemoryTrace trace;
  sim.add_trace_sink(&trace);
  sim.add_ue();
  register_all(sim);
  sim.advance(1000);
  ASSERT_TRUE(registered(sim, 0));
  trace.clear();
  sim.advance(11000);
  EXPECT_TRUE(registered(sim, 0));
  EXPECT_EQ(sim.amf().counters().authentications, 1u);
  EXPECT_EQ(sim.amf().counters().registrations_completed, 2u);
  // The second connection is set up with the 5G-S-TMSI and carries an integrity protected request.
  const auto msgs = trace.uu_messages();
  ASSERT_GE(msgs.size(), 3u);
  EXPECT_EQ(msgs[2], "rrcSetupComplete [RegistrationRequest*]");
  auto req = rrc::decode_ul_ccch(trace.records()[0].payload);
  ASSERT_TRUE(req);
  EXPECT_EQ(std::get<rrc::RrcSetupRequest>(*req).ue_identity.type, rrc::InitialUeIdentity::Type::ng_5G_S_TMSI_Part1);
}

TEST(Simulator, DeregistrationEndToEnd) {
  Simulator sim;
  sim.add_ue();
  register_all(sim);
  sim.advance(1000);
  ASSERT_TRUE(sim.ue(0).nas().deregister(false));
  sim.advance(1000);
  EXPECT_EQ(sim.ue(0).nas().state(), nas::MmState::Deregistered);
  EXPECT_EQ(sim.amf().ue(sim.ue(0).config().nas.subscription.supi)->state, core::AmfUeState::Deregistered);
  EXPECT_EQ(sim.ue(0).rrc().state(), rrc::UeState::Idle);
}

TEST(Simulator, Nea2CipheringEndToEnd) {
  SimConfig cfg;
  cfg.amf.ciphering_preference = {2};
  cfg.gnb.ciphering = rrc::CipheringAlgorithm::nea2;
  Simulator sim(cfg);
  MemoryTrace trace;
  sim.add_trace_sink(&trace);
  sim.add_ue();
  register_all(sim);
  sim.advance(1000);
  ASSERT_TRUE(registered(sim, 0));
  EXPECT_EQ(sim.ue(0).nas().security_context().algorithms.ciphering, 2);
  // The plaintext trace hint keeps ciphered DCCH traffic readable.
  EXPECT_EQ(trace.uu_messages().back(), "rrcRelease");
}

TEST(Simulator, UnknownSubscriberIsRejected) {
  Simulator sim;
  sim.add_ue(Simulator::default_ue_config(0), /*provision=*/false);
  register_all(sim);
  sim.advance(1000);
  EXPECT_EQ(sim.ue(0).nas().sub_state(), nas::MmSubState::NoSupi);
  EXPECT_EQ(sim.amf().counters().registration_rejects, 1u);
}

TEST(Simulator, WrongKeyFailsAuthentication) {
  Simulator sim;
  UeConfig cfg = Simulator::default_ue_config(0);
  sim.amf().add_subscriber(cfg.nas.subscription);
  cfg.nas.subscription.k[0] ^= 0x01;  // USIM disagrees with the network
  sim.add_ue(cfg, false);
  register_all(sim);
  sim.advance(1000);
  EXPECT_EQ(sim.ue(0).nas().counters().auth_failures_sent, 1u);
  EXPECT_FALSE(registered(sim, 0));
}

TEST(Simulator, SameSeedGivesIdenticalTraces) {
  auto run = [](std::uint64_t seed) {
    SimConfig cfg;
    cfg.seed = seed;
    Simulator sim(cfg);
    MemoryTrace trace;
    sim.add_trace_sink(&trace);
    sim.add_ue();
    sim.add_ue();
    register_all(sim);
    sim.advance(2000);
    std::vector<Bytes> raw;
    for (const auto& r : trace.records()) raw.push_back(r.raw);
    return raw;
  };
  EXPECT_EQ(run(42), run(42));
  EXPECT_NE(run(42), run(43));
}

TEST(Simulator, DetachedGnbHandsUplinkToTestSystem) {
  Simulator sim;
  std::vector<AirPdu> uplink;
  sim.detach_gnb([&](const AirPdu& p) { uplink.push_back(p); });
  UeNode& ue = sim.add_ue();
  ue.nas().power_on();
  ue.nas().register_ue();
  sim.advance(10);
  ASSERT_EQ(uplink.size(), 1u);
  EXPECT_EQ(uplink[0].channel, rrc::Channel::Ccch);
  ASSERT_TRUE(rrc::decode_ul_ccch(uplink[0].data));
  // The test system answers with its own RRCSetup.
  rrc::RrcSetup setup;
  setup.radio_bearer_config.srb_to_add_mod_list = {rrc::SrbToAddMod{1}};
  sim.inject_dl(ue.rnti(), rrc::Channel::Ccch, rrc::encode_dl_ccch(setup));
  sim.advance(10);
  EXPECT_EQ(ue.rrc().state(), rrc::UeState::Connected);
  ASSERT_EQ(uplink.size(), 2u);
  EXPECT_EQ(uplink[1].channel, rrc::Channel::Dcch);
  EXPECT_EQ(sim.gnb().ue_count(), 0u);
}

TEST(Simulator, PcapSinkWritesOneFramePerDeliveredPdu) {
  const std::string path = ::testing::TempDir() + "nrlite_sim_test.pcap";
  {
    Simulator sim;
    PcapTrace pcap(path);
    MemoryTrace mem;
    sim.add_trace_sink(&pcap);
    sim.add_trace_sink(&mem);
    sim.add_ue();
    register_all(sim);
    sim.advance(1000);
    pcap.flush();
    EXPECT_EQ(pcap.frames(), mem.records().size());
    EXPECT_EQ(pcap.frames(), 19u);  // 12 Uu RRC PDUs + 7 N2 NAS PDUs
  }
  std::ifstream in(path, std::ios::binary);
  ASSERT_TRUE(in);
  unsigned char magic[4];
  in.read(reinterpret_cast<char*>(magic), 4);
  EXPECT_EQ(magic[0], 0xd4);
  EXPECT_EQ(magic[3], 0xa1);
  std::remove(path.c_str());
}

TEST(Simulator, InterceptorDropsAreRecordedButNotDelivered) {
  Simulator sim;
  MemoryTrace trace;
  sim.add_trace_sink(&trace);
  sim.set_air_interceptor([](AirPdu&) { return InterceptDecision::drop(); });
  sim.add_ue();
  register_all(sim);
  sim.advance(100);
  ASSERT_EQ(trace.records().size(), 1u);
  EXPECT_TRUE(trace.records()[0].dropped);
  EXPECT_TRUE(trace.uu_messages().empty());
  EXPECT_EQ(sim.gnb().ue_count(), 0u);
}
