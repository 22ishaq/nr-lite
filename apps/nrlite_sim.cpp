// nrlite-sim: run a scenario on the NR-Lite testbed, print a message sequence chart and
// optionally write a pcap that Wireshark decodes with its NR RRC and NAS-5GS dissectors.
//
//   nrlite-sim --scenario registration --pcap reg.pcap
//   nrlite-sim --decode ul-ccch 1d4b6a3c09c6

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "nrlite/nas/messages.hpp"
#include "nrlite/rrc/messages.hpp"
#include "nrlite/sim/simulator.hpp"

using namespace nrlite;

namespace {

void usage() {
  std::puts(
      "usage: nrlite-sim [options]\n"
      "  --scenario NAME   registration | deregistration | reject | t300 | periodic | multi  (default registration)\n"
      "  --ues N           number of UEs (default 1; 'multi' defaults to 4)\n"
      "  --pcap FILE       write a Wireshark trace (LINKTYPE_WIRESHARK_UPPER_PDU)\n"
      "  --no-n2           leave N2 NAS PDUs out of the pcap\n"
      "  --nea2            use 128-5G-EA2 for NAS and 128-NEA2 for RRC ciphering (default: null ciphering)\n"
      "  --seed N          RNG seed (default 1)\n"
      "  --log LEVEL       debug | info | warn | error | off (default off)\n"
      "  --json            print one JSON object per PDU instead of the sequence chart\n"
      "  --decode CH HEX   decode one PDU and print JSON; CH = ul-ccch | dl-ccch | ul-dcch | dl-dcch | nas");
}

LogLevel parse_level(const std::string& s) {
  if (s == "debug") return LogLevel::Debug;
  if (s == "info") return LogLevel::Info;
  if (s == "warn") return LogLevel::Warn;
  if (s == "error") return LogLevel::Error;
  return LogLevel::Off;
}

int decode_one(const std::string& channel, const std::string& hex) {
  Bytes pdu;
  try {
    pdu = from_hex(hex);
  } catch (const std::exception& e) {
    std::fprintf(stderr, "bad hex: %s\n", e.what());
    return 2;
  }
  auto print = [](const auto& result) {
    if (!result) {
      std::printf("{\"error\":\"%s\"}\n", result.error().message.c_str());
      return 1;
    }
    std::printf("%s\n", rrc::to_json(*result).dump().c_str());
    return 0;
  };
  if (channel == "ul-ccch") return print(rrc::decode_ul_ccch(pdu));
  if (channel == "dl-ccch") return print(rrc::decode_dl_ccch(pdu));
  if (channel == "ul-dcch") return print(rrc::decode_ul_dcch(pdu));
  if (channel == "dl-dcch") return print(rrc::decode_dl_dcch(pdu));
  if (channel == "nas") {
    auto m = nas::decode_plain(pdu);
    if (!m) {
      std::printf("{\"error\":\"%s\",\"cause\":%d}\n", m.error().message.c_str(), m.error().code);
      return 1;
    }
    std::printf("%s\n", nas::to_json(*m).dump().c_str());
    return 0;
  }
  std::fprintf(stderr, "unknown channel %s\n", channel.c_str());
  return 2;
}

/// Prints each PDU as one line of a message sequence chart as it is delivered.
class ChartPrinter : public sim::TraceSink {
 public:
  explicit ChartPrinter(bool json) : json_(json) {
    if (!json_) std::printf("%10s  %-6s %-4s %-46s %s\n", "time(ms)", "link", "dir", "message", "bytes");
  }
  void on_record(const sim::TraceRecord& r) override {
    if (json_) {
      Json j = Json::object()
                   .set("t", r.time)
                   .set("if", r.iface == sim::Interface::Uu ? "Uu" : "N2")
                   .set("dir", sim::to_string(r.direction))
                   .set("channel", r.channel)
                   .set("message", r.message)
                   .set("dropped", r.dropped)
                   .set("hex", to_hex(r.raw));
      std::printf("%s\n", j.dump().c_str());
      return;
    }
    const char* link = r.iface == sim::Interface::Uu ? "Uu" : "N2";
    std::string arrow;
    if (r.iface == sim::Interface::Uu) {
      arrow = r.direction == sim::Direction::Uplink ? "UE->gNB" : "gNB->UE";
    } else {
      arrow = r.direction == sim::Direction::Uplink ? "gNB->AMF" : "AMF->gNB";
    }
    std::printf("%10lld  %-6s %-8s %-42s %zu%s\n", static_cast<long long>(r.time), link, arrow.c_str(),
                r.message.c_str(), r.raw.size(), r.dropped ? "  (dropped)" : "");
  }

 private:
  bool json_;
};

void print_summary(sim::Simulator& sim) {
  std::printf("\n%-6s %-20s %-36s %-14s %s\n", "UE", "RRC", "5GMM", "5G-TMSI", "AMF view");
  for (std::size_t i = 0; i < sim.ue_count(); ++i) {
    auto& ue = sim.ue(i);
    std::string mm = nas::to_string(ue.nas().state());
    if (ue.nas().sub_state() != nas::MmSubState::None) mm += std::string(".") + nas::to_string(ue.nas().sub_state());
    char tmsi[16] = "-";
    if (ue.nas().guti()) std::snprintf(tmsi, sizeof tmsi, "0x%08x", ue.nas().guti()->tmsi);
    const auto view = sim.amf().ue(ue.config().nas.subscription.supi);
    std::printf("%-6s %-20s %-36s %-14s %s\n", ue.config().name.c_str(), rrc::to_string(ue.rrc().state()), mm.c_str(),
                tmsi, view ? core::to_string(view->state) : "(no context)");
  }
}

}  // namespace

int main(int argc, char** argv) {
  std::string scenario = "registration";
  std::string pcap;
  std::size_t ues = 0;
  std::uint64_t seed = 1;
  bool nea2 = false;
  bool json = false;
  bool n2 = true;
  LogLevel level = LogLevel::Off;

  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto next = [&]() -> std::string {
      if (i + 1 >= argc) {
        usage();
        std::exit(2);
      }
      return argv[++i];
    };
    if (a == "--scenario") scenario = next();
    else if (a == "--pcap") pcap = next();
    else if (a == "--ues") ues = std::stoul(next());
    else if (a == "--seed") seed = std::stoull(next());
    else if (a == "--nea2") nea2 = true;
    else if (a == "--json") json = true;
    else if (a == "--no-n2") n2 = false;
    else if (a == "--log") level = parse_level(next());
    else if (a == "--decode") {
      const std::string ch = next();
      return decode_one(ch, next());
    } else if (a == "-h" || a == "--help") {
      usage();
      return 0;
    } else {
      std::fprintf(stderr, "unknown option %s\n", a.c_str());
      usage();
      return 2;
    }
  }
  if (ues == 0) ues = scenario == "multi" ? 4 : 1;

  sim::SimConfig cfg;
  cfg.seed = seed;
  cfg.log_level = level;
  if (nea2) {
    cfg.amf.ciphering_preference = {2, 0};
    cfg.gnb.ciphering = rrc::CipheringAlgorithm::nea2;
  }
  if (scenario == "reject") {
    cfg.amf.reject_registrations_with = nas::Cause::Congestion;
    cfg.amf.reject_t3346 = nas::GprsTimer{1, 2};  // 2 minutes
  }
  if (scenario == "periodic") cfg.amf.t3512 = nas::GprsTimer{3, 5};  // 10 s

  sim::Simulator sim(cfg);
  ChartPrinter chart(json);
  sim.add_trace_sink(&chart);
  std::unique_ptr<sim::PcapTrace> pcap_sink;
  if (!pcap.empty()) {
    pcap_sink = std::make_unique<sim::PcapTrace>(pcap, n2);
    sim.add_trace_sink(pcap_sink.get());
  }
  for (std::size_t i = 0; i < ues; ++i) sim.add_ue();
  if (scenario == "t300") sim.detach_gnb([](const sim::AirPdu&) {});  // nobody answers

  for (std::size_t i = 0; i < ues; ++i) {
    sim.ue(i).nas().power_on();
    sim.ue(i).nas().register_ue();
    sim.advance(5);
  }

  if (scenario == "t300") {
    sim.advance(25'000);  // T300 (1 s) fails, T3511 (10 s) retries
  } else {
    sim.advance(2'000);
  }
  if (scenario == "deregistration") {
    sim.ue(0).nas().deregister(false);
    sim.advance(2'000);
  }
  if (scenario == "periodic") sim.advance(12'000);

  if (!json) print_summary(sim);
  if (pcap_sink) {
    pcap_sink->flush();
    if (!json) std::printf("\nwrote %zu frames to %s\n", pcap_sink->frames(), pcap.c_str());
  }
  return 0;
}
