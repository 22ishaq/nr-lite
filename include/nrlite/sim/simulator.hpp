#pragma once

// Deterministic discrete-event testbed: N UEs, one gNB and one AMF joined by a simulated air
// interface (Uu) and N2 link, all driven by one virtual clock and one seeded RNG.
//
// Two hooks make it a test target:
//  * An interceptor sees every Uu PDU before delivery and can drop, delay (reorder) or rewrite it.
//  * The gNB can be detached so that a test system (e.g. Verdict) plays the network side itself:
//    uplink PDUs are handed to a callback and downlink PDUs are injected with inject_dl().

#include <cstdint>
#include <functional>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "nrlite/common/event_loop.hpp"
#include "nrlite/common/logger.hpp"
#include "nrlite/core/amf.hpp"
#include "nrlite/core/n2.hpp"
#include "nrlite/nas/ue_nas.hpp"
#include "nrlite/rrc/gnb_rrc.hpp"
#include "nrlite/rrc/ue_rrc.hpp"
#include "nrlite/sim/trace.hpp"

namespace nrlite::sim {

struct AirPdu {
  std::uint16_t rnti = 0;
  Direction direction = Direction::Uplink;
  rrc::Channel channel = rrc::Channel::Ccch;
  Bytes data;
  /// Plaintext RRC PDU supplied by the sender, used by the trace when `data` is unmodified.
  Bytes rrc_hint;
};

struct InterceptDecision {
  enum class Action : std::uint8_t { Deliver, Drop, Delay };
  Action action = Action::Deliver;
  TimeMs delay_ms = 0;

  static InterceptDecision deliver() { return {}; }
  static InterceptDecision drop() { return {Action::Drop, 0}; }
  static InterceptDecision delay(TimeMs ms) { return {Action::Delay, ms}; }
};

/// Called for every Uu PDU; may modify `pdu.data` in place.
using AirInterceptor = std::function<InterceptDecision(AirPdu& pdu)>;

struct UeConfig {
  std::string name = "UE1";
  nas::UeNasConfig nas;
  rrc::UeRrcConfig rrc;
};

class UeNode {
 public:
  UeNode(EventLoop& loop, const Logger& log, std::mt19937_64& rng, UeConfig config,
         std::function<void(rrc::Channel, const Bytes&, const Bytes&)> send_air);
  UeNode(const UeNode&) = delete;
  UeNode& operator=(const UeNode&) = delete;

  void on_air(rrc::Channel ch, const Bytes& pdu) { rrc_.on_pdu(ch, pdu); }

  rrc::UeRrc& rrc() { return rrc_; }
  nas::UeNas& nas() { return nas_; }
  const rrc::UeRrc& rrc() const { return rrc_; }
  const nas::UeNas& nas() const { return nas_; }
  const UeConfig& config() const { return config_; }
  std::uint16_t rnti() const { return rnti_; }
  void set_rnti(std::uint16_t r) { rnti_ = r; }

 private:
  UeConfig config_;
  rrc::UeRrc rrc_;
  nas::UeNas nas_;
  std::uint16_t rnti_ = 0;
};

struct SimConfig {
  std::uint64_t seed = 1;
  TimeMs air_latency_ms = 2;
  TimeMs n2_latency_ms = 1;
  rrc::GnbConfig gnb;
  core::AmfConfig amf;
  LogLevel log_level = LogLevel::Off;
};

class Simulator {
 public:
  explicit Simulator(SimConfig config = {});
  ~Simulator();
  Simulator(const Simulator&) = delete;
  Simulator& operator=(const Simulator&) = delete;

  /// Test subscriber `index` (0-based): IMSI 00101000000000<index+1>, K/OPc from TS 35.207 test set 1.
  static UeConfig default_ue_config(std::size_t index);

  /// Adds a UE; with `provision` the subscriber is also added to the AMF's database.
  UeNode& add_ue(UeConfig config, bool provision = true);
  UeNode& add_ue() { return add_ue(default_ue_config(ues_.size())); }
  UeNode& ue(std::size_t i) { return *ues_.at(i); }
  std::size_t ue_count() const { return ues_.size(); }

  rrc::GnbRrc& gnb() { return gnb_; }
  core::Amf& amf() { return amf_; }
  EventLoop& loop() { return loop_; }
  Logger& logger() { return logger_; }
  TimeMs now() const { return loop_.now(); }
  const SimConfig& config() const { return config_; }

  void advance(TimeMs ms) { loop_.advance(ms); }
  bool run_until(const std::function<bool()>& done, TimeMs limit) { return loop_.run_until_condition(done, limit); }

  void add_trace_sink(TraceSink* sink);
  void remove_trace_sink(TraceSink* sink);
  void set_air_interceptor(AirInterceptor fn) { interceptor_ = std::move(fn); }

  /// Replaces the gNB as the receiver of uplink PDUs (test-system mode).
  void detach_gnb(std::function<void(const AirPdu&)> uplink_handler);
  void reattach_gnb();
  bool gnb_attached() const { return gnb_attached_; }

  /// Receives downlink PDUs addressed to an RNTI that has no UeNode (a test system playing the
  /// UE injects uplink with inject_ul() and reads the gNB's answers here).
  void set_downlink_handler(std::function<void(const AirPdu&)> handler) { downlink_handler_ = std::move(handler); }

  /// Sends a downlink PDU over the air (latency, trace and interceptor apply).
  void inject_dl(std::uint16_t rnti, rrc::Channel ch, Bytes data, Bytes rrc_hint = {});
  /// Sends an uplink PDU over the air towards whoever receives uplink.
  void inject_ul(std::uint16_t rnti, rrc::Channel ch, Bytes data, Bytes rrc_hint = {});

 private:
  void transmit(AirPdu pdu);
  void deliver(const AirPdu& pdu);
  void transmit_n2(const n2::Message& m);
  void record_uu(const AirPdu& pdu, bool dropped);

  SimConfig config_;
  EventLoop loop_;
  Logger logger_;
  std::mt19937_64 rng_;
  rrc::GnbRrc gnb_;
  core::Amf amf_;
  std::vector<std::unique_ptr<UeNode>> ues_;
  std::vector<TraceSink*> sinks_;
  AirInterceptor interceptor_;
  bool gnb_attached_ = true;
  std::function<void(const AirPdu&)> uplink_handler_;
  std::function<void(const AirPdu&)> downlink_handler_;
};

}  // namespace nrlite::sim
