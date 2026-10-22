#pragma once

// gNB RRC (network side of TS 38.331 §5.3) with one context per C-RNTI:
//
//   (none) --RRCSetupRequest--> WaitSetupComplete --RRCSetupComplete--> Connected
//      ^           | admission fails: RRCReject(waitTime)                 | InitialContextSetupRequest (N2)
//      |           | guard timer expiry: drop context                     v
//      |                                                  WaitSecurityModeComplete --SMC Complete--> Secured
//      +------------- UEContextReleaseCommand (N2): RRCRelease ---------------------------------------+
//
// NAS PDUs are relayed between DL/ULInformationTransfer and N2 DownlinkNASTransport /
// UplinkNASTransport. The NAS PDU carried in InitialContextSetupRequest is delivered after AS
// security is active, as real gNBs do.

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>

#include "nrlite/common/event_loop.hpp"
#include "nrlite/common/logger.hpp"
#include "nrlite/core/n2.hpp"
#include "nrlite/pdcp/pdcp.hpp"
#include "nrlite/rrc/messages.hpp"
#include "nrlite/rrc/ue_rrc.hpp"

namespace nrlite::rrc {

enum class GnbUeState : std::uint8_t { WaitSetupComplete, Connected, WaitSecurityModeComplete, Secured };
const char* to_string(GnbUeState s);

struct GnbConfig {
  std::size_t max_ues = 64;               ///< admission control limit
  std::uint8_t reject_wait_time_s = 10;   ///< waitTime in RRCReject
  bool reject_all = false;                ///< test knob: reject every RRCSetupRequest
  TimeMs setup_complete_timeout_ms = 2000;
  TimeMs security_mode_timeout_ms = 2000;
  CipheringAlgorithm ciphering = CipheringAlgorithm::nea0;
};

class GnbRrc {
 public:
  struct Callbacks {
    /// `rrc_pdu` is the plaintext RRC PDU inside a DCCH PDCP PDU (trace hint).
    std::function<void(std::uint16_t rnti, Channel, const Bytes& pdu, const Bytes& rrc_pdu)> send_air;
    std::function<void(const n2::Message&)> send_n2;
  };

  struct Counters {
    unsigned setups = 0;
    unsigned rejects = 0;
    unsigned decode_errors = 0;
    unsigned integrity_failures = 0;
    unsigned ignored_messages = 0;
    unsigned guard_expiries = 0;
    unsigned releases = 0;
  };

  GnbRrc(EventLoop& loop, const Logger& log, GnbConfig config);

  void set_callbacks(Callbacks cb) { cb_ = std::move(cb); }
  GnbConfig& config() { return config_; }

  void on_air(std::uint16_t rnti, Channel ch, const Bytes& pdu);
  void on_n2(const n2::Message& m);

  std::size_t ue_count() const { return by_rnti_.size(); }
  std::optional<GnbUeState> state_of(std::uint16_t rnti) const;
  std::optional<std::uint32_t> ran_ue_id_of(std::uint16_t rnti) const;
  const Counters& counters() const { return counters_; }

 private:
  struct UeContext {
    UeContext(EventLoop& loop, std::uint16_t r, std::uint32_t id);
    std::uint16_t rnti;
    std::uint32_t ran_ue_id;
    std::optional<std::uint32_t> amf_ue_id;
    GnbUeState state = GnbUeState::WaitSetupComplete;
    std::uint8_t next_txid = 0;
    std::uint8_t expected_txid = 0;
    EstablishmentCause cause = EstablishmentCause::mo_Signalling;
    std::optional<std::uint64_t> s_tmsi_part1;
    std::optional<Bytes> nas_after_security;
    std::optional<sec::Key128> k_rrc_int;
    std::optional<sec::Key128> k_rrc_enc;
    pdcp::SrbEntity srb1;
    std::unique_ptr<Timer> guard;
  };

  void on_setup_request(std::uint16_t rnti, const RrcSetupRequest& m);
  void on_ul_dcch(UeContext& ue, const Bytes& pdu);
  void send_dcch(UeContext& ue, const DlDcchMessage& m);
  std::uint8_t take_txid(UeContext& ue);
  void release_context(std::uint16_t rnti);
  UeContext* find_by_ran_id(std::uint32_t ran_ue_id);
  std::string tag(const UeContext& ue) const;

  EventLoop& loop_;
  const Logger& log_;
  GnbConfig config_;
  Callbacks cb_;
  Counters counters_;
  std::map<std::uint16_t, std::unique_ptr<UeContext>> by_rnti_;
  std::uint32_t next_ran_ue_id_ = 1;
};

}  // namespace nrlite::rrc
