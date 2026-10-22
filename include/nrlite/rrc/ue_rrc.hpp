#pragma once

// UE RRC state machine (TS 38.331 §4.2.1, §5.3).
//
//                RRCSetupRequest / T300 started
//   RRC_IDLE  ---------------------------------->  (establishing)
//      ^   ^                                            |  RRCSetup: stop T300, send RRCSetupComplete
//      |   |  RRCReject (T302 = waitTime) / T300 expiry |
//      |   +--------------------------------------------+
//      |                                                v
//      +---- RRCRelease (+60 ms) / integrity or ---- RRC_CONNECTED
//            ASN.1 failure on DCCH / NAS abort         |  SecurityModeCommand -> AS security active
//
// RRC_INACTIVE, re-establishment and reconfiguration are out of scope. Where the spec would start
// RRC re-establishment (integrity check failure or abstract syntax error on DCCH) NR-Lite performs
// the "go to RRC_IDLE" actions with release cause "RRC connection failure" instead.

#include <cstdint>
#include <functional>
#include <optional>
#include <random>
#include <string>

#include "nrlite/common/event_loop.hpp"
#include "nrlite/common/logger.hpp"
#include "nrlite/pdcp/pdcp.hpp"
#include "nrlite/rrc/messages.hpp"
#include "nrlite/security/crypto.hpp"

namespace nrlite::rrc {

/// Logical channel of an RRC PDU on the air interface: SRB0 (CCCH) or SRB1 (DCCH).
enum class Channel : std::uint8_t { Ccch = 0, Dcch = 1 };
const char* to_string(Channel c);

enum class UeState : std::uint8_t { Idle, Connected };
const char* to_string(UeState s);

enum class EstablishmentFailure : std::uint8_t { T300Expiry, Rejected, AccessBarred, InvalidSetup };
const char* to_string(EstablishmentFailure f);

enum class ReleaseCause : std::uint8_t { RrcRelease, ConnectionFailure, LocalRelease };
const char* to_string(ReleaseCause c);

struct UeRrcConfig {
  TimeMs t300_ms = 1000;          ///< ue-TimersAndConstants.t300 (ms100..ms2000)
  TimeMs release_delay_ms = 60;   ///< §5.3.8.3: actions upon RRCRelease are delayed 60 ms
  std::uint8_t selected_plmn_identity = 1;
  std::vector<SNssai> s_nssai_list;
  bool accept_nea2 = true;        ///< UE AS ciphering capability
};

class UeRrc {
 public:
  struct Callbacks {
    /// CCCH: `pdu` is the RRC PDU. DCCH: `pdu` is the PDCP PDU and `rrc_pdu` the plaintext RRC
    /// PDU inside it (used only for tracing, so ciphered links still produce readable traces).
    std::function<void(Channel, const Bytes& pdu, const Bytes& rrc_pdu)> send;
    std::function<void(const Bytes&)> deliver_nas;
    std::function<void()> connected;
    std::function<void(EstablishmentFailure)> establishment_failed;
    std::function<void(ReleaseCause)> released;
    std::function<void()> barring_alleviated;
  };

  struct Counters {
    unsigned setup_requests = 0;
    unsigned decode_errors = 0;
    unsigned integrity_failures = 0;
    unsigned ignored_messages = 0;
    unsigned security_mode_failures = 0;
  };

  UeRrc(EventLoop& loop, const Logger& log, std::string name, UeRrcConfig config, std::mt19937_64& rng);

  void set_callbacks(Callbacks cb) { cb_ = std::move(cb); }

  // ---- NAS -> RRC ----
  /// Starts RRC connection establishment carrying `nas_pdu` in RRCSetupComplete. Returns false
  /// (without signalling) if already connected/establishing or if access is barred (T302).
  bool establish(EstablishmentCause cause, Bytes nas_pdu, std::optional<std::uint64_t> five_g_s_tmsi);
  /// Sends a NAS PDU in ULInformationTransfer. Returns false if not connected.
  bool send_nas(const Bytes& nas_pdu);
  /// K_gNB derived by NAS, used to derive K_RRCint/K_RRCenc on SecurityModeCommand.
  void set_kgnb(const sec::Key256& kgnb) { kgnb_ = kgnb; }
  /// NAS-requested abort of the connection (no signalling, §5.3.11).
  void abort_connection();

  // ---- Lower layers -> RRC ----
  void on_pdu(Channel ch, const Bytes& pdu);

  // ---- Inspection ----
  UeState state() const { return state_; }
  bool establishing() const { return t300_.running(); }
  bool as_security_active() const { return as_security_active_; }
  const Timer& t300() const { return t300_; }
  const Timer& t302() const { return t302_; }
  const pdcp::SrbEntity& srb1() const { return srb1_; }
  const Counters& counters() const { return counters_; }
  const std::string& name() const { return name_; }

 private:
  void on_dl_ccch(const Bytes& pdu);
  void on_dl_dcch(const Bytes& pdu);
  void handle_rrc_setup(const RrcSetup& m);
  void handle_rrc_reject(const RrcReject& m);
  void handle_security_mode_command(const SecurityModeCommand& m, const pdcp::RxPdu& rx);
  void handle_rrc_release(const RrcRelease& m);
  void send_dcch(const UlDcchMessage& m);
  void enter_idle(ReleaseCause cause, bool notify);
  void set_state(UeState s);

  EventLoop& loop_;
  const Logger& log_;
  std::string name_;
  std::string tag_;
  UeRrcConfig config_;
  std::mt19937_64& rng_;
  Callbacks cb_;
  Counters counters_;

  UeState state_ = UeState::Idle;
  bool releasing_ = false;
  bool as_security_active_ = false;
  EstablishmentCause pending_cause_ = EstablishmentCause::mo_Signalling;
  Bytes pending_nas_;
  std::optional<std::uint64_t> pending_s_tmsi_;
  std::optional<sec::Key256> kgnb_;
  pdcp::SrbEntity srb1_;
  Timer t300_;
  Timer t302_;
  std::optional<EventLoop::EventId> release_event_;
};

}  // namespace nrlite::rrc
