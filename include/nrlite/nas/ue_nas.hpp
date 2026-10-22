#pragma once

// UE 5GMM entity (TS 24.501 §5) for 3GPP access.
//
//   5GMM-NULL --power on--> 5GMM-DEREGISTERED.NORMAL-SERVICE
//        --register()--> 5GMM-REGISTERED-INITIATED  (T3510)
//             | Authentication / Identification / Security mode control (common procedures)
//             |--REGISTRATION ACCEPT--> 5GMM-REGISTERED.NORMAL-SERVICE (send REGISTRATION COMPLETE)
//             |--REGISTRATION REJECT--> 5GMM-DEREGISTERED.{LIMITED-SERVICE|ATTEMPTING-REGISTRATION|NO-SUPI}
//             |--T3510 expiry / lower layer failure--> attempt counter++, T3511 or T3502
//   5GMM-REGISTERED --deregister()--> 5GMM-DEREGISTERED-INITIATED (T3521) --DEREGISTRATION ACCEPT-->
//
// Message integrity rules (§4.4.4.2): before secure exchange only IDENTITY REQUEST (SUCI),
// AUTHENTICATION REQUEST/REJECT, REGISTRATION REJECT and DEREGISTRATION ACCEPT are processed in
// plain; afterwards every message must pass the integrity check or it is discarded.

#include <cstdint>
#include <functional>
#include <optional>
#include <random>
#include <string>

#include "nrlite/common/event_loop.hpp"
#include "nrlite/common/logger.hpp"
#include "nrlite/nas/messages.hpp"
#include "nrlite/nas/security.hpp"
#include "nrlite/rrc/messages.hpp"
#include "nrlite/rrc/ue_rrc.hpp"
#include "nrlite/security/aka.hpp"

namespace nrlite::nas {

enum class MmState : std::uint8_t { Null, Deregistered, RegisteredInitiated, Registered, DeregisteredInitiated };
enum class MmSubState : std::uint8_t {
  None,
  NormalService,
  AttemptingRegistration,
  LimitedService,
  NoSupi,  ///< USIM considered invalid (e.g. after AUTHENTICATION REJECT or cause #3)
};
enum class MmMode : std::uint8_t { Idle, Connected };

const char* to_string(MmState s);
const char* to_string(MmSubState s);
const char* to_string(MmMode m);

struct UeNasConfig {
  sec::Subscription subscription;
  std::uint64_t sqn_ms = 0;
  Plmn plmn;
  /// 5G-EA0 + 128-5G-EA2, 128-5G-IA2 (the algorithms NR-Lite implements).
  UeSecurityCapability security_capability{static_cast<std::uint8_t>(0x80 | 0x20), 0x20, std::nullopt, std::nullopt};
  std::vector<SNssai> requested_nssai{SNssai{1, std::nullopt}};
  std::string imeisv = "3534900698733190";
  TimeMs t3510_ms = 15000;
  TimeMs t3511_ms = 10000;
  TimeMs t3502_ms = 720000;
  TimeMs t3520_ms = 15000;
  TimeMs t3521_ms = 15000;
  unsigned max_registration_attempts = 5;
  unsigned max_deregistration_attempts = 5;
};

class UeNas {
 public:
  struct Callbacks {
    /// Request an RRC connection carrying the initial NAS message.
    std::function<bool(rrc::EstablishmentCause, const Bytes&, std::optional<std::uint64_t>)> establish;
    /// Send a NAS PDU over the existing connection.
    std::function<bool(const Bytes&)> send;
    /// Locally release the RRC connection (e.g. abort on T3510 expiry).
    std::function<void()> abort_connection;
    /// Provide K_gNB to the AS.
    std::function<void(const sec::Key256&)> set_kgnb;
  };

  struct Counters {
    unsigned registration_attempts = 0;
    unsigned discarded_plain = 0;
    unsigned integrity_failures = 0;
    unsigned decode_errors = 0;
    unsigned status_sent = 0;
    unsigned auth_failures_sent = 0;
  };

  UeNas(EventLoop& loop, const Logger& log, std::string name, UeNasConfig config);

  void set_callbacks(Callbacks cb) { cb_ = std::move(cb); }

  // ---- User / test triggers (the "MMI" of a conformance test) ----
  void power_on();
  void power_off();
  /// Starts initial registration. Returns false if not in a state that allows it.
  bool register_ue();
  /// UE-initiated de-registration. Returns false if not registered.
  bool deregister(bool switch_off);

  // ---- From RRC ----
  void on_dl_nas(const Bytes& pdu);
  void on_rrc_connected();
  void on_rrc_released(rrc::ReleaseCause cause);
  void on_establishment_failure(rrc::EstablishmentFailure f);
  void on_barring_alleviated();

  // ---- Inspection ----
  MmState state() const { return state_; }
  MmSubState sub_state() const { return sub_state_; }
  MmMode mode() const { return mode_; }
  const std::optional<Guti5g>& guti() const { return guti_; }
  const NasSecurityContext& security_context() const { return ctx_; }
  unsigned attempt_counter() const { return attempt_counter_; }
  const Counters& counters() const { return counters_; }
  const sec::Usim& usim() const { return usim_; }
  sec::Usim& usim() { return usim_; }
  const Timer& t3510() const { return t3510_; }
  const Timer& t3511() const { return t3511_; }
  const Timer& t3502() const { return t3502_; }
  const Timer& t3512() const { return t3512_; }
  const Timer& t3520() const { return t3520_; }
  const Timer& t3521() const { return t3521_; }
  const Timer& t3346() const { return t3346_; }
  /// True while a procedure waits for access barring to be alleviated.
  bool waiting_for_barring_alleviation() const { return pending_after_barring_.has_value(); }
  const std::string& name() const { return name_; }

 private:
  enum class InitialKind : std::uint8_t { Registration, Deregistration };

  void start_registration(std::uint8_t type);
  void on_access_barred();
  DeregistrationRequestUeOriginating make_deregistration_request(bool switch_off) const;
  void handle_registration_failure(const char* why);
  void set_state(MmState s, MmSubState sub);
  void send_initial(const PlainMessage& m);
  void send_nas(const PlainMessage& m);
  void send_status(Cause cause);
  void delete_identity_and_context();

  void dispatch(const PlainMessage& m, bool integrity_protected);
  void handle(const IdentityRequest& m, bool protected_);
  void handle(const AuthenticationRequest& m);
  void handle(const AuthenticationReject& m);
  void handle_security_mode_command(const Bytes& pdu, const SecurityModeCommand& m);
  void handle(const RegistrationAccept& m);
  void handle(const RegistrationReject& m, bool integrity_protected);
  void handle(const DeregistrationAcceptUeOriginating& m);

  Suci suci() const;
  std::string snn() const;

  EventLoop& loop_;
  const Logger& log_;
  std::string name_;
  std::string tag_;
  UeNasConfig config_;
  Callbacks cb_;
  Counters counters_;
  sec::Usim usim_;
  std::mt19937_64 rng_;  ///< e.g. the random T3346 value of TS 24.008 Table 11.3

  MmState state_ = MmState::Null;
  MmSubState sub_state_ = MmSubState::None;
  MmMode mode_ = MmMode::Idle;
  std::uint8_t registration_type_ = RegistrationType::Initial;
  unsigned attempt_counter_ = 0;
  unsigned deregistration_attempts_ = 0;
  bool deregistration_switch_off_ = false;

  std::optional<Guti5g> guti_;
  std::optional<TaiList> tai_list_;
  NasSecurityContext ctx_;         ///< current 5G NAS security context
  bool secure_exchange_ = false;   ///< secure exchange established on this NAS connection
  struct PendingAuth {
    Ngksi ngksi;
    sec::Key256 kamf;
  };
  std::optional<PendingAuth> pending_auth_;  ///< partial native context from the last 5G-AKA
  Bytes last_initial_message_;               ///< plain initial NAS message (for NAS container)

  // Access barring (TS 24.501 §5.5.1.2.7 b), §5.5.2.2.6): a barred attempt is postponed, not failed.
  InitialKind initial_kind_ = InitialKind::Registration;
  bool establish_reported_ = false;
  std::optional<InitialKind> pending_after_barring_;
  MmState state_before_registration_ = MmState::Deregistered;
  MmSubState sub_before_registration_ = MmSubState::NormalService;

  Timer t3510_, t3511_, t3502_, t3512_, t3520_, t3521_, t3346_;
  TimeMs t3512_ms_ = 3'600'000;
};

}  // namespace nrlite::nas
