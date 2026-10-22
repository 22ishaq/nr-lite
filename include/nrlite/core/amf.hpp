#pragma once

// Minimal AMF (with the UDM/AUSF/SEAF roles folded in) implementing the network side of the
// 5GMM procedures in TS 24.501 §5: registration, 5G-AKA authentication (including SQN
// re-synchronisation), identification, NAS security mode control and UE-initiated
// de-registration. Retransmission timers: T3550 (REGISTRATION ACCEPT), T3560 (AUTHENTICATION
// REQUEST / SECURITY MODE COMMAND) and T3570 (IDENTITY REQUEST).

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <vector>

#include "nrlite/common/event_loop.hpp"
#include "nrlite/common/logger.hpp"
#include "nrlite/core/n2.hpp"
#include "nrlite/nas/messages.hpp"
#include "nrlite/nas/security.hpp"
#include "nrlite/security/aka.hpp"

namespace nrlite::core {

enum class AmfUeState : std::uint8_t { Deregistered, CommonProcedureInitiated, Registered, DeregisteredInitiated };
const char* to_string(AmfUeState s);

struct AmfConfig {
  nas::Plmn plmn;
  std::uint32_t tac = 1;
  std::uint8_t amf_region_id = 0x01;
  std::uint16_t amf_set_id = 0x001;
  std::uint8_t amf_pointer = 0x01;
  TimeMs t3550_ms = 6000;
  TimeMs t3560_ms = 6000;
  TimeMs t3570_ms = 6000;
  unsigned max_retransmissions = 4;  ///< the 5th expiry aborts the procedure
  std::vector<std::uint8_t> integrity_preference{2};
  std::vector<std::uint8_t> ciphering_preference{0, 2};
  std::vector<nas::SNssai> supported_nssai{nas::SNssai{1, std::nullopt}};
  nas::GprsTimer t3512{1, 1};  ///< 1 hour
  bool release_after_registration = true;
  TimeMs release_delay_ms = 100;
  bool request_imeisv = false;
  bool request_initial_message_resend = false;  ///< sets RINMR in SECURITY MODE COMMAND
  nas::Cause unknown_subscriber_cause = nas::Cause::FiveGsServicesNotAllowed;
  std::optional<nas::Cause> reject_registrations_with;  ///< test knob
  std::optional<nas::GprsTimer> reject_t3346;
};

class Amf {
 public:
  struct Counters {
    unsigned registrations_completed = 0;
    unsigned registration_rejects = 0;
    unsigned authentications = 0;
    unsigned auth_failures = 0;
    unsigned resyncs = 0;
    unsigned integrity_failures = 0;
    unsigned decode_errors = 0;
    unsigned discarded_plain = 0;
    unsigned retransmissions = 0;
    unsigned deregistrations = 0;
  };

  struct UeView {
    std::uint32_t amf_ue_id = 0;
    std::string supi;
    AmfUeState state = AmfUeState::Deregistered;
    bool connected = false;
    bool security_active = false;
    std::optional<nas::Guti5g> guti;
    std::uint32_t ul_count = 0;
    std::uint32_t dl_count = 0;
  };

  Amf(EventLoop& loop, const Logger& log, AmfConfig config, std::mt19937_64& rng);
  ~Amf();

  void add_subscriber(const sec::Subscription& sub, std::uint64_t sqn = 0);
  void set_n2_sender(std::function<void(const n2::Message&)> send) { send_n2_ = std::move(send); }
  void on_n2(const n2::Message& m);

  AmfConfig& config() { return config_; }
  const Counters& counters() const { return counters_; }
  std::optional<UeView> ue(const std::string& supi) const;
  std::size_t context_count() const { return contexts_.size(); }
  std::optional<std::uint64_t> subscriber_sqn(const std::string& supi) const;

 private:
  enum class Proc : std::uint8_t { None, Identification, Authentication, SecurityMode, RegistrationAccept };
  struct UeContext;

  void on_initial_ue_message(const n2::InitialUeMessage& m);
  void handle_ul_nas(UeContext& ue, const Bytes& pdu);
  void dispatch(UeContext& ue, const nas::PlainMessage& m, bool integrity_ok, std::uint32_t count);

  void on_registration_request(UeContext& ue, const nas::RegistrationRequest& rr, bool integrity_ok,
                               std::uint32_t count);
  void continue_registration(UeContext& ue, bool integrity_ok, std::uint32_t count);
  void on_deregistration_request(UeContext& ue, const nas::DeregistrationRequestUeOriginating& d);
  void on_authentication_response(UeContext& ue, const nas::AuthenticationResponse& m);
  void on_authentication_failure(UeContext& ue, const nas::AuthenticationFailure& m);
  void on_security_mode_complete(UeContext& ue, const nas::SecurityModeComplete& m, std::uint32_t count);
  void on_identity_response(UeContext& ue, const nas::IdentityResponse& m);
  void on_registration_complete(UeContext& ue);

  void start_identification(UeContext& ue);
  void start_authentication(UeContext& ue);
  void start_security_mode(UeContext& ue);
  void accept_registration(UeContext& ue, std::uint32_t ul_count);
  void reject_registration(UeContext& ue, nas::Cause cause);
  void send_authentication_reject(UeContext& ue);
  void abort_procedure(UeContext& ue, const std::string& why);

  void send_nas(UeContext& ue, const nas::PlainMessage& m);
  void send_smc(UeContext& ue);
  void send_accept(UeContext& ue);
  void send_status(UeContext& ue, nas::Cause cause);
  void schedule_release(UeContext& ue, const std::string& cause);
  void on_retransmission_timer(std::uint32_t amf_ue_id, const char* timer);

  UeContext* find_by_amf_id(std::uint32_t id);
  UeContext* find_by_ran_id(std::uint32_t id);
  UeContext* find_by_supi(const std::string& supi);
  UeContext* find_by_tmsi(std::uint32_t tmsi);
  UeContext& create_context();
  void erase_context(std::uint32_t amf_ue_id);
  std::string snn() const;
  std::string tag(const UeContext& ue) const;

  EventLoop& loop_;
  const Logger& log_;
  AmfConfig config_;
  std::mt19937_64& rng_;
  Counters counters_;
  std::function<void(const n2::Message&)> send_n2_;

  struct Subscriber {
    sec::Subscription sub;
    std::uint64_t sqn = 0;
  };
  std::map<std::string, Subscriber> subscribers_;
  std::map<std::uint32_t, std::unique_ptr<UeContext>> contexts_;
  std::uint32_t next_amf_ue_id_ = 1;
};

}  // namespace nrlite::core
