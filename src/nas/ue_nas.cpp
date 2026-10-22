#include "nrlite/nas/ue_nas.hpp"
#include <algorithm>

#include "nrlite/security/kdf.hpp"

namespace nrlite::nas {

const char* to_string(MmState s) {
  switch (s) {
    case MmState::Null: return "5GMM-NULL";
    case MmState::Deregistered: return "5GMM-DEREGISTERED";
    case MmState::RegisteredInitiated: return "5GMM-REGISTERED-INITIATED";
    case MmState::Registered: return "5GMM-REGISTERED";
    case MmState::DeregisteredInitiated: return "5GMM-DEREGISTERED-INITIATED";
  }
  return "?";
}

const char* to_string(MmSubState s) {
  switch (s) {
    case MmSubState::None: return "";
    case MmSubState::NormalService: return "NORMAL-SERVICE";
    case MmSubState::AttemptingRegistration: return "ATTEMPTING-REGISTRATION";
    case MmSubState::LimitedService: return "LIMITED-SERVICE";
    case MmSubState::NoSupi: return "NO-SUPI";
  }
  return "?";
}

const char* to_string(MmMode m) { return m == MmMode::Idle ? "5GMM-IDLE" : "5GMM-CONNECTED"; }

UeNas::UeNas(EventLoop& loop, const Logger& log, std::string name, UeNasConfig config)
    : loop_(loop),
      log_(log),
      name_(std::move(name)),
      tag_(name_ + "/NAS"),
      config_(std::move(config)),
      usim_(config_.subscription, config_.sqn_ms),
      rng_(std::hash<std::string>{}(config_.subscription.supi)),
      t3510_(loop, "T3510",
             [this] {
               if (state_ != MmState::RegisteredInitiated) return;
               log_.warn(tag_, "T3510 expired: registration aborted");
               handle_registration_failure("T3510 expiry");
               if (cb_.abort_connection) cb_.abort_connection();
             }),
      t3511_(loop, "T3511",
             [this] {
               if (state_ == MmState::Deregistered && sub_state_ == MmSubState::AttemptingRegistration) {
                 log_.info(tag_, "T3511 expired: retrying registration (attempt ", attempt_counter_ + 1, ")");
                 start_registration(RegistrationType::Initial);
               }
             }),
      t3502_(loop, "T3502",
             [this] {
               attempt_counter_ = 0;
               if (state_ == MmState::Deregistered && sub_state_ == MmSubState::AttemptingRegistration) {
                 log_.info(tag_, "T3502 expired: retrying registration");
                 start_registration(RegistrationType::Initial);
               }
             }),
      t3512_(loop, "T3512",
             [this] {
               if (state_ == MmState::Registered && mode_ == MmMode::Idle) {
                 log_.info(tag_, "T3512 expired: periodic registration update");
                 start_registration(RegistrationType::PeriodicUpdating);
               }
             }),
      t3520_(loop, "T3520",
             [this] {
               log_.warn(tag_, "T3520 expired: network failed the authentication check");
               if (state_ == MmState::RegisteredInitiated) handle_registration_failure("T3520 expiry");
               if (cb_.abort_connection) cb_.abort_connection();
             }),
      t3521_(loop, "T3521",
             [this] {
               if (state_ != MmState::DeregisteredInitiated) return;
               ++deregistration_attempts_;
               if (deregistration_attempts_ >= config_.max_deregistration_attempts) {
                 log_.warn(tag_, "T3521 expired ", deregistration_attempts_, " times: de-registration aborted locally");
                 set_state(MmState::Deregistered, MmSubState::NormalService);
                 if (cb_.abort_connection) cb_.abort_connection();
                 return;
               }
               log_.info(tag_, "T3521 expired: retransmitting DEREGISTRATION REQUEST");
               const DeregistrationRequestUeOriginating d = make_deregistration_request(false);
               if (mode_ == MmMode::Connected) {
                 send_nas(d);
               } else {
                 send_initial(d);
               }
               t3521_.start(config_.t3521_ms);
             }),
      t3346_(loop, "T3346", [this] {
        if (state_ == MmState::Deregistered && sub_state_ == MmSubState::AttemptingRegistration) {
          log_.info(tag_, "T3346 expired: congestion back-off over, retrying registration");
          start_registration(RegistrationType::Initial);
        }
      }) {}

// ---- Helpers ------------------------------------------------------------------------------------

void UeNas::set_state(MmState s, MmSubState sub) {
  if (s == state_ && sub == sub_state_) return;
  auto full = [](MmState st, MmSubState ss) {
    std::string t = to_string(st);
    if (ss != MmSubState::None) t += std::string(".") + to_string(ss);
    return t;
  };
  log_.info(tag_, full(state_, sub_state_), " -> ", full(s, sub));
  state_ = s;
  sub_state_ = sub;
}

Suci UeNas::suci() const {
  Suci s;
  s.plmn = config_.plmn;
  const std::string& supi = config_.subscription.supi;
  const std::size_t prefix = config_.plmn.mcc.size() + config_.plmn.mnc.size();
  s.msin = supi.size() > prefix ? supi.substr(prefix) : supi;
  return s;
}

std::string UeNas::snn() const { return sec::serving_network_name(config_.plmn.mcc, config_.plmn.mnc); }

void UeNas::delete_identity_and_context() {
  guti_.reset();
  tai_list_.reset();
  ctx_.clear();
  pending_auth_.reset();
  secure_exchange_ = false;
}

void UeNas::send_initial(const PlainMessage& m) {
  const Bytes plain = encode(m);
  Bytes pdu = plain;
  if (ctx_.valid) {
    // Initial NAS message with a valid context: integrity protected, not ciphered (§4.4.6).
    const std::uint32_t count = ctx_.ul_count;
    pdu = protect(ctx_, plain, SecurityHeaderType::IntegrityProtected, sec::Direction::Uplink);
    if (cb_.set_kgnb) cb_.set_kgnb(sec::derive_kgnb(ctx_.kamf, count));
  }
  log_.info(tag_, "-> ", message_name(m), ctx_.valid ? " (integrity protected)" : " (plain)");
  if (mode_ == MmMode::Connected) {
    if (cb_.send) cb_.send(pdu);
    return;
  }
  const std::optional<std::uint64_t> s_tmsi = guti_ ? std::optional<std::uint64_t>(guti_->s_tmsi()) : std::nullopt;
  initial_kind_ = std::holds_alternative<DeregistrationRequestUeOriginating>(m) ? InitialKind::Deregistration
                                                                                : InitialKind::Registration;
  establish_reported_ = false;
  const bool ok = cb_.establish && cb_.establish(rrc::EstablishmentCause::mo_Signalling, pdu, s_tmsi);
  if (!ok && !establish_reported_) {
    // Refused without a reason from RRC: handled like a failed establishment, asynchronously.
    loop_.schedule_in(0, [this] {
      if (state_ == MmState::RegisteredInitiated) handle_registration_failure("RRC connection not established");
    });
  }
}

void UeNas::send_nas(const PlainMessage& m) {
  const Bytes plain = encode(m);
  const Bytes pdu =
      secure_exchange_ ? protect(ctx_, plain, SecurityHeaderType::IntegrityProtectedAndCiphered, sec::Direction::Uplink)
                       : plain;
  log_.info(tag_, "-> ", message_name(m), secure_exchange_ ? "" : " (plain)");
  if (cb_.send) cb_.send(pdu);
}

void UeNas::send_status(Cause cause) {
  ++counters_.status_sent;
  log_.warn(tag_, "sending 5GMM STATUS #", static_cast<int>(cause), " (", to_string(cause), ")");
  send_nas(Status5gmm{cause});
}

// ---- Triggers -----------------------------------------------------------------------------------

void UeNas::power_on() {
  if (state_ != MmState::Null) return;
  attempt_counter_ = 0;
  set_state(MmState::Deregistered, MmSubState::NormalService);
}

void UeNas::power_off() {
  if (state_ == MmState::Registered) deregister(true);
  for (Timer* t : {&t3510_, &t3511_, &t3502_, &t3512_, &t3520_, &t3521_, &t3346_}) t->stop();
  set_state(MmState::Null, MmSubState::None);
}

bool UeNas::register_ue() {
  if (state_ != MmState::Deregistered) {
    log_.warn(tag_, "register_ue() ignored in ", to_string(state_));
    return false;
  }
  if (sub_state_ == MmSubState::NoSupi) {
    log_.warn(tag_, "register_ue() ignored: USIM invalid");
    return false;
  }
  if (t3346_.running()) {
    log_.warn(tag_, "register_ue() ignored: T3346 (congestion back-off) running");
    return false;
  }
  t3511_.stop();
  t3502_.stop();
  attempt_counter_ = 0;
  start_registration(RegistrationType::Initial);
  return true;
}

bool UeNas::deregister(bool switch_off) {
  if (state_ != MmState::Registered) {
    log_.warn(tag_, "deregister() ignored in ", to_string(state_));
    return false;
  }
  const DeregistrationRequestUeOriginating d = make_deregistration_request(switch_off);
  deregistration_switch_off_ = switch_off;
  deregistration_attempts_ = 0;
  t3512_.stop();
  if (mode_ == MmMode::Connected) {
    send_nas(d);
  } else {
    send_initial(d);
  }
  if (switch_off) {
    set_state(MmState::Deregistered, MmSubState::NormalService);
  } else {
    t3521_.start(config_.t3521_ms);
    set_state(MmState::DeregisteredInitiated, MmSubState::None);
  }
  return true;
}

DeregistrationRequestUeOriginating UeNas::make_deregistration_request(bool switch_off) const {
  DeregistrationRequestUeOriginating d;
  d.deregistration_type = DeregistrationType{switch_off, false, 1};
  d.ngksi = ctx_.valid ? ctx_.ngksi : Ngksi{};
  d.mobile_identity = guti_ ? MobileIdentity{*guti_} : MobileIdentity{suci()};
  return d;
}

void UeNas::start_registration(std::uint8_t type) {
  registration_type_ = type;
  state_before_registration_ = state_;
  sub_before_registration_ = sub_state_;
  ++counters_.registration_attempts;
  RegistrationRequest rr;
  rr.registration_type = RegistrationType{false, type};
  rr.ngksi = ctx_.valid ? ctx_.ngksi : Ngksi{};
  rr.mobile_identity = guti_ ? MobileIdentity{*guti_} : MobileIdentity{suci()};
  rr.mm_capability = Bytes{0x00};
  rr.ue_security_capability = config_.security_capability;
  rr.requested_nssai = config_.requested_nssai;
  last_initial_message_ = encode(rr);
  set_state(MmState::RegisteredInitiated, MmSubState::None);
  t3510_.start(config_.t3510_ms);
  send_initial(rr);
}

void UeNas::handle_registration_failure(const char* why) {
  t3510_.stop();
  t3520_.stop();  // the authentication guard belongs to the aborted procedure
  pending_auth_.reset();
  ++attempt_counter_;
  log_.warn(tag_, "registration failed (", why, "), attempt counter ", attempt_counter_);
  if (attempt_counter_ < config_.max_registration_attempts) {
    t3511_.start(config_.t3511_ms);
  } else {
    // §5.5.1.2.7: at the 5th failure delete the 5G-GUTI, TAI list and ngKSI and wait for T3502.
    delete_identity_and_context();
    t3502_.start(config_.t3502_ms);
  }
  set_state(MmState::Deregistered, MmSubState::AttemptingRegistration);
}

// ---- RRC indications ----------------------------------------------------------------------------

void UeNas::on_rrc_connected() {
  mode_ = MmMode::Connected;
  t3512_.stop();
}

void UeNas::on_rrc_released(rrc::ReleaseCause cause) {
  mode_ = MmMode::Idle;
  secure_exchange_ = false;
  pending_auth_.reset();
  if (state_ == MmState::RegisteredInitiated) {
    handle_registration_failure(cause == rrc::ReleaseCause::RrcRelease ? "connection released before REGISTRATION ACCEPT"
                                                                       : "lower layer failure");
  } else if (state_ == MmState::DeregisteredInitiated) {
    t3521_.stop();
    set_state(MmState::Deregistered, MmSubState::NormalService);
  } else if (state_ == MmState::Registered && t3512_ms_ > 0) {
    t3512_.start(t3512_ms_);
  }
}

void UeNas::on_establishment_failure(rrc::EstablishmentFailure f) {
  establish_reported_ = true;
  if (f == rrc::EstablishmentFailure::AccessBarred) {
    on_access_barred();
    return;
  }
  log_.warn(tag_, "RRC establishment failed: ", rrc::to_string(f));
  if (state_ == MmState::RegisteredInitiated) handle_registration_failure(rrc::to_string(f));
}

void UeNas::on_access_barred() {
  // §5.5.1.2.7 b) and §5.5.2.2.6: when the lower layers bar the access attempt the procedure is not
  // started (and not counted as a failure); it is started when the barring is alleviated.
  if (initial_kind_ == InitialKind::Registration && state_ == MmState::RegisteredInitiated) {
    t3510_.stop();
    set_state(state_before_registration_, sub_before_registration_);
    pending_after_barring_ = InitialKind::Registration;
    log_.info(tag_, "access barred: registration postponed until barring is alleviated");
  } else if (initial_kind_ == InitialKind::Deregistration) {
    pending_after_barring_ = InitialKind::Deregistration;
    log_.info(tag_, "access barred: de-registration postponed until barring is alleviated");
  }
}

void UeNas::on_barring_alleviated() {
  log_.info(tag_, "access barring alleviated");
  const std::optional<InitialKind> pending = pending_after_barring_;
  pending_after_barring_.reset();
  if (!pending) return;
  if (*pending == InitialKind::Registration) {
    const bool may_register = (state_ == MmState::Deregistered && sub_state_ != MmSubState::NoSupi &&
                               sub_state_ != MmSubState::LimitedService) ||
                              state_ == MmState::Registered;
    if (may_register && !t3346_.running()) start_registration(registration_type_);
  } else if (state_ == MmState::DeregisteredInitiated) {
    send_initial(make_deregistration_request(false));
    t3521_.start(config_.t3521_ms);
  }
}

// ---- Downlink NAS -------------------------------------------------------------------------------

void UeNas::on_dl_nas(const Bytes& pdu) {
  const auto sht = peek_security_header_type(pdu);
  if (!sht) {
    ++counters_.decode_errors;
    log_.warn(tag_, "ignoring NAS PDU: ", sht.error().message);
    return;
  }

  if (*sht == SecurityHeaderType::Plain) {
    auto msg = decode_plain(pdu);
    if (!msg) {
      ++counters_.decode_errors;
      log_.warn(tag_, msg.error().message);
      const int c = msg.error().code;
      if (c == static_cast<int>(Cause::MessageTypeNonExistent) || c == static_cast<int>(Cause::InvalidMandatoryInformation)) {
        send_status(static_cast<Cause>(c));
      }
      return;
    }
    // §4.4.4.2: the only messages processed without integrity protection.
    const bool allowed =
        std::holds_alternative<AuthenticationRequest>(*msg) || std::holds_alternative<AuthenticationReject>(*msg) ||
        std::holds_alternative<RegistrationReject>(*msg) ||
        std::holds_alternative<DeregistrationAcceptUeOriginating>(*msg) ||
        (std::holds_alternative<IdentityRequest>(*msg) &&
         std::get<IdentityRequest>(*msg).identity_type == IdentityType::Suci);
    if (!allowed) {
      ++counters_.discarded_plain;
      log_.warn(tag_, "discarding unprotected ", message_name(*msg), " (TS 24.501 4.4.4.2)");
      return;
    }
    dispatch(*msg, false);
    return;
  }

  if (*sht == SecurityHeaderType::IntegrityProtectedWithNewContext) {
    auto secured = parse_secured(pdu);
    auto inner = secured ? decode_plain(secured->payload) : Result<PlainMessage>(Error{"malformed"});
    if (!inner || !std::holds_alternative<SecurityModeCommand>(*inner)) {
      ++counters_.decode_errors;
      log_.warn(tag_, "discarding message with 'new security context' header that is not a SECURITY MODE COMMAND");
      return;
    }
    handle_security_mode_command(pdu, std::get<SecurityModeCommand>(*inner));
    return;
  }

  if (*sht == SecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext || !ctx_.valid) {
    ++counters_.integrity_failures;
    log_.warn(tag_, "discarding protected NAS message: no usable security context");
    return;
  }
  auto un = unprotect(ctx_, pdu, sec::Direction::Downlink);
  if (!un) {
    ++counters_.integrity_failures;
    log_.warn(tag_, "discarding NAS message: ", un.error().message);
    return;
  }
  auto msg = decode_plain(un->plain);
  if (!msg) {
    ++counters_.decode_errors;
    log_.warn(tag_, msg.error().message);
    const int c = msg.error().code;
    if (c == static_cast<int>(Cause::MessageTypeNonExistent) || c == static_cast<int>(Cause::InvalidMandatoryInformation)) {
      secure_exchange_ = true;
      send_status(static_cast<Cause>(c));
    }
    return;
  }
  secure_exchange_ = true;
  dispatch(*msg, true);
}

void UeNas::dispatch(const PlainMessage& m, bool integrity_protected) {
  log_.info(tag_, "<- ", message_name(m), integrity_protected ? "" : " (plain)");
  std::visit(overloaded{
                 [&](const IdentityRequest& x) { handle(x, integrity_protected); },
                 [&](const AuthenticationRequest& x) { handle(x); },
                 [&](const AuthenticationReject& x) { handle(x); },
                 [&](const RegistrationAccept& x) { handle(x); },
                 [&](const RegistrationReject& x) { handle(x, integrity_protected); },
                 [&](const DeregistrationAcceptUeOriginating& x) { handle(x); },
                 [&](const SecurityModeCommand&) {
                   // Re-keying with an existing context is not supported.
                   send_nas(SecurityModeReject{Cause::SecurityModeRejectedUnspecified});
                 },
                 [&](const Status5gmm& x) {
                   log_.warn(tag_, "5GMM STATUS from network, cause #", static_cast<int>(x.cause));
                 },
                 [&](const auto&) {
                   // A message only defined in the uplink direction.
                   send_status(Cause::MessageTypeNonExistent);
                 }},
             m);
}

void UeNas::handle(const IdentityRequest& m, bool) {
  IdentityResponse r;
  switch (m.identity_type) {
    case IdentityType::Suci: r.mobile_identity = suci(); break;
    case IdentityType::Guti:
      r.mobile_identity = guti_ ? MobileIdentity{*guti_} : MobileIdentity{NoIdentity{}};
      break;
    case IdentityType::Imeisv: r.mobile_identity = Imeisv{config_.imeisv}; break;
    case IdentityType::Imei: r.mobile_identity = Imei{imei_from_imeisv(config_.imeisv)}; break;
    case IdentityType::STmsi:
      r.mobile_identity = guti_ ? MobileIdentity{STmsi5g{guti_->amf_set_id, guti_->amf_pointer, guti_->tmsi}}
                                : MobileIdentity{NoIdentity{}};
      break;
    default: r.mobile_identity = NoIdentity{}; break;
  }
  send_nas(r);
}

void UeNas::handle(const AuthenticationRequest& m) {
  if (!m.rand || !m.autn) {
    send_status(Cause::ConditionalIeError);
    return;
  }
  auto fail = [&](Cause cause, std::optional<Auts> auts) {
    ++counters_.auth_failures_sent;
    log_.warn(tag_, "authentication failed: #", static_cast<int>(cause), " ", to_string(cause));
    send_nas(AuthenticationFailure{cause, auts});
    t3520_.start(config_.t3520_ms);
  };
  // §5.4.1.3.7 c): the ngKSI is already associated with a context in the UE.
  if (ctx_.valid && !m.ngksi.mapped && m.ngksi.ksi == ctx_.ngksi.ksi) {
    return fail(Cause::NgksiAlreadyInUse, std::nullopt);
  }
  const auto res = usim_.authenticate(*m.rand, *m.autn, snn());
  switch (res.status) {
    case sec::Usim::AuthStatus::MacFailure: return fail(Cause::MacFailure, std::nullopt);
    case sec::Usim::AuthStatus::Non5gAuthUnacceptable: return fail(Cause::Non5gAuthenticationUnacceptable, std::nullopt);
    case sec::Usim::AuthStatus::SynchFailure: return fail(Cause::SynchFailure, res.auts);
    case sec::Usim::AuthStatus::Ok: break;
  }
  t3520_.stop();
  pending_auth_ = PendingAuth{m.ngksi, sec::derive_kamf(res.kseaf, config_.subscription.supi, m.abba)};
  AuthenticationResponse resp;
  ResStar rs{};
  std::copy(res.res_star.begin(), res.res_star.end(), rs.begin());
  resp.res_star = rs;
  send_nas(resp);
}

void UeNas::handle(const AuthenticationReject&) {
  log_.warn(tag_, "AUTHENTICATION REJECT: USIM considered invalid");
  for (Timer* t : {&t3510_, &t3511_, &t3502_, &t3520_, &t3521_}) t->stop();
  delete_identity_and_context();
  set_state(MmState::Deregistered, MmSubState::NoSupi);
  loop_.schedule_in(0, [this] {
    if (cb_.abort_connection) cb_.abort_connection();
  });
}

void UeNas::handle_security_mode_command(const Bytes& pdu, const SecurityModeCommand& m) {
  auto reject = [&](Cause cause, const char* why) {
    log_.warn(tag_, "SECURITY MODE COMMAND not accepted: ", why);
    send_nas(SecurityModeReject{cause});
  };
  log_.info(tag_, "<- SecurityModeCommand (new context, ngKSI ", int{m.ngksi.ksi}, ")");
  if (!pending_auth_ || pending_auth_->ngksi.ksi != m.ngksi.ksi) {
    return reject(Cause::SecurityModeRejectedUnspecified, "ngKSI does not identify a context from authentication");
  }
  if (m.replayed_ue_security_capability != config_.security_capability) {
    return reject(Cause::UeSecurityCapabilitiesMismatch, "replayed UE security capabilities do not match");
  }
  const NasSecurityAlgorithms& algs = m.selected_algorithms;
  if (algs.integrity == 0) return reject(Cause::SecurityModeRejectedUnspecified, "5G-IA0 not allowed");
  if (!config_.security_capability.supports_ia(algs.integrity) || !integrity_algorithm_supported(algs.integrity) ||
      !config_.security_capability.supports_ea(algs.ciphering) || !ciphering_algorithm_supported(algs.ciphering)) {
    return reject(Cause::UeSecurityCapabilitiesMismatch, "selected algorithm not supported");
  }
  NasSecurityContext candidate;
  candidate.activate(pending_auth_->kamf, algs, m.ngksi);
  auto un = unprotect(candidate, pdu, sec::Direction::Downlink);
  if (!un) {
    ++counters_.integrity_failures;
    return reject(Cause::SecurityModeRejectedUnspecified, "integrity check failed");
  }

  ctx_ = candidate;
  pending_auth_.reset();
  secure_exchange_ = true;
  SecurityModeComplete c;
  if (m.imeisv_request.value_or(false)) c.imeisv = Imeisv{config_.imeisv};
  if (m.additional_security_information && (*m.additional_security_information & 0x02) != 0) {
    c.nas_message_container = last_initial_message_;  // RINMR: resend the complete initial message
  }
  const std::uint32_t count = ctx_.ul_count;
  const Bytes out = protect(ctx_, encode(c), SecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext,
                            sec::Direction::Uplink);
  log_.info(tag_, "-> SecurityModeComplete: NAS security context taken into use (EA", int{algs.ciphering}, ", IA",
            int{algs.integrity}, ")");
  if (cb_.send) cb_.send(out);
  if (cb_.set_kgnb) cb_.set_kgnb(sec::derive_kgnb(ctx_.kamf, count));
}

void UeNas::handle(const RegistrationAccept& m) {
  if (state_ == MmState::Registered) {
    // Retransmission by the network (T3550): acknowledge again.
    if (m.guti) {
      guti_ = *m.guti;
      send_nas(RegistrationComplete{});
    }
    return;
  }
  if (state_ != MmState::RegisteredInitiated) {
    send_status(Cause::MessageTypeNotCompatibleWithProtocolState);
    return;
  }
  for (Timer* t : {&t3510_, &t3511_, &t3502_, &t3520_}) t->stop();
  attempt_counter_ = 0;
  if (m.guti) guti_ = *m.guti;
  if (m.tai_list) tai_list_ = *m.tai_list;
  if (m.t3512) {
    const auto s = m.t3512->seconds_timer3();
    t3512_ms_ = s ? TimeMs{*s} * 1000 : 0;
  }
  if (m.t3502) {
    const auto s = m.t3502->seconds_timer2();
    if (s) config_.t3502_ms = TimeMs{*s} * 1000;
  }
  set_state(MmState::Registered, MmSubState::NormalService);
  if (m.guti) send_nas(RegistrationComplete{});
}

void UeNas::handle(const RegistrationReject& m, bool integrity_protected) {
  if (state_ != MmState::RegisteredInitiated) {
    send_status(Cause::MessageTypeNotCompatibleWithProtocolState);
    return;
  }
  t3510_.stop();
  t3520_.stop();
  const int cause = static_cast<int>(m.cause);
  log_.warn(tag_, "REGISTRATION REJECT #", cause, " (", to_string(m.cause), ")");
  switch (m.cause) {
    case Cause::IllegalUe:
    case Cause::IllegalMe:
    case Cause::FiveGsServicesNotAllowed:
      delete_identity_and_context();
      attempt_counter_ = 0;
      set_state(MmState::Deregistered, MmSubState::NoSupi);
      break;
    case Cause::PlmnNotAllowed:
    case Cause::N1ModeNotAllowed:
      delete_identity_and_context();
      attempt_counter_ = 0;
      set_state(MmState::Deregistered, MmSubState::LimitedService);
      break;
    case Cause::TrackingAreaNotAllowed:
    case Cause::RoamingNotAllowedInTrackingArea:
    case Cause::NoSuitableCellsInTrackingArea:
      tai_list_.reset();
      attempt_counter_ = 0;
      set_state(MmState::Deregistered, MmSubState::LimitedService);
      break;
    case Cause::Congestion: {
      // §5.5.1.2.5 #22: the T3346 value IE is only trusted from an integrity protected message;
      // otherwise T3346 gets a random value from the default range (15-30 min, TS 24.008).
      std::optional<std::uint32_t> secs;
      if (integrity_protected && m.t3346) secs = m.t3346->seconds_timer2();
      const TimeMs ms = secs && *secs > 0
                            ? TimeMs{*secs} * 1000
                            : std::uniform_int_distribution<TimeMs>(15 * 60 * 1000, 30 * 60 * 1000)(rng_);
      t3346_.start(ms);
      set_state(MmState::Deregistered, MmSubState::AttemptingRegistration);
      break;
    }
    default: handle_registration_failure("REGISTRATION REJECT with other cause"); break;
  }
}

void UeNas::handle(const DeregistrationAcceptUeOriginating&) {
  if (state_ != MmState::DeregisteredInitiated) {
    send_status(Cause::MessageTypeNotCompatibleWithProtocolState);
    return;
  }
  t3521_.stop();
  set_state(MmState::Deregistered, MmSubState::NormalService);
}

}  // namespace nrlite::nas
