#include "nrlite/core/amf.hpp"

#include <algorithm>
#include <memory>
#include <string>

#include "nrlite/security/kdf.hpp"

namespace nrlite::core {

using namespace nrlite::nas;

const char* to_string(AmfUeState s) {
  switch (s) {
    case AmfUeState::Deregistered: return "5GMM-DEREGISTERED";
    case AmfUeState::CommonProcedureInitiated: return "5GMM-COMMON-PROCEDURE-INITIATED";
    case AmfUeState::Registered: return "5GMM-REGISTERED";
    case AmfUeState::DeregisteredInitiated: return "5GMM-DEREGISTERED-INITIATED";
  }
  return "?";
}

struct Amf::UeContext {
  std::uint32_t amf_ue_id = 0;
  std::optional<std::uint32_t> ran_ue_id;
  bool connected = false;
  std::string supi;
  AmfUeState state = AmfUeState::Deregistered;
  Proc proc = Proc::None;

  NasSecurityContext ctx;        ///< current context
  NasSecurityContext candidate;  ///< context being established by SECURITY MODE COMMAND
  bool secure_exchange = false;

  std::optional<sec::HeAuthVector> av;
  Ngksi auth_ngksi;
  Bytes abba{0x00, 0x00};
  sec::Key256 kamf_pending{};
  unsigned resyncs = 0;

  std::optional<Guti5g> guti;
  UeSecurityCapability ue_caps;
  std::vector<SNssai> requested_nssai;
  bool follow_on = false;
  std::optional<RegistrationRequest> pending_registration;
  std::optional<SecurityModeCommand> pending_smc;
  std::optional<RegistrationAccept> pending_accept;
  unsigned retransmissions = 0;

  std::unique_ptr<Timer> t3550, t3560, t3570;
  std::optional<EventLoop::EventId> release_event;
};

Amf::Amf(EventLoop& loop, const Logger& log, AmfConfig config, std::mt19937_64& rng)
    : loop_(loop), log_(log), config_(std::move(config)), rng_(rng) {}

Amf::~Amf() {
  for (auto& [id, ue] : contexts_) {
    if (ue->release_event) loop_.cancel(*ue->release_event);
  }
}

void Amf::add_subscriber(const sec::Subscription& sub, std::uint64_t sqn) { subscribers_[sub.supi] = Subscriber{sub, sqn}; }

std::optional<Amf::UeView> Amf::ue(const std::string& supi) const {
  for (const auto& [id, ue] : contexts_) {
    if (ue->supi != supi) continue;
    UeView v;
    v.amf_ue_id = ue->amf_ue_id;
    v.supi = ue->supi;
    v.state = ue->state;
    v.connected = ue->connected;
    v.security_active = ue->ctx.valid;
    v.guti = ue->guti;
    v.ul_count = ue->ctx.ul_count;
    v.dl_count = ue->ctx.dl_count;
    return v;
  }
  return std::nullopt;
}

std::optional<std::uint64_t> Amf::subscriber_sqn(const std::string& supi) const {
  auto it = subscribers_.find(supi);
  if (it == subscribers_.end()) return std::nullopt;
  return it->second.sqn;
}

std::string Amf::snn() const { return sec::serving_network_name(config_.plmn.mcc, config_.plmn.mnc); }

std::string Amf::tag(const UeContext& ue) const {
  return "AMF[" + (ue.supi.empty() ? "ue-" + std::to_string(ue.amf_ue_id) : ue.supi) + "]";
}

// ---- Context bookkeeping ------------------------------------------------------------------------

Amf::UeContext* Amf::find_by_amf_id(std::uint32_t id) {
  auto it = contexts_.find(id);
  return it == contexts_.end() ? nullptr : it->second.get();
}

Amf::UeContext* Amf::find_by_ran_id(std::uint32_t id) {
  for (auto& [k, ue] : contexts_) {
    if (ue->connected && ue->ran_ue_id == id) return ue.get();
  }
  return nullptr;
}

Amf::UeContext* Amf::find_by_supi(const std::string& supi) {
  for (auto& [k, ue] : contexts_) {
    if (!supi.empty() && ue->supi == supi) return ue.get();
  }
  return nullptr;
}

Amf::UeContext* Amf::find_by_tmsi(std::uint32_t tmsi) {
  for (auto& [k, ue] : contexts_) {
    if (ue->guti && ue->guti->tmsi == tmsi) return ue.get();
  }
  return nullptr;
}

Amf::UeContext& Amf::create_context() {
  auto ue = std::make_unique<UeContext>();
  ue->amf_ue_id = next_amf_ue_id_++;
  const std::uint32_t id = ue->amf_ue_id;
  ue->t3550 = std::make_unique<Timer>(loop_, "T3550", [this, id] { on_retransmission_timer(id, "T3550"); });
  ue->t3560 = std::make_unique<Timer>(loop_, "T3560", [this, id] { on_retransmission_timer(id, "T3560"); });
  ue->t3570 = std::make_unique<Timer>(loop_, "T3570", [this, id] { on_retransmission_timer(id, "T3570"); });
  UeContext& ref = *ue;
  contexts_[id] = std::move(ue);
  return ref;
}

void Amf::erase_context(std::uint32_t amf_ue_id) {
  auto it = contexts_.find(amf_ue_id);
  if (it == contexts_.end()) return;
  std::shared_ptr<UeContext> doomed(it->second.release());
  contexts_.erase(it);
  for (Timer* t : {doomed->t3550.get(), doomed->t3560.get(), doomed->t3570.get()}) t->stop();
  if (doomed->release_event) loop_.cancel(*doomed->release_event);
  loop_.schedule_in(0, [doomed] {});  // destroy outside any timer callback of this context
}

// ---- N2 entry points ----------------------------------------------------------------------------

void Amf::on_n2(const n2::Message& msg) {
  std::visit(overloaded{
                 [&](const n2::InitialUeMessage& m) { on_initial_ue_message(m); },
                 [&](const n2::UplinkNasTransport& m) {
                   UeContext* ue = find_by_amf_id(m.amf_ue_id);
                   if (ue == nullptr || !ue->connected || ue->ran_ue_id != m.ran_ue_id) ue = find_by_ran_id(m.ran_ue_id);
                   if (ue == nullptr) {
                     log_.warn("AMF", "UplinkNASTransport for unknown UE ignored");
                     return;
                   }
                   handle_ul_nas(*ue, m.nas_pdu);
                 },
                 [&](const n2::InitialContextSetupResponse& m) {
                   if (UeContext* ue = find_by_ran_id(m.ran_ue_id)) log_.info(tag(*ue), "InitialContextSetupResponse");
                 },
                 [&](const n2::InitialContextSetupFailure& m) {
                   if (UeContext* ue = find_by_ran_id(m.ran_ue_id)) {
                     log_.warn(tag(*ue), "InitialContextSetupFailure (", m.cause, ")");
                     abort_procedure(*ue, "AS security setup failed");
                   }
                 },
                 [&](const n2::UeContextReleaseRequest& m) {
                   if (UeContext* ue = find_by_ran_id(m.ran_ue_id)) {
                     log_.info(tag(*ue), "UEContextReleaseRequest (", m.cause, ")");
                     if (ue->proc != Proc::None) abort_procedure(*ue, m.cause);
                     else schedule_release(*ue, m.cause);
                   }
                 },
                 [&](const n2::UeContextReleaseComplete& m) {
                   UeContext* ue = find_by_amf_id(m.amf_ue_id);
                   if (ue == nullptr || ue->ran_ue_id != m.ran_ue_id) ue = find_by_ran_id(m.ran_ue_id);
                   if (ue == nullptr) return;
                   log_.info(tag(*ue), "UEContextReleaseComplete: NAS signalling connection released");
                   ue->connected = false;
                   ue->ran_ue_id.reset();
                   ue->secure_exchange = false;
                   ue->t3560->stop();
                   ue->t3570->stop();
                   if (ue->state == AmfUeState::CommonProcedureInitiated) ue->state = AmfUeState::Deregistered;
                   if (ue->supi.empty() && !ue->guti) erase_context(ue->amf_ue_id);
                 },
                 [&](const auto& other) {
                   log_.warn("AMF", "unexpected N2 message ", n2::name(n2::Message{other}), " ignored");
                 }},
             msg);
}

void Amf::on_initial_ue_message(const n2::InitialUeMessage& m) {
  // Release a stale association for the same RAN UE id, if any.
  if (UeContext* stale = find_by_ran_id(m.ran_ue_id)) {
    stale->connected = false;
    stale->ran_ue_id.reset();
  }

  const auto sht = peek_security_header_type(m.nas_pdu);
  Bytes plain;
  if (sht && *sht == SecurityHeaderType::Plain) {
    plain = m.nas_pdu;
  } else if (sht && *sht == SecurityHeaderType::IntegrityProtected) {
    auto s = parse_secured(m.nas_pdu);
    if (s) plain = s->payload;  // initial NAS messages are integrity protected but not ciphered
  }
  auto msg = plain.empty() ? Result<PlainMessage>(Error{"undecodable initial NAS message", 111}) : decode_plain(plain);

  // Locate an existing context by the identity in the message (or the 5G-S-TMSI from RRC).
  UeContext* ue = nullptr;
  const MobileIdentity* id = nullptr;
  if (msg) {
    if (const auto* rr = std::get_if<RegistrationRequest>(&*msg)) id = &rr->mobile_identity;
    if (const auto* dr = std::get_if<DeregistrationRequestUeOriginating>(&*msg)) id = &dr->mobile_identity;
  }
  if (id != nullptr) {
    if (const auto* g = std::get_if<Guti5g>(id)) ue = find_by_tmsi(g->tmsi);
    if (const auto* s = std::get_if<Suci>(id); s != nullptr && s->protection_scheme_id == 0) ue = find_by_supi(s->supi());
  }
  if (ue == nullptr && m.five_g_s_tmsi) ue = find_by_tmsi(static_cast<std::uint32_t>(*m.five_g_s_tmsi & 0xFFFFFFFF));
  if (ue == nullptr) ue = &create_context();

  if (ue->release_event) {
    loop_.cancel(*ue->release_event);
    ue->release_event.reset();
  }
  ue->ran_ue_id = m.ran_ue_id;
  ue->connected = true;
  ue->secure_exchange = false;
  ue->proc = Proc::None;
  for (Timer* t : {ue->t3550.get(), ue->t3560.get(), ue->t3570.get()}) t->stop();

  if (!msg) {
    ++counters_.decode_errors;
    log_.warn(tag(*ue), "initial NAS message not decodable: ", msg.error().message);
    if (m.nas_pdu.size() >= 3 && m.nas_pdu[2] == static_cast<std::uint8_t>(MessageType::RegistrationRequest) &&
        msg.error().code == static_cast<int>(Cause::InvalidMandatoryInformation)) {
      reject_registration(*ue, Cause::InvalidMandatoryInformation);
    } else {
      schedule_release(*ue, "NAS decoding error");
    }
    return;
  }

  bool integrity_ok = false;
  std::uint32_t count = 0;
  if (*sht == SecurityHeaderType::IntegrityProtected) {
    if (ue->ctx.valid) {
      auto un = unprotect(ue->ctx, m.nas_pdu, sec::Direction::Uplink);
      if (un) {
        integrity_ok = true;
        count = un->count;
      } else {
        ++counters_.integrity_failures;
        log_.warn(tag(*ue), "initial NAS message failed integrity check: re-authenticating");
      }
    }
  }

  if (const auto* rr = std::get_if<RegistrationRequest>(&*msg)) {
    on_registration_request(*ue, *rr, integrity_ok, count);
  } else if (const auto* dr = std::get_if<DeregistrationRequestUeOriginating>(&*msg)) {
    ue->secure_exchange = integrity_ok;
    on_deregistration_request(*ue, *dr);
  } else {
    log_.warn(tag(*ue), message_name(*msg), " is not an initial NAS message");
    send_status(*ue, Cause::MessageNotCompatibleWithProtocolState);
    schedule_release(*ue, "unexpected initial NAS message");
  }
}

void Amf::handle_ul_nas(UeContext& ue, const Bytes& pdu) {
  const auto sht = peek_security_header_type(pdu);
  if (!sht) {
    ++counters_.decode_errors;
    log_.warn(tag(ue), "ignoring UL NAS PDU: ", sht.error().message);
    return;
  }

  if (*sht == SecurityHeaderType::Plain) {
    auto msg = decode_plain(pdu);
    if (!msg) {
      ++counters_.decode_errors;
      log_.warn(tag(ue), msg.error().message);
      const int c = msg.error().code;
      if (c == static_cast<int>(Cause::MessageTypeNonExistent) || c == static_cast<int>(Cause::InvalidMandatoryInformation)) {
        send_status(ue, static_cast<Cause>(c));
      }
      return;
    }
    // §4.4.4.3: messages the AMF processes without integrity protection.
    const bool before_security =
        std::holds_alternative<RegistrationRequest>(*msg) || std::holds_alternative<AuthenticationResponse>(*msg) ||
        std::holds_alternative<AuthenticationFailure>(*msg) || std::holds_alternative<SecurityModeReject>(*msg) ||
        std::holds_alternative<DeregistrationRequestUeOriginating>(*msg) || std::holds_alternative<Status5gmm>(*msg) ||
        (std::holds_alternative<IdentityResponse>(*msg) &&
         std::holds_alternative<Suci>(std::get<IdentityResponse>(*msg).mobile_identity));
    const bool after_security = std::holds_alternative<AuthenticationFailure>(*msg) ||
                                std::holds_alternative<SecurityModeReject>(*msg) || std::holds_alternative<Status5gmm>(*msg);
    if (!(ue.secure_exchange ? after_security : before_security)) {
      ++counters_.discarded_plain;
      log_.warn(tag(ue), "discarding unprotected ", message_name(*msg), " (TS 24.501 4.4.4.3)");
      return;
    }
    dispatch(ue, *msg, false, 0);
    return;
  }

  if (*sht == SecurityHeaderType::IntegrityProtectedAndCipheredWithNewContext) {
    if (ue.proc != Proc::SecurityMode || !ue.candidate.valid) {
      ++counters_.integrity_failures;
      log_.warn(tag(ue), "unexpected message protected with a new context: discarded");
      return;
    }
    auto un = unprotect(ue.candidate, pdu, sec::Direction::Uplink);
    if (!un) {
      ++counters_.integrity_failures;
      log_.warn(tag(ue), "SECURITY MODE COMPLETE failed integrity check: discarded");
      return;
    }
    auto msg = decode_plain(un->plain);
    if (!msg || !std::holds_alternative<SecurityModeComplete>(*msg)) {
      ++counters_.decode_errors;
      log_.warn(tag(ue), "expected SECURITY MODE COMPLETE under the new context");
      return;
    }
    on_security_mode_complete(ue, std::get<SecurityModeComplete>(*msg), un->count);
    return;
  }

  if (*sht == SecurityHeaderType::IntegrityProtectedWithNewContext || !ue.ctx.valid) {
    ++counters_.integrity_failures;
    log_.warn(tag(ue), "protected UL NAS message without a usable context: discarded");
    return;
  }
  auto un = unprotect(ue.ctx, pdu, sec::Direction::Uplink);
  if (!un) {
    ++counters_.integrity_failures;
    log_.warn(tag(ue), "discarding UL NAS message: ", un.error().message);
    return;
  }
  auto msg = decode_plain(un->plain);
  if (!msg) {
    ++counters_.decode_errors;
    log_.warn(tag(ue), msg.error().message);
    return;
  }
  ue.secure_exchange = true;
  dispatch(ue, *msg, true, un->count);
}

void Amf::dispatch(UeContext& ue, const PlainMessage& m, bool integrity_ok, std::uint32_t count) {
  log_.info(tag(ue), "<- ", message_name(m), integrity_ok ? "" : " (plain)");
  std::visit(overloaded{
                 [&](const RegistrationRequest& x) { on_registration_request(ue, x, integrity_ok, count); },
                 [&](const DeregistrationRequestUeOriginating& x) { on_deregistration_request(ue, x); },
                 [&](const AuthenticationResponse& x) { on_authentication_response(ue, x); },
                 [&](const AuthenticationFailure& x) { on_authentication_failure(ue, x); },
                 [&](const IdentityResponse& x) { on_identity_response(ue, x); },
                 [&](const RegistrationComplete&) { on_registration_complete(ue); },
                 [&](const SecurityModeReject& x) {
                   if (ue.proc != Proc::SecurityMode) return;
                   log_.warn(tag(ue), "SECURITY MODE REJECT #", static_cast<int>(x.cause));
                   ue.candidate.clear();
                   abort_procedure(ue, "security mode rejected");
                 },
                 [&](const SecurityModeComplete&) {
                   log_.warn(tag(ue), "SECURITY MODE COMPLETE without the new-context header: ignored");
                 },
                 [&](const Status5gmm& x) {
                   log_.warn(tag(ue), "5GMM STATUS from UE, cause #", static_cast<int>(x.cause));
                 },
                 [&](const auto&) { send_status(ue, Cause::MessageTypeNonExistent); }},
             m);
}

// ---- Registration -------------------------------------------------------------------------------

void Amf::on_registration_request(UeContext& ue, const RegistrationRequest& rr, bool integrity_ok,
                                  std::uint32_t count) {
  ue.follow_on = rr.registration_type.follow_on_request;
  if (rr.ue_security_capability) ue.ue_caps = *rr.ue_security_capability;
  if (rr.requested_nssai) ue.requested_nssai = *rr.requested_nssai;
  ue.state = AmfUeState::CommonProcedureInitiated;

  if (config_.reject_registrations_with) return reject_registration(ue, *config_.reject_registrations_with);
  if (!rr.ue_security_capability && !integrity_ok) {
    // The UE must include its security capabilities unless it is integrity protected with a
    // context the AMF already holds (TS 24.501 §5.5.1.2.2).
    return reject_registration(ue, Cause::InvalidMandatoryInformation);
  }

  if (ue.supi.empty()) {
    if (const auto* s = std::get_if<Suci>(&rr.mobile_identity)) {
      if (s->protection_scheme_id != 0) return reject_registration(ue, Cause::UeIdentityCannotBeDerived);
      ue.supi = s->supi();
    } else {
      ue.pending_registration = rr;
      return start_identification(ue);
    }
  }
  continue_registration(ue, integrity_ok, count);
}

void Amf::continue_registration(UeContext& ue, bool integrity_ok, std::uint32_t count) {
  if (subscribers_.count(ue.supi) == 0) {
    log_.warn(tag(ue), "unknown subscriber");
    return reject_registration(ue, config_.unknown_subscriber_cause);
  }
  if (integrity_ok && ue.ctx.valid) {
    log_.info(tag(ue), "registration request integrity protected with the stored context: no re-authentication");
    ue.secure_exchange = true;
    return accept_registration(ue, count);
  }
  start_authentication(ue);
}

void Amf::start_identification(UeContext& ue) {
  log_.info(tag(ue), "unknown 5G-GUTI: starting identification (SUCI)");
  ue.proc = Proc::Identification;
  ue.retransmissions = 0;
  send_nas(ue, IdentityRequest{IdentityType::Suci});
  ue.t3570->start(config_.t3570_ms);
}

void Amf::on_identity_response(UeContext& ue, const IdentityResponse& m) {
  if (ue.proc != Proc::Identification) {
    log_.warn(tag(ue), "unexpected IDENTITY RESPONSE ignored");
    return;
  }
  ue.t3570->stop();
  ue.proc = Proc::None;
  const auto* s = std::get_if<Suci>(&m.mobile_identity);
  if (s == nullptr || s->protection_scheme_id != 0) return reject_registration(ue, Cause::UeIdentityCannotBeDerived);
  const std::string supi = s->supi();
  if (UeContext* other = find_by_supi(supi); other != nullptr && other != &ue) {
    // A context for this SUPI exists under an older identity: keep it, drop the temporary one.
    other->ran_ue_id = ue.ran_ue_id;
    other->connected = true;
    other->secure_exchange = false;
    other->pending_registration = ue.pending_registration;
    other->ue_caps = ue.ue_caps;
    other->requested_nssai = ue.requested_nssai;
    other->state = AmfUeState::CommonProcedureInitiated;
    const std::uint32_t temp = ue.amf_ue_id;
    ue.connected = false;
    erase_context(temp);
    return continue_registration(*other, false, 0);
  }
  ue.supi = supi;
  continue_registration(ue, false, 0);
}

void Amf::start_authentication(UeContext& ue) {
  Subscriber& sub = subscribers_.at(ue.supi);
  sub.sqn += 1;
  sec::Block rand{};
  for (auto& b : rand) b = static_cast<std::uint8_t>(rng_());
  ue.av = sec::generate_he_av(sub.sub, rand, sub.sqn, snn());
  const std::uint8_t base = ue.ctx.valid ? ue.ctx.ngksi.ksi : ue.auth_ngksi.ksi;
  ue.auth_ngksi = Ngksi{false, static_cast<std::uint8_t>(base == Ngksi::kNoKey ? 0 : (base + 1) % 7)};
  ue.proc = Proc::Authentication;
  ue.retransmissions = 0;
  ++counters_.authentications;
  log_.info(tag(ue), "5G-AKA: AUTHENTICATION REQUEST (ngKSI ", int{ue.auth_ngksi.ksi}, ", SQN ", sub.sqn, ")");
  AuthenticationRequest req;
  req.ngksi = ue.auth_ngksi;
  req.abba = ue.abba;
  req.rand = ue.av->rand;
  req.autn = ue.av->autn;
  send_nas(ue, req);
  ue.t3560->start(config_.t3560_ms);
}

void Amf::on_authentication_response(UeContext& ue, const AuthenticationResponse& m) {
  if (ue.proc != Proc::Authentication || !ue.av) {
    log_.warn(tag(ue), "unexpected AUTHENTICATION RESPONSE ignored");
    return;
  }
  ue.t3560->stop();
  bool ok = false;
  if (m.res_star) {
    sec::Key128 res{};
    std::copy(m.res_star->begin(), m.res_star->end(), res.begin());
    const sec::Key128 hres = sec::derive_hres_star(ue.av->rand, res);
    // SEAF compares HRES* with HXRES*, then the AUSF compares RES* with XRES*.
    ok = sec::equal_ct(hres.data(), ue.av->hxres_star.data(), 16) &&
         sec::equal_ct(res.data(), ue.av->xres_star.data(), 16);
  }
  if (!ok) {
    ++counters_.auth_failures;
    log_.warn(tag(ue), "RES* verification failed");
    return send_authentication_reject(ue);
  }
  ue.kamf_pending = sec::derive_kamf(ue.av->kseaf, ue.supi, ue.abba);
  ue.resyncs = 0;
  start_security_mode(ue);
}

void Amf::on_authentication_failure(UeContext& ue, const AuthenticationFailure& m) {
  if (ue.proc != Proc::Authentication || !ue.av) {
    log_.warn(tag(ue), "unexpected AUTHENTICATION FAILURE ignored");
    return;
  }
  ue.t3560->stop();
  ++counters_.auth_failures;
  log_.warn(tag(ue), "AUTHENTICATION FAILURE #", static_cast<int>(m.cause), " (", to_string(m.cause), ")");
  switch (m.cause) {
    case Cause::SynchFailure: {
      if (!m.auts || ue.resyncs >= 2) return send_authentication_reject(ue);
      const auto sqn_ms = sec::verify_auts(subscribers_.at(ue.supi).sub, ue.av->rand, *m.auts);
      if (!sqn_ms) {
        log_.warn(tag(ue), "AUTS MAC-S verification failed");
        return send_authentication_reject(ue);
      }
      ++ue.resyncs;
      ++counters_.resyncs;
      subscribers_.at(ue.supi).sqn = *sqn_ms;
      log_.info(tag(ue), "SQN re-synchronised to ", *sqn_ms);
      return start_authentication(ue);
    }
    case Cause::NgksiAlreadyInUse:
      ue.auth_ngksi.ksi = static_cast<std::uint8_t>((ue.auth_ngksi.ksi + 1) % 7);
      return start_authentication(ue);
    default: return abort_procedure(ue, "authentication failure reported by UE");
  }
}

void Amf::send_authentication_reject(UeContext& ue) {
  send_nas(ue, AuthenticationReject{});
  ue.proc = Proc::None;
  ue.state = AmfUeState::Deregistered;
  ue.ctx.clear();
  schedule_release(ue, "authentication rejected");
}

void Amf::start_security_mode(UeContext& ue) {
  auto pick = [](const std::vector<std::uint8_t>& prefs, auto supported_by_ue, auto implemented) -> std::optional<std::uint8_t> {
    for (std::uint8_t a : prefs) {
      if (supported_by_ue(a) && implemented(a)) return a;
    }
    return std::nullopt;
  };
  const auto ia = pick(
      config_.integrity_preference, [&](std::uint8_t a) { return a != 0 && ue.ue_caps.supports_ia(a); },
      integrity_algorithm_supported);
  const auto ea = pick(
      config_.ciphering_preference, [&](std::uint8_t a) { return ue.ue_caps.supports_ea(a); },
      ciphering_algorithm_supported);
  if (!ia || !ea) {
    log_.warn(tag(ue), "no common NAS security algorithm");
    return reject_registration(ue, Cause::UeSecurityCapabilitiesMismatch);
  }
  const NasSecurityAlgorithms algs{*ea, *ia};
  ue.candidate.activate(ue.kamf_pending, algs, ue.auth_ngksi);
  SecurityModeCommand smc;
  smc.selected_algorithms = algs;
  smc.ngksi = ue.auth_ngksi;
  smc.replayed_ue_security_capability = ue.ue_caps;
  if (config_.request_imeisv) smc.imeisv_request = true;
  if (config_.request_initial_message_resend) smc.additional_security_information = 0x02;
  ue.pending_smc = smc;
  ue.proc = Proc::SecurityMode;
  ue.retransmissions = 0;
  send_smc(ue);
  ue.t3560->start(config_.t3560_ms);
}

void Amf::on_security_mode_complete(UeContext& ue, const SecurityModeComplete& m, std::uint32_t count) {
  ue.t3560->stop();
  ue.ctx = ue.candidate;
  ue.candidate.clear();
  ue.secure_exchange = true;
  ue.pending_smc.reset();
  log_.info(tag(ue), "<- SecurityModeComplete: NAS security context in use");
  if (m.nas_message_container) {
    if (auto inner = decode_plain(*m.nas_message_container)) {
      if (const auto* rr = std::get_if<RegistrationRequest>(&*inner)) {
        if (rr->ue_security_capability) ue.ue_caps = *rr->ue_security_capability;
        if (rr->requested_nssai) ue.requested_nssai = *rr->requested_nssai;
      }
    }
  }
  accept_registration(ue, count);
}

void Amf::accept_registration(UeContext& ue, std::uint32_t ul_count) {
  Guti5g g;
  g.plmn = config_.plmn;
  g.amf_region_id = config_.amf_region_id;
  g.amf_set_id = config_.amf_set_id;
  g.amf_pointer = config_.amf_pointer;
  do {
    g.tmsi = static_cast<std::uint32_t>(rng_());
  } while (find_by_tmsi(g.tmsi) != nullptr);
  ue.guti = g;

  std::vector<SNssai> allowed;
  for (const auto& s : ue.requested_nssai) {
    if (std::find(config_.supported_nssai.begin(), config_.supported_nssai.end(), s) != config_.supported_nssai.end()) {
      allowed.push_back(s);
    }
  }
  if (allowed.empty()) allowed = config_.supported_nssai;

  RegistrationAccept acc;
  acc.registration_result = 0x01;
  acc.guti = g;
  acc.tai_list = TaiList{{Tai{config_.plmn, config_.tac}}};
  acc.allowed_nssai = allowed;
  acc.t3512 = config_.t3512;
  ue.pending_accept = acc;
  ue.proc = Proc::RegistrationAccept;
  ue.retransmissions = 0;

  const Bytes pdu = protect(ue.ctx, encode(acc), SecurityHeaderType::IntegrityProtectedAndCiphered, sec::Direction::Downlink);
  n2::InitialContextSetupRequest ics;
  ics.ran_ue_id = ue.ran_ue_id.value_or(0);
  ics.amf_ue_id = ue.amf_ue_id;
  ics.kgnb = sec::derive_kgnb(ue.ctx.kamf, ul_count);
  ics.ue_security_capability = ue.ue_caps;
  ics.nas_pdu = pdu;
  log_.info(tag(ue), "-> InitialContextSetupRequest + REGISTRATION ACCEPT (5G-TMSI ", g.tmsi, ")");
  if (send_n2_) send_n2_(ics);
  ue.t3550->start(config_.t3550_ms);
}

void Amf::on_registration_complete(UeContext& ue) {
  if (ue.proc != Proc::RegistrationAccept) {
    log_.warn(tag(ue), "unexpected REGISTRATION COMPLETE ignored");
    return;
  }
  ue.t3550->stop();
  ue.proc = Proc::None;
  ue.pending_accept.reset();
  ue.state = AmfUeState::Registered;
  ++counters_.registrations_completed;
  log_.info(tag(ue), "registered");
  if (config_.release_after_registration && !ue.follow_on) schedule_release(ue, "registration complete");
}

void Amf::reject_registration(UeContext& ue, Cause cause) {
  ++counters_.registration_rejects;
  log_.warn(tag(ue), "-> REGISTRATION REJECT #", static_cast<int>(cause), " (", to_string(cause), ")");
  RegistrationReject rej;
  rej.cause = cause;
  if (cause == Cause::Congestion && config_.reject_t3346) rej.t3346 = config_.reject_t3346;
  send_nas(ue, rej);
  ue.proc = Proc::None;
  ue.state = AmfUeState::Deregistered;
  for (Timer* t : {ue.t3550.get(), ue.t3560.get(), ue.t3570.get()}) t->stop();
  schedule_release(ue, "registration rejected");
}

void Amf::on_deregistration_request(UeContext& ue, const DeregistrationRequestUeOriginating& d) {
  ++counters_.deregistrations;
  for (Timer* t : {ue.t3550.get(), ue.t3560.get(), ue.t3570.get()}) t->stop();
  ue.proc = Proc::None;
  log_.info(tag(ue), "UE-initiated de-registration", d.deregistration_type.switch_off ? " (switch off)" : "");
  if (!d.deregistration_type.switch_off) send_nas(ue, DeregistrationAcceptUeOriginating{});
  ue.state = AmfUeState::Deregistered;
  schedule_release(ue, "deregistration");
}

void Amf::abort_procedure(UeContext& ue, const std::string& why) {
  log_.warn(tag(ue), "procedure aborted: ", why);
  for (Timer* t : {ue.t3550.get(), ue.t3560.get(), ue.t3570.get()}) t->stop();
  ue.proc = Proc::None;
  if (ue.state == AmfUeState::CommonProcedureInitiated) ue.state = AmfUeState::Deregistered;
  schedule_release(ue, why);
}

// ---- Timers -------------------------------------------------------------------------------------

void Amf::on_retransmission_timer(std::uint32_t amf_ue_id, const char* timer) {
  UeContext* ue = find_by_amf_id(amf_ue_id);
  if (ue == nullptr || !ue->connected) return;
  ++ue->retransmissions;
  if (ue->retransmissions > config_.max_retransmissions) {
    log_.warn(tag(*ue), timer, " expired ", ue->retransmissions, " times");
    if (ue->proc == Proc::RegistrationAccept) {
      // §5.5.1.2.8: on the 5th expiry of T3550 the procedure is aborted; the new 5G-GUTI stays valid.
      ue->proc = Proc::None;
      ue->state = AmfUeState::Registered;
      return;
    }
    return abort_procedure(*ue, std::string(timer) + " expiry");
  }
  ++counters_.retransmissions;
  log_.info(tag(*ue), timer, " expired: retransmission ", ue->retransmissions);
  switch (ue->proc) {
    case Proc::Identification:
      send_nas(*ue, IdentityRequest{IdentityType::Suci});
      ue->t3570->start(config_.t3570_ms);
      break;
    case Proc::Authentication: {
      AuthenticationRequest req;
      req.ngksi = ue->auth_ngksi;
      req.abba = ue->abba;
      req.rand = ue->av->rand;
      req.autn = ue->av->autn;
      send_nas(*ue, req);
      ue->t3560->start(config_.t3560_ms);
      break;
    }
    case Proc::SecurityMode:
      send_smc(*ue);
      ue->t3560->start(config_.t3560_ms);
      break;
    case Proc::RegistrationAccept:
      send_accept(*ue);
      ue->t3550->start(config_.t3550_ms);
      break;
    case Proc::None: break;
  }
}

// ---- Sending ------------------------------------------------------------------------------------

void Amf::send_nas(UeContext& ue, const PlainMessage& m) {
  if (!ue.connected || !ue.ran_ue_id) return;
  Bytes pdu = encode(m);
  if (ue.secure_exchange) {
    pdu = protect(ue.ctx, pdu, SecurityHeaderType::IntegrityProtectedAndCiphered, sec::Direction::Downlink);
  }
  log_.info(tag(ue), "-> ", message_name(m), ue.secure_exchange ? "" : " (plain)");
  if (send_n2_) send_n2_(n2::DownlinkNasTransport{*ue.ran_ue_id, ue.amf_ue_id, pdu});
}

void Amf::send_smc(UeContext& ue) {
  if (!ue.connected || !ue.ran_ue_id || !ue.pending_smc) return;
  const Bytes pdu = protect(ue.candidate, encode(*ue.pending_smc), SecurityHeaderType::IntegrityProtectedWithNewContext,
                            sec::Direction::Downlink);
  log_.info(tag(ue), "-> SecurityModeCommand (5G-EA", int{ue.pending_smc->selected_algorithms.ciphering}, ", 5G-IA",
            int{ue.pending_smc->selected_algorithms.integrity}, ")");
  if (send_n2_) send_n2_(n2::DownlinkNasTransport{*ue.ran_ue_id, ue.amf_ue_id, pdu});
}

void Amf::send_accept(UeContext& ue) {
  if (!ue.pending_accept) return;
  send_nas(ue, *ue.pending_accept);
}

void Amf::send_status(UeContext& ue, Cause cause) {
  log_.warn(tag(ue), "-> 5GMM STATUS #", static_cast<int>(cause));
  send_nas(ue, Status5gmm{cause});
}

void Amf::schedule_release(UeContext& ue, const std::string& cause) {
  if (!ue.connected || !ue.ran_ue_id || ue.release_event) return;
  const std::uint32_t id = ue.amf_ue_id;
  ue.release_event = loop_.schedule_in(config_.release_delay_ms, [this, id, cause] {
    UeContext* u = find_by_amf_id(id);
    if (u == nullptr) return;
    u->release_event.reset();
    if (!u->connected || !u->ran_ue_id) return;
    log_.info(tag(*u), "-> UEContextReleaseCommand (", cause, ")");
    if (send_n2_) send_n2_(n2::UeContextReleaseCommand{*u->ran_ue_id, u->amf_ue_id, cause});
  });
}

}  // namespace nrlite::core
