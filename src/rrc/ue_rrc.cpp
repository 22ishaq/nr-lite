#include "nrlite/rrc/ue_rrc.hpp"

#include "nrlite/security/kdf.hpp"

namespace nrlite::rrc {

const char* to_string(Channel c) { return c == Channel::Ccch ? "CCCH" : "DCCH"; }

const char* to_string(UeState s) { return s == UeState::Idle ? "RRC_IDLE" : "RRC_CONNECTED"; }

const char* to_string(EstablishmentFailure f) {
  switch (f) {
    case EstablishmentFailure::T300Expiry: return "T300 expiry";
    case EstablishmentFailure::Rejected: return "RRCReject";
    case EstablishmentFailure::AccessBarred: return "access barred (T302 running)";
    case EstablishmentFailure::InvalidSetup: return "invalid RRCSetup";
  }
  return "?";
}

const char* to_string(ReleaseCause c) {
  switch (c) {
    case ReleaseCause::RrcRelease: return "RRCRelease";
    case ReleaseCause::ConnectionFailure: return "RRC connection failure";
    case ReleaseCause::LocalRelease: return "local release";
  }
  return "?";
}

UeRrc::UeRrc(EventLoop& loop, const Logger& log, std::string name, UeRrcConfig config, std::mt19937_64& rng)
    : loop_(loop),
      log_(log),
      name_(std::move(name)),
      tag_(name_ + "/RRC"),
      config_(std::move(config)),
      rng_(rng),
      srb1_(1, sec::Direction::Uplink),
      t300_(loop, "T300",
            [this] {
              log_.warn(tag_, "T300 expired: RRC connection establishment failed");
              pending_nas_.clear();
              if (cb_.establishment_failed) cb_.establishment_failed(EstablishmentFailure::T300Expiry);
            }),
      t302_(loop, "T302", [this] {
        log_.info(tag_, "T302 expired: barring alleviated");
        if (cb_.barring_alleviated) cb_.barring_alleviated();
      }) {}

void UeRrc::set_state(UeState s) {
  if (s == state_) return;
  log_.info(tag_, to_string(state_), " -> ", to_string(s));
  state_ = s;
}

bool UeRrc::establish(EstablishmentCause cause, Bytes nas_pdu, std::optional<std::uint64_t> five_g_s_tmsi) {
  if (state_ != UeState::Idle) {
    log_.warn(tag_, "establish() ignored: already ", to_string(state_));
    return false;
  }
  if (t300_.running()) {
    log_.warn(tag_, "establish() ignored: establishment already in progress");
    return false;
  }
  // §5.3.15.2 / TS 38.304: while T302 runs, access is barred except for emergency and MT access.
  if (t302_.running() && cause != EstablishmentCause::emergency && cause != EstablishmentCause::mt_Access) {
    log_.warn(tag_, "access barred: T302 running for another ", t302_.remaining(), " ms");
    if (cb_.establishment_failed) cb_.establishment_failed(EstablishmentFailure::AccessBarred);
    return false;
  }

  pending_cause_ = cause;
  pending_nas_ = std::move(nas_pdu);
  pending_s_tmsi_ = five_g_s_tmsi;

  RrcSetupRequest req;
  req.establishment_cause = cause;
  if (five_g_s_tmsi) {
    req.ue_identity.type = InitialUeIdentity::Type::ng_5G_S_TMSI_Part1;
    req.ue_identity.value = *five_g_s_tmsi & ((std::uint64_t{1} << 39) - 1);
  } else {
    req.ue_identity.type = InitialUeIdentity::Type::randomValue;
    req.ue_identity.value = rng_() & ((std::uint64_t{1} << 39) - 1);
  }
  ++counters_.setup_requests;
  log_.info(tag_, "-> RRCSetupRequest (", to_string(cause), "), T300 started");
  t300_.start(config_.t300_ms);
  const Bytes pdu = encode_ul_ccch(req);
  if (cb_.send) cb_.send(Channel::Ccch, pdu, pdu);
  return true;
}

bool UeRrc::send_nas(const Bytes& nas_pdu) {
  if (state_ != UeState::Connected || releasing_) {
    log_.warn(tag_, "send_nas() ignored: not connected");
    return false;
  }
  send_dcch(UlInformationTransfer{nas_pdu});
  return true;
}

void UeRrc::abort_connection() {
  if (t300_.running()) {
    t300_.stop();
    pending_nas_.clear();
    log_.info(tag_, "establishment aborted by NAS");
  }
  if (state_ == UeState::Connected) enter_idle(ReleaseCause::LocalRelease, true);
}

void UeRrc::on_pdu(Channel ch, const Bytes& pdu) {
  if (ch == Channel::Ccch) {
    on_dl_ccch(pdu);
  } else {
    on_dl_dcch(pdu);
  }
}

void UeRrc::on_dl_ccch(const Bytes& pdu) {
  auto msg = decode_dl_ccch(pdu);
  if (!msg) {
    // §10.3: abstract syntax error on CCCH -> ignore the message.
    ++counters_.decode_errors;
    log_.warn(tag_, "ignoring undecodable DL-CCCH message: ", msg.error().message);
    return;
  }
  std::visit(overloaded{[this](const RrcSetup& m) { handle_rrc_setup(m); },
                        [this](const RrcReject& m) { handle_rrc_reject(m); }},
             *msg);
}

void UeRrc::handle_rrc_setup(const RrcSetup& m) {
  if (!t300_.running() || state_ != UeState::Idle) {
    ++counters_.ignored_messages;
    log_.warn(tag_, "ignoring RRCSetup: no establishment in progress");
    return;
  }
  bool has_srb1 = false;
  for (const auto& s : m.radio_bearer_config.srb_to_add_mod_list) has_srb1 |= s.srb_identity == 1;
  t300_.stop();
  if (!has_srb1) {
    log_.warn(tag_, "RRCSetup without SRB1: cannot comply");
    pending_nas_.clear();
    if (cb_.establishment_failed) cb_.establishment_failed(EstablishmentFailure::InvalidSetup);
    return;
  }

  srb1_.reset();
  set_state(UeState::Connected);
  releasing_ = false;
  log_.info(tag_, "<- RRCSetup (txid ", int{m.rrc_transaction_identifier}, "): SRB1 established");

  RrcSetupComplete c;
  c.rrc_transaction_identifier = m.rrc_transaction_identifier;
  c.selected_plmn_identity = config_.selected_plmn_identity;
  c.s_nssai_list = config_.s_nssai_list;
  c.dedicated_nas_message = std::move(pending_nas_);
  pending_nas_.clear();
  if (pending_s_tmsi_) {
    // §5.3.3.4: the 9 most significant bits of the 48-bit 5G-S-TMSI go in RRCSetupComplete.
    c.ng_5g_s_tmsi_value = RrcSetupComplete::Ng5gSTmsiValue{false, (*pending_s_tmsi_ >> 39) & 0x1FF};
  }
  send_dcch(c);
  if (cb_.connected) cb_.connected();
}

void UeRrc::handle_rrc_reject(const RrcReject& m) {
  if (!t300_.running()) {
    ++counters_.ignored_messages;
    log_.warn(tag_, "ignoring RRCReject: no establishment in progress");
    return;
  }
  t300_.stop();
  pending_nas_.clear();
  if (m.wait_time) {
    t302_.start(TimeMs{*m.wait_time} * 1000);
    log_.info(tag_, "<- RRCReject: T302 started (", int{*m.wait_time}, " s)");
  } else {
    log_.info(tag_, "<- RRCReject without waitTime");
  }
  if (cb_.establishment_failed) cb_.establishment_failed(EstablishmentFailure::Rejected);
}

void UeRrc::on_dl_dcch(const Bytes& pdu) {
  if (state_ != UeState::Connected || releasing_) {
    ++counters_.ignored_messages;
    log_.warn(tag_, "ignoring DL-DCCH PDU while not connected");
    return;
  }
  auto rx = srb1_.receive(pdu);
  if (!rx) {
    if (rx.error().code == static_cast<int>(pdcp::RxError::IntegrityFailure)) {
      ++counters_.integrity_failures;
      log_.warn(tag_, rx.error().message, ": treating as RRC connection failure");
      enter_idle(ReleaseCause::ConnectionFailure, true);
    } else {
      ++counters_.ignored_messages;
      log_.warn(tag_, "PDCP discarded PDU: ", rx.error().message);
    }
    return;
  }
  auto msg = decode_dl_dcch(rx->sdu);
  if (!msg) {
    ++counters_.decode_errors;
    log_.warn(tag_, "abstract syntax error on DL-DCCH (", msg.error().message, "): treating as RRC connection failure");
    enter_idle(ReleaseCause::ConnectionFailure, true);
    return;
  }
  std::visit(overloaded{[&](const SecurityModeCommand& m) { handle_security_mode_command(m, *rx); },
                        [&](const DlInformationTransfer& m) {
                          if (!m.dedicated_nas_message) {
                            ++counters_.ignored_messages;
                            return;
                          }
                          log_.debug(tag_, "<- DLInformationTransfer (", m.dedicated_nas_message->size(), " octets NAS)");
                          if (cb_.deliver_nas) cb_.deliver_nas(*m.dedicated_nas_message);
                        },
                        [&](const RrcRelease& m) { handle_rrc_release(m); }},
             *msg);
}

void UeRrc::handle_security_mode_command(const SecurityModeCommand& m, const pdcp::RxPdu& rx) {
  if (as_security_active_) {
    ++counters_.ignored_messages;
    log_.warn(tag_, "ignoring SecurityModeCommand: AS security already active");
    return;
  }
  auto fail = [&](const std::string& why) {
    // §5.3.4.3: keep the configuration used before the SMC and reply SecurityModeFailure unprotected.
    ++counters_.security_mode_failures;
    log_.warn(tag_, "SecurityModeCommand not accepted: ", why);
    send_dcch(SecurityModeFailure{m.rrc_transaction_identifier});
  };
  if (!kgnb_) return fail("no K_gNB available");
  if (!m.integrity_prot_algorithm || *m.integrity_prot_algorithm != IntegrityProtAlgorithm::nia2) {
    return fail("integrity algorithm not supported");
  }
  const bool nea2 = m.ciphering_algorithm == CipheringAlgorithm::nea2;
  if (m.ciphering_algorithm != CipheringAlgorithm::nea0 && !(nea2 && config_.accept_nea2)) {
    return fail("ciphering algorithm not supported");
  }
  const sec::Key128 k_int = sec::derive_algorithm_key(*kgnb_, sec::AlgorithmDistinguisher::RrcInt, 2);
  if (!srb1_.verify(rx, k_int)) {
    ++counters_.integrity_failures;
    return fail("integrity check of SecurityModeCommand failed");
  }

  // Integrity protection starts with SecurityModeComplete; ciphering only after it is sent.
  srb1_.enable_tx_integrity(k_int);
  srb1_.enable_rx_integrity(k_int);
  log_.info(tag_, "<- SecurityModeCommand: AS security activated (", to_string(m.ciphering_algorithm), ", nia2)");
  send_dcch(SecurityModeComplete{m.rrc_transaction_identifier});
  if (nea2) {
    const sec::Key128 k_enc = sec::derive_algorithm_key(*kgnb_, sec::AlgorithmDistinguisher::RrcEnc, 2);
    srb1_.enable_tx_ciphering(k_enc);
    srb1_.enable_rx_ciphering(k_enc);
  }
  as_security_active_ = true;
}

void UeRrc::handle_rrc_release(const RrcRelease& m) {
  log_.info(tag_, "<- RRCRelease: entering RRC_IDLE in ", config_.release_delay_ms, " ms");
  releasing_ = true;
  const std::optional<std::uint8_t> wait = m.wait_time;
  release_event_ = loop_.schedule_in(config_.release_delay_ms, [this, wait] {
    release_event_.reset();
    if (wait) t302_.start(TimeMs{*wait} * 1000);
    enter_idle(ReleaseCause::RrcRelease, true);
  });
}

void UeRrc::send_dcch(const UlDcchMessage& m) {
  log_.debug(tag_, "-> ", message_name(m));
  const Bytes rrc_pdu = encode_ul_dcch(m);
  const Bytes pdu = srb1_.transmit(rrc_pdu);
  if (cb_.send) cb_.send(Channel::Dcch, pdu, rrc_pdu);
}

void UeRrc::enter_idle(ReleaseCause cause, bool notify) {
  if (release_event_) {
    loop_.cancel(*release_event_);
    release_event_.reset();
  }
  releasing_ = false;
  as_security_active_ = false;
  kgnb_.reset();
  srb1_.reset();
  t300_.stop();
  pending_nas_.clear();
  const bool was_connected = state_ == UeState::Connected;
  set_state(UeState::Idle);
  if (was_connected) log_.info(tag_, "released: ", to_string(cause));
  if (notify && was_connected && cb_.released) cb_.released(cause);
}

}  // namespace nrlite::rrc
