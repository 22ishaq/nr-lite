#include "nrlite/rrc/gnb_rrc.hpp"

#include <sstream>

#include "nrlite/security/kdf.hpp"

namespace nrlite::rrc {

const char* to_string(GnbUeState s) {
  switch (s) {
    case GnbUeState::WaitSetupComplete: return "WAIT_SETUP_COMPLETE";
    case GnbUeState::Connected: return "CONNECTED";
    case GnbUeState::WaitSecurityModeComplete: return "WAIT_SMC_COMPLETE";
    case GnbUeState::Secured: return "SECURED";
  }
  return "?";
}

GnbRrc::UeContext::UeContext(EventLoop& loop, std::uint16_t r, std::uint32_t id)
    : rnti(r), ran_ue_id(id), srb1(1, sec::Direction::Downlink), guard(std::make_unique<Timer>(loop, "guard", nullptr)) {}

GnbRrc::GnbRrc(EventLoop& loop, const Logger& log, GnbConfig config)
    : loop_(loop), log_(log), config_(config) {}

std::string GnbRrc::tag(const UeContext& ue) const {
  std::ostringstream os;
  os << "gNB/RRC[" << std::hex << ue.rnti << "]";
  return os.str();
}

std::optional<GnbUeState> GnbRrc::state_of(std::uint16_t rnti) const {
  auto it = by_rnti_.find(rnti);
  if (it == by_rnti_.end()) return std::nullopt;
  return it->second->state;
}

std::optional<std::uint32_t> GnbRrc::ran_ue_id_of(std::uint16_t rnti) const {
  auto it = by_rnti_.find(rnti);
  if (it == by_rnti_.end()) return std::nullopt;
  return it->second->ran_ue_id;
}

GnbRrc::UeContext* GnbRrc::find_by_ran_id(std::uint32_t ran_ue_id) {
  for (auto& [rnti, ue] : by_rnti_) {
    if (ue->ran_ue_id == ran_ue_id) return ue.get();
  }
  return nullptr;
}

std::uint8_t GnbRrc::take_txid(UeContext& ue) {
  const std::uint8_t id = ue.next_txid;
  ue.next_txid = static_cast<std::uint8_t>((ue.next_txid + 1) % 4);
  return id;
}

void GnbRrc::on_air(std::uint16_t rnti, Channel ch, const Bytes& pdu) {
  if (ch == Channel::Ccch) {
    auto msg = decode_ul_ccch(pdu);
    if (!msg) {
      ++counters_.decode_errors;
      log_.warn("gNB/RRC", "ignoring undecodable UL-CCCH from RNTI ", rnti, ": ", msg.error().message);
      return;
    }
    on_setup_request(rnti, std::get<RrcSetupRequest>(*msg));
    return;
  }
  auto it = by_rnti_.find(rnti);
  if (it == by_rnti_.end()) {
    ++counters_.ignored_messages;
    log_.warn("gNB/RRC", "UL-DCCH from unknown RNTI ", rnti, " ignored");
    return;
  }
  on_ul_dcch(*it->second, pdu);
}

void GnbRrc::on_setup_request(std::uint16_t rnti, const RrcSetupRequest& m) {
  if (by_rnti_.count(rnti) != 0) {
    // The UE restarted establishment (e.g. after T300): the old context is stale.
    log_.info("gNB/RRC", "new RRCSetupRequest from RNTI ", rnti, ": replacing stale context");
    UeContext& old = *by_rnti_.at(rnti);
    if (old.amf_ue_id && cb_.send_n2) {
      cb_.send_n2(n2::UeContextReleaseRequest{old.ran_ue_id, *old.amf_ue_id, "radio connection with UE lost"});
    }
    release_context(rnti);
  }
  if (config_.reject_all || by_rnti_.size() >= config_.max_ues) {
    ++counters_.rejects;
    log_.info("gNB/RRC", "admission rejected for RNTI ", rnti, ": RRCReject waitTime ", int{config_.reject_wait_time_s},
              " s");
    if (cb_.send_air) {
      const Bytes pdu = encode_dl_ccch(RrcReject{config_.reject_wait_time_s});
      cb_.send_air(rnti, Channel::Ccch, pdu, pdu);
    }
    return;
  }

  auto ctx = std::make_unique<UeContext>(loop_, rnti, next_ran_ue_id_++);
  UeContext& ue = *ctx;
  by_rnti_[rnti] = std::move(ctx);
  ue.cause = m.establishment_cause;
  if (m.ue_identity.type == InitialUeIdentity::Type::ng_5G_S_TMSI_Part1) ue.s_tmsi_part1 = m.ue_identity.value;
  ue.expected_txid = take_txid(ue);
  ++counters_.setups;

  RrcSetup setup;
  setup.rrc_transaction_identifier = ue.expected_txid;
  setup.radio_bearer_config.srb_to_add_mod_list = {SrbToAddMod{1, false, false}};
  RlcBearerConfig rlc;
  rlc.logical_channel_identity = 1;
  rlc.served_radio_bearer = RlcBearerConfig::ServedRadioBearer{true, 1};
  setup.master_cell_group.rlc_bearer_to_add_mod_list = {rlc};

  log_.info(tag(ue), "<- RRCSetupRequest (", to_string(m.establishment_cause), ") -> RRCSetup, ran-UE-id ", ue.ran_ue_id);
  const std::uint16_t key = rnti;
  ue.guard = std::make_unique<Timer>(loop_, "setup-guard", [this, key] {
    ++counters_.guard_expiries;
    log_.warn("gNB/RRC", "no RRCSetupComplete from RNTI ", key, ": context dropped");
    release_context(key);
  });
  ue.guard->start(config_.setup_complete_timeout_ms);
  if (cb_.send_air) {
    const Bytes pdu = encode_dl_ccch(setup);
    cb_.send_air(rnti, Channel::Ccch, pdu, pdu);
  }
}

void GnbRrc::on_ul_dcch(UeContext& ue, const Bytes& pdu) {
  auto rx = ue.srb1.receive(pdu);
  if (!rx) {
    if (rx.error().code == static_cast<int>(pdcp::RxError::IntegrityFailure)) ++counters_.integrity_failures;
    ++counters_.ignored_messages;
    log_.warn(tag(ue), "PDCP discarded UL PDU: ", rx.error().message);
    return;
  }
  auto msg = decode_ul_dcch(rx->sdu);
  if (!msg) {
    ++counters_.decode_errors;
    log_.warn(tag(ue), "ignoring undecodable UL-DCCH: ", msg.error().message);
    return;
  }

  std::visit(
      overloaded{
          [&](const RrcSetupComplete& m) {
            if (ue.state != GnbUeState::WaitSetupComplete || m.rrc_transaction_identifier != ue.expected_txid) {
              ++counters_.ignored_messages;
              log_.warn(tag(ue), "unexpected RRCSetupComplete ignored");
              return;
            }
            ue.guard->stop();
            ue.state = GnbUeState::Connected;
            n2::InitialUeMessage ini;
            ini.ran_ue_id = ue.ran_ue_id;
            ini.nas_pdu = m.dedicated_nas_message;
            ini.establishment_cause = ue.cause;
            if (ue.s_tmsi_part1 && m.ng_5g_s_tmsi_value && !m.ng_5g_s_tmsi_value->full) {
              ini.five_g_s_tmsi = (m.ng_5g_s_tmsi_value->value << 39) | *ue.s_tmsi_part1;
            }
            log_.info(tag(ue), "<- RRCSetupComplete -> InitialUEMessage");
            if (cb_.send_n2) cb_.send_n2(ini);
          },
          [&](const UlInformationTransfer& m) {
            if (ue.state == GnbUeState::WaitSetupComplete || !m.dedicated_nas_message) {
              ++counters_.ignored_messages;
              log_.warn(tag(ue), "unexpected ULInformationTransfer ignored");
              return;
            }
            if (cb_.send_n2) {
              cb_.send_n2(n2::UplinkNasTransport{ue.ran_ue_id, ue.amf_ue_id.value_or(0), *m.dedicated_nas_message});
            }
          },
          [&](const SecurityModeComplete& m) {
            if (ue.state != GnbUeState::WaitSecurityModeComplete || m.rrc_transaction_identifier != ue.expected_txid) {
              ++counters_.ignored_messages;
              log_.warn(tag(ue), "unexpected SecurityModeComplete ignored");
              return;
            }
            // UL integrity is verified here rather than in PDCP so that an unprotected
            // SecurityModeFailure can still be received in this state.
            if (!ue.k_rrc_int || !ue.srb1.verify(*rx, *ue.k_rrc_int)) {
              ++counters_.integrity_failures;
              log_.warn(tag(ue), "SecurityModeComplete failed integrity check: ignored");
              return;
            }
            ue.guard->stop();
            ue.state = GnbUeState::Secured;
            ue.srb1.enable_rx_integrity(*ue.k_rrc_int);
            if (ue.k_rrc_enc) {  // ciphering in both directions from the next PDU on
              ue.srb1.enable_tx_ciphering(*ue.k_rrc_enc);
              ue.srb1.enable_rx_ciphering(*ue.k_rrc_enc);
            }
            log_.info(tag(ue), "<- SecurityModeComplete: AS security active");
            if (ue.nas_after_security) {
              send_dcch(ue, DlInformationTransfer{take_txid(ue), std::move(*ue.nas_after_security)});
              ue.nas_after_security.reset();
            }
            if (cb_.send_n2) cb_.send_n2(n2::InitialContextSetupResponse{ue.ran_ue_id, ue.amf_ue_id.value_or(0)});
          },
          [&](const SecurityModeFailure& m) {
            if (ue.state != GnbUeState::WaitSecurityModeComplete || m.rrc_transaction_identifier != ue.expected_txid) {
              ++counters_.ignored_messages;
              return;
            }
            ue.guard->stop();
            ue.state = GnbUeState::Connected;
            ue.srb1.disable_security();  // fall back to the configuration without AS security
            ue.k_rrc_int.reset();
            ue.k_rrc_enc.reset();
            log_.warn(tag(ue), "<- SecurityModeFailure -> InitialContextSetupFailure");
            if (cb_.send_n2) {
              cb_.send_n2(n2::InitialContextSetupFailure{ue.ran_ue_id, ue.amf_ue_id.value_or(0),
                                                         "security mode failure"});
            }
          }},
      *msg);
}

void GnbRrc::on_n2(const n2::Message& msg) {
  UeContext* ue = find_by_ran_id(n2::ran_ue_id(msg));
  if (ue == nullptr) {
    log_.warn("gNB/RRC", "N2 ", n2::name(msg), " for unknown RAN UE id ", n2::ran_ue_id(msg), " ignored");
    if (const auto* rel = std::get_if<n2::UeContextReleaseCommand>(&msg); rel != nullptr && cb_.send_n2) {
      cb_.send_n2(n2::UeContextReleaseComplete{rel->ran_ue_id, rel->amf_ue_id});
    }
    return;
  }
  std::visit(
      overloaded{
          [&](const n2::DownlinkNasTransport& m) {
            ue->amf_ue_id = m.amf_ue_id;
            send_dcch(*ue, DlInformationTransfer{take_txid(*ue), m.nas_pdu});
          },
          [&](const n2::InitialContextSetupRequest& m) {
            ue->amf_ue_id = m.amf_ue_id;
            if (ue->state != GnbUeState::Connected) {
              log_.warn(tag(*ue), "InitialContextSetupRequest in state ", to_string(ue->state), " ignored");
              return;
            }
            // NR-Lite implements NIA2 and NEA0/NEA2; the UE must support what we pick.
            const bool ia2 = m.ue_security_capability.supports_ia(2);
            const bool ea_ok = config_.ciphering == CipheringAlgorithm::nea0 ||
                               (config_.ciphering == CipheringAlgorithm::nea2 && m.ue_security_capability.supports_ea(2));
            if (!ia2 || !ea_ok) {
              log_.warn(tag(*ue), "no common AS security algorithm: InitialContextSetupFailure");
              if (cb_.send_n2) {
                cb_.send_n2(n2::InitialContextSetupFailure{ue->ran_ue_id, m.amf_ue_id, "encryption/integrity not supported"});
              }
              return;
            }
            const sec::Key128 k_int = sec::derive_algorithm_key(m.kgnb, sec::AlgorithmDistinguisher::RrcInt, 2);
            if (config_.ciphering == CipheringAlgorithm::nea2) {
              ue->k_rrc_enc = sec::derive_algorithm_key(m.kgnb, sec::AlgorithmDistinguisher::RrcEnc, 2);
            }
            ue->nas_after_security = m.nas_pdu;
            ue->expected_txid = take_txid(*ue);
            ue->state = GnbUeState::WaitSecurityModeComplete;
            ue->k_rrc_int = k_int;
            ue->srb1.enable_tx_integrity(k_int);
            log_.info(tag(*ue), "InitialContextSetupRequest -> SecurityModeCommand");
            send_dcch(*ue, SecurityModeCommand{ue->expected_txid, config_.ciphering, IntegrityProtAlgorithm::nia2});
            const std::uint16_t key = ue->rnti;
            ue->guard = std::make_unique<Timer>(loop_, "smc-guard", [this, key] {
              ++counters_.guard_expiries;
              auto it = by_rnti_.find(key);
              if (it == by_rnti_.end()) return;
              log_.warn(tag(*it->second), "no SecurityModeComplete: requesting UE context release");
              if (cb_.send_n2) {
                cb_.send_n2(n2::UeContextReleaseRequest{it->second->ran_ue_id, it->second->amf_ue_id.value_or(0),
                                                        "security mode procedure timeout"});
              }
            });
            ue->guard->start(config_.security_mode_timeout_ms);
          },
          [&](const n2::UeContextReleaseCommand& m) {
            ++counters_.releases;
            log_.info(tag(*ue), "UEContextReleaseCommand (", m.cause, ") -> RRCRelease");
            send_dcch(*ue, RrcRelease{take_txid(*ue), std::nullopt, std::nullopt});
            const std::uint32_t ran = ue->ran_ue_id;
            release_context(ue->rnti);
            if (cb_.send_n2) cb_.send_n2(n2::UeContextReleaseComplete{ran, m.amf_ue_id});
          },
          [&](const auto& other) {
            log_.warn(tag(*ue), "unexpected N2 message ", n2::name(n2::Message{other}), " ignored");
          }},
      msg);
}

void GnbRrc::send_dcch(UeContext& ue, const DlDcchMessage& m) {
  log_.debug(tag(ue), "-> ", message_name(m));
  const Bytes rrc_pdu = encode_dl_dcch(m);
  const Bytes pdu = ue.srb1.transmit(rrc_pdu);
  if (cb_.send_air) cb_.send_air(ue.rnti, Channel::Dcch, pdu, rrc_pdu);
}

void GnbRrc::release_context(std::uint16_t rnti) {
  auto it = by_rnti_.find(rnti);
  if (it == by_rnti_.end()) return;
  // Timers may be running from inside their own callback; defer destruction to the loop.
  std::shared_ptr<UeContext> doomed(it->second.release());
  by_rnti_.erase(it);
  doomed->guard->stop();
  loop_.schedule_in(0, [doomed] {});
}

}  // namespace nrlite::rrc
