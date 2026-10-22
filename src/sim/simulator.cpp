#include "nrlite/sim/simulator.hpp"

#include <algorithm>
#include <memory>
#include <string>

namespace nrlite::sim {

namespace {

std::string channel_name(Direction d, rrc::Channel c) {
  return std::string(to_string(d)) + "-" + rrc::to_string(c);
}

}  // namespace

UeNode::UeNode(EventLoop& loop, const Logger& log, std::mt19937_64& rng, UeConfig config,
               std::function<void(rrc::Channel, const Bytes&, const Bytes&)> send_air)
    : config_(std::move(config)),
      rrc_(loop, log, config_.name, config_.rrc, rng),
      nas_(loop, log, config_.name, config_.nas) {
  rrc_.set_callbacks(rrc::UeRrc::Callbacks{
      std::move(send_air),
      [this](const Bytes& pdu) { nas_.on_dl_nas(pdu); },
      [this] { nas_.on_rrc_connected(); },
      [this](rrc::EstablishmentFailure f) { nas_.on_establishment_failure(f); },
      [this](rrc::ReleaseCause c) { nas_.on_rrc_released(c); },
      [this] { nas_.on_barring_alleviated(); },
  });
  nas_.set_callbacks(nas::UeNas::Callbacks{
      [this](rrc::EstablishmentCause c, const Bytes& pdu, std::optional<std::uint64_t> s_tmsi) {
        return rrc_.establish(c, pdu, s_tmsi);
      },
      [this](const Bytes& pdu) { return rrc_.send_nas(pdu); },
      [this] { rrc_.abort_connection(); },
      [this](const sec::Key256& k) { rrc_.set_kgnb(k); },
  });
}

Simulator::Simulator(SimConfig config)
    : config_(std::move(config)),
      logger_(&loop_, config_.log_level),
      rng_(config_.seed),
      gnb_(loop_, logger_, config_.gnb),
      amf_(loop_, logger_, config_.amf, rng_) {
  gnb_.set_callbacks(rrc::GnbRrc::Callbacks{
      [this](std::uint16_t rnti, rrc::Channel ch, const Bytes& pdu, const Bytes& rrc_pdu) {
        transmit(AirPdu{rnti, Direction::Downlink, ch, pdu, rrc_pdu});
      },
      [this](const n2::Message& m) { transmit_n2(m); },
  });
  amf_.set_n2_sender([this](const n2::Message& m) { transmit_n2(m); });
}

Simulator::~Simulator() = default;

UeConfig Simulator::default_ue_config(std::size_t index) {
  UeConfig c;
  c.name = "UE" + std::to_string(index + 1);
  std::string msin = std::to_string(index + 1);
  msin = std::string(10 - std::min<std::size_t>(10, msin.size()), '0') + msin;
  c.nas.plmn = nas::Plmn{"001", "01"};
  c.nas.subscription.supi = "00101" + msin;
  c.nas.subscription.k = array_from_hex<16>("465b5ce8b199b49faa5f0a2ee238a6bc");
  c.nas.subscription.opc = array_from_hex<16>("cd63cb71954a9f4e48a5994e37a02baf");
  c.rrc.s_nssai_list = {rrc::SNssai{1, std::nullopt}};
  return c;
}

UeNode& Simulator::add_ue(UeConfig config, bool provision) {
  if (provision) amf_.add_subscriber(config.nas.subscription, config.nas.sqn_ms);
  const std::uint16_t rnti = static_cast<std::uint16_t>(0x4601 + ues_.size());
  auto node = std::make_unique<UeNode>(loop_, logger_, rng_, std::move(config),
                                       [this, rnti](rrc::Channel ch, const Bytes& pdu, const Bytes& rrc_pdu) {
                                         transmit(AirPdu{rnti, Direction::Uplink, ch, pdu, rrc_pdu});
                                       });
  node->set_rnti(rnti);
  ues_.push_back(std::move(node));
  return *ues_.back();
}

void Simulator::add_trace_sink(TraceSink* sink) {
  if (std::find(sinks_.begin(), sinks_.end(), sink) == sinks_.end()) sinks_.push_back(sink);
}

void Simulator::remove_trace_sink(TraceSink* sink) {
  sinks_.erase(std::remove(sinks_.begin(), sinks_.end(), sink), sinks_.end());
}

void Simulator::detach_gnb(std::function<void(const AirPdu&)> uplink_handler) {
  gnb_attached_ = false;
  uplink_handler_ = std::move(uplink_handler);
}

void Simulator::reattach_gnb() {
  gnb_attached_ = true;
  uplink_handler_ = nullptr;
}

void Simulator::inject_dl(std::uint16_t rnti, rrc::Channel ch, Bytes data, Bytes rrc_hint) {
  transmit(AirPdu{rnti, Direction::Downlink, ch, std::move(data), std::move(rrc_hint)});
}

void Simulator::inject_ul(std::uint16_t rnti, rrc::Channel ch, Bytes data, Bytes rrc_hint) {
  transmit(AirPdu{rnti, Direction::Uplink, ch, std::move(data), std::move(rrc_hint)});
}

void Simulator::record_uu(const AirPdu& pdu, bool dropped) {
  if (sinks_.empty()) return;
  TraceRecord r;
  r.time = loop_.now();
  r.iface = Interface::Uu;
  r.direction = pdu.direction;
  r.channel = channel_name(pdu.direction, pdu.channel);
  r.rnti = pdu.rnti;
  r.raw = pdu.data;
  if (!pdu.rrc_hint.empty()) {
    r.payload = pdu.rrc_hint;
  } else {
    r.payload = pdu.channel == rrc::Channel::Dcch ? strip_pdcp(pdu.data) : pdu.data;
  }
  r.message = summarize_uu(pdu.direction, pdu.channel, r.payload);
  r.dropped = dropped;
  for (TraceSink* s : sinks_) s->on_record(r);
}

void Simulator::transmit(AirPdu pdu) {
  TimeMs latency = config_.air_latency_ms;
  if (interceptor_) {
    const Bytes before = pdu.data;
    const InterceptDecision d = interceptor_(pdu);
    if (pdu.data != before) pdu.rrc_hint.clear();  // trace what is really on the air
    if (d.action == InterceptDecision::Action::Drop) {
      logger_.info("AIR", "interceptor dropped ", to_string(pdu.direction), " ", rrc::to_string(pdu.channel), " PDU");
      record_uu(pdu, true);
      return;
    }
    if (d.action == InterceptDecision::Action::Delay) latency += d.delay_ms;
  }
  loop_.schedule_in(latency, [this, pdu] {
    record_uu(pdu, false);
    deliver(pdu);
  });
}

void Simulator::deliver(const AirPdu& pdu) {
  if (pdu.direction == Direction::Uplink) {
    if (gnb_attached_) {
      gnb_.on_air(pdu.rnti, pdu.channel, pdu.data);
    } else if (uplink_handler_) {
      uplink_handler_(pdu);
    }
    return;
  }
  for (auto& ue : ues_) {
    if (ue->rnti() == pdu.rnti) {
      ue->on_air(pdu.channel, pdu.data);
      return;
    }
  }
  if (downlink_handler_) {
    downlink_handler_(pdu);
    return;
  }
  logger_.warn("AIR", "DL PDU for unknown RNTI ", pdu.rnti, " dropped");
}

void Simulator::transmit_n2(const n2::Message& m) {
  const bool to_amf = n2::is_uplink(m);
  loop_.schedule_in(config_.n2_latency_ms, [this, m, to_amf] {
    if (const Bytes* nas = n2::nas_pdu(m); nas != nullptr && !sinks_.empty()) {
      TraceRecord r;
      r.time = loop_.now();
      r.iface = Interface::N2;
      r.direction = to_amf ? Direction::Uplink : Direction::Downlink;
      r.channel = "N2";
      r.ran_ue_id = n2::ran_ue_id(m);
      r.raw = *nas;
      r.payload = *nas;
      r.message = n2::name(m) + " [" + summarize_nas(*nas) + "]";
      for (TraceSink* s : sinks_) s->on_record(r);
    }
    if (to_amf) {
      amf_.on_n2(m);
    } else {
      gnb_.on_n2(m);
    }
  });
}

}  // namespace nrlite::sim
