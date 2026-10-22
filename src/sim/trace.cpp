#include "nrlite/sim/trace.hpp"

#include "nrlite/nas/messages.hpp"
#include "nrlite/pdcp/pdcp.hpp"

namespace nrlite::sim {

const char* to_string(Direction d) { return d == Direction::Uplink ? "UL" : "DL"; }

Bytes strip_pdcp(const Bytes& pdcp_pdu) {
  if (pdcp_pdu.size() < pdcp::kHeaderSize + pdcp::kMacSize) return {};
  return Bytes(pdcp_pdu.begin() + pdcp::kHeaderSize, pdcp_pdu.end() - pdcp::kMacSize);
}

std::string summarize_nas(const Bytes& nas_pdu) {
  const auto sht = nas::peek_security_header_type(nas_pdu);
  if (!sht) return "<undecodable NAS>";
  Bytes plain = nas_pdu;
  std::string prefix;
  if (*sht != nas::SecurityHeaderType::Plain) {
    auto s = nas::parse_secured(nas_pdu);
    if (!s) return "<malformed protected NAS>";
    plain = s->payload;
  }
  auto m = nas::decode_plain(plain);
  if (!m) return *sht == nas::SecurityHeaderType::Plain ? "<undecodable NAS>" : "<ciphered NAS>";
  std::string name = nas::message_name(*m);
  if (*sht != nas::SecurityHeaderType::Plain) name += "*";  // '*' marks a protected message
  return name;
}

std::string summarize_uu(Direction dir, rrc::Channel ch, const Bytes& rrc_pdu) {
  auto with_nas = [](std::string name, const std::optional<Bytes>& nas) {
    if (nas) name += " [" + summarize_nas(*nas) + "]";
    return name;
  };
  if (ch == rrc::Channel::Ccch) {
    if (dir == Direction::Uplink) {
      auto m = rrc::decode_ul_ccch(rrc_pdu);
      return m ? rrc::message_name(*m) : "<undecodable UL-CCCH>";
    }
    auto m = rrc::decode_dl_ccch(rrc_pdu);
    return m ? rrc::message_name(*m) : "<undecodable DL-CCCH>";
  }
  if (dir == Direction::Uplink) {
    auto m = rrc::decode_ul_dcch(rrc_pdu);
    if (!m) return "<undecodable UL-DCCH>";
    if (const auto* c = std::get_if<rrc::RrcSetupComplete>(&*m)) return with_nas(rrc::message_name(*m), c->dedicated_nas_message);
    if (const auto* u = std::get_if<rrc::UlInformationTransfer>(&*m)) return with_nas(rrc::message_name(*m), u->dedicated_nas_message);
    return rrc::message_name(*m);
  }
  auto m = rrc::decode_dl_dcch(rrc_pdu);
  if (!m) return "<undecodable DL-DCCH>";
  if (const auto* d = std::get_if<rrc::DlInformationTransfer>(&*m)) return with_nas(rrc::message_name(*m), d->dedicated_nas_message);
  return rrc::message_name(*m);
}

std::vector<std::string> MemoryTrace::uu_messages() const {
  std::vector<std::string> out;
  for (const auto& r : records_) {
    if (r.iface == Interface::Uu && !r.dropped) out.push_back(r.message);
  }
  return out;
}

PcapTrace::PcapTrace(const std::string& path, bool include_n2) : writer_(path), include_n2_(include_n2) {}

void PcapTrace::on_record(const TraceRecord& r) {
  if (r.dropped) return;
  if (r.iface == Interface::Uu) {
    if (r.payload.empty()) return;
    const bool ul = r.direction == Direction::Uplink;
    const bool dcch = r.channel.find("DCCH") != std::string::npos;
    const std::uint32_t ue = ue_ip(r.rnti);
    writer_.write(r.time, trace::rrc_dissector(ul, dcch), ul ? ue : kGnbIp, ul ? kGnbIp : ue, r.payload);
    return;
  }
  if (!include_n2_ || r.payload.empty()) return;
  const bool ul = r.direction == Direction::Uplink;
  writer_.write(r.time, "nas-5gs", ul ? kGnbIp : kAmfIp, ul ? kAmfIp : kGnbIp, r.payload);
}

}  // namespace nrlite::sim
