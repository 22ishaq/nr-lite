#include "nrlite/trace/pcap_writer.hpp"

#include <stdexcept>

namespace nrlite::trace {

namespace {

void put_tag(Bytes& out, ExportTag tag, const Bytes& value) {
  put_u16(out, static_cast<std::uint16_t>(tag));
  put_u16(out, static_cast<std::uint16_t>(value.size()));
  out.insert(out.end(), value.begin(), value.end());
}

/// String tags are NUL padded to a multiple of four octets, as Wireshark itself writes them.
Bytes padded_string(const std::string& s) {
  Bytes v(s.begin(), s.end());
  v.resize((v.size() + 3) & ~std::size_t{3}, 0);
  if (v.size() == s.size()) v.resize(v.size() + 4, 0);  // keep a terminating NUL
  return v;
}

void put_le32(std::ofstream& out, std::uint32_t v) {
  const char b[4] = {static_cast<char>(v), static_cast<char>(v >> 8), static_cast<char>(v >> 16),
                     static_cast<char>(v >> 24)};
  out.write(b, 4);
}

void put_le16(std::ofstream& out, std::uint16_t v) {
  const char b[2] = {static_cast<char>(v), static_cast<char>(v >> 8)};
  out.write(b, 2);
}

}  // namespace

Bytes exported_pdu_frame(const std::string& dissector, std::uint32_t src_ipv4, std::uint32_t dst_ipv4,
                         const Bytes& payload, const std::string& info) {
  Bytes out;
  put_tag(out, ExportTag::DissectorName, padded_string(dissector));
  if (src_ipv4 != 0) {
    Bytes v;
    put_u32(v, src_ipv4);
    put_tag(out, ExportTag::Ipv4Src, v);
  }
  if (dst_ipv4 != 0) {
    Bytes v;
    put_u32(v, dst_ipv4);
    put_tag(out, ExportTag::Ipv4Dst, v);
  }
  if (!info.empty()) put_tag(out, ExportTag::ColumnInfoText, padded_string(info));
  put_tag(out, ExportTag::EndOfOptions, {});
  out.insert(out.end(), payload.begin(), payload.end());
  return out;
}

std::string rrc_dissector(bool uplink, bool dcch) {
  return std::string("nr-rrc.") + (uplink ? "ul." : "dl.") + (dcch ? "dcch" : "ccch");
}

PcapWriter::PcapWriter(const std::string& path) : out_(path, std::ios::binary | std::ios::trunc) {
  if (!out_) throw std::runtime_error("PcapWriter: cannot open " + path);
  put_le32(out_, 0xa1b2c3d4);  // microsecond-resolution pcap
  put_le16(out_, 2);
  put_le16(out_, 4);
  put_le32(out_, 0);       // thiszone
  put_le32(out_, 0);       // sigfigs
  put_le32(out_, 65535);   // snaplen
  put_le32(out_, kLinkTypeWiresharkUpperPdu);
}

void PcapWriter::write(TimeMs t, const std::string& dissector, std::uint32_t src_ipv4, std::uint32_t dst_ipv4,
                       const Bytes& payload, const std::string& info) {
  const Bytes frame = exported_pdu_frame(dissector, src_ipv4, dst_ipv4, payload, info);
  const std::uint32_t sec = kEpochSeconds + static_cast<std::uint32_t>(t / 1000);
  const std::uint32_t usec = static_cast<std::uint32_t>((t % 1000) * 1000);
  put_le32(out_, sec);
  put_le32(out_, usec);
  put_le32(out_, static_cast<std::uint32_t>(frame.size()));
  put_le32(out_, static_cast<std::uint32_t>(frame.size()));
  out_.write(reinterpret_cast<const char*>(frame.data()), static_cast<std::streamsize>(frame.size()));
  ++frames_;
}

}  // namespace nrlite::trace
