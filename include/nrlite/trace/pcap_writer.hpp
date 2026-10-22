#pragma once

// Writes protocol traces as classic libpcap files using LINKTYPE_WIRESHARK_UPPER_PDU (252).
// Every frame starts with "exported PDU" tags that name the Wireshark dissector to call
// (e.g. "nr-rrc.ul.ccch" or "nas-5gs"), followed by the raw PDU. Wireshark and tshark open the
// file directly and decode the RRC/NAS content with their own ASN.1 and NAS dissectors, which is
// how NR-Lite's codecs are cross-checked against an independent implementation.

#include <cstdint>
#include <fstream>
#include <string>

#include "nrlite/common/bytes.hpp"
#include "nrlite/common/event_loop.hpp"

namespace nrlite::trace {

constexpr std::uint32_t kLinkTypeWiresharkUpperPdu = 252;

/// Exported PDU tag numbers (Wireshark epan/exported_pdu.h).
enum class ExportTag : std::uint16_t {
  EndOfOptions = 0,
  DissectorName = 12,
  Ipv4Src = 20,
  Ipv4Dst = 21,
  ColumnInfoText = 36,
};

/// Builds one frame: tags (dissector name, optional IPv4 endpoints and Info text) + payload.
Bytes exported_pdu_frame(const std::string& dissector, std::uint32_t src_ipv4, std::uint32_t dst_ipv4,
                         const Bytes& payload, const std::string& info = {});

/// Wireshark dissector name for an RRC logical channel, e.g. ("UL", "CCCH") -> "nr-rrc.ul.ccch".
std::string rrc_dissector(bool uplink, bool dcch);

class PcapWriter {
 public:
  /// Opens `path` for writing and emits the pcap global header. Throws std::runtime_error on failure.
  explicit PcapWriter(const std::string& path);

  /// Appends a frame stamped with virtual time `t` (ms) relative to a fixed epoch.
  void write(TimeMs t, const std::string& dissector, std::uint32_t src_ipv4, std::uint32_t dst_ipv4,
             const Bytes& payload, const std::string& info = {});
  std::size_t frames() const { return frames_; }
  void flush() { out_.flush(); }

  static constexpr std::uint32_t kEpochSeconds = 1767225600;  // 2026-01-01T00:00:00Z

 private:
  std::ofstream out_;
  std::size_t frames_ = 0;
};

/// Dotted-quad helper: ipv4(10, 0, 0, 1).
constexpr std::uint32_t ipv4(std::uint8_t a, std::uint8_t b, std::uint8_t c, std::uint8_t d) {
  return (std::uint32_t{a} << 24) | (std::uint32_t{b} << 16) | (std::uint32_t{c} << 8) | std::uint32_t{d};
}

}  // namespace nrlite::trace
