#pragma once

// Trace records for every PDU that crosses the Uu (air) or N2 interface, with sinks that keep
// them in memory or write a Wireshark-readable pcap.

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "nrlite/common/bytes.hpp"
#include "nrlite/common/event_loop.hpp"
#include "nrlite/rrc/ue_rrc.hpp"
#include "nrlite/trace/pcap_writer.hpp"

namespace nrlite::sim {

enum class Direction : std::uint8_t { Uplink, Downlink };
const char* to_string(Direction d);

enum class Interface : std::uint8_t { Uu, N2 };

struct TraceRecord {
  TimeMs time = 0;
  Interface iface = Interface::Uu;
  Direction direction = Direction::Uplink;
  std::string channel;        ///< "UL-CCCH", "DL-DCCH", ... or "N2"
  std::uint16_t rnti = 0;     ///< Uu only
  std::uint32_t ran_ue_id = 0;
  Bytes raw;                  ///< as transmitted (PDCP PDU on DCCH)
  Bytes payload;              ///< RRC PDU for Uu (PDCP removed), NAS PDU for N2
  std::string message;        ///< decoded summary, e.g. "dlInformationTransfer [AuthenticationRequest]"
  bool dropped = false;       ///< removed by a fault-injection interceptor
};

/// Best-effort RRC + embedded NAS summary for a Uu PDU (assumes NEA0 when reading through PDCP).
std::string summarize_uu(Direction dir, rrc::Channel ch, const Bytes& rrc_pdu);
/// NAS message name for a 5GMM PDU, looking inside 5G-EA0 protected messages.
std::string summarize_nas(const Bytes& nas_pdu);
/// Strips the 2-octet PDCP header and 4-octet MAC-I of an SRB PDU.
Bytes strip_pdcp(const Bytes& pdcp_pdu);

class TraceSink {
 public:
  virtual ~TraceSink() = default;
  virtual void on_record(const TraceRecord& r) = 0;
};

class MemoryTrace : public TraceSink {
 public:
  void on_record(const TraceRecord& r) override { records_.push_back(r); }
  const std::vector<TraceRecord>& records() const { return records_; }
  void clear() { records_.clear(); }
  /// Message names in order, e.g. {"rrcSetupRequest", "rrcSetup", ...} for Uu records.
  std::vector<std::string> uu_messages() const;

 private:
  std::vector<TraceRecord> records_;
};

/// Writes Uu records with the nr-rrc dissectors and N2 records with nas-5gs. Dropped PDUs are
/// not written (they never reached the receiver).
class PcapTrace : public TraceSink {
 public:
  explicit PcapTrace(const std::string& path, bool include_n2 = true);
  void on_record(const TraceRecord& r) override;
  std::size_t frames() const { return writer_.frames(); }
  void flush() { writer_.flush(); }

  static constexpr std::uint32_t kGnbIp = trace::ipv4(10, 0, 0, 1);
  static constexpr std::uint32_t kAmfIp = trace::ipv4(10, 0, 0, 2);
  static std::uint32_t ue_ip(std::uint16_t rnti) { return trace::ipv4(10, 45, static_cast<std::uint8_t>(rnti >> 8), static_cast<std::uint8_t>(rnti)); }

 private:
  trace::PcapWriter writer_;
  bool include_n2_;
};

}  // namespace nrlite::sim
