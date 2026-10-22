#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <iterator>

#include "nrlite/nas/messages.hpp"
#include "nrlite/rrc/messages.hpp"
#include "nrlite/sim/trace.hpp"
#include "nrlite/trace/pcap_writer.hpp"

using namespace nrlite;

TEST(PcapWriter, GlobalHeaderUsesUpperPduLinkType) {
  const std::string path = ::testing::TempDir() + "nrlite_header.pcap";
  { trace::PcapWriter w(path); }
  std::ifstream in(path, std::ios::binary);
  const Bytes b((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  ASSERT_EQ(b.size(), 24u);
  EXPECT_EQ(to_hex(b), "d4c3b2a1" "0200" "0400" "00000000" "00000000" "ffff0000" "fc000000");
  std::remove(path.c_str());
}

TEST(PcapWriter, RecordHeaderCarriesVirtualTime) {
  const std::string path = ::testing::TempDir() + "nrlite_record.pcap";
  {
    trace::PcapWriter w(path);
    w.write(1234, "nas-5gs", 0, 0, Bytes{0x7e, 0x00, 0x43});
    EXPECT_EQ(w.frames(), 1u);
  }
  std::ifstream in(path, std::ios::binary);
  const Bytes b((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  ASSERT_GT(b.size(), 40u);
  const auto le32 = [&](std::size_t o) {
    return std::uint32_t{b[o]} | (std::uint32_t{b[o + 1]} << 8) | (std::uint32_t{b[o + 2]} << 16) |
           (std::uint32_t{b[o + 3]} << 24);
  };
  EXPECT_EQ(le32(24), trace::PcapWriter::kEpochSeconds + 1);
  EXPECT_EQ(le32(28), 234000u);
  EXPECT_EQ(le32(32), b.size() - 40);
  std::remove(path.c_str());
}

TEST(ExportedPdu, TagLayout) {
  const Bytes f = trace::exported_pdu_frame("nas-5gs", trace::ipv4(10, 0, 0, 1), trace::ipv4(10, 0, 0, 2), Bytes{0xAB});
  // dissector name tag (12), padded to 8 octets
  EXPECT_EQ(to_hex(Bytes(f.begin(), f.begin() + 12)), "000c0008" "6e61732d35677300");
  // IPv4 source (20) and destination (21)
  EXPECT_EQ(to_hex(Bytes(f.begin() + 12, f.begin() + 28)), "00140004" "0a000001" "00150004" "0a000002");
  // end of options then payload
  EXPECT_EQ(to_hex(Bytes(f.begin() + 28, f.end())), "00000000" "ab");
}

TEST(ExportedPdu, StringTagsAreNulTerminatedAndPadded) {
  const Bytes f = trace::exported_pdu_frame("nr-rrc.ul.ccch", 0, 0, Bytes{});
  EXPECT_EQ(f[3], 16);  // 14 characters -> 16 octets
  EXPECT_EQ(f[4 + 14], 0);
  const Bytes g = trace::exported_pdu_frame("abcd", 0, 0, Bytes{});
  EXPECT_EQ(g[3], 8);   // exact multiple of 4 still gets a NUL
}

TEST(ExportedPdu, RrcDissectorNames) {
  EXPECT_EQ(trace::rrc_dissector(true, false), "nr-rrc.ul.ccch");
  EXPECT_EQ(trace::rrc_dissector(false, false), "nr-rrc.dl.ccch");
  EXPECT_EQ(trace::rrc_dissector(true, true), "nr-rrc.ul.dcch");
  EXPECT_EQ(trace::rrc_dissector(false, true), "nr-rrc.dl.dcch");
}

TEST(TraceSummary, UuWithEmbeddedNas) {
  rrc::RrcSetupComplete c;
  c.dedicated_nas_message = nas::encode(nas::RegistrationComplete{});
  EXPECT_EQ(sim::summarize_uu(sim::Direction::Uplink, rrc::Channel::Dcch, rrc::encode_ul_dcch(c)),
            "rrcSetupComplete [RegistrationComplete]");
  EXPECT_EQ(sim::summarize_uu(sim::Direction::Downlink, rrc::Channel::Ccch, Bytes{0xFF}), "<undecodable DL-CCCH>");
}

TEST(TraceSummary, NasProtectedAndBroken) {
  nas::SecuredPdu s;
  s.security_header_type = nas::SecurityHeaderType::IntegrityProtectedAndCiphered;
  s.payload = nas::encode(nas::RegistrationComplete{});
  EXPECT_EQ(sim::summarize_nas(nas::build_secured(s)), "RegistrationComplete*");
  s.payload = Bytes{0x13, 0x37, 0x00};
  EXPECT_EQ(sim::summarize_nas(nas::build_secured(s)), "<ciphered NAS>");
  EXPECT_EQ(sim::summarize_nas(Bytes{0x01}), "<undecodable NAS>");
}

TEST(TraceSummary, StripPdcp) {
  EXPECT_EQ(sim::strip_pdcp(from_hex("0001aabb00000000")), (Bytes{0xaa, 0xbb}));
  EXPECT_TRUE(sim::strip_pdcp(Bytes{1, 2, 3}).empty());
}
