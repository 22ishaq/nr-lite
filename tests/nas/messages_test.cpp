// 5GMM message codec tests. Golden encodings are hand-derived from TS 24.501 §8.2 and were also
// decoded field by field with Wireshark's nas-5gs dissector.

#include "nrlite/nas/messages.hpp"

#include <gtest/gtest.h>
#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

#include "support/fixtures.hpp"

using namespace nrlite;
using namespace nrlite::nas;
using nrlite::testing::test_caps;
using nrlite::testing::test_suci;

namespace {

Guti5g sample_guti() {
  Guti5g g;
  g.plmn = Plmn{"001", "01"};
  g.amf_region_id = 1;
  g.amf_set_id = 1;
  g.amf_pointer = 1;
  g.tmsi = 0xaaf708ba;
  return g;
}

RegistrationRequest sample_registration_request() {
  RegistrationRequest rr;
  rr.mobile_identity = test_suci();
  rr.mm_capability = Bytes{0x00};
  rr.ue_security_capability = test_caps();
  rr.requested_nssai = std::vector<SNssai>{SNssai{1, std::nullopt}};
  return rr;
}

std::vector<PlainMessage> all_messages() {
  RegistrationRequest rr = sample_registration_request();
  rr.registration_type = RegistrationType{true, RegistrationType::MobilityUpdating};
  rr.ngksi = Ngksi{false, 3};
  rr.last_visited_registered_tai = Tai{Plmn{"001", "01"}, 7};
  rr.nas_message_container = Bytes{0x7e, 0x00, 0x43};

  RegistrationAccept acc;
  acc.guti = sample_guti();
  acc.tai_list = TaiList{{Tai{Plmn{"001", "01"}, 1}}};
  acc.allowed_nssai = std::vector<SNssai>{SNssai{1, std::nullopt}};
  acc.t3512 = GprsTimer{1, 1};
  acc.t3502 = GprsTimer{1, 12};

  AuthenticationRequest auth;
  auth.ngksi = Ngksi{false, 2};
  auth.rand = Rand{};
  auth.rand->fill(0x11);
  auth.autn = Autn{};
  auth.autn->fill(0x22);

  ResStar res{};
  res.fill(0x33);
  Auts auts{};
  auts.fill(0x44);

  SecurityModeCommand smc;
  smc.selected_algorithms = NasSecurityAlgorithms{2, 2};
  smc.ngksi = Ngksi{false, 2};
  smc.replayed_ue_security_capability = test_caps();
  smc.imeisv_request = true;
  smc.additional_security_information = 0x02;
  smc.abba = Bytes{0x00, 0x00};

  SecurityModeComplete smc_complete;
  smc_complete.imeisv = Imeisv{"3534900698733190"};
  smc_complete.nas_message_container = encode(sample_registration_request());

  return {rr,
          acc,
          RegistrationComplete{},
          RegistrationReject{Cause::Congestion, GprsTimer{1, 5}, GprsTimer{2, 1}},
          DeregistrationRequestUeOriginating{DeregistrationType{false, false, 1}, Ngksi{false, 1}, sample_guti()},
          DeregistrationAcceptUeOriginating{},
          auth,
          AuthenticationResponse{res},
          AuthenticationReject{},
          AuthenticationFailure{Cause::SynchFailure, auts},
          IdentityRequest{IdentityType::Suci},
          IdentityResponse{test_suci()},
          smc,
          smc_complete,
          SecurityModeReject{Cause::UeSecurityCapabilitiesMismatch},
          Status5gmm{Cause::MessageTypeNonExistent}};
}

class NasRoundTrip : public ::testing::TestWithParam<std::size_t> {};

}  // namespace

TEST_P(NasRoundTrip, EncodeDecodeIsIdentity) {
  const PlainMessage m = all_messages().at(GetParam());
  const Bytes enc = encode(m);
  EXPECT_EQ(enc[0], kEpd5gmm);
  EXPECT_EQ(enc[1], 0x00);
  EXPECT_EQ(enc[2], static_cast<std::uint8_t>(message_type(m)));
  auto dec = decode_plain(enc);
  ASSERT_TRUE(dec) << message_name(m) << ": " << dec.error().message;
  EXPECT_EQ(*dec, m) << message_name(m);
}

INSTANTIATE_TEST_SUITE_P(AllMessages, NasRoundTrip, ::testing::Range<std::size_t>(0, 16),
                         [](const auto& info) {
                           std::string n = message_name(all_messages().at(info.param));
                           n.erase(std::remove_if(n.begin(), n.end(), [](char c) { return !std::isalnum(c); }), n.end());
                           return n;
                         });

TEST(NasGolden, RegistrationRequestInitialWithSuci) {
  EXPECT_EQ(to_hex(encode(sample_registration_request())),
            "7e004171"                           // header, ngKSI 7 / initial registration
            "000d0100f110000000000000000010"     // 5GS mobile identity (SUCI, null scheme)
            "100100"                             // 5GMM capability
            "2e02a020"                           // UE security capability: EA0, EA2 / IA2
            "2f020101");                         // requested NSSAI: SST 1
}

TEST(NasGolden, RegistrationAccept) {
  RegistrationAccept acc;
  acc.guti = sample_guti();
  acc.tai_list = TaiList{{Tai{Plmn{"001", "01"}, 1}}};
  acc.allowed_nssai = std::vector<SNssai>{SNssai{1, std::nullopt}};
  acc.t3512 = GprsTimer{1, 1};
  EXPECT_EQ(to_hex(encode(acc)),
            "7e0042" "0101"
            "77000bf200f110010041aaf708ba"
            "54070000f110000001"
            "15020101"
            "5e0121");
}

TEST(NasGolden, AuthenticationRequestLayout) {
  AuthenticationRequest a;
  a.ngksi = Ngksi{false, 0};
  a.rand = Rand{};
  a.autn = Autn{};
  const Bytes enc = encode(a);
  ASSERT_EQ(enc.size(), 3u + 1u + 3u + 17u + 18u);
  EXPECT_EQ(to_hex(Bytes(enc.begin(), enc.begin() + 7)), "7e005600020000");
  EXPECT_EQ(enc[7], 0x21);   // RAND IEI (TV)
  EXPECT_EQ(enc[24], 0x20);  // AUTN IEI (TLV)
  EXPECT_EQ(enc[25], 16);
}

TEST(NasGolden, SecurityModeCommand) {
  SecurityModeCommand smc;
  smc.selected_algorithms = NasSecurityAlgorithms{0, 2};
  smc.ngksi = Ngksi{false, 0};
  smc.replayed_ue_security_capability = test_caps();
  smc.imeisv_request = true;
  EXPECT_EQ(to_hex(encode(smc)), "7e005d020002a020e1");
}

TEST(NasDecode, TooShortIsIgnoredWithCause111) {
  auto r = decode_plain(Bytes{0x7e, 0x00});
  ASSERT_FALSE(r);
  EXPECT_EQ(r.error().code, static_cast<int>(Cause::ProtocolErrorUnspecified));
}

TEST(NasDecode, UnknownMessageTypeGivesCause97) {
  auto r = decode_plain(Bytes{0x7e, 0x00, 0x99});
  ASSERT_FALSE(r);
  EXPECT_EQ(r.error().code, static_cast<int>(Cause::MessageTypeNonExistent));
}

TEST(NasDecode, WrongEpdRejected) {
  auto r = decode_plain(Bytes{0x2e, 0x00, 0x41});
  ASSERT_FALSE(r);
  EXPECT_EQ(r.error().code, static_cast<int>(Cause::MessageTypeNonExistent));
}

TEST(NasDecode, ProtectedHeaderIsNotPlain) { EXPECT_FALSE(decode_plain(Bytes{0x7e, 0x02, 0x00, 0, 0, 0, 0})); }

TEST(NasDecode, MissingMandatoryIeGivesCause96) {
  // REGISTRATION REQUEST without the 5GS mobile identity
  auto r = decode_plain(from_hex("7e004171"));
  ASSERT_FALSE(r);
  EXPECT_EQ(r.error().code, static_cast<int>(Cause::InvalidMandatoryInformation));
  // AUTHENTICATION REQUEST without ABBA
  auto a = decode_plain(from_hex("7e005600"));
  ASSERT_FALSE(a);
  EXPECT_EQ(a.error().code, static_cast<int>(Cause::InvalidMandatoryInformation));
}

TEST(NasDecode, LengthOverrunGivesCause96) {
  // mobile identity claims 0x20 octets but only 2 follow
  auto r = decode_plain(from_hex("7e00417100200100"));
  ASSERT_FALSE(r);
  EXPECT_EQ(r.error().code, static_cast<int>(Cause::InvalidMandatoryInformation));
}

TEST(NasDecode, ReservedRegistrationTypeRejected) {
  auto r = decode_plain(from_hex("7e004177000d0100f110000000000000000010"));
  ASSERT_FALSE(r);
  EXPECT_EQ(r.error().code, static_cast<int>(Cause::InvalidMandatoryInformation));
}

TEST(NasDecode, UnknownOptionalIesAreSkipped) {
  Bytes enc = encode(sample_registration_request());
  // Append an unknown TLV (0x13), an unknown TLV-E (0x7F) and an unknown type-1 IE (0x9-).
  for (std::uint8_t b : from_hex("1302abcd" "7f0003010203" "91")) enc.push_back(b);
  auto r = decode_plain(enc);
  ASSERT_TRUE(r) << r.error().message;
  EXPECT_EQ(std::get<RegistrationRequest>(*r), sample_registration_request());
}

TEST(NasDecode, RepeatedOptionalIeKeepsFirstOccurrence) {
  Bytes enc = encode(sample_registration_request());
  for (std::uint8_t b : from_hex("2e02ffff")) enc.push_back(b);
  auto r = decode_plain(enc);
  ASSERT_TRUE(r);
  EXPECT_EQ(std::get<RegistrationRequest>(*r).ue_security_capability, test_caps());
}

TEST(NasDecode, TruncatedOptionalIeRejected) {
  Bytes enc = encode(sample_registration_request());
  enc.pop_back();
  EXPECT_FALSE(decode_plain(enc));
}

// TS 24.501 §7.7.2: syntactically incorrect optional IEs are treated as not present.
TEST(NasDecode, MalformedOptionalIeIsTreatedAsNotPresent) {
  // AUTHENTICATION RESPONSE with a 15-octet RES*
  auto r = decode_plain(from_hex("7e00572d0f" "000000000000000000000000000000"));
  ASSERT_TRUE(r) << r.error().message;
  EXPECT_FALSE(std::get<AuthenticationResponse>(*r).res_star);
}

// Regression for Verdict VD-MM-020 (DEFECT_LOG #5): a T3502 IE of length 2 used to reject the
// whole REGISTRATION ACCEPT with cause #96.
TEST(NasDecode, RegistrationAcceptWithBadT3502KeepsOtherIes) {
  RegistrationAccept acc;
  acc.guti = sample_guti();
  acc.t3512 = GprsTimer{1, 1};
  Bytes enc = encode(acc);
  for (std::uint8_t b : from_hex("16022121")) enc.push_back(b);
  auto r = decode_plain(enc);
  ASSERT_TRUE(r) << r.error().message;
  const auto& dec = std::get<RegistrationAccept>(*r);
  EXPECT_EQ(dec.guti, acc.guti);
  EXPECT_EQ(dec.t3512, acc.t3512);
  EXPECT_FALSE(dec.t3502);
}

TEST(NasDecode, RegistrationAcceptGutiIeWithoutGutiIsIgnored) {
  auto r = decode_plain(from_hex("7e00420101" "77000d0100f110000000000000000010"));
  ASSERT_TRUE(r);
  EXPECT_FALSE(std::get<RegistrationAccept>(*r).guti);
}

TEST(NasDecode, EveryTruncationOfEveryMessageIsHandled) {
  for (const auto& m : all_messages()) {
    const Bytes enc = encode(m);
    for (std::size_t n = 0; n < enc.size(); ++n) {
      (void)decode_plain(Bytes(enc.begin(), enc.begin() + static_cast<std::ptrdiff_t>(n)));
    }
  }
  SUCCEED();
}

TEST(NasDecode, RandomInputNeverCrashes) {
  std::uint32_t x = 99;
  for (int i = 0; i < 5000; ++i) {
    Bytes b(3 + i % 50);
    for (auto& v : b) {
      x = x * 1103515245u + 12345u;
      v = static_cast<std::uint8_t>(x >> 16);
    }
    b[0] = kEpd5gmm;
    b[1] = 0x00;
    b[2] = static_cast<std::uint8_t>(0x41 + i % 0x24);
    (void)decode_plain(b);
  }
  SUCCEED();
}

TEST(NasSecurityHeader, ParseAndBuild) {
  SecuredPdu s;
  s.security_header_type = SecurityHeaderType::IntegrityProtectedAndCiphered;
  s.mac = {1, 2, 3, 4};
  s.sqn = 9;
  s.payload = encode(RegistrationComplete{});
  const Bytes pdu = build_secured(s);
  EXPECT_EQ(to_hex(pdu), "7e0201020304097e0043");
  auto p = parse_secured(pdu);
  ASSERT_TRUE(p);
  EXPECT_EQ(p->sqn, 9);
  EXPECT_EQ(p->payload, s.payload);
  EXPECT_EQ(*peek_security_header_type(pdu), SecurityHeaderType::IntegrityProtectedAndCiphered);
}

TEST(NasSecurityHeader, Errors) {
  EXPECT_FALSE(parse_secured(encode(RegistrationComplete{})));  // plain
  EXPECT_FALSE(parse_secured(from_hex("7e020102")));             // short
  EXPECT_FALSE(peek_security_header_type(from_hex("7e0f00")));   // reserved header type
  EXPECT_FALSE(peek_security_header_type(Bytes{0x7e}));
}

TEST(NasJson, RegistrationRequestFields) {
  const std::string j = to_json(sample_registration_request()).dump();
  EXPECT_NE(j.find(R"("message":"RegistrationRequest")"), std::string::npos);
  EXPECT_NE(j.find(R"("msin":"0000000001")"), std::string::npos);
  EXPECT_NE(j.find(R"("5G-EA":160)"), std::string::npos);
}

TEST(NasJson, MessageNames) {
  EXPECT_EQ(message_name(DeregistrationRequestUeOriginating{}), "DeregistrationRequest(UE originating)");
  EXPECT_EQ(message_name(Status5gmm{}), "5GMMStatus");
  EXPECT_STREQ(to_string(SecurityHeaderType::IntegrityProtectedWithNewContext),
               "Integrity protected with new 5G NAS security context");
}
