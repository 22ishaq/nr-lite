#include "nrlite/nas/ies.hpp"

#include <gtest/gtest.h>

using namespace nrlite;
using namespace nrlite::nas;

TEST(NasPlmn, TwoDigitMncUsesFiller) {
  EXPECT_EQ(to_hex(encode_plmn(Plmn{"001", "01"})), "00f110");
  EXPECT_EQ(to_hex(encode_plmn(Plmn{"208", "93"})), "02f839");
}

TEST(NasPlmn, ThreeDigitMnc) {
  EXPECT_EQ(to_hex(encode_plmn(Plmn{"310", "410"})), "130014");
  const Bytes b = encode_plmn(Plmn{"310", "410"});
  EXPECT_EQ(decode_plmn(b.data()), (Plmn{"310", "410"}));
}

TEST(NasPlmn, RejectsBadDigits) {
  EXPECT_THROW(encode_plmn(Plmn{"0a1", "01"}), std::invalid_argument);
  EXPECT_THROW(encode_plmn(Plmn{"01", "01"}), std::invalid_argument);
  const Bytes bad{0xAA, 0xF1, 0x10};
  EXPECT_THROW(decode_plmn(bad.data()), NasDecodeError);
}

TEST(NasBcd, OddAndEvenDigitCounts) {
  EXPECT_EQ(to_hex(encode_bcd("12345")), "2143f5");
  EXPECT_EQ(to_hex(encode_bcd("0000000001")), "0000000010");
  const Bytes odd = encode_bcd("98765");
  EXPECT_EQ(decode_bcd(odd.data(), odd.size()), "98765");
}

TEST(NasBcd, FillerOnlyAllowedInLastOctet) {
  const Bytes b{0xF1, 0x23};
  EXPECT_THROW(decode_bcd(b.data(), b.size()), NasDecodeError);
}

TEST(NasMobileIdentity, SuciNullSchemeGolden) {
  Suci s;
  s.plmn = Plmn{"001", "01"};
  s.msin = "0000000001";
  // type SUCI, PLMN, routing indicator 0000, null scheme, key id 0, MSIN BCD
  EXPECT_EQ(to_hex(encode_mobile_identity(s)), "0100f110000000000000000010");
}

TEST(NasMobileIdentity, SuciRoundTripAndSupi) {
  Suci s;
  s.plmn = Plmn{"208", "93"};
  s.routing_indicator = "17";
  s.msin = "0000001234";
  const auto id = decode_mobile_identity(encode_mobile_identity(s));
  ASSERT_TRUE(std::holds_alternative<Suci>(id));
  EXPECT_EQ(std::get<Suci>(id), s);
  EXPECT_EQ(std::get<Suci>(id).supi(), "208930000001234");
}

TEST(NasMobileIdentity, SuciNonNullSchemeKeepsOutputOpaque) {
  Suci s;
  s.protection_scheme_id = 1;  // ECIES profile A
  s.home_network_public_key_id = 3;
  s.scheme_output = Bytes(40, 0xAB);
  const auto id = decode_mobile_identity(encode_mobile_identity(s));
  EXPECT_EQ(std::get<Suci>(id).scheme_output, s.scheme_output);
  EXPECT_TRUE(std::get<Suci>(id).msin.empty());
}

TEST(NasMobileIdentity, GutiGolden) {
  Guti5g g;
  g.plmn = Plmn{"001", "01"};
  g.amf_region_id = 1;
  g.amf_set_id = 1;
  g.amf_pointer = 1;
  g.tmsi = 0xaaf708ba;
  EXPECT_EQ(to_hex(encode_mobile_identity(g)), "f200f1100100" "41" "aaf708ba");
  EXPECT_EQ(std::get<Guti5g>(decode_mobile_identity(encode_mobile_identity(g))), g);
}

TEST(NasMobileIdentity, GutiDerivedIdentifiers) {
  Guti5g g;
  g.amf_region_id = 0xCA;
  g.amf_set_id = 0x3FF;
  g.amf_pointer = 0x3F;
  g.tmsi = 0x12345678;
  EXPECT_EQ(g.s_tmsi(), 0xFFFF12345678ull);
  EXPECT_EQ(g.amf_identifier(), 0xCAFFFFu);
}

TEST(NasMobileIdentity, GutiFieldOverflowRejected) {
  Guti5g g;
  g.amf_set_id = 0x400;
  EXPECT_THROW(encode_mobile_identity(g), std::invalid_argument);
}

TEST(NasMobileIdentity, STmsiAndImeisvRoundTrip) {
  const STmsi5g s{0x155, 0x2A, 0xCAFEBABE};
  EXPECT_EQ(std::get<STmsi5g>(decode_mobile_identity(encode_mobile_identity(s))), s);
  const Imeisv v{"3534900698733190"};
  const Bytes enc = encode_mobile_identity(v);
  EXPECT_EQ(enc[0] & 0x0F, 0x05);  // even number of digits, type IMEISV
  EXPECT_EQ(std::get<Imeisv>(decode_mobile_identity(enc)), v);
  const Imei i{"353490069873319"};
  const Bytes ienc = encode_mobile_identity(i);
  EXPECT_EQ(ienc[0] & 0x0F, 0x0B);  // odd number of digits, type IMEI
  EXPECT_EQ(std::get<Imei>(decode_mobile_identity(ienc)), i);
}

TEST(NasMobileIdentity, DecodeErrors) {
  EXPECT_THROW(decode_mobile_identity(Bytes{}), NasDecodeError);
  EXPECT_THROW(decode_mobile_identity(from_hex("f200f110")), NasDecodeError);   // short GUTI
  EXPECT_THROW(decode_mobile_identity(from_hex("0100f1")), NasDecodeError);     // short SUCI
  EXPECT_THROW(decode_mobile_identity(from_hex("06")), NasDecodeError);         // MAC address type
  EXPECT_THROW(decode_mobile_identity(from_hex("1100f11000000000")), NasDecodeError);  // NAI format
}

TEST(NasMobileIdentity, IdentityType) {
  EXPECT_EQ(identity_type(Suci{}), IdentityType::Suci);
  EXPECT_EQ(identity_type(Guti5g{}), IdentityType::Guti);
  EXPECT_EQ(identity_type(NoIdentity{}), IdentityType::NoIdentity);
  EXPECT_EQ(identity_type(Imeisv{}), IdentityType::Imeisv);
  EXPECT_STREQ(to_string(IdentityType::STmsi), "5G-S-TMSI");
}

TEST(NasSecurityCaps, EncodingAndQueries) {
  UeSecurityCapability c{0xA0, 0x20, std::nullopt, std::nullopt};
  EXPECT_TRUE(c.supports_ea(0));
  EXPECT_FALSE(c.supports_ea(1));
  EXPECT_TRUE(c.supports_ea(2));
  EXPECT_TRUE(c.supports_ia(2));
  EXPECT_FALSE(c.supports_ia(0));
  EXPECT_EQ(to_hex(encode_ue_security_capability(c)), "a020");
  c.eutra_ea = 0xF0;
  EXPECT_EQ(to_hex(encode_ue_security_capability(c)), "a020f000");
  EXPECT_EQ(decode_ue_security_capability(encode_ue_security_capability(c)).eutra_ea, 0xF0);
  EXPECT_THROW(decode_ue_security_capability(Bytes{0xA0}), NasDecodeError);
  EXPECT_THROW(decode_ue_security_capability(Bytes(9, 0)), NasDecodeError);
}

TEST(NasSimpleIes, NibblesAndOctets) {
  EXPECT_EQ((Ngksi{false, 7}).nibble(), 0x07);
  EXPECT_EQ((Ngksi{true, 2}).nibble(), 0x0A);
  EXPECT_EQ(Ngksi::from_nibble(0x0A), (Ngksi{true, 2}));
  EXPECT_EQ((NasSecurityAlgorithms{2, 2}).octet(), 0x22);
  EXPECT_EQ(NasSecurityAlgorithms::from_octet(0x02), (NasSecurityAlgorithms{0, 2}));
  EXPECT_EQ((RegistrationType{true, RegistrationType::PeriodicUpdating}).nibble(), 0x0B);
  EXPECT_EQ((DeregistrationType{true, false, 1}).nibble(), 0x09);
}

TEST(NasNssai, RoundTripWithAndWithoutSd) {
  const std::vector<SNssai> list{SNssai{1, std::nullopt}, SNssai{2, 0x010203}};
  const Bytes enc = encode_nssai(list);
  EXPECT_EQ(to_hex(enc), "0101" "0402010203");
  EXPECT_EQ(decode_nssai(enc), list);
}

TEST(NasNssai, MalformedEntriesRejected) {
  EXPECT_THROW(decode_nssai(from_hex("0301")), NasDecodeError);      // length 3 invalid
  EXPECT_THROW(decode_nssai(from_hex("040102")), NasDecodeError);    // overruns IE
}

TEST(NasTaiList, Type00RoundTrip) {
  TaiList l{{Tai{Plmn{"001", "01"}, 1}, Tai{Plmn{"001", "01"}, 0x00FFEE}}};
  const Bytes enc = encode_tai_list(l);
  EXPECT_EQ(to_hex(enc), "01" "00f110" "000001" "00ffee");
  EXPECT_EQ(decode_tai_list(enc), l);
}

TEST(NasTaiList, Type01ConsecutiveAndType10Lists) {
  // type 01: 3 consecutive TACs starting at 0x10
  const TaiList consecutive = decode_tai_list(from_hex("22" "00f110" "000010"));
  ASSERT_EQ(consecutive.tais.size(), 3u);
  EXPECT_EQ(consecutive.tais[2].tac, 0x12u);
  // type 10: two TAIs with their own PLMNs
  const TaiList mixed = decode_tai_list(from_hex("41" "00f110" "000001" "02f839" "000002"));
  ASSERT_EQ(mixed.tais.size(), 2u);
  EXPECT_EQ(mixed.tais[1].plmn, (Plmn{"208", "93"}));
}

TEST(NasTaiList, MalformedRejected) {
  EXPECT_THROW(decode_tai_list(Bytes{}), NasDecodeError);
  EXPECT_THROW(decode_tai_list(from_hex("0100f110000001")), NasDecodeError);  // claims 2 TACs, has 1
  EXPECT_THROW(decode_tai_list(from_hex("6000f110000001")), NasDecodeError);  // reserved type 11
  EXPECT_THROW(encode_tai_list(TaiList{}), std::invalid_argument);
}

TEST(NasTimers, GprsTimer2And3Units) {
  EXPECT_EQ((GprsTimer{0, 5}).seconds_timer2(), 10u);
  EXPECT_EQ((GprsTimer{1, 2}).seconds_timer2(), 120u);
  EXPECT_EQ((GprsTimer{2, 1}).seconds_timer2(), 360u);
  EXPECT_FALSE((GprsTimer{7, 1}).seconds_timer2());
  EXPECT_EQ((GprsTimer{1, 1}).seconds_timer3(), 3600u);
  EXPECT_EQ((GprsTimer{3, 5}).seconds_timer3(), 10u);
  EXPECT_EQ((GprsTimer{4, 2}).seconds_timer3(), 60u);
  EXPECT_FALSE((GprsTimer{7, 0}).seconds_timer3());
  EXPECT_EQ((GprsTimer{1, 1}).octet(), 0x21);
  EXPECT_EQ(GprsTimer::from_octet(0x21), (GprsTimer{1, 1}));
}

TEST(NasCause, Names) {
  EXPECT_STREQ(to_string(Cause::Congestion), "Congestion");
  EXPECT_STREQ(to_string(Cause::NgksiAlreadyInUse), "ngKSI already in use");
  EXPECT_STREQ(to_string(static_cast<Cause>(200)), "unknown cause");
}
