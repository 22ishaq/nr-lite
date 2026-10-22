// RRC codec tests. The golden encodings below were cross-checked by decoding them with
// Wireshark's nr-rrc dissector (tshark 4.6), which is generated from the TS 38.331 ASN.1.

#include "nrlite/rrc/messages.hpp"

#include <gtest/gtest.h>

#include "nrlite/asn1/per.hpp"

using namespace nrlite;
using namespace nrlite::rrc;

namespace {

RrcSetup standard_setup(std::uint8_t txid = 0) {
  RrcSetup s;
  s.rrc_transaction_identifier = txid;
  s.radio_bearer_config.srb_to_add_mod_list = {SrbToAddMod{1, false, false}};
  RlcBearerConfig rlc;
  rlc.logical_channel_identity = 1;
  rlc.served_radio_bearer = RlcBearerConfig::ServedRadioBearer{true, 1};
  s.master_cell_group.rlc_bearer_to_add_mod_list = {rlc};
  return s;
}

RrcSetupComplete full_setup_complete() {
  RrcSetupComplete c;
  c.rrc_transaction_identifier = 2;
  c.selected_plmn_identity = 12;
  RegisteredAmf amf;
  amf.amf_identifier = 0x010041;
  amf.plmn_identity = PlmnIdentity{std::array<std::uint8_t, 3>{0, 0, 1}, {0, 1}};
  c.registered_amf = amf;
  c.guami_type = RrcSetupComplete::GuamiType::mapped;
  c.s_nssai_list = {SNssai{1, std::nullopt}, SNssai{2, 0xABCDEF}};
  c.dedicated_nas_message = from_hex("7e004171000d0100f110000000000000000010");
  c.ng_5g_s_tmsi_value = RrcSetupComplete::Ng5gSTmsiValue{false, 0x1AB};
  return c;
}

}  // namespace

// ---- Golden encodings ---------------------------------------------------------------------------

TEST(RrcGolden, RrcSetupRequestIs48Bits) {
  RrcSetupRequest req;
  req.ue_identity = InitialUeIdentity{InitialUeIdentity::Type::randomValue, 0x123456789A};
  req.establishment_cause = EstablishmentCause::mo_Signalling;
  const Bytes enc = encode_ul_ccch(req);
  EXPECT_EQ(to_hex(enc), "12468acf1346");
  EXPECT_EQ(enc.size(), 6u);  // the CCCH message is exactly 48 bits
}

TEST(RrcGolden, RrcSetupRequestWithSTmsiPart1) {
  RrcSetupRequest req;
  req.ue_identity = InitialUeIdentity{InitialUeIdentity::Type::ng_5G_S_TMSI_Part1, (1ull << 39) - 1};
  req.establishment_cause = EstablishmentCause::mt_Access;
  // c1(0) rrcSetupRequest(00) ng-5G-S-TMSI-Part1(0) 39 x '1', cause 0010, spare 0
  EXPECT_EQ(to_hex(encode_ul_ccch(req)), "0fffffffffe4");
}

TEST(RrcGolden, RrcSetup) { EXPECT_EQ(to_hex(encode_dl_ccch(standard_setup())), "2040002200040000"); }

TEST(RrcGolden, RrcRejectWithWaitTime) { EXPECT_EQ(to_hex(encode_dl_ccch(RrcReject{5})), "0880"); }

TEST(RrcGolden, RrcRejectWithoutWaitTime) { EXPECT_EQ(to_hex(encode_dl_ccch(RrcReject{})), "00"); }

TEST(RrcGolden, SecurityModeCommand) {
  EXPECT_EQ(to_hex(encode_dl_dcch(SecurityModeCommand{1, CipheringAlgorithm::nea0, IntegrityProtAlgorithm::nia2})),
            "220810");
}

TEST(RrcGolden, SecurityModeComplete) { EXPECT_EQ(to_hex(encode_ul_dcch(SecurityModeComplete{1})), "2a00"); }

TEST(RrcGolden, SecurityModeFailure) { EXPECT_EQ(to_hex(encode_ul_dcch(SecurityModeFailure{1})), "3200"); }

TEST(RrcGolden, RrcReleaseWithDeprioritisationAndWaitTime) {
  RrcRelease r;
  r.rrc_transaction_identifier = 3;
  r.deprioritisation_req =
      RrcRelease::DeprioritisationReq{RrcRelease::DeprioritisationReq::Type::nr, RrcRelease::DeprioritisationReq::Timer::min10};
  r.wait_time = 7;
  EXPECT_EQ(to_hex(encode_dl_dcch(r)), "1616cc");
}

TEST(RrcGolden, PlainRrcRelease) { EXPECT_EQ(to_hex(encode_dl_dcch(RrcRelease{})), "1000"); }

TEST(RrcGolden, CellGroupConfigContainer) {
  EXPECT_EQ(to_hex(encode_cell_group_config(standard_setup().master_cell_group)), "40008000");
}

// ---- Round trips --------------------------------------------------------------------------------

TEST(RrcRoundTrip, UlCcchAllEstablishmentCauses) {
  for (unsigned c = 0; c < 16; ++c) {
    RrcSetupRequest req;
    req.ue_identity = InitialUeIdentity{InitialUeIdentity::Type::randomValue, 0x5555555555ull & ((1ull << 39) - 1)};
    req.establishment_cause = static_cast<EstablishmentCause>(c);
    auto dec = decode_ul_ccch(encode_ul_ccch(req));
    ASSERT_TRUE(dec) << dec.error().message;
    EXPECT_EQ(std::get<RrcSetupRequest>(*dec), req);
  }
}

TEST(RrcRoundTrip, RrcSetup) {
  for (std::uint8_t txid = 0; txid < 4; ++txid) {
    const RrcSetup s = standard_setup(txid);
    auto dec = decode_dl_ccch(encode_dl_ccch(s));
    ASSERT_TRUE(dec) << dec.error().message;
    EXPECT_EQ(std::get<RrcSetup>(*dec), s);
  }
}

TEST(RrcRoundTrip, RrcSetupWithAllModelledOptions) {
  RrcSetup s = standard_setup(3);
  s.radio_bearer_config.srb_to_add_mod_list = {SrbToAddMod{1, true, true}, SrbToAddMod{2, false, true}};
  s.radio_bearer_config.srb3_to_release = true;
  s.master_cell_group.cell_group_id = 3;
  RlcBearerConfig drb;
  drb.logical_channel_identity = 32;
  drb.served_radio_bearer = RlcBearerConfig::ServedRadioBearer{false, 32};
  drb.reestablish_rlc = true;
  s.master_cell_group.rlc_bearer_to_add_mod_list.push_back(drb);
  auto dec = decode_dl_ccch(encode_dl_ccch(s));
  ASSERT_TRUE(dec) << dec.error().message;
  EXPECT_EQ(std::get<RrcSetup>(*dec), s);
}

TEST(RrcRoundTrip, RrcReject) {
  for (std::uint8_t w = 1; w <= 16; ++w) {
    auto dec = decode_dl_ccch(encode_dl_ccch(RrcReject{w}));
    ASSERT_TRUE(dec);
    EXPECT_EQ(std::get<RrcReject>(*dec).wait_time, w);
  }
}

TEST(RrcRoundTrip, RrcSetupCompleteMinimal) {
  RrcSetupComplete c;
  c.dedicated_nas_message = Bytes{0x7e, 0x00, 0x43};
  auto dec = decode_ul_dcch(encode_ul_dcch(c));
  ASSERT_TRUE(dec) << dec.error().message;
  EXPECT_EQ(std::get<RrcSetupComplete>(*dec), c);
}

TEST(RrcRoundTrip, RrcSetupCompleteWithAllOptions) {
  const RrcSetupComplete c = full_setup_complete();
  auto dec = decode_ul_dcch(encode_ul_dcch(c));
  ASSERT_TRUE(dec) << dec.error().message;
  EXPECT_EQ(std::get<RrcSetupComplete>(*dec), c);
}

TEST(RrcRoundTrip, RrcSetupCompleteWithFull5gSTmsi) {
  RrcSetupComplete c;
  c.dedicated_nas_message = Bytes(200, 0x5A);  // forces the two-octet length form
  c.ng_5g_s_tmsi_value = RrcSetupComplete::Ng5gSTmsiValue{true, 0xFFFFFFFFFFFFull};
  auto dec = decode_ul_dcch(encode_ul_dcch(c));
  ASSERT_TRUE(dec) << dec.error().message;
  EXPECT_EQ(std::get<RrcSetupComplete>(*dec), c);
}

TEST(RrcRoundTrip, SecurityModeCommandAllAlgorithmCombinations) {
  for (unsigned ea = 0; ea < 8; ++ea) {
    for (unsigned ia = 0; ia < 8; ++ia) {
      SecurityModeCommand smc{static_cast<std::uint8_t>(ia % 4), static_cast<CipheringAlgorithm>(ea),
                              static_cast<IntegrityProtAlgorithm>(ia)};
      auto dec = decode_dl_dcch(encode_dl_dcch(smc));
      ASSERT_TRUE(dec);
      EXPECT_EQ(std::get<SecurityModeCommand>(*dec), smc);
    }
  }
}

TEST(RrcRoundTrip, SecurityModeCommandWithoutIntegrity) {
  SecurityModeCommand smc{2, CipheringAlgorithm::nea2, std::nullopt};
  auto dec = decode_dl_dcch(encode_dl_dcch(smc));
  ASSERT_TRUE(dec);
  EXPECT_EQ(std::get<SecurityModeCommand>(*dec), smc);
}

TEST(RrcRoundTrip, InformationTransfers) {
  const Bytes nas = from_hex("7e0056000200002101020304050607080910111213141516");
  auto dl = decode_dl_dcch(encode_dl_dcch(DlInformationTransfer{3, nas}));
  ASSERT_TRUE(dl);
  EXPECT_EQ(std::get<DlInformationTransfer>(*dl).dedicated_nas_message, nas);
  auto ul = decode_ul_dcch(encode_ul_dcch(UlInformationTransfer{nas}));
  ASSERT_TRUE(ul);
  EXPECT_EQ(std::get<UlInformationTransfer>(*ul).dedicated_nas_message, nas);
  auto empty = decode_ul_dcch(encode_ul_dcch(UlInformationTransfer{}));
  ASSERT_TRUE(empty);
  EXPECT_FALSE(std::get<UlInformationTransfer>(*empty).dedicated_nas_message);
}

TEST(RrcRoundTrip, SecurityModeCompleteAndFailure) {
  for (std::uint8_t t = 0; t < 4; ++t) {
    auto c = decode_ul_dcch(encode_ul_dcch(SecurityModeComplete{t}));
    ASSERT_TRUE(c);
    EXPECT_EQ(std::get<SecurityModeComplete>(*c).rrc_transaction_identifier, t);
    auto f = decode_ul_dcch(encode_ul_dcch(SecurityModeFailure{t}));
    ASSERT_TRUE(f);
    EXPECT_EQ(std::get<SecurityModeFailure>(*f).rrc_transaction_identifier, t);
  }
}

TEST(RrcRoundTrip, RrcReleaseVariants) {
  for (unsigned type = 0; type < 2; ++type) {
    for (unsigned timer = 0; timer < 4; ++timer) {
      RrcRelease r;
      r.rrc_transaction_identifier = 1;
      r.deprioritisation_req = RrcRelease::DeprioritisationReq{static_cast<RrcRelease::DeprioritisationReq::Type>(type),
                                                               static_cast<RrcRelease::DeprioritisationReq::Timer>(timer)};
      r.wait_time = static_cast<std::uint8_t>(1 + timer);
      auto dec = decode_dl_dcch(encode_dl_dcch(r));
      ASSERT_TRUE(dec) << dec.error().message;
      EXPECT_EQ(std::get<RrcRelease>(*dec), r);
    }
  }
}

// ---- Encoder constraint checks ------------------------------------------------------------------

TEST(RrcEncode, RejectsOutOfRangeFields) {
  RrcSetupComplete c;
  c.selected_plmn_identity = 13;  // maxPLMN = 12
  EXPECT_THROW(encode_ul_dcch(c), asn1::EncodeError);
  c.selected_plmn_identity = 1;
  c.s_nssai_list = std::vector<SNssai>(9, SNssai{});  // maxNrofS-NSSAI = 8
  EXPECT_THROW(encode_ul_dcch(c), asn1::EncodeError);
}

TEST(RrcEncode, RejectsTooManySrbsAndBadIdentity) {
  RrcSetup s = standard_setup();
  s.radio_bearer_config.srb_to_add_mod_list = {SrbToAddMod{1}, SrbToAddMod{2}, SrbToAddMod{3}};
  EXPECT_THROW(encode_dl_ccch(s), asn1::EncodeError);
  s = standard_setup();
  s.radio_bearer_config.srb_to_add_mod_list = {SrbToAddMod{4}};
  EXPECT_THROW(encode_dl_ccch(s), asn1::EncodeError);
}

TEST(RrcEncode, RejectsOversizedUeIdentityAndTxid) {
  RrcSetupRequest req;
  req.ue_identity.value = 1ull << 39;
  EXPECT_THROW(encode_ul_ccch(req), asn1::EncodeError);
  EXPECT_THROW(encode_ul_dcch(SecurityModeComplete{4}), asn1::EncodeError);
  EXPECT_THROW(encode_dl_ccch(RrcReject{17}), asn1::EncodeError);
}

// ---- Decoder robustness -------------------------------------------------------------------------

TEST(RrcDecode, EmptyPduIsAnError) {
  EXPECT_FALSE(decode_ul_ccch(Bytes{}));
  EXPECT_FALSE(decode_dl_ccch(Bytes{}));
  EXPECT_FALSE(decode_ul_dcch(Bytes{}));
  EXPECT_FALSE(decode_dl_dcch(Bytes{}));
}

TEST(RrcDecode, EveryTruncationOfRrcSetupCompleteFails) {
  const Bytes enc = encode_ul_dcch(full_setup_complete());
  for (std::size_t n = 0; n < enc.size(); ++n) {
    EXPECT_FALSE(decode_ul_dcch(Bytes(enc.begin(), enc.begin() + static_cast<std::ptrdiff_t>(n)))) << "length " << n;
  }
}

TEST(RrcDecode, EveryTruncationOfRrcSetupFails) {
  const Bytes enc = encode_dl_ccch(standard_setup());
  for (std::size_t n = 0; n < enc.size(); ++n) {
    EXPECT_FALSE(decode_dl_ccch(Bytes(enc.begin(), enc.begin() + static_cast<std::ptrdiff_t>(n)))) << "length " << n;
  }
}

TEST(RrcDecode, TrailingOctetsAreRejected) {
  Bytes enc = encode_ul_ccch(RrcSetupRequest{});
  enc.push_back(0x00);
  auto dec = decode_ul_ccch(enc);
  ASSERT_FALSE(dec);
  EXPECT_NE(dec.error().message.find("trailing"), std::string::npos);
}

TEST(RrcDecode, UnsupportedUlCcchAlternativeNamed) {
  // c1 = rrcResumeRequest (01)
  auto dec = decode_ul_ccch(from_hex("200000000000"));
  ASSERT_FALSE(dec);
  EXPECT_NE(dec.error().message.find("rrcResumeRequest"), std::string::npos);
}

TEST(RrcDecode, MessageClassExtensionRejected) {
  EXPECT_FALSE(decode_ul_ccch(from_hex("800000000000")));
  EXPECT_FALSE(decode_dl_dcch(from_hex("80")));
}

TEST(RrcDecode, UnsupportedDlDcchAlternativeNamed) {
  // c1 index 0 = rrcReconfiguration
  auto dec = decode_dl_dcch(from_hex("0000"));
  ASSERT_FALSE(dec);
  EXPECT_NE(dec.error().message.find("rrcReconfiguration"), std::string::npos);
}

TEST(RrcDecode, UnsupportedUlDcchAlternativeNamed) {
  // c1 index 9 = ueCapabilityInformation
  auto dec = decode_ul_dcch(from_hex("4800"));
  ASSERT_FALSE(dec);
  EXPECT_NE(dec.error().message.find("ueCapabilityInformation"), std::string::npos);
}

TEST(RrcDecode, CriticalExtensionsFutureRejected) {
  // c1 (0), securityModeComplete (0101), txid (00), criticalExtensionsFuture (1)
  auto dec = decode_ul_dcch(from_hex("2900"));
  ASSERT_FALSE(dec);
  EXPECT_NE(dec.error().message.find("criticalExtensionsFuture"), std::string::npos);
}

TEST(RrcDecode, SelectedPlmnIdentityAboveMaxRejected) {
  RrcSetupComplete c;
  c.dedicated_nas_message = Bytes{1};
  Bytes enc = encode_ul_dcch(c);
  // The 4-bit selectedPLMN-Identity starts at bit 14 (after 1+4+2+1+6 bits); force it to 1111 = 16.
  asn1::BitWriter w;
  asn1::BitReader r(enc);
  w.put_bits(r.get_bits(14), 14);
  r.get_bits(4);
  w.put_bits(0xF, 4);
  while (r.remaining() > 0) w.put_bit(r.get_bit());
  auto dec = decode_ul_dcch(w.complete());
  ASSERT_FALSE(dec);
  EXPECT_NE(dec.error().message.find("outside"), std::string::npos);
}

TEST(RrcDecode, UnsupportedOptionalComponentReported) {
  // RRCRelease with suspendConfig present cannot be skipped in UPER and must be reported.
  asn1::BitWriter w;
  asn1::encode_choice_index(w, 0, 2);
  asn1::encode_choice_index(w, 2, 16);
  asn1::encode_integer(w, 0, 0, 3);
  asn1::encode_choice_index(w, 0, 2);
  asn1::encode_sequence_preamble(w, false, false, {false, false, true, false, false, false});
  auto dec = decode_dl_dcch(w.complete());
  ASSERT_FALSE(dec);
  EXPECT_NE(dec.error().message.find("suspendConfig"), std::string::npos);
}

TEST(RrcDecode, MasterCellGroupGarbageRejected) {
  RrcSetup s = standard_setup();
  asn1::BitWriter w;
  asn1::encode_choice_index(w, 0, 2);
  asn1::encode_choice_index(w, 1, 4);
  asn1::encode_integer(w, 0, 0, 3);
  asn1::encode_choice_index(w, 0, 2);
  asn1::encode_sequence_preamble(w, false, false, {false, false});
  asn1::encode_sequence_preamble(w, true, false, {false, false, false, false, false});
  asn1::encode_octet_string(w, Bytes{0xFF, 0xFF, 0xFF}, asn1::Size::unbounded());
  EXPECT_FALSE(decode_dl_ccch(w.complete()));
}

TEST(RrcDecode, CellGroupConfigStandalone) {
  auto ok = decode_cell_group_config(from_hex("40008000"));
  ASSERT_TRUE(ok);
  EXPECT_EQ(ok->rlc_bearer_to_add_mod_list.size(), 1u);
  EXPECT_FALSE(decode_cell_group_config(Bytes{}));
}

TEST(RrcDecode, RandomBytesNeverCrash) {
  std::uint32_t x = 12345;
  for (int i = 0; i < 2000; ++i) {
    Bytes b(1 + i % 40);
    for (auto& v : b) {
      x = x * 1664525u + 1013904223u;
      v = static_cast<std::uint8_t>(x >> 24);
    }
    (void)decode_ul_ccch(b);
    (void)decode_dl_ccch(b);
    (void)decode_ul_dcch(b);
    (void)decode_dl_dcch(b);
  }
  SUCCEED();
}

// ---- Names and JSON -----------------------------------------------------------------------------

TEST(RrcJson, MessageNames) {
  EXPECT_EQ(message_name(UlCcchMessage{RrcSetupRequest{}}), "rrcSetupRequest");
  EXPECT_EQ(message_name(DlCcchMessage{RrcReject{}}), "rrcReject");
  EXPECT_EQ(message_name(DlCcchMessage{RrcSetup{}}), "rrcSetup");
  EXPECT_EQ(message_name(UlDcchMessage{UlInformationTransfer{}}), "ulInformationTransfer");
  EXPECT_EQ(message_name(DlDcchMessage{RrcRelease{}}), "rrcRelease");
}

TEST(RrcJson, SetupRequestUsesAsn1FieldNames) {
  RrcSetupRequest req;
  req.ue_identity = InitialUeIdentity{InitialUeIdentity::Type::randomValue, 77};
  EXPECT_EQ(to_json(UlCcchMessage{req}).dump(),
            R"({"message":"rrcSetupRequest","body":{"ue-Identity":{"randomValue":77},"establishmentCause":"mo-Signalling"}})");
}

TEST(RrcJson, SecurityModeCommand) {
  EXPECT_EQ(to_json(DlDcchMessage{SecurityModeCommand{1, CipheringAlgorithm::nea2, IntegrityProtAlgorithm::nia2}}).dump(),
            R"({"message":"securityModeCommand","body":{"rrc-TransactionIdentifier":1,"securityConfigSMC":{"securityAlgorithmConfig":{"cipheringAlgorithm":"nea2","integrityProtAlgorithm":"nia2"}}}})");
}

TEST(RrcJson, EnumNames) {
  EXPECT_STREQ(to_string(EstablishmentCause::mt_Access), "mt-Access");
  EXPECT_STREQ(to_string(EstablishmentCause::spare1), "spare1");
  EXPECT_STREQ(to_string(CipheringAlgorithm::nea3), "nea3");
  EXPECT_STREQ(to_string(IntegrityProtAlgorithm::spare4), "spare4");
}
