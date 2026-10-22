// MILENAGE conformance test data from TS 35.207 (test sets 1-3) and 5G key-derivation checks.

#include "nrlite/security/milenage.hpp"

#include <gtest/gtest.h>
#include <algorithm>
#include <string>

#include "nrlite/security/kdf.hpp"

using namespace nrlite;
using namespace nrlite::sec;

namespace {

struct MilenageVector {
  const char* name;
  const char* k;
  const char* rand;
  const char* sqn;
  const char* amf;
  const char* op;
  const char* opc;
  const char* f1;
  const char* f1_star;
  const char* f2;
  const char* f5;
  const char* f3;
  const char* f4;
  const char* f5_star;
};

const MilenageVector kVectors[] = {
    {"TestSet1", "465b5ce8b199b49faa5f0a2ee238a6bc", "23553cbe9637a89d218ae64dae47bf35", "ff9bb4d0b607", "b9b9",
     "cdc202d5123e20f62b6d676ac72cb318", "cd63cb71954a9f4e48a5994e37a02baf", "4a9ffac354dfafb3", "01cfaf9ec4e871e9",
     "a54211d5e3ba50bf", "aa689c648370", "b40ba9a3c58b2a05bbf0d987b21bf8cb", "f769bcd751044604127672711c6d3441",
     "451e8beca43b"},
    {"TestSet2", "0396eb317b6d1c36f19c1c84cd6ffd16", "c00d603103dcee52c4478119494202e8", "fd8eef40df7d", "af17",
     "ff53bade17df5d4e793073ce9d7579fa", "53c15671c60a4b731c55b4a441c0bde2", "5df5b31807e258b0", "a8c016e51ef4a343",
     "d3a628ed988620f0", "c47783995f72", "58c433ff7a7082acd424220f2b67c556", "21a8c1f929702adb3e738488b9f5c5da",
     "30f1197061c1"},
    {"TestSet3", "fec86ba6eb707ed08905757b1bb44b8f", "9f7c8d021accf4db213ccff0c7f71a6a", "9d0277595ffc", "725c",
     "dbc59adcb6f9a0ef735477b7fadf8374", "1006020f0a478bf6b699f15c062e42b3", "9cabc3e99baf7281", "95814ba2b3044324",
     "8011c48c0c214ed2", "33484dc2136b", "5dbdbb2954e8f3cde665b046179a5098", "59a92d3b476a0443487055cf88b2307b",
     "deacdd848cc6"},
};

class MilenageTest : public ::testing::TestWithParam<MilenageVector> {};

}  // namespace

TEST_P(MilenageTest, OpcDerivation) {
  const auto& v = GetParam();
  EXPECT_EQ(to_hex(Milenage::compute_opc(array_from_hex<16>(v.k), array_from_hex<16>(v.op))), v.opc);
}

TEST_P(MilenageTest, F1AndF1Star) {
  const auto& v = GetParam();
  const Milenage m(array_from_hex<16>(v.k), array_from_hex<16>(v.opc));
  const auto out = m.f1(array_from_hex<16>(v.rand), array_from_hex<6>(v.sqn), array_from_hex<2>(v.amf));
  EXPECT_EQ(to_hex(out.mac_a), v.f1);
  EXPECT_EQ(to_hex(out.mac_s), v.f1_star);
}

TEST_P(MilenageTest, F2F3F4F5) {
  const auto& v = GetParam();
  const Milenage m(array_from_hex<16>(v.k), array_from_hex<16>(v.opc));
  const auto out = m.f2345(array_from_hex<16>(v.rand));
  EXPECT_EQ(to_hex(out.res), v.f2);
  EXPECT_EQ(to_hex(out.ck), v.f3);
  EXPECT_EQ(to_hex(out.ik), v.f4);
  EXPECT_EQ(to_hex(out.ak), v.f5);
}

TEST_P(MilenageTest, F5Star) {
  const auto& v = GetParam();
  const Milenage m(array_from_hex<16>(v.k), array_from_hex<16>(v.opc));
  EXPECT_EQ(to_hex(m.f5_star(array_from_hex<16>(v.rand))), v.f5_star);
}

INSTANTIATE_TEST_SUITE_P(Ts35207, MilenageTest, ::testing::ValuesIn(kVectors),
                         [](const auto& info) { return std::string(info.param.name); });

TEST(Sqn, U64RoundTrip) {
  EXPECT_EQ(sqn_to_u64(sqn_from_u64(0x0000DEADBEEFull)), 0x0000DEADBEEFull);
  EXPECT_EQ(to_hex(sqn_from_u64(0x0123456789ABull)), "0123456789ab");
}

// ---- 5G key hierarchy -----------------------------------------------------------------------

TEST(Kdf, MatchesHmacOverEncodedString) {
  const Bytes key(32, 0x01);
  const Key256 k = kdf(key, 0x6C, {Bytes{'a', 'b'}, Bytes{0x00}});
  const Bytes s{0x6C, 'a', 'b', 0x00, 0x02, 0x00, 0x00, 0x01};
  EXPECT_EQ(k, hmac_sha256(key, s));
}

TEST(Kdf, ServingNetworkNamePadsTwoDigitMnc) {
  EXPECT_EQ(serving_network_name("001", "01"), "5G:mnc001.mcc001.3gppnetwork.org");
  EXPECT_EQ(serving_network_name("208", "93"), "5G:mnc093.mcc208.3gppnetwork.org");
  EXPECT_EQ(serving_network_name("310", "410"), "5G:mnc410.mcc310.3gppnetwork.org");
  EXPECT_THROW(serving_network_name("01", "01"), std::invalid_argument);
}

TEST(Kdf, ResStarIsLow128BitsOfKdf) {
  const Key128 ck = array_from_hex<16>("b40ba9a3c58b2a05bbf0d987b21bf8cb");
  const Key128 ik = array_from_hex<16>("f769bcd751044604127672711c6d3441");
  const Block rand = array_from_hex<16>("23553cbe9637a89d218ae64dae47bf35");
  const Res64 res = array_from_hex<8>("a54211d5e3ba50bf");
  const std::string snn = serving_network_name("001", "01");
  Bytes key(ck.begin(), ck.end());
  key.insert(key.end(), ik.begin(), ik.end());
  const Key256 full = kdf(key, 0x6B, {Bytes(snn.begin(), snn.end()), Bytes(rand.begin(), rand.end()),
                                      Bytes(res.begin(), res.end())});
  const Key128 res_star = derive_res_star(ck, ik, snn, rand, res);
  EXPECT_TRUE(std::equal(res_star.begin(), res_star.end(), full.begin() + 16));
}

TEST(Kdf, HresStarIsLow128BitsOfSha256) {
  const Block rand = array_from_hex<16>("00112233445566778899aabbccddeeff");
  const Key128 res_star = array_from_hex<16>("ffeeddccbbaa99887766554433221100");
  Bytes s(rand.begin(), rand.end());
  s.insert(s.end(), res_star.begin(), res_star.end());
  const Digest256 h = sha256(s);
  const Key128 hres = derive_hres_star(rand, res_star);
  EXPECT_TRUE(std::equal(hres.begin(), hres.end(), h.begin() + 16));
}

TEST(Kdf, KeyHierarchyIsDeterministicAndSeparated) {
  const Key256 kseaf = derive_kseaf(Key256{}, serving_network_name("001", "01"));
  const Key256 kamf = derive_kamf(kseaf, "001010000000001", Bytes{0x00, 0x00});
  EXPECT_EQ(kamf, derive_kamf(kseaf, "001010000000001", Bytes{0x00, 0x00}));
  EXPECT_NE(kamf, derive_kamf(kseaf, "001010000000002", Bytes{0x00, 0x00}));
  const Key128 nas_int = derive_algorithm_key(kamf, AlgorithmDistinguisher::NasInt, 2);
  const Key128 nas_enc = derive_algorithm_key(kamf, AlgorithmDistinguisher::NasEnc, 2);
  EXPECT_NE(nas_int, nas_enc);
  EXPECT_NE(derive_kgnb(kamf, 0), derive_kgnb(kamf, 1));
}
