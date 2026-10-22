// Known-answer tests against the published vectors for each primitive.

#include "nrlite/security/crypto.hpp"

#include <gtest/gtest.h>

#include <string>

using namespace nrlite;
using namespace nrlite::sec;

namespace {

Bytes ascii(const std::string& s) { return Bytes(s.begin(), s.end()); }

}  // namespace

// FIPS-197 Appendix C.1
TEST(Aes128, Fips197AppendixC1) {
  const Aes128 aes(array_from_hex<16>("000102030405060708090a0b0c0d0e0f"));
  EXPECT_EQ(to_hex(aes.encrypt(array_from_hex<16>("00112233445566778899aabbccddeeff"))),
            "69c4e0d86a7b0430d8cdb78070b4c55a");
}

// FIPS-197 Appendix B
TEST(Aes128, Fips197AppendixB) {
  const Aes128 aes(array_from_hex<16>("2b7e151628aed2a6abf7158809cf4f3c"));
  EXPECT_EQ(to_hex(aes.encrypt(array_from_hex<16>("3243f6a8885a308d313198a2e0370734"))),
            "3925841d02dc09fbdc118597196a0b32");
}

// NIST SP 800-38A F.1.1 (ECB-AES128, block 1)
TEST(Aes128, Sp80038aEcbBlock1) {
  const Aes128 aes(array_from_hex<16>("2b7e151628aed2a6abf7158809cf4f3c"));
  EXPECT_EQ(to_hex(aes.encrypt(array_from_hex<16>("6bc1bee22e409f96e93d7e117393172a"))),
            "3ad77bb40d7a3660a89ecaf32466ef97");
}

// FIPS 180-4 examples
TEST(Sha256, EmptyString) {
  EXPECT_EQ(to_hex(sha256(Bytes{})), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(Sha256, Abc) {
  EXPECT_EQ(to_hex(sha256(ascii("abc"))), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(Sha256, TwoBlockMessage) {
  EXPECT_EQ(to_hex(sha256(ascii("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST(Sha256, OneMillionA) {
  EXPECT_EQ(to_hex(sha256(Bytes(1'000'000, 'a'))),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

// RFC 4231 HMAC-SHA-256 test cases 1, 2, 3 and 6
TEST(HmacSha256, Rfc4231Case1) {
  EXPECT_EQ(to_hex(hmac_sha256(Bytes(20, 0x0b), ascii("Hi There"))),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

TEST(HmacSha256, Rfc4231Case2) {
  EXPECT_EQ(to_hex(hmac_sha256(ascii("Jefe"), ascii("what do ya want for nothing?"))),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
}

TEST(HmacSha256, Rfc4231Case3) {
  EXPECT_EQ(to_hex(hmac_sha256(Bytes(20, 0xaa), Bytes(50, 0xdd))),
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
}

TEST(HmacSha256, Rfc4231Case6KeyLongerThanBlock) {
  EXPECT_EQ(to_hex(hmac_sha256(Bytes(131, 0xaa), ascii("Test Using Larger Than Block-Size Key - Hash Key First"))),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");
}

// RFC 4493 AES-CMAC examples 1-4
class Rfc4493Test : public ::testing::Test {
 protected:
  const Key128 key = array_from_hex<16>("2b7e151628aed2a6abf7158809cf4f3c");
  const Bytes msg64 = from_hex(
      "6bc1bee22e409f96e93d7e117393172a ae2d8a571e03ac9c9eb76fac45af8e51"
      "30c81c46a35ce411e5fbc1191a0a52ef f69f2445df4f9b17ad2b417be66c3710");
};

TEST_F(Rfc4493Test, Example1EmptyMessage) { EXPECT_EQ(to_hex(aes_cmac(key, Bytes{})), "bb1d6929e95937287fa37d129b756746"); }

TEST_F(Rfc4493Test, Example2OneBlock) {
  EXPECT_EQ(to_hex(aes_cmac(key, Bytes(msg64.begin(), msg64.begin() + 16))), "070a16b46b4d4144f79bdd9dd04a287c");
}

TEST_F(Rfc4493Test, Example3PartialLastBlock) {
  EXPECT_EQ(to_hex(aes_cmac(key, Bytes(msg64.begin(), msg64.begin() + 40))), "dfa66747de9ae63030ca32611497c827");
}

TEST_F(Rfc4493Test, Example4FourBlocks) { EXPECT_EQ(to_hex(aes_cmac(key, msg64)), "51f0bebf7e3b9d92fc49741779363cfe"); }

TEST(AesCmac, RejectsBitLengthBeyondMessage) {
  EXPECT_THROW(aes_cmac(Key128{}, Bytes{1, 2}, 17), std::invalid_argument);
}

TEST(AesCmac, BitLengthTruncationChangesMac) {
  const Key128 key{};
  const Bytes m{0xFF, 0xFF};
  EXPECT_NE(aes_cmac(key, m, 16), aes_cmac(key, m, 15));
}

// TS 33.401 Annex C.2: 128-EIA2 test set 1 (identical algorithm to 128-NIA2). 58-bit message.
TEST(Nia2, Eia2TestSet1) {
  const Mac32 mac = nia2(array_from_hex<16>("2bd6459f82c5b300952c49104881ff48"), 0x38a6f056, 0x18,
                         Direction::Uplink, from_hex("3332346263393840"), 58);
  EXPECT_EQ(to_hex(mac), "118c6eb8");
}

// TS 33.401 Annex C.2: 128-EIA2 test set 2. 64-bit message, downlink.
TEST(Nia2, Eia2TestSet2) {
  const Mac32 mac = nia2(array_from_hex<16>("d3c5d592327fb11c4035c6680af8c6d1"), 0x398a59b4, 0x1a,
                         Direction::Downlink, from_hex("484583d5afe082ae"), 64);
  EXPECT_EQ(to_hex(mac), "b93787e6");
}

TEST(Nia2, InputsAreBound) {
  const Key128 key = array_from_hex<16>("000102030405060708090a0b0c0d0e0f");
  const Bytes m{1, 2, 3};
  const Mac32 base = nia2(key, 1, 1, Direction::Uplink, m);
  EXPECT_NE(base, nia2(key, 2, 1, Direction::Uplink, m));
  EXPECT_NE(base, nia2(key, 1, 2, Direction::Uplink, m));
  EXPECT_NE(base, nia2(key, 1, 1, Direction::Downlink, m));
  EXPECT_NE(base, nia2(key, 1, 1, Direction::Uplink, Bytes{1, 2, 4}));
}

TEST(Nia2, RejectsBearerOutOfRange) {
  EXPECT_THROW(nia2(Key128{}, 0, 32, Direction::Uplink, Bytes{}), std::invalid_argument);
}

// TS 33.401 Annex C.1: 128-EEA2 test set 1 (identical algorithm to 128-NEA2). 253-bit message.
TEST(Nea2, Eea2TestSet1) {
  const Bytes ct = nea2(array_from_hex<16>("d3c5d592327fb11c4035c6680af8c6d1"), 0x398a59b4, 0x15,
                        Direction::Downlink,
                        from_hex("981ba6824c1bfb1ab485472029b71d808ce33e2cc3c0b5fc1f3de8a6dc66b1f0"), 253);
  EXPECT_EQ(to_hex(ct), "e9fed8a63d155304d71df20bf3e82214b20ed7dad2f233dc3c22d7bdeeed8e78");
}

TEST(Nea2, IsAnInvolution) {
  const Key128 key = array_from_hex<16>("2b7e151628aed2a6abf7158809cf4f3c");
  Bytes data(100);
  for (std::size_t i = 0; i < data.size(); ++i) data[i] = static_cast<std::uint8_t>(i);
  const Bytes ct = nea2(key, 77, 3, Direction::Uplink, data);
  EXPECT_NE(ct, data);
  EXPECT_EQ(nea2(key, 77, 3, Direction::Uplink, ct), data);
}

TEST(ConstantTime, EqualCt) {
  const Bytes a{1, 2, 3}, b{1, 2, 3}, c{1, 2, 4};
  EXPECT_TRUE(equal_ct(a.data(), b.data(), 3));
  EXPECT_FALSE(equal_ct(a.data(), c.data(), 3));
}
