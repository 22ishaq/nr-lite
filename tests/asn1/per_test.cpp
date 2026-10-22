#include "nrlite/asn1/per.hpp"

#include <gtest/gtest.h>

using namespace nrlite;
using namespace nrlite::asn1;

namespace {

std::string bits_of(const BitWriter& w) {
  std::string s;
  BitReader r(w.bytes());
  for (std::size_t i = 0; i < w.bit_length(); ++i) s.push_back(r.get_bit() ? '1' : '0');
  return s;
}

}  // namespace

// ---- BitWriter / BitReader --------------------------------------------------------------------

TEST(BitWriter, PacksBitsMsbFirst) {
  BitWriter w;
  w.put_bits(0b101, 3);
  w.put_bits(0b11001, 5);
  EXPECT_EQ(w.bytes(), (Bytes{0xB9}));
  EXPECT_EQ(w.bit_length(), 8u);
}

TEST(BitWriter, UnalignedBytesShiftAcrossOctets) {
  BitWriter w;
  w.put_bit(true);
  w.put_bytes(Bytes{0xFF, 0x00});
  EXPECT_EQ(bits_of(w), "11111111100000000");
  EXPECT_EQ(w.bytes(), (Bytes{0xFF, 0x80, 0x00}));
}

TEST(BitWriter, CompleteEncodingOfEmptyValueIsOneZeroOctet) {
  BitWriter w;
  EXPECT_EQ(w.complete(), (Bytes{0x00}));
}

TEST(BitWriter, AlignPadsWithZeros) {
  BitWriter w;
  w.put_bits(0b11, 2);
  w.align();
  EXPECT_EQ(w.bit_length(), 8u);
  EXPECT_EQ(w.bytes(), (Bytes{0xC0}));
}

TEST(BitWriter, Put64Bits) {
  BitWriter w;
  w.put_bits(0x0123456789ABCDEFull, 64);
  EXPECT_EQ(to_hex(w.bytes()), "0123456789abcdef");
}

TEST(BitReader, ReadsBackWhatWasWritten) {
  BitWriter w;
  w.put_bits(5, 3);
  w.put_bits(1000, 10);
  w.put_bit(false);
  w.put_bits(0xABCDEF, 24);
  BitReader r(w.bytes());
  EXPECT_EQ(r.get_bits(3), 5u);
  EXPECT_EQ(r.get_bits(10), 1000u);
  EXPECT_FALSE(r.get_bit());
  EXPECT_EQ(r.get_bits(24), 0xABCDEFu);
}

TEST(BitReader, ThrowsOnOverrun) {
  const Bytes b{0xAA};
  BitReader r(b);
  r.get_bits(6);
  EXPECT_THROW(r.get_bits(3), DecodeError);
}

TEST(BitReader, EmptyInputThrows) {
  const Bytes empty;
  BitReader r(empty);
  EXPECT_THROW(r.get_bit(), DecodeError);
}

TEST(BitReader, UnalignedByteRead) {
  const Bytes b{0x7F, 0x80};
  BitReader r(b);
  EXPECT_FALSE(r.get_bit());
  EXPECT_EQ(r.get_bytes(1), (Bytes{0xFF}));
  EXPECT_EQ(r.remaining(), 7u);
}

TEST(BitReader, AlignSkipsPadding) {
  const Bytes b{0x80, 0x42};
  BitReader r(b);
  r.get_bit();
  r.align();
  EXPECT_EQ(r.get_bits(8), 0x42u);
}

// ---- BitString ------------------------------------------------------------------------------

TEST(BitString, FromUintRoundTrip) {
  const BitString bs = BitString::from_uint(0x5A5A5A5A5Aull & ((1ull << 39) - 1), 39);
  EXPECT_EQ(bs.length, 39u);
  EXPECT_EQ(bs.to_uint(), 0x5A5A5A5A5Aull & ((1ull << 39) - 1));
}

TEST(BitString, FromUintRejectsOversizedValue) { EXPECT_THROW(BitString::from_uint(0x200, 9), EncodeError); }

TEST(BitString, EqualityIgnoresUnusedBits) {
  BitString a{{0xF0}, 4};
  BitString b{{0xFF}, 4};
  EXPECT_EQ(a, b);
  BitString c{{0xE0}, 4};
  EXPECT_NE(a, c);
}

// ---- Whole numbers ----------------------------------------------------------------------------

TEST(Per, BitsForRange) {
  EXPECT_EQ(bits_for_range(1), 0u);
  EXPECT_EQ(bits_for_range(2), 1u);
  EXPECT_EQ(bits_for_range(3), 2u);
  EXPECT_EQ(bits_for_range(4), 2u);
  EXPECT_EQ(bits_for_range(5), 3u);
  EXPECT_EQ(bits_for_range(12), 4u);
  EXPECT_EQ(bits_for_range(16), 4u);
  EXPECT_EQ(bits_for_range(17), 5u);
  EXPECT_EQ(bits_for_range(256), 8u);
  EXPECT_EQ(bits_for_range(257), 9u);
}

TEST(Per, ConstrainedWholeNumberUsesMinimalBits) {
  BitWriter w;
  encode_constrained_whole_number(w, 3, 1, 3);  // range 3 -> 2 bits, offset 2
  EXPECT_EQ(bits_of(w), "10");
}

TEST(Per, ConstrainedSingleValueRangeIsEmpty) {
  BitWriter w;
  encode_constrained_whole_number(w, 7, 7, 7);
  EXPECT_EQ(w.bit_length(), 0u);
  const Bytes empty;
  BitReader r(empty);
  EXPECT_EQ(decode_constrained_whole_number(r, 7, 7), 7);
}

TEST(Per, ConstrainedNegativeLowerBound) {
  BitWriter w;
  encode_constrained_whole_number(w, -5, -8, 7);  // offset 3 in 4 bits
  EXPECT_EQ(bits_of(w), "0011");
  BitReader r(w.bytes());
  EXPECT_EQ(decode_constrained_whole_number(r, -8, 7), -5);
}

TEST(Per, ConstrainedOutOfRangeEncodeThrows) {
  BitWriter w;
  EXPECT_THROW(encode_constrained_whole_number(w, 13, 1, 12), EncodeError);
  EXPECT_THROW(encode_constrained_whole_number(w, 0, 1, 12), EncodeError);
}

TEST(Per, ConstrainedDecodeRejectsValueAboveUpperBound) {
  // INTEGER (1..12) uses 4 bits; 0b1111 would be 16, which is outside the range.
  const Bytes b{0xF0};
  BitReader r(b);
  EXPECT_THROW(decode_constrained_whole_number(r, 1, 12), DecodeError);
}

TEST(Per, NormallySmallNumberShortForm) {
  BitWriter w;
  encode_normally_small_number(w, 5);
  EXPECT_EQ(bits_of(w), "0000101");
  BitReader r(w.bytes());
  EXPECT_EQ(decode_normally_small_number(r), 5u);
}

TEST(Per, NormallySmallNumberLongForm) {
  BitWriter w;
  encode_normally_small_number(w, 64);
  // '1' + length octet (1) + value octet (64)
  EXPECT_EQ(bits_of(w), "1" "00000001" "01000000");
  BitReader r(w.bytes());
  EXPECT_EQ(decode_normally_small_number(r), 64u);
}

TEST(Per, NormallySmallLength) {
  BitWriter w;
  encode_normally_small_length(w, 1);
  encode_normally_small_length(w, 64);
  EXPECT_EQ(bits_of(w), "0000000" "0111111");
  BitReader r(w.bytes());
  EXPECT_EQ(decode_normally_small_length(r), 1u);
  EXPECT_EQ(decode_normally_small_length(r), 64u);
  BitWriter z;
  EXPECT_THROW(encode_normally_small_length(z, 0), EncodeError);
}

TEST(Per, UnconstrainedLengthOneOctetForm) {
  BitWriter w;
  encode_unconstrained_length(w, 127);
  EXPECT_EQ(w.bytes(), (Bytes{0x7F}));
}

TEST(Per, UnconstrainedLengthTwoOctetForm) {
  BitWriter w;
  encode_unconstrained_length(w, 128);
  encode_unconstrained_length(w, 16383);
  EXPECT_EQ(w.bytes(), (Bytes{0x80, 0x80, 0xBF, 0xFF}));
  BitReader r(w.bytes());
  EXPECT_EQ(decode_unconstrained_length(r), 128u);
  EXPECT_EQ(decode_unconstrained_length(r), 16383u);
}

TEST(Per, UnconstrainedLengthRefusesFragmentSizes) {
  BitWriter w;
  EXPECT_THROW(encode_unconstrained_length(w, 16384), EncodeError);
  const Bytes fragment_marker{0xC1};
  BitReader r(fragment_marker);
  EXPECT_THROW(decode_unconstrained_length(r), DecodeError);
}

TEST(Per, SemiConstrainedWholeNumberMinimalOctets) {
  BitWriter w;
  encode_semi_constrained_whole_number(w, 0);
  encode_semi_constrained_whole_number(w, 256);
  EXPECT_EQ(w.bytes(), (Bytes{0x01, 0x00, 0x02, 0x01, 0x00}));
}

// ---- INTEGER / BOOLEAN / ENUMERATED -----------------------------------------------------------

TEST(Per, BooleanIsOneBit) {
  BitWriter w;
  encode_boolean(w, true);
  encode_boolean(w, false);
  EXPECT_EQ(bits_of(w), "10");
}

TEST(Per, ExtensibleIntegerInRoot) {
  BitWriter w;
  encode_integer(w, 2, 0, 3, true);
  EXPECT_EQ(bits_of(w), "010");
  BitReader r(w.bytes());
  EXPECT_EQ(decode_integer(r, 0, 3, true), 2);
}

TEST(Per, ExtensibleIntegerOutsideRootUsesUnconstrainedForm) {
  BitWriter w;
  encode_integer(w, 300, 0, 3, true);
  BitReader r(w.bytes());
  EXPECT_EQ(decode_integer(r, 0, 3, true), 300);
}

class UnconstrainedIntegerTest : public ::testing::TestWithParam<std::int64_t> {};

TEST_P(UnconstrainedIntegerTest, RoundTrip) {
  BitWriter w;
  encode_unconstrained_integer(w, GetParam());
  BitReader r(w.bytes());
  EXPECT_EQ(decode_unconstrained_integer(r), GetParam());
}

INSTANTIATE_TEST_SUITE_P(Values, UnconstrainedIntegerTest,
                         ::testing::Values(0, 1, -1, 127, 128, -128, -129, 32767, -32768, 1'000'000, -1'000'000,
                                           INT64_MAX, INT64_MIN));

TEST(Per, UnconstrainedIntegerUsesTwosComplementMinimalOctets) {
  BitWriter w;
  encode_unconstrained_integer(w, -1);
  encode_unconstrained_integer(w, 128);
  EXPECT_EQ(w.bytes(), (Bytes{0x01, 0xFF, 0x02, 0x00, 0x80}));
}

TEST(Per, SemiConstrainedIntegerRoundTrip) {
  BitWriter w;
  encode_semi_constrained_integer(w, 1000, -5);
  BitReader r(w.bytes());
  EXPECT_EQ(decode_semi_constrained_integer(r, -5), 1000);
  EXPECT_THROW(encode_semi_constrained_integer(w, -6, -5), EncodeError);
}

TEST(Per, EnumeratedRootValue) {
  BitWriter w;
  encode_enumerated(w, 3, 16);  // EstablishmentCause mo-Signalling
  EXPECT_EQ(bits_of(w), "0011");
}

TEST(Per, ExtensibleEnumeratedRootAndExtensionValues) {
  BitWriter w;
  encode_enumerated(w, 2, 8, true);
  encode_enumerated(w, 9, 8, true);
  EXPECT_EQ(bits_of(w), "0010" "1" "0000001");
  BitReader r(w.bytes());
  EXPECT_EQ(decode_enumerated(r, 8, true), 2u);
  EXPECT_EQ(decode_enumerated(r, 8, true), 9u);
}

TEST(Per, NonExtensibleEnumeratedRejectsOutOfRange) {
  BitWriter w;
  EXPECT_THROW(encode_enumerated(w, 2, 2), EncodeError);
}

TEST(Per, SingleValueEnumeratedTakesNoBits) {
  BitWriter w;
  encode_enumerated(w, 0, 1);  // ENUMERATED {true}
  EXPECT_EQ(w.bit_length(), 0u);
}

// ---- CHOICE ---------------------------------------------------------------------------------

TEST(Per, ChoiceIndexNonExtensible) {
  BitWriter w;
  encode_choice_index(w, 2, 4);
  EXPECT_EQ(bits_of(w), "10");
}

TEST(Per, ChoiceIndexExtensibleRoot) {
  BitWriter w;
  encode_choice_index(w, 1, 2, true);
  EXPECT_EQ(bits_of(w), "01");
  BitReader r(w.bytes());
  const auto ci = decode_choice_index(r, 2, true);
  EXPECT_EQ(ci.index, 1u);
  EXPECT_FALSE(ci.extension);
}

TEST(Per, ChoiceExtensionAlternativeIsOpenType) {
  BitWriter w;
  encode_choice_extension(w, 0, Bytes{0xAB});
  BitReader r(w.bytes());
  const auto ci = decode_choice_index(r, 3, true);
  EXPECT_TRUE(ci.extension);
  EXPECT_EQ(ci.index, 0u);
  EXPECT_EQ(decode_open_type(r), (Bytes{0xAB}));
}

TEST(Per, ChoiceIndexOutOfRangeThrows) {
  BitWriter w;
  EXPECT_THROW(encode_choice_index(w, 4, 4), EncodeError);
}

// ---- Strings and lengths ------------------------------------------------------------------------

TEST(Per, FixedSizeBitStringHasNoLength) {
  BitWriter w;
  encode_bit_string(w, BitString::from_uint(0x1FF, 9), Size::fixed(9));
  EXPECT_EQ(w.bit_length(), 9u);
}

TEST(Per, FixedSizeBitStringRejectsWrongSize) {
  BitWriter w;
  EXPECT_THROW(encode_bit_string(w, BitString::from_uint(1, 8), Size::fixed(9)), EncodeError);
}

TEST(Per, ConstrainedLengthBitString) {
  BitWriter w;
  encode_bit_string(w, BitString::from_uint(0b101, 3), Size::range(1, 8));
  EXPECT_EQ(bits_of(w), "010" "101");
  BitReader r(w.bytes());
  EXPECT_EQ(decode_bit_string(r, Size::range(1, 8)).to_uint(), 0b101u);
}

TEST(Per, UnboundedOctetStringRoundTrip) {
  const Bytes v{1, 2, 3, 4, 5};
  BitWriter w;
  w.put_bit(true);  // misalign on purpose: UPER does not align strings
  encode_octet_string(w, v, Size::unbounded());
  BitReader r(w.bytes());
  r.get_bit();
  EXPECT_EQ(decode_octet_string(r, Size::unbounded()), v);
}

TEST(Per, FixedSizeOctetString) {
  BitWriter w;
  encode_octet_string(w, Bytes{0xDE, 0xAD}, Size::fixed(2));
  EXPECT_EQ(w.bytes(), (Bytes{0xDE, 0xAD}));
}

TEST(Per, ExtensibleSizeOutsideRoot) {
  BitWriter w;
  encode_octet_string(w, Bytes(5, 0x11), Size::range(1, 4, true));
  BitReader r(w.bytes());
  EXPECT_EQ(decode_octet_string(r, Size::range(1, 4, true)), Bytes(5, 0x11));
}

TEST(Per, OctetStringTruncatedThrows) {
  BitWriter w;
  encode_octet_string(w, Bytes(10, 0x22), Size::unbounded());
  Bytes enc = w.complete();
  enc.resize(5);
  BitReader r(enc);
  EXPECT_THROW(decode_octet_string(r, Size::unbounded()), DecodeError);
}

class FragmentationTest : public ::testing::TestWithParam<std::size_t> {};

TEST_P(FragmentationTest, OctetStringRoundTrip) {
  Bytes v(GetParam());
  for (std::size_t i = 0; i < v.size(); ++i) v[i] = static_cast<std::uint8_t>(i * 7);
  BitWriter w;
  encode_octet_string(w, v, Size::unbounded());
  BitReader r(w.bytes());
  EXPECT_EQ(decode_octet_string(r, Size::unbounded()), v);
  EXPECT_TRUE(r.at_padding());
}

INSTANTIATE_TEST_SUITE_P(Sizes, FragmentationTest,
                         ::testing::Values(0u, 127u, 128u, 16383u, 16384u, 16385u, 65536u, 70000u, 2 * 65536u));

TEST(Per, FragmentHeaderForExactly16K) {
  Bytes v(16384, 0x00);
  BitWriter w;
  encode_octet_string(w, v, Size::unbounded());
  // 0xC1 (one 16K fragment) + 16384 octets + 0x00 (final zero-length chunk)
  ASSERT_EQ(w.bytes().size(), 1u + 16384u + 1u);
  EXPECT_EQ(w.bytes().front(), 0xC1);
  EXPECT_EQ(w.bytes().back(), 0x00);
}

TEST(Per, InvalidFragmentMultiplierRejected) {
  const Bytes bad_multiplier{0xC5};
  BitReader r(bad_multiplier);
  EXPECT_THROW(decode_octet_string(r, Size::unbounded()), DecodeError);
}

TEST(Per, SequenceOfLengthWithSizeConstraint) {
  BitWriter w;
  encode_length(w, 2, Size::range(1, 2));
  encode_length(w, 8, Size::range(1, 8));
  EXPECT_EQ(bits_of(w), "1" "111");
  BitReader r(w.bytes());
  EXPECT_EQ(decode_length(r, Size::range(1, 2)), 2u);
  EXPECT_EQ(decode_length(r, Size::range(1, 8)), 8u);
}

TEST(Per, SequenceOfLengthViolationThrows) {
  BitWriter w;
  EXPECT_THROW(encode_length(w, 0, Size::range(1, 2)), EncodeError);
  EXPECT_THROW(encode_length(w, 3, Size::range(1, 2)), EncodeError);
}

// ---- SEQUENCE preamble and extensions -----------------------------------------------------------

TEST(Per, SequencePreambleExtensibleWithOptionals) {
  BitWriter w;
  encode_sequence_preamble(w, true, false, {true, false, true});
  EXPECT_EQ(bits_of(w), "0101");
  BitReader r(w.bytes());
  const Preamble p = decode_sequence_preamble(r, true, 3);
  EXPECT_FALSE(p.extensions_present);
  EXPECT_TRUE(p[0]);
  EXPECT_FALSE(p[1]);
  EXPECT_TRUE(p[2]);
}

TEST(Per, SequencePreambleNonExtensibleRejectsExtensions) {
  BitWriter w;
  EXPECT_THROW(encode_sequence_preamble(w, false, true, {}), EncodeError);
}

TEST(Per, ExtensionAdditionsRoundTrip) {
  BitWriter w;
  encode_extension_additions(w, {std::nullopt, Bytes{0x80}, std::nullopt, Bytes{0x01, 0x02}});
  BitReader r(w.bytes());
  const auto adds = decode_extension_additions(r);
  ASSERT_EQ(adds.size(), 4u);
  EXPECT_FALSE(adds[0]);
  EXPECT_EQ(*adds[1], (Bytes{0x80}));
  EXPECT_FALSE(adds[2]);
  EXPECT_EQ(*adds[3], (Bytes{0x01, 0x02}));
}

TEST(Per, ExtensionAdditionsRequireOnePresent) {
  BitWriter w;
  EXPECT_THROW(encode_extension_additions(w, {std::nullopt}), EncodeError);
}

TEST(Per, OpenTypeRejectsEmptyEncoding) {
  BitWriter w;
  EXPECT_THROW(encode_open_type(w, Bytes{}), EncodeError);
  const Bytes zero_length{0x00};
  BitReader r(zero_length);
  EXPECT_THROW(decode_open_type(r), DecodeError);
}
