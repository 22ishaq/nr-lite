#pragma once

// ASN.1 Packed Encoding Rules, UNALIGNED variant (ITU-T X.691), as used by NR RRC (TS 38.331 §8).
//
// This is a hand-written runtime for the subset of X.691 that RRC needs: constrained whole
// numbers, length determinants (including fragmentation), normally-small numbers, BOOLEAN,
// INTEGER, ENUMERATED, BIT STRING, OCTET STRING, SEQUENCE / SEQUENCE OF preambles, CHOICE and
// open types for extension additions. Message codecs in nrlite/rrc compose these primitives in
// the order the ASN.1 definitions dictate.
//
// Errors are reported with exceptions inside the codec (DecodeError / EncodeError) and converted
// to Result<> at the message boundary, which keeps every per-field decoder short.

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <stdexcept>
#include <vector>

#include "nrlite/common/bytes.hpp"

namespace nrlite::asn1 {

class DecodeError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class EncodeError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

/// BIT STRING value: `length` bits stored MSB first in `data` (unused trailing bits are zero).
struct BitString {
  Bytes data;
  std::size_t length = 0;

  static BitString from_uint(std::uint64_t value, std::size_t nbits);
  std::uint64_t to_uint() const;
  bool bit(std::size_t i) const;
  bool operator==(const BitString& o) const;
  bool operator!=(const BitString& o) const { return !(*this == o); }
};

class BitWriter {
 public:
  void put_bit(bool bit);
  void put_bits(std::uint64_t value, unsigned nbits);
  void put_bytes(const std::uint8_t* data, std::size_t len);
  void put_bytes(const Bytes& b) { put_bytes(b.data(), b.size()); }
  void put_bit_string_bits(const BitString& bs);
  void align();
  std::size_t bit_length() const { return bits_; }
  /// Raw buffer; the final octet may be partially filled (unused bits are zero).
  const Bytes& bytes() const { return buf_; }
  /// X.691 §11.1 complete encoding: octet aligned and never empty.
  Bytes complete() const;

 private:
  Bytes buf_;
  std::size_t bits_ = 0;
};

class BitReader {
 public:
  BitReader(const std::uint8_t* data, std::size_t len);
  explicit BitReader(const Bytes& b) : BitReader(b.data(), b.size()) {}
  /// The reader does not own its input; binding to a temporary would dangle.
  explicit BitReader(Bytes&&) = delete;

  bool get_bit();
  std::uint64_t get_bits(unsigned nbits);
  void get_bytes(std::uint8_t* out, std::size_t len);
  Bytes get_bytes(std::size_t len);
  BitString get_bit_string_bits(std::size_t nbits);
  void skip(std::size_t nbits);
  void align();
  std::size_t position() const { return pos_; }
  std::size_t remaining() const { return len_bits_ - pos_; }
  /// True when fewer than 8 bits remain (i.e. only octet padding is left).
  bool at_padding() const { return remaining() < 8; }

 private:
  void need(std::size_t nbits) const;
  const std::uint8_t* data_;
  std::size_t len_bits_;
  std::size_t pos_ = 0;
};

/// SIZE constraint for strings and SEQUENCE OF.
struct Size {
  std::size_t lb = 0;
  std::optional<std::size_t> ub;  ///< nullopt: no upper bound
  bool extensible = false;

  static Size fixed(std::size_t n) { return {n, n, false}; }
  static Size range(std::size_t lb, std::size_t ub, bool ext = false) { return {lb, ub, ext}; }
  static Size unbounded(std::size_t lb = 0) { return {lb, std::nullopt, false}; }
};

// --- X.691 §11 building blocks -------------------------------------------------------------

/// Number of bits UPER uses for a constrained whole number with `range` = ub - lb + 1 values.
unsigned bits_for_range(std::uint64_t range);

void encode_constrained_whole_number(BitWriter& w, std::int64_t value, std::int64_t lb, std::int64_t ub);
std::int64_t decode_constrained_whole_number(BitReader& r, std::int64_t lb, std::int64_t ub);

/// §11.6 normally small non-negative whole number (CHOICE / ENUMERATED extension indices).
void encode_normally_small_number(BitWriter& w, std::uint64_t n);
std::uint64_t decode_normally_small_number(BitReader& r);

/// §11.9.3.4 normally small length (extension-addition bitmap length), n >= 1.
void encode_normally_small_length(BitWriter& w, std::size_t n);
std::size_t decode_normally_small_length(BitReader& r);

/// §11.9.3.6-7 unconstrained length determinant, n < 16384 (no fragmentation).
void encode_unconstrained_length(BitWriter& w, std::size_t n);
std::size_t decode_unconstrained_length(BitReader& r);

/// §11.7 semi-constrained whole number (value already offset by the lower bound).
void encode_semi_constrained_whole_number(BitWriter& w, std::uint64_t offset);
std::uint64_t decode_semi_constrained_whole_number(BitReader& r);

// --- Types ---------------------------------------------------------------------------------

void encode_boolean(BitWriter& w, bool v);
bool decode_boolean(BitReader& r);

void encode_integer(BitWriter& w, std::int64_t v, std::int64_t lb, std::int64_t ub, bool extensible = false);
std::int64_t decode_integer(BitReader& r, std::int64_t lb, std::int64_t ub, bool extensible = false);
void encode_semi_constrained_integer(BitWriter& w, std::int64_t v, std::int64_t lb);
std::int64_t decode_semi_constrained_integer(BitReader& r, std::int64_t lb);
void encode_unconstrained_integer(BitWriter& w, std::int64_t v);
std::int64_t decode_unconstrained_integer(BitReader& r);

/// ENUMERATED with `root_count` root values. With `extensible`, indices >= root_count are
/// extension values. Decoding returns root_count + k for the k-th extension value.
void encode_enumerated(BitWriter& w, unsigned index, unsigned root_count, bool extensible = false);
unsigned decode_enumerated(BitReader& r, unsigned root_count, bool extensible = false);

struct ChoiceIndex {
  unsigned index = 0;
  bool extension = false;  ///< true: `index` is an extension-addition alternative
};
/// Encodes a root alternative of a CHOICE.
void encode_choice_index(BitWriter& w, unsigned index, unsigned root_count, bool extensible = false);
ChoiceIndex decode_choice_index(BitReader& r, unsigned root_count, bool extensible = false);
/// Encodes an extension-addition alternative of an extensible CHOICE (§23.8).
void encode_choice_extension(BitWriter& w, unsigned ext_index, const Bytes& complete_encoding);

/// Length of a SEQUENCE OF / string under a SIZE constraint (no fragmentation).
void encode_length(BitWriter& w, std::size_t n, const Size& size);
std::size_t decode_length(BitReader& r, const Size& size);

void encode_bit_string(BitWriter& w, const BitString& v, const Size& size);
BitString decode_bit_string(BitReader& r, const Size& size);

/// OCTET STRING; unbounded strings >= 16K octets are fragmented per §11.9.3.8.
void encode_octet_string(BitWriter& w, const Bytes& v, const Size& size);
Bytes decode_octet_string(BitReader& r, const Size& size);

/// Open type (§11.2): a complete encoding wrapped as an unconstrained octet string.
void encode_open_type(BitWriter& w, const Bytes& complete_encoding);
Bytes decode_open_type(BitReader& r);

/// SEQUENCE preamble: extension bit (if the type is extensible) then the presence bitmap of the
/// OPTIONAL / DEFAULT root components, in declaration order.
void encode_sequence_preamble(BitWriter& w, bool extensible, bool extensions_present,
                              std::initializer_list<bool> optionals);

struct Preamble {
  bool extensions_present = false;
  std::vector<bool> present;
  bool operator[](std::size_t i) const { return present.at(i); }
};
Preamble decode_sequence_preamble(BitReader& r, bool extensible, std::size_t optional_count);

/// Extension additions of a SEQUENCE (§19.7-19.9). Each entry is the complete encoding of one
/// addition (or an addition group) or nullopt if absent. At least one entry must be present.
void encode_extension_additions(BitWriter& w, const std::vector<std::optional<Bytes>>& additions);
std::vector<std::optional<Bytes>> decode_extension_additions(BitReader& r);

}  // namespace nrlite::asn1
