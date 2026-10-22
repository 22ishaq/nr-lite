#include "nrlite/asn1/per.hpp"

#include <algorithm>
#include <string>
#include <utility>

namespace nrlite::asn1 {

namespace {

constexpr std::size_t k16K = 16384;
constexpr std::size_t k64K = 65536;

std::string str(std::uint64_t v) { return std::to_string(v); }

std::string size_text(const Size& s) {
  std::string t = "SIZE(" + str(s.lb);
  if (!s.ub) return t + "..MAX)";
  if (*s.ub != s.lb) t += ".." + str(*s.ub);
  return t + (s.extensible ? ",...)" : ")");
}

bool in_root(std::size_t n, const Size& s) { return n >= s.lb && (!s.ub || n <= *s.ub); }

/// Uses the constrained (bit-field) length form: ub present and < 64K.
bool small_bounded(const Size& s) { return s.ub && *s.ub < k64K; }

/// Reads one length chunk of a possibly fragmented encoding. `more` is true when the chunk is
/// a fragment (16K..64K items) and further chunks follow.
std::size_t decode_length_chunk(BitReader& r, bool& more) {
  more = false;
  if (!r.get_bit()) return r.get_bits(7);
  if (!r.get_bit()) return r.get_bits(14);
  const std::uint64_t m = r.get_bits(6);
  if (m < 1 || m > 4) throw DecodeError("invalid length fragment multiplier " + str(m));
  more = true;
  return m * k16K;
}

void encode_fragmented_octets(BitWriter& w, const std::uint8_t* p, std::size_t n) {
  std::size_t off = 0;
  while (n - off >= k16K) {
    const std::size_t m = std::min<std::size_t>(4, (n - off) / k16K);
    w.put_bits(0xC0u | m, 8);
    w.put_bytes(p + off, m * k16K);
    off += m * k16K;
  }
  encode_unconstrained_length(w, n - off);
  w.put_bytes(p + off, n - off);
}

Bytes decode_fragmented_octets(BitReader& r) {
  Bytes out;
  bool more = true;
  while (more) {
    const std::size_t count = decode_length_chunk(r, more);
    const Bytes chunk = r.get_bytes(count);
    out.insert(out.end(), chunk.begin(), chunk.end());
  }
  return out;
}

}  // namespace

// ------------------------------------------------------------------------------------------
// BitString

BitString BitString::from_uint(std::uint64_t value, std::size_t nbits) {
  if (nbits > 64) throw EncodeError("BitString::from_uint: more than 64 bits");
  if (nbits < 64 && (value >> nbits) != 0) {
    throw EncodeError("BitString::from_uint: value does not fit in " + str(nbits) + " bits");
  }
  BitWriter w;
  w.put_bits(value, static_cast<unsigned>(nbits));
  return BitString{w.bytes(), nbits};
}

std::uint64_t BitString::to_uint() const {
  if (length > 64) throw DecodeError("BitString::to_uint: more than 64 bits");
  std::uint64_t v = 0;
  for (std::size_t i = 0; i < length; ++i) v = (v << 1) | (bit(i) ? 1u : 0u);
  return v;
}

bool BitString::bit(std::size_t i) const {
  if (i >= length) throw std::out_of_range("BitString::bit: index out of range");
  return ((data.at(i / 8) >> (7 - i % 8)) & 1u) != 0;
}

bool BitString::operator==(const BitString& o) const {
  if (length != o.length) return false;
  for (std::size_t i = 0; i < length; ++i) {
    if (bit(i) != o.bit(i)) return false;
  }
  return true;
}

// ------------------------------------------------------------------------------------------
// BitWriter / BitReader

void BitWriter::put_bit(bool bit) {
  if (bits_ % 8 == 0) buf_.push_back(0);
  if (bit) buf_.back() = static_cast<std::uint8_t>(buf_.back() | (0x80u >> (bits_ % 8)));
  ++bits_;
}

void BitWriter::put_bits(std::uint64_t value, unsigned nbits) {
  if (nbits > 64) throw EncodeError("put_bits: more than 64 bits");
  for (unsigned i = nbits; i-- > 0;) put_bit(((value >> i) & 1u) != 0);
}

void BitWriter::put_bytes(const std::uint8_t* data, std::size_t len) {
  if (len == 0) return;
  if (bits_ % 8 == 0) {
    buf_.insert(buf_.end(), data, data + len);
    bits_ += 8 * len;
    return;
  }
  for (std::size_t i = 0; i < len; ++i) put_bits(data[i], 8);
}

void BitWriter::put_bit_string_bits(const BitString& bs) {
  for (std::size_t i = 0; i < bs.length; ++i) put_bit(bs.bit(i));
}

void BitWriter::align() {
  while (bits_ % 8 != 0) put_bit(false);
}

Bytes BitWriter::complete() const {
  Bytes out = buf_;
  if (out.empty()) out.push_back(0);
  return out;
}

BitReader::BitReader(const std::uint8_t* data, std::size_t len) : data_(data), len_bits_(len * 8) {}

void BitReader::need(std::size_t nbits) const {
  if (nbits > remaining()) {
    throw DecodeError("unexpected end of data: need " + str(nbits) + " bit(s) at bit offset " + str(pos_) + ", " +
                      str(remaining()) + " left");
  }
}

bool BitReader::get_bit() {
  need(1);
  const bool b = ((data_[pos_ / 8] >> (7 - pos_ % 8)) & 1u) != 0;
  ++pos_;
  return b;
}

std::uint64_t BitReader::get_bits(unsigned nbits) {
  if (nbits > 64) throw DecodeError("get_bits: more than 64 bits");
  need(nbits);
  std::uint64_t v = 0;
  for (unsigned i = 0; i < nbits; ++i) v = (v << 1) | (get_bit() ? 1u : 0u);
  return v;
}

void BitReader::get_bytes(std::uint8_t* out, std::size_t len) {
  need(len * 8);
  if (pos_ % 8 == 0) {
    std::copy(data_ + pos_ / 8, data_ + pos_ / 8 + len, out);
    pos_ += len * 8;
    return;
  }
  for (std::size_t i = 0; i < len; ++i) out[i] = static_cast<std::uint8_t>(get_bits(8));
}

Bytes BitReader::get_bytes(std::size_t len) {
  need(len * 8);
  Bytes b(len);
  get_bytes(b.data(), len);
  return b;
}

BitString BitReader::get_bit_string_bits(std::size_t nbits) {
  need(nbits);
  BitWriter w;
  for (std::size_t i = 0; i < nbits; ++i) w.put_bit(get_bit());
  return BitString{w.bytes(), nbits};
}

void BitReader::skip(std::size_t nbits) {
  need(nbits);
  pos_ += nbits;
}

void BitReader::align() { skip((8 - pos_ % 8) % 8); }

// ------------------------------------------------------------------------------------------
// Whole numbers and lengths

unsigned bits_for_range(std::uint64_t range) {
  if (range == 0) return 64;  // full 64-bit range wrapped around
  unsigned n = 0;
  for (std::uint64_t v = range - 1; v != 0; v >>= 1) ++n;
  return n;
}

void encode_constrained_whole_number(BitWriter& w, std::int64_t value, std::int64_t lb, std::int64_t ub) {
  if (lb > ub) throw EncodeError("constrained whole number: empty range");
  if (value < lb || value > ub) {
    throw EncodeError("value " + std::to_string(value) + " outside (" + std::to_string(lb) + ".." +
                      std::to_string(ub) + ")");
  }
  const std::uint64_t range = static_cast<std::uint64_t>(ub) - static_cast<std::uint64_t>(lb) + 1;
  w.put_bits(static_cast<std::uint64_t>(value) - static_cast<std::uint64_t>(lb), bits_for_range(range));
}

std::int64_t decode_constrained_whole_number(BitReader& r, std::int64_t lb, std::int64_t ub) {
  if (lb > ub) throw DecodeError("constrained whole number: empty range");
  const std::uint64_t span = static_cast<std::uint64_t>(ub) - static_cast<std::uint64_t>(lb);
  const std::uint64_t offset = r.get_bits(bits_for_range(span + 1));
  if (offset > span) {
    throw DecodeError("value " + std::to_string(static_cast<std::int64_t>(static_cast<std::uint64_t>(lb) + offset)) +
                      " outside (" + std::to_string(lb) + ".." + std::to_string(ub) + ")");
  }
  return static_cast<std::int64_t>(static_cast<std::uint64_t>(lb) + offset);
}

void encode_normally_small_number(BitWriter& w, std::uint64_t n) {
  if (n <= 63) {
    w.put_bit(false);
    w.put_bits(n, 6);
  } else {
    w.put_bit(true);
    encode_semi_constrained_whole_number(w, n);
  }
}

std::uint64_t decode_normally_small_number(BitReader& r) {
  if (!r.get_bit()) return r.get_bits(6);
  return decode_semi_constrained_whole_number(r);
}

void encode_normally_small_length(BitWriter& w, std::size_t n) {
  if (n == 0) throw EncodeError("normally small length must be >= 1");
  if (n <= 64) {
    w.put_bit(false);
    w.put_bits(n - 1, 6);
  } else {
    w.put_bit(true);
    encode_unconstrained_length(w, n);
  }
}

std::size_t decode_normally_small_length(BitReader& r) {
  if (!r.get_bit()) return static_cast<std::size_t>(r.get_bits(6)) + 1;
  return decode_unconstrained_length(r);
}

void encode_unconstrained_length(BitWriter& w, std::size_t n) {
  if (n < 128) {
    w.put_bits(n, 8);
  } else if (n < k16K) {
    w.put_bits(0x8000u | n, 16);
  } else {
    throw EncodeError("length " + str(n) + " needs fragmentation");
  }
}

std::size_t decode_unconstrained_length(BitReader& r) {
  bool more = false;
  const std::size_t n = decode_length_chunk(r, more);
  if (more) throw DecodeError("fragmented length not allowed here");
  return n;
}

void encode_semi_constrained_whole_number(BitWriter& w, std::uint64_t offset) {
  unsigned octets = 1;
  while (octets < 8 && (offset >> (8 * octets)) != 0) ++octets;
  encode_unconstrained_length(w, octets);
  w.put_bits(offset, 8 * octets);
}

std::uint64_t decode_semi_constrained_whole_number(BitReader& r) {
  const std::size_t octets = decode_unconstrained_length(r);
  if (octets == 0 || octets > 8) throw DecodeError("semi-constrained number of " + str(octets) + " octets");
  return r.get_bits(static_cast<unsigned>(8 * octets));
}

// ------------------------------------------------------------------------------------------
// Types

void encode_boolean(BitWriter& w, bool v) { w.put_bit(v); }
bool decode_boolean(BitReader& r) { return r.get_bit(); }

void encode_integer(BitWriter& w, std::int64_t v, std::int64_t lb, std::int64_t ub, bool extensible) {
  if (extensible) {
    const bool root = v >= lb && v <= ub;
    w.put_bit(!root);
    if (!root) {
      encode_unconstrained_integer(w, v);
      return;
    }
  }
  encode_constrained_whole_number(w, v, lb, ub);
}

std::int64_t decode_integer(BitReader& r, std::int64_t lb, std::int64_t ub, bool extensible) {
  if (extensible && r.get_bit()) return decode_unconstrained_integer(r);
  return decode_constrained_whole_number(r, lb, ub);
}

void encode_semi_constrained_integer(BitWriter& w, std::int64_t v, std::int64_t lb) {
  if (v < lb) throw EncodeError("semi-constrained integer below lower bound");
  encode_semi_constrained_whole_number(w, static_cast<std::uint64_t>(v) - static_cast<std::uint64_t>(lb));
}

std::int64_t decode_semi_constrained_integer(BitReader& r, std::int64_t lb) {
  return static_cast<std::int64_t>(static_cast<std::uint64_t>(lb) + decode_semi_constrained_whole_number(r));
}

void encode_unconstrained_integer(BitWriter& w, std::int64_t v) {
  unsigned octets = 1;
  while (octets < 8) {
    const std::int64_t hi = (std::int64_t{1} << (8 * octets - 1)) - 1;
    const std::int64_t lo = -hi - 1;
    if (v >= lo && v <= hi) break;
    ++octets;
  }
  encode_unconstrained_length(w, octets);
  w.put_bits(static_cast<std::uint64_t>(v), 8 * octets);
}

std::int64_t decode_unconstrained_integer(BitReader& r) {
  const std::size_t octets = decode_unconstrained_length(r);
  if (octets == 0 || octets > 8) throw DecodeError("integer of " + str(octets) + " octets unsupported");
  const unsigned nbits = static_cast<unsigned>(8 * octets);
  std::uint64_t raw = r.get_bits(nbits);
  if (nbits < 64 && ((raw >> (nbits - 1)) & 1u) != 0) raw |= ~std::uint64_t{0} << nbits;
  return static_cast<std::int64_t>(raw);
}

void encode_enumerated(BitWriter& w, unsigned index, unsigned root_count, bool extensible) {
  if (root_count == 0) throw EncodeError("ENUMERATED without root values");
  if (extensible) {
    const bool ext = index >= root_count;
    w.put_bit(ext);
    if (ext) {
      encode_normally_small_number(w, index - root_count);
      return;
    }
  } else if (index >= root_count) {
    throw EncodeError("ENUMERATED index " + str(index) + " outside " + str(root_count) + " values");
  }
  encode_constrained_whole_number(w, index, 0, root_count - 1);
}

unsigned decode_enumerated(BitReader& r, unsigned root_count, bool extensible) {
  if (extensible && r.get_bit()) {
    const std::uint64_t k = decode_normally_small_number(r);
    if (k > 0xFFFF) throw DecodeError("ENUMERATED extension index too large");
    return root_count + static_cast<unsigned>(k);
  }
  return static_cast<unsigned>(decode_constrained_whole_number(r, 0, root_count - 1));
}

void encode_choice_index(BitWriter& w, unsigned index, unsigned root_count, bool extensible) {
  if (index >= root_count) throw EncodeError("CHOICE index " + str(index) + " outside " + str(root_count));
  if (extensible) w.put_bit(false);
  encode_constrained_whole_number(w, index, 0, root_count - 1);
}

ChoiceIndex decode_choice_index(BitReader& r, unsigned root_count, bool extensible) {
  if (extensible && r.get_bit()) {
    const std::uint64_t k = decode_normally_small_number(r);
    if (k > 0xFFFF) throw DecodeError("CHOICE extension index too large");
    return {static_cast<unsigned>(k), true};
  }
  return {static_cast<unsigned>(decode_constrained_whole_number(r, 0, root_count - 1)), false};
}

void encode_choice_extension(BitWriter& w, unsigned ext_index, const Bytes& complete_encoding) {
  w.put_bit(true);
  encode_normally_small_number(w, ext_index);
  encode_open_type(w, complete_encoding);
}

void encode_length(BitWriter& w, std::size_t n, const Size& size) {
  const bool root = in_root(n, size);
  if (size.extensible) {
    w.put_bit(!root);
    if (!root) {
      encode_unconstrained_length(w, n);
      return;
    }
  } else if (!root) {
    throw EncodeError("size " + str(n) + " violates " + size_text(size));
  }
  if (small_bounded(size)) {
    if (*size.ub != size.lb) encode_constrained_whole_number(w, static_cast<std::int64_t>(n), size.lb, *size.ub);
    return;
  }
  encode_unconstrained_length(w, n);
}

std::size_t decode_length(BitReader& r, const Size& size) {
  if (size.extensible && r.get_bit()) return decode_unconstrained_length(r);
  if (small_bounded(size)) {
    if (*size.ub == size.lb) return size.lb;
    return static_cast<std::size_t>(decode_constrained_whole_number(r, size.lb, *size.ub));
  }
  const std::size_t n = decode_unconstrained_length(r);
  if (n < size.lb || (size.ub && n > *size.ub)) throw DecodeError("size " + str(n) + " violates " + size_text(size));
  return n;
}

void encode_bit_string(BitWriter& w, const BitString& v, const Size& size) {
  encode_length(w, v.length, size);
  w.put_bit_string_bits(v);
}

BitString decode_bit_string(BitReader& r, const Size& size) {
  const std::size_t n = decode_length(r, size);
  return r.get_bit_string_bits(n);
}

void encode_octet_string(BitWriter& w, const Bytes& v, const Size& size) {
  const std::size_t n = v.size();
  const bool root = in_root(n, size);
  if (size.extensible) {
    w.put_bit(!root);
  } else if (!root) {
    throw EncodeError("octet string of " + str(n) + " octets violates " + size_text(size));
  }
  if (root && small_bounded(size)) {
    if (*size.ub != size.lb) encode_constrained_whole_number(w, static_cast<std::int64_t>(n), size.lb, *size.ub);
    w.put_bytes(v);
    return;
  }
  encode_fragmented_octets(w, v.data(), n);
}

Bytes decode_octet_string(BitReader& r, const Size& size) {
  const bool ext = size.extensible && r.get_bit();
  if (!ext && small_bounded(size)) {
    const std::size_t n = (*size.ub == size.lb)
                              ? size.lb
                              : static_cast<std::size_t>(decode_constrained_whole_number(r, size.lb, *size.ub));
    return r.get_bytes(n);
  }
  Bytes v = decode_fragmented_octets(r);
  if (!ext && !in_root(v.size(), size)) {
    throw DecodeError("octet string of " + str(v.size()) + " octets violates " + size_text(size));
  }
  return v;
}

void encode_open_type(BitWriter& w, const Bytes& complete_encoding) {
  if (complete_encoding.empty()) throw EncodeError("open type requires a complete (non-empty) encoding");
  encode_fragmented_octets(w, complete_encoding.data(), complete_encoding.size());
}

Bytes decode_open_type(BitReader& r) {
  Bytes v = decode_fragmented_octets(r);
  if (v.empty()) throw DecodeError("empty open type");
  return v;
}

void encode_sequence_preamble(BitWriter& w, bool extensible, bool extensions_present,
                              std::initializer_list<bool> optionals) {
  if (extensible) {
    w.put_bit(extensions_present);
  } else if (extensions_present) {
    throw EncodeError("extension additions on a non-extensible SEQUENCE");
  }
  for (bool present : optionals) w.put_bit(present);
}

Preamble decode_sequence_preamble(BitReader& r, bool extensible, std::size_t optional_count) {
  Preamble p;
  if (extensible) p.extensions_present = r.get_bit();
  p.present.reserve(optional_count);
  for (std::size_t i = 0; i < optional_count; ++i) p.present.push_back(r.get_bit());
  return p;
}

void encode_extension_additions(BitWriter& w, const std::vector<std::optional<Bytes>>& additions) {
  const bool any = std::any_of(additions.begin(), additions.end(), [](const auto& a) { return a.has_value(); });
  if (!any) throw EncodeError("extension bit set but no extension addition present");
  encode_normally_small_length(w, additions.size());
  for (const auto& a : additions) w.put_bit(a.has_value());
  for (const auto& a : additions) {
    if (a) encode_open_type(w, *a);
  }
}

std::vector<std::optional<Bytes>> decode_extension_additions(BitReader& r) {
  const std::size_t n = decode_normally_small_length(r);
  std::vector<bool> present;
  present.reserve(n);
  for (std::size_t i = 0; i < n; ++i) present.push_back(r.get_bit());
  std::vector<std::optional<Bytes>> out(n);
  for (std::size_t i = 0; i < n; ++i) {
    if (present[i]) out[i] = decode_open_type(r);
  }
  return out;
}

}  // namespace nrlite::asn1
