#include "nrlite/common/bytes.hpp"

#include <cctype>

namespace nrlite {

namespace {

int hex_value(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

}  // namespace

std::string to_hex(const std::uint8_t* data, std::size_t len, bool spaced) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  out.reserve(len * (spaced ? 3 : 2));
  for (std::size_t i = 0; i < len; ++i) {
    if (spaced && i != 0) out.push_back(' ');
    out.push_back(kDigits[data[i] >> 4]);
    out.push_back(kDigits[data[i] & 0x0f]);
  }
  return out;
}

Bytes from_hex(std::string_view hex) {
  if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) hex.remove_prefix(2);
  Bytes out;
  int pending = -1;
  for (char c : hex) {
    if (std::isspace(static_cast<unsigned char>(c)) || c == ':') continue;
    const int v = hex_value(c);
    if (v < 0) throw std::invalid_argument(std::string("from_hex: invalid character '") + c + "'");
    if (pending < 0) {
      pending = v;
    } else {
      out.push_back(static_cast<std::uint8_t>((pending << 4) | v));
      pending = -1;
    }
  }
  if (pending >= 0) throw std::invalid_argument("from_hex: odd number of hex digits");
  return out;
}

}  // namespace nrlite
