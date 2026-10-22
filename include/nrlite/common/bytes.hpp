#pragma once

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace nrlite {

using Bytes = std::vector<std::uint8_t>;

/// Lower-case hex rendering, optionally with a space between octets.
std::string to_hex(const std::uint8_t* data, std::size_t len, bool spaced = false);

inline std::string to_hex(const Bytes& b, bool spaced = false) { return to_hex(b.data(), b.size(), spaced); }

template <std::size_t N>
std::string to_hex(const std::array<std::uint8_t, N>& a, bool spaced = false) {
  return to_hex(a.data(), N, spaced);
}

/// Parses a hex string, ignoring whitespace and an optional "0x" prefix.
/// Throws std::invalid_argument on an odd number of digits or a non-hex character.
Bytes from_hex(std::string_view hex);

template <std::size_t N>
std::array<std::uint8_t, N> array_from_hex(std::string_view hex) {
  const Bytes b = from_hex(hex);
  if (b.size() != N) {
    throw std::invalid_argument("array_from_hex: expected " + std::to_string(N) + " octets, got " +
                                std::to_string(b.size()));
  }
  std::array<std::uint8_t, N> out{};
  std::copy(b.begin(), b.end(), out.begin());
  return out;
}

template <std::size_t N>
Bytes to_bytes(const std::array<std::uint8_t, N>& a) {
  return Bytes(a.begin(), a.end());
}

/// Big-endian helpers used by the NAS and trace code.
inline void put_u16(Bytes& out, std::uint16_t v) {
  out.push_back(static_cast<std::uint8_t>(v >> 8));
  out.push_back(static_cast<std::uint8_t>(v));
}

inline void put_u32(Bytes& out, std::uint32_t v) {
  for (int shift = 24; shift >= 0; shift -= 8) out.push_back(static_cast<std::uint8_t>(v >> shift));
}

}  // namespace nrlite
