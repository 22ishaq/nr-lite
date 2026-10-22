#pragma once

#include <cstdint>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace nrlite {

/// Tiny ordered JSON value used to render decoded messages. Keys follow the ASN.1 / 3GPP field
/// names (e.g. "establishmentCause") so that test tooling can match on spec names directly.
class Json {
 public:
  using Array = std::vector<Json>;
  using Object = std::vector<std::pair<std::string, Json>>;

  Json() : v_(nullptr) {}
  Json(std::nullptr_t) : v_(nullptr) {}  // NOLINT
  Json(bool b) : v_(b) {}                // NOLINT
  template <typename T, typename = std::enable_if_t<std::is_integral_v<T> && !std::is_same_v<T, bool>>>
  Json(T v) : v_(static_cast<std::int64_t>(v)) {}  // NOLINT
  Json(const char* s) : v_(std::string(s)) {}      // NOLINT
  Json(std::string s) : v_(std::move(s)) {}        // NOLINT

  static Json object() {
    Json j;
    j.v_ = Object{};
    return j;
  }
  static Json array() {
    Json j;
    j.v_ = Array{};
    return j;
  }

  /// Object: sets (or replaces) a key. Returns *this for chaining.
  Json& set(const std::string& key, Json value);
  /// Array: appends a value.
  Json& push(Json value);

  bool is_object() const { return std::holds_alternative<Object>(v_); }
  bool is_array() const { return std::holds_alternative<Array>(v_); }
  /// Object lookup; returns nullptr when absent or not an object.
  const Json* find(const std::string& key) const;
  const std::string* as_string() const { return std::get_if<std::string>(&v_); }
  const std::int64_t* as_int() const { return std::get_if<std::int64_t>(&v_); }

  std::string dump() const;

 private:
  void dump_to(std::string& out) const;
  std::variant<std::nullptr_t, bool, std::int64_t, std::string, Array, Object> v_;
};

}  // namespace nrlite
